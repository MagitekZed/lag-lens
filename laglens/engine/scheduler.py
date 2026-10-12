"""The ICMP engine: one thread, two DGRAM sockets, a 250 ms slot grid (SPEC_FULL §5.1).

``Engine(ctx)`` → ``.start()`` / ``.stop(timeout)`` / ``.stats()``.

* **Sockets**: one unconnected non-blocking DGRAM ICMP socket per address
  family, registered in a ``selectors.DefaultSelector`` together with a
  self-pipe for wake-ups. A family whose socket cannot be opened
  (``PermissionError`` / ``EACCES`` / ``EPROTONOSUPPORT``) falls back to the
  ping-binary backend (:mod:`laglens.probes.pingbin`); without a ping binary
  the family's targets are disabled with a visible reason. ``IP_RECVERR`` is
  **never** enabled on these sockets (SPEC §4.12).
* **Grid**: slot ``k`` starts at ``state.slot_origin_ms + k × 250 ms``; each
  target sends at ``slot start + (id × 23) mod 200 ms``. A 4 Hz target sends
  every slot, 2 Hz every other slot, 1 Hz every fourth. ``next_send`` is
  computed from the grid (never from ``last_send``) so there is no drift;
  after a long stall (laptop sleep) the schedule skips ahead instead of
  bursting. The selector timeout is ``min(next deadline) − now``, floor 1 ms.
* **Pending table** keyed ``(target_id, seq)``; a 100 ms sweep marks entries
  older than ``timeout_ms`` **lost** (``value -1``, ``F_LOST``); a reply for
  a lost seq within ``late_window_ms`` is recorded as a second sample with
  ``F_LATE`` and the real RTT; then the entry is forgotten. RTT comes from
  the pending table's monotonic send time; the payload copy is only a
  cross-check. Replies must carry our magic + cookie (macOS delivers other
  processes' replies to every ICMP socket).
* **Flags**: ``slot = state.slot_for(ts_ms)``; ``F_LOADTEST`` while
  ``state.loadtest['running']``; ``F_XBOX_ASLEEP`` on the xbox target while
  ``state.xbox['state'] == 'asleep'``; ``F_STALL`` on the samples of a wall
  second in which a send was > 50 ms late or the loop gap exceeded 200 ms
  (``stats()`` exposes ``late_ms_max`` / ``loop_gap_ms`` for the host collector).
* **Dynamic targets**: every second the enabled ICMP targets are re-read from
  ``state.targets_list()`` (the tracer and the Xbox collector add targets
  later; ``enabled=False`` is respected).
* **gw6 no_responder**: 60 s with zero replies from the first send → the
  target is disabled ("IPv6 gateway does not answer ping") and a note raised.
* **macOS Local Network privacy**: ``EHOSTUNREACH`` (errno 65) on sends to a
  LAN target while an internet target replied within the last 10 s → every
  LAN ICMP target is disabled with reason ``local network permission``, the
  engine is ``degraded`` with the user message (terminal app name from
  ``platform.terminal_app_name()``), one ``probe_error`` note is raised, and
  the targets are retried every 60 s (re-enabled when a send succeeds).
* Any other ``OSError`` on send → an ``F_ERROR`` sample carrying the errno.

Every sample goes ``state.add_sample(s)`` then ``store.append_sample(s)``.
The loop body runs under the supervisor (``engine=True``: always restarted)
and never lets a bad packet or a registry failure escape.
"""
from __future__ import annotations

import errno
import ipaddress
import logging
import math
import os
import selectors
import sys
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from laglens.platform import is_private
from laglens.probes.icmp import (
    REPLIES_HAVE_IP_HEADER,
    build_echo,
    is_fallback_error,
    open_icmp_socket,
    parse_reply,
    sockaddr_for,
)
from laglens.probes.pingbin import PingBackend, find_ping_binary
from laglens.state import (
    F_ERROR,
    F_LATE,
    F_LOADTEST,
    F_LOST,
    F_STALL,
    F_XBOX_ASLEEP,
    KIND_ICMP,
    ON_GRID_KINDS,
    SLOT_MS,
    Sample,
    Target,
)
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.engine")

SLOT_S = SLOT_MS / 1000.0
SLOTS_PER_S = int(round(1000 / SLOT_MS))  # 4
STAGGER_MUL = 23
STAGGER_MOD_MS = 200
SWEEP_S = 0.1
TICK_S = 1.0
LATE_STALL_MS = 50.0
GAP_STALL_MS = 200.0
GW6_NO_RESPONDER_S = 60.0
LAN_RETRY_S = 60.0
INET_EVIDENCE_S = 10.0
MIN_TIMEOUT_S = 0.001
MAX_TIMEOUT_S = 0.25
SEND_SLACK_S = 0.0005
MAX_RECV_PER_WAKE = 64
RATE_CAP_HZ = 5.0
REANCHOR_MS = 10.0
STALL_KEEP_S = 120
ERROR_LOG_INTERVAL_S = 60.0

LAN_REASON = "local network permission"
GW6_REASON = "IPv6 gateway does not answer ping"
NO_CAPABILITY_REASON = "no ICMP capability (socket EACCES and no ping binary)"
LOCAL_NETWORK_MSG = (
    "macOS blocked traffic to your local network for this app. Open System Settings > Privacy & Security > "
    "Local Network and enable %s, then restart Lag Lens. (The first run usually shows a prompt — click Allow.)"
)


class _Sched:
    """Per-target schedule state (socket backend only)."""

    __slots__ = (
        "target", "tid", "key", "family", "sockaddr", "period", "offset_s", "next_slot", "next_send", "seq", "lan",
        "sent", "received", "lost", "errors", "first_send", "last_reply", "last_error", "last_error_log",
    )

    def __init__(self, target: Target, period: int, offset_s: float, sockaddr: Tuple[Any, ...], lan: bool) -> None:
        self.target = target
        self.tid = target.id
        self.key = target.key
        self.family = 6 if target.family == 6 else 4
        self.sockaddr = sockaddr
        self.period = period
        self.offset_s = offset_s
        self.next_slot = 0
        self.next_send = 0.0
        self.seq = 0
        self.lan = lan
        self.sent = 0
        self.received = 0
        self.lost = 0
        self.errors = 0
        self.first_send: Optional[float] = None
        self.last_reply: Optional[float] = None
        self.last_error: Optional[str] = None
        self.last_error_log: float = -1e9


class _Pending:
    """One in-flight (or recently lost) probe."""

    __slots__ = ("tid", "key", "seq", "t_send", "t_send_ns", "ts_ms", "flags", "lost", "done")

    def __init__(self, tid: int, key: str, seq: int, t_send: float, t_send_ns: int, ts_ms: int, flags: int) -> None:
        self.tid = tid
        self.key = key
        self.seq = seq
        self.t_send = t_send
        self.t_send_ns = t_send_ns
        self.ts_ms = ts_ms
        self.flags = flags
        self.lost = False
        self.done = False


class _SecondStats:
    __slots__ = ("sent", "late_ms_max", "gap_ms_max", "stall")

    def __init__(self) -> None:
        self.sent = 0
        self.late_ms_max = 0.0
        self.gap_ms_max = 0.0
        self.stall = False


def period_for_rate(rate_hz: float, cap: float = RATE_CAP_HZ) -> int:
    """Slots between sends for ``rate_hz``: 4 Hz → 1, 2 Hz → 2, 1 Hz → 4 (≥ 4 Hz → every slot)."""
    try:
        rate = float(rate_hz)
    except (TypeError, ValueError):
        rate = 4.0
    if not rate or rate <= 0:
        rate = 4.0
    rate = min(rate, cap)
    return max(1, int(round(SLOTS_PER_S / rate)))


def stagger_ms(target_id: int) -> int:
    """Fixed per-target offset inside the slot: ``(id × 23) mod 200`` ms."""
    return (int(target_id) * STAGGER_MUL) % STAGGER_MOD_MS


class Engine:
    """The ICMP probe engine (see the module docstring)."""

    def __init__(
        self,
        ctx: Any,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        socket_factory: Optional[Callable[[int], Any]] = None,
        selector_factory: Optional[Callable[[], Any]] = None,
        pingbin_factory: Optional[Callable[..., Any]] = None,
        has_ip_header: Optional[bool] = None,
        platform_name: Optional[str] = None,
        nametoindex: Optional[Callable[[str], int]] = None,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.platform = ctx.platform
        self.cfg: dict = ctx.cfg or {}
        self.platform_name = platform_name or getattr(self.platform, "name", None) or sys.platform
        self._clock = clock
        self._wall = wall
        self._socket_factory = socket_factory or open_icmp_socket
        self._selector_factory = selector_factory or selectors.DefaultSelector
        self._pingbin_factory = pingbin_factory or self._default_pingbin
        if has_ip_header is None:
            has_ip_header = (self.platform_name != "linux") if platform_name else REPLIES_HAVE_IP_HEADER
        self._has_ip_header = bool(has_ip_header)
        self._nametoindex = nametoindex
        self.timeout_s = float(self.cfg.get("timeout_ms", 2000) or 2000) / 1000.0
        self.late_window_s = float(self.cfg.get("late_window_ms", 10000) or 10000) / 1000.0
        if self.late_window_s < self.timeout_s:
            self.late_window_s = self.timeout_s

        self.sockets: Dict[int, Any] = {}
        self.backend: Dict[int, Optional[str]] = {4: None, 6: None}
        self.backend_reason: Dict[int, Optional[str]] = {4: None, 6: None}
        self.pingbins: Dict[int, Any] = {}

        self._sched: Dict[int, _Sched] = {}
        self._pending: Dict[Tuple[int, int], _Pending] = {}
        self._awaiting: Deque[_Pending] = deque()
        self._lost_q: Deque[_Pending] = deque()

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._selector: Any = None
        self._pipe_r: Optional[int] = None
        self._pipe_w: Optional[int] = None
        self._mono_origin: float = 0.0
        self._last_loop: Optional[float] = None
        self._next_sweep: float = 0.0
        self._next_tick: float = 0.0
        self._started_at: Optional[float] = None

        self._lock = threading.Lock()
        self._cur = _SecondStats()
        self._last = _SecondStats()
        self._stall_seconds: Dict[int, bool] = {}
        self.totals: Dict[str, int] = {
            "sent": 0, "received": 0, "lost": 0, "late": 0, "errors": 0, "foreign": 0, "stray": 0,
            "icmp_errors": 0, "recv_errors": 0, "missed": 0, "loops": 0,
        }

        self._inet_last_reply: Optional[float] = None
        self._lan_blocked: Dict[str, Target] = {}
        self._next_lan_retry: float = 0.0
        self._lan_msg: Optional[str] = None
        self._lan_net4: Optional[Any] = None
        self._lan_net6: Optional[Any] = None
        self._gw6_done = False
        self._rate_warned = False

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Open the sockets (or arrange the fallback) and start the loop thread."""
        self._open_sockets()
        self._refresh_lan_net()
        self._started_at = self._clock()
        self._thread = start_thread("engine", self._loop, self.state, stop_event=self._stop, engine=True)

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the loop, the ping children and close the sockets."""
        self._stop.set()
        self.wake()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout)
        for pb in list(self.pingbins.values()):
            try:
                pb.stop(timeout)
            except Exception:  # noqa: BLE001
                log.exception("engine: pingbin stop failed")
        for s in list(self.sockets.values()):
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        self.sockets.clear()
        self._close_pipe()

    def wake(self) -> None:
        """Interrupt the selector wait (safe from any thread)."""
        w = self._pipe_w
        if w is None:
            return
        try:
            os.write(w, b"x")
        except OSError:
            pass

    def stats(self) -> dict:
        """Loop health for the host collector: ``pps``, ``late_ms_max``, ``loop_gap_ms``, ``stall`` + totals."""
        with self._lock:
            cur, last = self._cur, self._last
            d = {
                "pps": last.sent,
                "late_ms_max": round(max(cur.late_ms_max, last.late_ms_max), 1),
                "loop_gap_ms": round(max(cur.gap_ms_max, last.gap_ms_max), 1),
                "stall": bool(cur.stall or last.stall),
            }
        d.update(self.totals)
        d["pending"] = len(self._pending)
        d["targets"] = len(self._sched)
        d["backend"] = {"4": self.backend.get(4), "6": self.backend.get(6)}
        d["local_network"] = "denied" if self._lan_blocked else "ok"
        d["uptime_s"] = round(self._clock() - self._started_at, 1) if self._started_at is not None else 0.0
        d["pingbin"] = {str(f): pb.stats() for f, pb in self.pingbins.items()} if self.pingbins else {}
        return d

    # ------------------------------------------------------------- sockets
    def _default_pingbin(self, ctx: Any, family: int, emit: Callable[[Sample], None], binary: Optional[str]) -> Any:
        return PingBackend(ctx, family, emit, binary=binary, clock=self._clock, wall=self._wall,
                           platform_name=self.platform_name)

    def _open_sockets(self) -> None:
        for fam in (4, 6):
            if fam in self.sockets:
                continue
            try:
                self.sockets[fam] = self._socket_factory(fam)
                self.backend[fam] = "socket"
                self.backend_reason[fam] = None
                continue
            except OSError as exc:
                err = exc
            desc = "IPv%d ICMP socket: %s" % (fam, err.strerror or str(err))
            if is_fallback_error(err):
                binary = None
                try:
                    binary = find_ping_binary(self.platform, fam)
                except Exception:  # noqa: BLE001
                    binary = None
                if binary:
                    try:
                        self.pingbins[fam] = self._pingbin_factory(self.ctx, fam, self._emit_external, binary)
                        self.backend[fam] = "pingbin"
                        self.backend_reason[fam] = "%s; using %s (ping-binary backend)" % (desc, binary)
                        log.warning("engine: %s", self.backend_reason[fam])
                        continue
                    except Exception as exc2:  # noqa: BLE001
                        desc = "%s; ping backend failed: %s" % (desc, exc2)
                self.backend[fam] = None
                self.backend_reason[fam] = "IPv%d: %s" % (fam, NO_CAPABILITY_REASON)
            else:
                self.backend[fam] = None
                self.backend_reason[fam] = desc
            log.warning("engine: %s", self.backend_reason[fam])

    def _open_pipe(self) -> None:
        if self._pipe_r is not None:
            return
        r, w = os.pipe()
        os.set_blocking(r, False)
        os.set_blocking(w, False)
        self._pipe_r, self._pipe_w = r, w

    def _close_pipe(self) -> None:
        for fd in (self._pipe_r, self._pipe_w):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._pipe_r = self._pipe_w = None

    # ---------------------------------------------------------------- loop
    def _loop(self) -> None:
        """Thread body (supervised): set up, iterate until stop, tear down."""
        self._setup()
        try:
            while not self._stop.is_set() and not self.state.stop_event.is_set():
                self._iterate()
        finally:
            if self.state.stop_event.is_set():
                self._stop.set()
            self._teardown_selector()

    def _setup(self) -> None:
        """(Re)create the selector, register sockets + self-pipe, anchor the grid."""
        self._open_pipe()
        self._teardown_selector()
        self._selector = self._selector_factory()
        for fam, s in self.sockets.items():
            self._selector.register(s, selectors.EVENT_READ, ("sock", fam))
        if self._pipe_r is not None:
            self._selector.register(self._pipe_r, selectors.EVENT_READ, ("pipe", 0))
        now = self._clock()
        self._reanchor(now, force=True)
        self._last_loop = now
        self._next_sweep = now + SWEEP_S
        self._next_tick = now + TICK_S
        if self._started_at is None:
            self._started_at = now
        self._refresh_lan_net()
        self._rescan(now)
        self._announce_status()

    def _teardown_selector(self) -> None:
        if self._selector is not None:
            try:
                self._selector.close()
            except Exception:  # noqa: BLE001
                pass
            self._selector = None

    def _iterate(self) -> None:
        """One scheduler cycle: send due probes, wait, receive, sweep, tick."""
        now = self._clock()
        self.totals["loops"] += 1
        if self._last_loop is not None:
            gap_ms = (now - self._last_loop) * 1000.0
            if gap_ms > self._cur.gap_ms_max:
                self._cur.gap_ms_max = gap_ms
            if gap_ms > GAP_STALL_MS:
                self._mark_stall_span(now - self._last_loop)
        self._last_loop = now
        self._send_due(now)
        timeout = self._next_deadline() - self._clock()
        timeout = min(MAX_TIMEOUT_S, max(MIN_TIMEOUT_S, timeout))
        try:
            events = self._selector.select(timeout) if self._selector is not None else []
        except (OSError, ValueError) as exc:  # a closed fd during stop
            log.debug("engine: select failed: %s", exc)
            events = []
            if self._stop.is_set():
                return
        for key, _mask in events:
            kind, fam = key.data
            if kind == "pipe":
                self._drain_pipe()
            else:
                self._recv(fam, key.fileobj)
        now = self._clock()
        if now >= self._next_sweep:
            self._sweep(now)
            self._next_sweep = now + SWEEP_S
        if now >= self._next_tick:
            self._tick(now)
            self._next_tick = now + TICK_S

    def _drain_pipe(self) -> None:
        if self._pipe_r is None:
            return
        try:
            while os.read(self._pipe_r, 4096):
                pass
        except (BlockingIOError, InterruptedError, OSError):
            pass

    def _next_deadline(self) -> float:
        nxt = min(self._next_sweep, self._next_tick)
        for sch in self._sched.values():
            if sch.next_send < nxt:
                nxt = sch.next_send
        return nxt

    # ---------------------------------------------------------------- grid
    def _reanchor(self, now: float, force: bool = False) -> None:
        """Map the wall-clock slot origin onto the monotonic clock (re-done on clock jumps)."""
        wall_now = self._wall()
        origin = now - (wall_now - self.state.slot_origin_ms / 1000.0)
        if force or abs(origin - self._mono_origin) * 1000.0 > REANCHOR_MS:
            if not force:
                log.info("engine: wall clock moved %.0f ms against the monotonic clock; re-anchoring the slot grid",
                         (origin - self._mono_origin) * 1000.0)
            self._mono_origin = origin
            for sch in self._sched.values():
                self._schedule_from(sch, now)

    def _send_time(self, sch: _Sched, slot: int) -> float:
        return self._mono_origin + slot * SLOT_S + sch.offset_s

    def _schedule_from(self, sch: _Sched, now: float) -> None:
        """First grid send time ``>= now`` that fits the target's period."""
        k = int(math.floor((now - self._mono_origin - sch.offset_s) / SLOT_S))
        if self._send_time(sch, k) < now - 1e-9:
            k += 1
        k = int(math.ceil(k / float(sch.period))) * sch.period
        sch.next_slot = k
        sch.next_send = self._send_time(sch, k)

    def _advance(self, sch: _Sched, now: float) -> None:
        k = sch.next_slot + sch.period
        t = self._send_time(sch, k)
        if t < now - SLOT_S * sch.period:
            # more than a whole period behind (sleep, long stall): skip ahead instead of bursting
            before = k
            self._schedule_from(sch, now)
            self.totals["missed"] += max(0, (sch.next_slot - before) // sch.period)
            return
        sch.next_slot = k
        sch.next_send = t

    # --------------------------------------------------------------- sends
    def _send_due(self, now: float) -> None:
        for sch in list(self._sched.values()):
            if now - sch.next_send > SLOT_S * sch.period:
                # more than a whole period overdue (sleep, long stall): skip ahead, never burst or send off-grid
                before = sch.next_slot
                self._schedule_from(sch, now)
                self.totals["missed"] += max(0, (sch.next_slot - before) // sch.period)
            guard = 0
            while sch.next_send <= now + SEND_SLACK_S and guard < 4:
                self._send_one(sch, now)
                guard += 1
                now = self._clock()

    def _send_one(self, sch: _Sched, now: float) -> None:
        sock = self.sockets.get(sch.family)
        if sock is None:
            self._advance(sch, now)
            return
        seq = sch.seq
        sch.seq = (sch.seq + 1) & 0xFFFFFFFF
        lateness_ms = max(0.0, (now - sch.next_send) * 1000.0)
        wall_now = self._wall()
        ts_ms = int(round(wall_now * 1000.0))
        with self._lock:
            if lateness_ms > self._cur.late_ms_max:
                self._cur.late_ms_max = lateness_ms
            if lateness_ms > LATE_STALL_MS:
                self._cur.stall = True
                self._stall_seconds[ts_ms // 1000] = True
        t_send_ns = int(now * 1e9)
        pkt = build_echo(sch.family, seq, sch.tid, t_send_ns)
        flags = F_LOADTEST if self.state.loadtest.get("running") else 0
        if sch.first_send is None:
            sch.first_send = now  # first attempt, successful or not (gw6 no_responder counts from here)
        try:
            sock.sendto(pkt, sch.sockaddr)
        except OSError as exc:
            self._on_send_error(sch, exc, seq, ts_ms, now, flags)
            self._advance(sch, now)
            return
        self.totals["sent"] += 1
        self._cur.sent += 1
        sch.sent += 1
        entry = _Pending(sch.tid, sch.key, seq, now, t_send_ns, ts_ms, flags)
        self._pending[(sch.tid, seq)] = entry
        self._awaiting.append(entry)
        self._advance(sch, now)

    def _on_send_error(self, sch: _Sched, exc: OSError, seq: int, ts_ms: int, now: float, flags: int) -> None:
        code = int(getattr(exc, "errno", None) or 0)
        self.totals["errors"] += 1
        sch.errors += 1
        sch.last_error = "%s (errno %d)" % (exc.strerror or exc, code)
        lan_detected = False
        if code == errno.EHOSTUNREACH and sch.lan and self.platform_name == "darwin":
            lan_detected = self._lan_detect(sch, now)
        if not lan_detected and now - sch.last_error_log >= ERROR_LOG_INTERVAL_S:
            sch.last_error_log = now
            log.warning("engine: send to %s (%s) failed: %s", sch.key, sch.target.addr, sch.last_error)
        self._emit(Sample(ts_ms=ts_ms, target_id=sch.tid, kind=KIND_ICMP, flags=flags | F_ERROR, seq=seq, value=code),
                   sch.key)

    # ------------------------------------------------------------- receive
    def _recv(self, fam: int, sock: Any) -> None:
        for _ in range(MAX_RECV_PER_WAKE):
            try:
                buf, addr = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                self.totals["recv_errors"] += 1
                log.debug("engine: recvfrom v%d: %s", fam, exc)
                return
            try:
                self._handle_datagram(fam, buf, addr)
            except Exception:  # noqa: BLE001 - one odd packet must not stop the engine
                self.totals["foreign"] += 1
                log.exception("engine: bad datagram from %r", addr)

    def _handle_datagram(self, fam: int, buf: bytes, addr: Any) -> None:
        now = self._clock()
        now_ns = int(now * 1e9)
        reply = parse_reply(fam, buf, self._has_ip_header)
        if reply is None:
            self.totals["foreign"] += 1
            return
        if not reply.is_echo_reply:
            if reply.is_error:
                self.totals["icmp_errors"] += 1
            return
        p = reply.payload
        if p is None or not p.matches():
            self.totals["foreign"] += 1
            return
        key = (p.target_id, p.seq)
        entry = self._pending.get(key)
        if entry is None or entry.done:
            self.totals["stray"] += 1
            return
        rtt_us = max(0, (now_ns - entry.t_send_ns) // 1000)
        entry.done = True
        del self._pending[key]
        sch = self._sched.get(entry.tid)
        if entry.lost:
            if now - entry.t_send <= self.late_window_s:
                self.totals["late"] += 1
                self._emit(Sample(ts_ms=entry.ts_ms, target_id=entry.tid, kind=KIND_ICMP, flags=entry.flags | F_LATE,
                                  seq=entry.seq, value=int(rtt_us)), entry.key)
            return
        self.totals["received"] += 1
        if sch is not None:
            sch.received += 1
            sch.last_reply = now
            if not sch.lan:
                self._inet_last_reply = now
        self._emit(Sample(ts_ms=entry.ts_ms, target_id=entry.tid, kind=KIND_ICMP, flags=entry.flags, seq=entry.seq,
                          value=int(rtt_us)), entry.key)

    # --------------------------------------------------------------- sweep
    def _sweep(self, now: float) -> None:
        aw = self._awaiting
        while aw:
            e = aw[0]
            if e.done:
                aw.popleft()
                continue
            if now - e.t_send < self.timeout_s:
                break
            aw.popleft()
            e.lost = True
            self.totals["lost"] += 1
            sch = self._sched.get(e.tid)
            if sch is not None:
                sch.lost += 1
            self._emit(Sample(ts_ms=e.ts_ms, target_id=e.tid, kind=KIND_ICMP, flags=e.flags | F_LOST, seq=e.seq, value=-1),
                       e.key)
            self._lost_q.append(e)
        lq = self._lost_q
        while lq:
            e = lq[0]
            if e.done:
                lq.popleft()
                continue
            if now - e.t_send < self.late_window_s:
                break
            lq.popleft()
            e.done = True
            self._pending.pop((e.tid, e.seq), None)

    # ---------------------------------------------------------------- emit
    def _emit(self, s: Sample, key: str) -> None:
        """Finalise flags and slot, then ``state.add_sample`` + ``store.append_sample``."""
        try:
            if key == "xbox" and (self.state.xbox or {}).get("state") == "asleep":
                s.flags |= F_XBOX_ASLEEP
            if self._stall_seconds.get(s.ts_ms // 1000):
                s.flags |= F_STALL
            if s.kind in ON_GRID_KINDS:
                s.slot = self.state.slot_for(s.ts_ms)
            self.state.add_sample(s)
        except Exception:  # noqa: BLE001
            log.exception("engine: state.add_sample failed")
            return
        try:
            self.store.append_sample(s)
        except Exception:  # noqa: BLE001
            log.exception("engine: store.append_sample failed")

    def _emit_external(self, s: Sample) -> None:
        """Entry point for the ping-binary backend (its samples already carry ``F_FALLBACK``)."""
        t = self.state.target_by_id(s.target_id)
        if self.state.loadtest.get("running"):
            s.flags |= F_LOADTEST
        self._emit(s, t.key if t is not None else "")

    def _mark_stall_span(self, span_s: float) -> None:
        wall_now = self._wall()
        end = int(wall_now)
        start = int(wall_now - min(span_s, 30.0))
        with self._lock:
            self._cur.stall = True
            for sec in range(start, end + 1):
                self._stall_seconds[sec] = True

    # ---------------------------------------------------------------- tick
    def _tick(self, now: float) -> None:
        with self._lock:
            self._last = self._cur
            self._cur = _SecondStats()
        try:
            self._reanchor(now)
            self._refresh_lan_net()
            self._rescan(now)
            self._check_gw6(now)
            self._lan_retry(now)
            self._prune_stalls()
            self._announce_status()
        except Exception:  # noqa: BLE001 - housekeeping must never kill the loop
            log.exception("engine: tick failed")

    def _prune_stalls(self) -> None:
        if len(self._stall_seconds) > STALL_KEEP_S:
            cutoff = int(self._wall()) - STALL_KEEP_S
            with self._lock:
                for sec in [k for k in self._stall_seconds if k < cutoff]:
                    del self._stall_seconds[sec]

    def _refresh_lan_net(self) -> None:
        route = getattr(self.ctx, "route", None) or {}
        lan_ip = route.get("lan_ip")
        plen = route.get("prefixlen")
        net4 = None
        if lan_ip and plen:
            try:
                net4 = ipaddress.ip_network("%s/%d" % (lan_ip, int(plen)), strict=False)
            except ValueError:
                net4 = None
        self._lan_net4 = net4

    def _is_lan(self, addr: Optional[str]) -> bool:
        """Whether ``addr`` is on the local link (gateway, Xbox…), i.e. subject to Local Network privacy."""
        if not addr:
            return False
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return False
        if ip.is_link_local or ip.is_loopback:
            return True
        if ip.version == 4 and self._lan_net4 is not None:
            return ip in self._lan_net4
        if ip.version == 6:
            return False
        return is_private(addr)

    def _announce_status(self) -> None:
        reasons = [r for r in (self.backend_reason.get(4), self.backend_reason.get(6)) if r]
        status = "ok"
        reason: Optional[str] = None
        if reasons:
            status = "degraded"
            reason = "; ".join(reasons)
        if self._lan_msg:
            status = "degraded"
            reason = self._lan_msg if reason is None else "%s; %s" % (self._lan_msg, reason)
        try:
            self.state.set_collector(
                "engine", status, reason=reason, backend4=self.backend.get(4), backend6=self.backend.get(6),
                local_network="denied" if self._lan_blocked else "ok", targets=len(self._sched),
            )
        except Exception:  # noqa: BLE001
            log.exception("engine: set_collector failed")

    # ------------------------------------------------------------- targets
    def _rescan(self, now: float) -> None:
        """Re-read the ICMP targets: schedule new ones, drop disabled ones, feed the ping backend."""
        try:
            targets = self.state.targets_list()
        except Exception:  # noqa: BLE001
            log.exception("engine: targets_list failed")
            return
        want: Dict[int, Target] = {}
        pingbin_targets: Dict[int, List[Target]] = {4: [], 6: []}
        for t in targets:
            if t.kind != "icmp":
                continue
            fam = 6 if t.family == 6 else 4
            be = self.backend.get(fam)
            if be is None:
                if t.enabled and t.addr:
                    self.state.set_target_state(t.key, enabled=False, reason=self.backend_reason.get(fam) or NO_CAPABILITY_REASON)
                continue
            if not t.enabled or not t.addr or t.mode != "direct":
                continue
            if be == "pingbin":
                if t.backend != "pingbin":
                    self.state.set_target_state(t.key, backend="pingbin")
                pingbin_targets[fam].append(t)
                continue
            if float(t.rate_hz or 0) > SLOTS_PER_S and not self._rate_warned:
                self._rate_warned = True
                log.info("engine: rate_hz %.1f exceeds the 250 ms grid; probing at %d Hz", float(t.rate_hz), SLOTS_PER_S)
            want[t.id] = t
        for fam, pb in self.pingbins.items():
            try:
                pb.sync(pingbin_targets[fam])
            except Exception:  # noqa: BLE001
                log.exception("engine: pingbin sync failed")
        for tid in [tid for tid in self._sched if tid not in want]:
            del self._sched[tid]
        for tid, t in want.items():
            fam = 6 if t.family == 6 else 4
            period = period_for_rate(t.rate_hz)
            try:
                sockaddr = (sockaddr_for(t.addr, fam, nametoindex=self._nametoindex) if self._nametoindex
                            else sockaddr_for(t.addr, fam))
            except Exception as exc:  # noqa: BLE001
                log.warning("engine: bad address %r for %s: %s", t.addr, t.key, exc)
                continue
            sch = self._sched.get(tid)
            if sch is None:
                sch = _Sched(t, period, stagger_ms(tid) / 1000.0, sockaddr, self._is_lan(t.addr))
                self._schedule_from(sch, now)
                self._sched[tid] = sch
                log.info("engine: probing %s (%s) at %.2g Hz, offset %d ms", t.key, t.addr, SLOTS_PER_S / period,
                         stagger_ms(tid))
                continue
            sch.target = t
            sch.key = t.key
            sch.sockaddr = sockaddr
            sch.lan = self._is_lan(t.addr)
            if sch.period != period:
                sch.period = period
                self._schedule_from(sch, now)

    def _sched_by_key(self, key: str) -> Optional[_Sched]:
        for sch in self._sched.values():
            if sch.key == key:
                return sch
        return None

    def _check_gw6(self, now: float) -> None:
        if self._gw6_done:
            return
        sch = self._sched_by_key("gw6")
        if sch is None or sch.first_send is None:
            return
        if sch.received > 0:
            self._gw6_done = True
            return
        if now - sch.first_send < GW6_NO_RESPONDER_S:
            return
        self._gw6_done = True
        log.warning("engine: %s after %d s (%d probes): disabling gw6", GW6_REASON, int(GW6_NO_RESPONDER_S), sch.sent)
        self.state.set_target_state("gw6", enabled=False, reason=GW6_REASON)
        self.state.raise_note("probe_error", target=sch.tid, severity=1, note=GW6_REASON, key="gw6", sent=sch.sent,
                              reason="no_responder")
        self._sched.pop(sch.tid, None)

    # ------------------------------------------------ macOS Local Network
    def _lan_detect(self, sch: _Sched, now: float) -> bool:
        """EHOSTUNREACH to a LAN target while the internet answers → Local Network permission denied."""
        if self._inet_last_reply is None or now - self._inet_last_reply > INET_EVIDENCE_S:
            return False
        first = not self._lan_blocked
        try:
            app = self.platform.terminal_app_name()
        except Exception:  # noqa: BLE001
            app = "your terminal app"
        msg = LOCAL_NETWORK_MSG % app
        for t in self.state.targets_list():
            if t.kind == "icmp" and t.enabled and t.addr and self._is_lan(t.addr):
                self.state.set_target_state(t.key, enabled=False, reason=LAN_REASON)
                self._lan_blocked[t.key] = t
                self._sched.pop(t.id, None)
        if first:
            log.warning("engine: %s", msg)
            self.state.raise_note("probe_error", target=sch.tid, severity=2, note=msg, reason="local_network_permission",
                                  app=app, errno=errno.EHOSTUNREACH)
        self._lan_msg = msg
        self._next_lan_retry = now + LAN_RETRY_S
        self._announce_status()
        return True

    def _lan_retry(self, now: float) -> None:
        if not self._lan_blocked or now < self._next_lan_retry:
            return
        self._next_lan_retry = now + LAN_RETRY_S
        for key in list(self._lan_blocked):
            cur = self.state.target(key)
            if cur is None or cur.reason != LAN_REASON or not cur.addr:
                self._lan_blocked.pop(key, None)
                continue
            fam = 6 if cur.family == 6 else 4
            sock = self.sockets.get(fam)
            if sock is None:
                continue
            try:
                sockaddr = (sockaddr_for(cur.addr, fam, nametoindex=self._nametoindex) if self._nametoindex
                            else sockaddr_for(cur.addr, fam))
                sock.sendto(build_echo(fam, 0xFFFFFFFF, cur.id, int(now * 1e9)), sockaddr)
            except OSError as exc:
                if getattr(exc, "errno", None) == errno.EHOSTUNREACH:
                    continue
            self._lan_blocked.pop(key, None)
            self.state.set_target_state(key, enabled=True, reason=None)
            log.info("engine: %s is reachable again; re-enabled", key)
        if not self._lan_blocked:
            self._lan_msg = None
            self._announce_status()


__all__ = [
    "Engine", "period_for_rate", "stagger_ms", "LAN_REASON", "GW6_REASON", "NO_CAPABILITY_REASON", "LOCAL_NETWORK_MSG",
    "SLOT_S", "SWEEP_S", "LATE_STALL_MS", "GAP_STALL_MS", "GW6_NO_RESPONDER_S", "LAN_RETRY_S",
]
