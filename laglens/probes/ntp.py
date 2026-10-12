"""NTP probe with four-timestamp direction attribution (SPEC_FULL §5.6).

Every target of kind ``ntp`` is queried once per 5 s with a 48-byte client
packet (LI 0, VN 4, mode 3). The transmit timestamp we send is our wall clock
in NTP format; the reply is matched by its *originate* field being exactly
that value, and the monotonic send time is kept keyed by it so the RTT does
not depend on wall-clock jumps.

Per reply (all four timestamps in seconds; ``t1`` our send, ``t2`` server
receive, ``t3`` server transmit, ``t4`` our receive):

* ``δ = (t4 − t1) − (t3 − t2)`` → the sample's ``value`` in microseconds,
* ``θ = ((t2 − t1) + (t3 − t4)) / 2`` → the clock offset.

Per server a rolling 10-minute median of ``δ`` and ``θ`` is the baseline;
``Δθ`` and ``ΔRTT`` are the deviations of the newest reply from it and
``upstream_share = 0.5 + Δθ / ΔRTT`` whenever ``ΔRTT ≥ 20 ms`` (an added
delay on the way *to* the server grows ``θ`` by half of it and ``δ`` by all
of it, so the share is 1.0; an added delay on the way back yields 0.0).
Direction per server: ``upstream`` (share ≥ 0.7), ``downstream`` (≤ 0.3),
``symmetric`` otherwise, ``n/a`` when undefined; the combined direction is
``mixed`` when two servers disagree by more than 0.2.

A Kiss-o'-Death reply (stratum 0) or 100 % loss for 5 minutes marks the
target ``reason='unreliable'`` (no notes are raised); after a KoD the server
is polled once per 60 s for the rest of the session.
"""
from __future__ import annotations

import logging
import select
import socket
import statistics
import struct
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from laglens.state import F_ERROR, F_LOADTEST, F_LOST, KIND_NTP, Sample, Target
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.ntp")

NTP_EPOCH_OFFSET = 2208988800  # seconds between 1900-01-01 and 1970-01-01
PACKET_SIZE = 48
LI_VN_MODE = (0 << 6) | (4 << 3) | 3  # LI 0, VN 4, mode 3 (client) = 0x23
INTERVAL_S = 5.0
KOD_INTERVAL_S = 60.0
TIMEOUT_S = 2.0
BASELINE_WINDOW_S = 600.0
BASELINE_MIN_SAMPLES = 3
SHARE_MIN_DRTT_MS = 20.0
UPSTREAM_SHARE = 0.7
DOWNSTREAM_SHARE = 0.3
DISAGREE_SHARE = 0.2
LOSS_UNRELIABLE_S = 300.0
MAX_SELECT_WAIT_S = 0.25
RECV_SIZE = 512


# ---------------------------------------------------------------------------
# Timestamp format and packet helpers
# ---------------------------------------------------------------------------
def to_ntp(t: float) -> int:
    """Unix time (float s) → 64-bit NTP timestamp (32.32 fixed point since 1900)."""
    sec = int(t) + NTP_EPOCH_OFFSET
    frac = int(round((t - int(t)) * 4294967296.0))
    if frac >= 4294967296:
        sec += 1
        frac -= 4294967296
    return ((sec & 0xFFFFFFFF) << 32) | (frac & 0xFFFFFFFF)


def from_ntp(v: int) -> float:
    """64-bit NTP timestamp → unix time (float s)."""
    sec = (v >> 32) & 0xFFFFFFFF
    frac = v & 0xFFFFFFFF
    return (sec - NTP_EPOCH_OFFSET) + frac / 4294967296.0


def build_packet(transmit: int) -> bytes:
    """48-byte client request (LI 0, VN 4, mode 3) with ``transmit`` as its transmit timestamp."""
    return struct.pack(">B", LI_VN_MODE) + b"\x00" * 39 + struct.pack(">Q", transmit & 0xFFFFFFFFFFFFFFFF)


def parse_packet(data: bytes) -> Optional[Dict[str, int]]:
    """Parse a server reply. ``None`` unless it is at least 48 bytes long."""
    if len(data) < PACKET_SIZE:
        return None
    first, stratum, poll, precision = struct.unpack(">BBbb", data[:4])
    ref_id = data[12:16]
    reference, originate, receive, transmit = struct.unpack(">QQQQ", data[16:48])
    return {
        "li": first >> 6,
        "vn": (first >> 3) & 7,
        "mode": first & 7,
        "stratum": stratum,
        "poll": poll,
        "precision": precision,
        "ref_id": ref_id,
        "reference": reference,
        "originate": originate,
        "receive": receive,
        "transmit": transmit,
    }


def delay_offset(t1: float, t2: float, t3: float, t4: float) -> Tuple[float, float]:
    """RFC 5905 round-trip delay ``δ`` and clock offset ``θ`` (seconds)."""
    delay = (t4 - t1) - (t3 - t2)
    offset = ((t2 - t1) + (t3 - t4)) / 2.0
    return delay, offset


def upstream_share(d_offset_ms: Optional[float], d_rtt_ms: Optional[float]) -> Optional[float]:
    """``0.5 + Δθ/ΔRTT`` when ``ΔRTT ≥ 20 ms``; ``None`` otherwise (clamped to 0..1)."""
    if d_offset_ms is None or d_rtt_ms is None or d_rtt_ms < SHARE_MIN_DRTT_MS:
        return None
    share = 0.5 + d_offset_ms / d_rtt_ms
    return max(0.0, min(1.0, share))


def direction_for(share: Optional[float]) -> str:
    """``upstream`` / ``downstream`` / ``symmetric`` / ``n/a`` for one share value."""
    if share is None:
        return "n/a"
    if share >= UPSTREAM_SHARE:
        return "upstream"
    if share <= DOWNSTREAM_SHARE:
        return "downstream"
    return "symmetric"


def combine_direction(shares: Dict[str, Optional[float]]) -> Tuple[str, Optional[float]]:
    """Combined ``(direction, share)`` over several servers.

    Servers without a defined share are ignored; two defined shares that
    differ by more than 0.2 give ``mixed``; otherwise the mean share decides.
    """
    vals = [v for v in shares.values() if v is not None]
    if not vals:
        return "n/a", None
    mean = sum(vals) / len(vals)
    if len(vals) >= 2 and (max(vals) - min(vals)) > DISAGREE_SHARE:
        return "mixed", round(mean, 3)
    return direction_for(mean), round(mean, 3)


def short_key(key: str) -> str:
    """``ntp_cf`` → ``cf`` (the key used in the ``ntp`` latest row)."""
    return key[4:] if key.startswith("ntp_") else key


# ---------------------------------------------------------------------------
# Prober
# ---------------------------------------------------------------------------
class _Pending:
    __slots__ = ("target", "sent_mono", "ts_ms", "t1", "deadline", "seq", "flags")

    def __init__(self, target: Target, sent_mono: float, ts_ms: int, t1: float, deadline: float, seq: int,
                 flags: int) -> None:
        self.target = target
        self.sent_mono = sent_mono
        self.ts_ms = ts_ms
        self.t1 = t1
        self.deadline = deadline
        self.seq = seq
        self.flags = flags


class _TargetState:
    __slots__ = ("next_due", "seq", "interval", "history", "first_sent", "last_reply", "unreliable", "last",
                 "sent", "received")

    def __init__(self, next_due: float, interval: float) -> None:
        self.next_due = next_due
        self.seq = 0
        self.interval = interval
        self.history: Deque[Tuple[float, float, float]] = deque()  # (mono, rtt_ms, offset_ms)
        self.first_sent: Optional[float] = None
        self.last_reply: Optional[float] = None
        self.unreliable = False
        self.last: Optional[dict] = None
        self.sent = 0
        self.received = 0


class NtpProber:
    """Query every ``ntp`` target once per 5 s; publish RTT/offset/direction.

    Injectable for tests: ``sock_factory(family, type)``, ``select_fn``,
    ``clock`` (monotonic) and ``wall`` (unix time).
    """

    def __init__(
        self,
        ctx: Any,
        sock_factory: Callable[..., Any] = socket.socket,
        select_fn: Callable[..., Any] = select.select,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.sock_factory = sock_factory
        self.select_fn = select_fn
        self.clock = clock
        self.wall = wall
        self.interval_s = INTERVAL_S
        self.timeout_s = TIMEOUT_S
        self._targets: Dict[str, _TargetState] = {}
        self._pending: Dict[int, _Pending] = {}  # originate timestamp -> pending
        self._socks: Dict[int, Any] = {}  # family -> UDP socket
        self._last_tx = 0
        self.direction = "n/a"
        self.share: Optional[float] = None
        self.thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.thread = start_thread("ntp", self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        if self.thread is not None:
            self.thread.join(timeout)
        self._close_all()

    def _loop(self) -> None:
        stop = self.state.stop_event
        try:
            while not stop.is_set():
                self.step()
        finally:
            self._close_all()

    # --------------------------------------------------------------- targets
    def _ntp_targets(self) -> List[Target]:
        try:
            return [t for t in self.state.targets_list() if t.kind == "ntp"]
        except Exception:  # noqa: BLE001
            log.exception("cannot list targets")
            return []

    def _ensure_states(self, targets: List[Target], now: float) -> None:
        n = max(1, len(targets))
        for i, t in enumerate(targets):
            if t.key not in self._targets:
                self._targets[t.key] = _TargetState(now + i * self.interval_s / n, self.interval_s)

    def _sock(self, family: int) -> Optional[Any]:
        s = self._socks.get(family)
        if s is not None:
            return s
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        try:
            s = self.sock_factory(fam, socket.SOCK_DGRAM)
            s.setblocking(False)
        except OSError as exc:
            log.warning("cannot create NTP socket (v%d): %s", family, exc)
            return None
        self._socks[family] = s
        return s

    # ------------------------------------------------------------------ step
    def step(self) -> None:
        """One scheduler iteration (send due queries, expire timeouts, read replies)."""
        now = self.clock()
        targets = self._ntp_targets()
        self._ensure_states(targets, now)
        for t in targets:
            ts = self._targets[t.key]
            if now >= ts.next_due:
                ts.next_due = now + ts.interval
                if t.enabled and t.addr:
                    self._send(t, ts, now)
            self._check_silence(t, ts, now)
        self._expire(now)
        wait = self._wait_for(now)
        socks = list(self._socks.values())
        if socks:
            try:
                readable, _w, _x = self.select_fn(socks, [], [], wait)
            except (OSError, ValueError) as exc:
                log.warning("select failed: %s", exc)
                self._close_all()
                readable = []
            for s in readable:
                self._read(s)
        elif wait > 0:
            self.state.stop_event.wait(wait)

    def _wait_for(self, now: float) -> float:
        nxt = now + MAX_SELECT_WAIT_S
        for ts in self._targets.values():
            nxt = min(nxt, ts.next_due)
        for p in self._pending.values():
            nxt = min(nxt, p.deadline)
        return max(0.0, min(MAX_SELECT_WAIT_S, nxt - now))

    # ------------------------------------------------------------------ send
    def _next_transmit(self, t1: float) -> int:
        tx = to_ntp(t1)
        if tx <= self._last_tx:  # keep originate values unique so matching is unambiguous
            tx = self._last_tx + 1
        self._last_tx = tx
        return tx

    def _send(self, t: Target, ts: _TargetState, now: float) -> None:
        sock = self._sock(t.family)
        ts.seq += 1
        flags = F_LOADTEST if self._loadtest_running() else 0
        port = t.port or 123
        addr = (t.addr, port, 0, 0) if t.family == 6 else (t.addr, port)
        if sock is None:
            self._emit(Sample(int(self.wall() * 1000), t.id, KIND_NTP, flags | F_ERROR, ts.seq, 0))
            return
        t1 = self.wall()
        tx = self._next_transmit(t1)
        pkt = build_packet(tx)
        try:
            sent_mono = self.clock()
            sock.sendto(pkt, addr)
        except OSError as exc:
            log.debug("ntp %s send failed: %s", t.key, exc)
            self._emit(Sample(int(t1 * 1000), t.id, KIND_NTP, flags | F_ERROR, ts.seq, exc.errno or 0))
            return
        ts.sent += 1
        if ts.first_sent is None:
            ts.first_sent = now
        self._pending[tx] = _Pending(t, sent_mono, int(t1 * 1000), t1, sent_mono + self.timeout_s, ts.seq, flags)

    # ------------------------------------------------------------------ recv
    def _read(self, sock: Any) -> None:
        for _ in range(64):  # drain without starving the scheduler
            try:
                data, _peer = sock.recvfrom(RECV_SIZE)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                log.debug("ntp recv error: %s", exc)
                return
            self._handle_reply(data, self.clock())

    def _handle_reply(self, data: bytes, now: float) -> None:
        pkt = parse_packet(data)
        if pkt is None:
            return
        p = self._pending.pop(pkt["originate"], None)
        if p is None:
            return  # stray or duplicate
        t = p.target
        ts = self._targets.get(t.key)
        if ts is None:
            return
        if pkt["stratum"] == 0:
            kod = pkt["ref_id"].decode("ascii", "replace")
            log.warning("ntp %s: kiss-o'-death %r; polling every %ds", t.key, kod, int(KOD_INTERVAL_S))
            ts.interval = KOD_INTERVAL_S
            ts.next_due = max(ts.next_due, now + KOD_INTERVAL_S)
            self._emit(Sample(p.ts_ms, t.id, KIND_NTP, p.flags | F_ERROR, p.seq, 0))
            self._mark_unreliable(t, ts, "unreliable (kiss-o'-death %s)" % kod.strip("\x00") or "unreliable")
            return
        rtt_mono = now - p.sent_mono
        t1 = p.t1
        t4 = t1 + rtt_mono
        t2 = from_ntp(pkt["receive"])
        t3 = from_ntp(pkt["transmit"])
        delay, offset = delay_offset(t1, t2, t3, t4)
        rtt_us = max(0, int(round(delay * 1e6)))
        self._emit(Sample(p.ts_ms, t.id, KIND_NTP, p.flags, p.seq, rtt_us))
        ts.received += 1
        ts.last_reply = now
        if ts.unreliable:
            ts.unreliable = False
            self._set_reason(t.key, None)
        self._account(t, ts, now, rtt_us / 1000.0, offset * 1000.0)

    def _expire(self, now: float) -> None:
        for tx in [tx for tx, p in self._pending.items() if now >= p.deadline]:
            p = self._pending.pop(tx)
            self._emit(Sample(p.ts_ms, p.target.id, KIND_NTP, p.flags | F_LOST, p.seq, -1))

    def _check_silence(self, t: Target, ts: _TargetState, now: float) -> None:
        """100 % loss for 5 min → ``unreliable``."""
        if ts.unreliable or ts.first_sent is None:
            return
        last = ts.last_reply if ts.last_reply is not None else ts.first_sent
        if now - last >= LOSS_UNRELIABLE_S and ts.sent > 0:
            self._mark_unreliable(t, ts, "unreliable (no reply for %d min)" % int(LOSS_UNRELIABLE_S // 60))

    def _mark_unreliable(self, t: Target, ts: _TargetState, reason: str) -> None:
        ts.unreliable = True
        self._set_reason(t.key, reason)

    # ----------------------------------------------------------- statistics
    def _account(self, t: Target, ts: _TargetState, now: float, rtt_ms: float, offset_ms: float) -> None:
        hist = ts.history
        hist.append((now, rtt_ms, offset_ms))
        cutoff = now - BASELINE_WINDOW_S
        while hist and hist[0][0] < cutoff:
            hist.popleft()
        d_rtt: Optional[float] = None
        d_offset: Optional[float] = None
        if len(hist) >= BASELINE_MIN_SAMPLES:
            base_rtt = statistics.median(h[1] for h in hist)
            base_off = statistics.median(h[2] for h in hist)
            d_rtt = rtt_ms - base_rtt
            d_offset = offset_ms - base_off
        share = upstream_share(d_offset, d_rtt)
        ts.last = {
            "rtt": round(rtt_ms, 3),
            "offset": round(offset_ms, 3),
            "d_rtt": round(d_rtt, 3) if d_rtt is not None else None,
            "d_offset": round(d_offset, 3) if d_offset is not None else None,
            "share": round(share, 3) if share is not None else None,
            "direction": direction_for(share),
            "n": len(hist),
        }
        self._publish_latest()

    def _publish_latest(self) -> None:
        row: Dict[str, Any] = {}
        shares: Dict[str, Optional[float]] = {}
        for key, ts in self._targets.items():
            if ts.last is not None:
                row[short_key(key)] = dict(ts.last)
                shares[key] = ts.last.get("share")
        self.direction, self.share = combine_direction(shares)
        row["direction"] = self.direction
        row["share"] = self.share
        row["t"] = self.wall()
        try:
            self.state.set_latest("ntp", row)
        except Exception:  # noqa: BLE001
            log.exception("set_latest failed")

    def current(self) -> dict:
        """The newest ``ntp`` row (same shape as ``state.latest('ntp')``)."""
        try:
            return self.state.latest("ntp") or {"direction": self.direction, "share": self.share}
        except Exception:  # noqa: BLE001
            return {"direction": self.direction, "share": self.share}

    # --------------------------------------------------------------- helpers
    def _set_reason(self, key: str, reason: Optional[str]) -> None:
        try:
            self.state.set_target_state(key, reason=reason)
        except Exception:  # noqa: BLE001
            log.exception("set_target_state failed")

    def _loadtest_running(self) -> bool:
        try:
            return bool(self.state.loadtest.get("running"))
        except Exception:  # noqa: BLE001
            return False

    def _emit(self, s: Sample) -> None:
        try:
            self.state.add_sample(s)
        except Exception:  # noqa: BLE001
            log.exception("add_sample failed")
        try:
            self.store.append_sample(s)
        except Exception:  # noqa: BLE001
            log.exception("append_sample failed")

    def _close_all(self) -> None:
        for s in self._socks.values():
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        self._socks.clear()
        self._pending.clear()


__all__ = [
    "NtpProber", "to_ntp", "from_ntp", "build_packet", "parse_packet", "delay_offset", "upstream_share",
    "direction_for", "combine_direction", "short_key", "NTP_EPOCH_OFFSET", "PACKET_SIZE", "LI_VN_MODE",
    "INTERVAL_S", "KOD_INTERVAL_S", "TIMEOUT_S", "BASELINE_WINDOW_S", "SHARE_MIN_DRTT_MS", "LOSS_UNRELIABLE_S",
]
