"""TCP connect probes (SPEC_FULL §5.7) for every target of kind ``tcp``.

Each probe is a non-blocking ``connect_ex`` registered for write-readiness in
a selector with a 3 s timeout. When the socket becomes writable
``SO_ERROR`` decides the outcome: ``0`` → a received sample whose ``value`` is
the connect RTT in microseconds; otherwise ``F_ERROR`` with the errno as the
value (``ECONNREFUSED`` for a closed port). No reply within 3 s → ``F_LOST``.
Every socket is closed with ``SO_LINGER (1, 0)`` so the kernel sends RST
instead of leaving TIME_WAIT entries behind.

One connect every 2 s per target (faster when the target's ``rate_hz`` asks for
it, as the Plex server's does), with the first sends staggered across the
interval. Five refusals in a row back the target off to one connect every
30 s (``reason='connection refused'`` on the target, probing continues);
the first success clears it. Five timeouts in a row raise a ``tcp_timeout``
note once.

Targets that carry ``Target.extra['name']`` (the Xbox Live hosts) are
re-resolved every 300 s with ``getaddrinfo`` for their family on a helper
thread; a new address is applied with ``state.set_target_state(key,
addr=ip, enabled=True, reason=None)`` and a failed lookup keeps the last
address (a target that never resolved stays disabled with its
``'cannot resolve'`` reason). An IPv4-mapped answer (``::ffff:a.b.c.d``, what
macOS returns for a name without AAAA records) is not an IPv6 address: it is
rejected, and a family-6 target that only ever had one is disabled with
``reason='no AAAA record (IPv4-mapped answer only)'``.
"""
from __future__ import annotations

import errno
import ipaddress
import logging
import selectors
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from laglens.state import F_ERROR, F_LOADTEST, F_LOST, KIND_TCP, Sample, Target
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.tcp")

INTERVAL_S = 2.0
BACKOFF_INTERVAL_S = 30.0
TIMEOUT_S = 3.0
REFUSALS_BEFORE_BACKOFF = 5
TIMEOUTS_BEFORE_NOTE = 5
RESOLVE_INTERVAL_S = 300.0
REASON_NO_AAAA = "no AAAA record (IPv4-mapped answer only)"
MAX_SELECT_WAIT_S = 0.25
LINGER_RST = struct.pack("ii", 1, 0)
#: ``connect_ex`` return codes that mean "in progress" on a non-blocking socket.
IN_PROGRESS = frozenset(
    v for v in (getattr(errno, n, None) for n in ("EINPROGRESS", "EWOULDBLOCK", "EAGAIN", "EALREADY", "WSAEWOULDBLOCK"))
    if v is not None
)


class _Pending:
    __slots__ = ("sock", "target", "t0", "ts_ms", "deadline", "seq", "flags")

    def __init__(self, sock: Any, target: Target, t0: float, ts_ms: int, deadline: float, seq: int, flags: int) -> None:
        self.sock = sock
        self.target = target
        self.t0 = t0
        self.ts_ms = ts_ms
        self.deadline = deadline
        self.seq = seq
        self.flags = flags


class _TargetState:
    __slots__ = ("next_due", "seq", "refusals", "timeouts", "backed_off", "in_flight")

    def __init__(self, next_due: float) -> None:
        self.next_due = next_due
        self.seq = 0
        self.refusals = 0
        self.timeouts = 0
        self.backed_off = False
        self.in_flight = False


class TcpProber:
    """Connect to every ``tcp`` target once per 2 s and time the handshake.

    Injectable for tests: ``sock_factory(family, type)``, ``selector_factory``,
    ``clock`` (monotonic), ``wall`` (unix time) and ``getaddrinfo``.
    """

    def __init__(
        self,
        ctx: Any,
        sock_factory: Callable[..., Any] = socket.socket,
        selector_factory: Callable[[], Any] = selectors.DefaultSelector,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        getaddrinfo: Callable[..., Any] = socket.getaddrinfo,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.sock_factory = sock_factory
        self.selector_factory = selector_factory
        self.clock = clock
        self.wall = wall
        self.getaddrinfo = getaddrinfo
        # an injected resolver (ctx.resolver, used by offline tests) takes precedence over getaddrinfo
        self.ctx_resolver: Optional[Callable[[str, int], Optional[str]]] = getattr(ctx, "resolver", None)
        self.interval_s = INTERVAL_S
        self.backoff_interval_s = BACKOFF_INTERVAL_S
        self.timeout_s = TIMEOUT_S
        self.resolve_interval_s = RESOLVE_INTERVAL_S
        self._targets: Dict[str, _TargetState] = {}
        self._pending: Dict[int, _Pending] = {}
        self._sel: Any = None
        self.thread: Optional[threading.Thread] = None
        self.resolve_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.thread = start_thread("tcp", self._loop, self.state)
        self.resolve_thread = start_thread("tcp_resolve", self._resolve_loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        for t in (self.thread, self.resolve_thread):
            if t is not None:
                t.join(timeout)
        self._close_all()

    def _loop(self) -> None:
        stop = self.state.stop_event
        try:
            while not stop.is_set():
                self.step()
        finally:
            self._close_all()

    def _resolve_loop(self) -> None:
        """Re-resolve named targets every 300 s (immediately for unresolved ones)."""
        stop = self.state.stop_event
        self.resolve_names(only_unresolved=True)
        while not stop.wait(self.resolve_interval_s):
            self.resolve_names()

    # --------------------------------------------------------------- targets
    def _tcp_targets(self) -> List[Target]:
        try:
            return [t for t in self.state.targets_list() if t.kind == "tcp"]
        except Exception:  # noqa: BLE001
            log.exception("cannot list targets")
            return []

    def _interval_for(self, t: Target) -> float:
        """The default interval, or a faster one a target asks for (the Plex server: 2 Hz)."""
        rate = t.rate_hz or 0.0
        return min(self.interval_s, 1.0 / rate) if rate > 0 else self.interval_s

    def _ensure_states(self, targets: List[Target], now: float) -> None:
        n = max(1, len(targets))
        for i, t in enumerate(targets):
            if t.key not in self._targets:
                self._targets[t.key] = _TargetState(now + i * self.interval_s / n)

    def _selector(self) -> Any:
        if self._sel is None:
            self._sel = self.selector_factory()
        return self._sel

    # ------------------------------------------------------------------ step
    def step(self) -> None:
        """One scheduler iteration (send due connects, reap results, expire timeouts)."""
        now = self.clock()
        self._expire(now)
        targets = self._tcp_targets()
        self._ensure_states(targets, now)
        for t in targets:
            ts = self._targets[t.key]
            if now >= ts.next_due:
                ts.next_due = now + (self.backoff_interval_s if ts.backed_off else self._interval_for(t))
                if t.enabled and t.addr and not ts.in_flight:
                    self._connect(t, ts, now)
        wait = self._wait_for(now)
        if self._pending:
            try:
                ready = self._selector().select(wait)
            except (OSError, ValueError) as exc:
                log.warning("selector failed: %s", exc)
                self._close_all()
                ready = []
            for key, _mask in ready:
                self._finish(key.fileobj)
        elif wait > 0:
            self.state.stop_event.wait(wait)

    def _wait_for(self, now: float) -> float:
        nxt = now + MAX_SELECT_WAIT_S
        for ts in self._targets.values():
            nxt = min(nxt, ts.next_due)
        for p in self._pending.values():
            nxt = min(nxt, p.deadline)
        return max(0.0, min(MAX_SELECT_WAIT_S, nxt - now))

    # --------------------------------------------------------------- connect
    def _connect(self, t: Target, ts: _TargetState, now: float) -> None:
        fam = socket.AF_INET6 if t.family == 6 else socket.AF_INET
        port = t.port or 443
        addr = (t.addr, port, 0, 0) if t.family == 6 else (t.addr, port)
        ts.seq += 1
        flags = F_LOADTEST if self._loadtest_running() else 0
        sock = None
        try:
            sock = self.sock_factory(fam, socket.SOCK_STREAM)
            sock.setblocking(False)
            ts_ms = int(self.wall() * 1000)
            t0 = self.clock()
            rc = sock.connect_ex(addr)
        except OSError as exc:
            if sock is not None:
                _safe_close(sock)
            self._emit(Sample(int(self.wall() * 1000), t.id, KIND_TCP, flags | F_ERROR, ts.seq, exc.errno or 0))
            self._outcome(t, ts, "error", exc.errno or 0)
            return
        if rc == 0:
            rtt_us = max(0, int(round((self.clock() - t0) * 1e6)))
            self._rst_close(sock)
            self._emit(Sample(ts_ms, t.id, KIND_TCP, flags, ts.seq, rtt_us))
            self._outcome(t, ts, "ok", rtt_us)
            return
        if rc not in IN_PROGRESS:
            _safe_close(sock)
            self._emit(Sample(ts_ms, t.id, KIND_TCP, flags | F_ERROR, ts.seq, rc))
            self._outcome(t, ts, "error", rc)
            return
        try:
            self._selector().register(sock, selectors.EVENT_WRITE)
        except (OSError, ValueError, KeyError) as exc:
            _safe_close(sock)
            log.warning("tcp %s: cannot register socket: %s", t.key, exc)
            self._emit(Sample(ts_ms, t.id, KIND_TCP, flags | F_ERROR, ts.seq, 0))
            self._outcome(t, ts, "error", 0)
            return
        ts.in_flight = True
        self._pending[sock.fileno()] = _Pending(sock, t, t0, ts_ms, t0 + self.timeout_s, ts.seq, flags)

    def _finish(self, sock: Any) -> None:
        p = self._pending.pop(sock.fileno(), None)
        self._unregister(sock)
        if p is None:
            _safe_close(sock)
            return
        now = self.clock()
        try:
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        except OSError as exc:
            err = exc.errno or errno.EIO
        ts = self._targets.get(p.target.key)
        if ts is not None:
            ts.in_flight = False
        if err == 0:
            rtt_us = max(0, int(round((now - p.t0) * 1e6)))
            self._rst_close(sock)
            self._emit(Sample(p.ts_ms, p.target.id, KIND_TCP, p.flags, p.seq, rtt_us))
            if ts is not None:
                self._outcome(p.target, ts, "ok", rtt_us)
        else:
            _safe_close(sock)
            self._emit(Sample(p.ts_ms, p.target.id, KIND_TCP, p.flags | F_ERROR, p.seq, err))
            if ts is not None:
                self._outcome(p.target, ts, "error", err)

    def _expire(self, now: float) -> None:
        for fd in [fd for fd, p in self._pending.items() if now >= p.deadline]:
            p = self._pending.pop(fd)
            self._unregister(p.sock)
            _safe_close(p.sock)
            self._emit(Sample(p.ts_ms, p.target.id, KIND_TCP, p.flags | F_LOST, p.seq, -1))
            ts = self._targets.get(p.target.key)
            if ts is not None:
                ts.in_flight = False
                self._outcome(p.target, ts, "timeout", -1)

    # ---------------------------------------------------------------- state
    def _outcome(self, t: Target, ts: _TargetState, kind: str, value: int) -> None:
        if kind == "ok":
            ts.refusals = 0
            ts.timeouts = 0
            if ts.backed_off:
                ts.backed_off = False
                ts.next_due = min(ts.next_due, self.clock() + self.interval_s)
                log.info("tcp %s: connects again; back to 1/%ds", t.key, int(self.interval_s))
                self._set_reason(t.key, None)
        elif kind == "error":
            ts.timeouts = 0
            if value == errno.ECONNREFUSED:
                ts.refusals += 1
                if ts.refusals >= REFUSALS_BEFORE_BACKOFF and not ts.backed_off:
                    ts.backed_off = True
                    log.warning("tcp %s: %d refusals in a row; backing off to 1/%ds", t.key, ts.refusals,
                                int(self.backoff_interval_s))
                    self._set_reason(t.key, "connection refused")
            else:
                ts.refusals = 0
        else:  # timeout
            ts.refusals = 0
            ts.timeouts += 1
            if ts.timeouts == TIMEOUTS_BEFORE_NOTE:
                try:
                    self.state.raise_note("tcp_timeout", target=t.id, severity=2,
                                          note="%s: %d connects in a row timed out" % (t.label, ts.timeouts))
                except Exception:  # noqa: BLE001
                    log.exception("raise_note failed")

    def _set_reason(self, key: str, reason: Optional[str]) -> None:
        try:
            self.state.set_target_state(key, reason=reason)
        except Exception:  # noqa: BLE001
            log.exception("set_target_state failed")

    # -------------------------------------------------------------- resolve
    def resolve_names(self, only_unresolved: bool = False) -> Dict[str, Optional[str]]:
        """Re-resolve every named target; returns ``{key: new_or_kept_addr}``."""
        out: Dict[str, Optional[str]] = {}
        for t in self._tcp_targets():
            name = (t.extra or {}).get("name") if isinstance(t.extra, dict) else None
            if not name:
                continue
            if only_unresolved and t.addr:
                continue
            ip = self.resolve(name, t.family)
            if ip is None:
                if t.family == 6 and is_v4_mapped(t.addr):
                    # targets.py accepted an IPv4-mapped "AAAA" answer: not a real IPv6 path
                    log.info("tcp %s: %s has no AAAA record; disabling", t.key, name)
                    try:
                        self.state.set_target_state(t.key, enabled=False, reason=REASON_NO_AAAA)
                    except Exception:  # noqa: BLE001
                        log.exception("set_target_state failed")
                    out[t.key] = None
                else:
                    log.debug("tcp %s: %s did not resolve; keeping %s", t.key, name, t.addr)
                    out[t.key] = t.addr
                continue
            out[t.key] = ip
            if ip != t.addr or not t.enabled:
                log.info("tcp %s: %s -> %s", t.key, name, ip)
                try:
                    self.state.set_target_state(t.key, addr=ip, enabled=True, reason=None)
                except Exception:  # noqa: BLE001
                    log.exception("set_target_state failed")
            if self.state.stop_event.is_set():
                break
        return out

    def resolve(self, name: str, family: int) -> Optional[str]:
        """First address of ``name`` in ``family`` (4/6) via ``getaddrinfo``; ``None`` on failure."""
        if self.ctx_resolver is not None:
            try:
                return self.ctx_resolver(name, family)
            except Exception:  # noqa: BLE001
                log.exception("injected resolver failed for %s", name)
                return None
        fam = socket.AF_INET6 if family == 6 else socket.AF_INET
        try:
            infos = self.getaddrinfo(name, None, fam, socket.SOCK_STREAM)
        except (socket.gaierror, OSError, UnicodeError):
            return None
        except Exception:  # noqa: BLE001
            log.exception("getaddrinfo(%s) failed", name)
            return None
        for info in infos or []:
            try:
                addr = info[4][0]
            except (IndexError, TypeError):
                continue
            if not addr:
                continue
            if family == 6 and is_v4_mapped(addr):
                continue  # macOS hands out ::ffff:a.b.c.d when there is no AAAA record
            return addr
        return None

    # --------------------------------------------------------------- helpers
    def _rst_close(self, sock: Any) -> None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER_RST)
        except OSError:
            pass
        _safe_close(sock)

    def _unregister(self, sock: Any) -> None:
        if self._sel is None:
            return
        try:
            self._sel.unregister(sock)
        except (KeyError, ValueError, OSError):
            pass

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
        for p in list(self._pending.values()):
            self._unregister(p.sock)
            _safe_close(p.sock)
            ts = self._targets.get(p.target.key)
            if ts is not None:
                ts.in_flight = False
        self._pending.clear()
        if self._sel is not None:
            try:
                self._sel.close()
            except Exception:  # noqa: BLE001
                pass
            self._sel = None


def is_v4_mapped(addr: Optional[str]) -> bool:
    """``True`` for an IPv4-mapped IPv6 literal such as ``::ffff:40.90.8.102``."""
    if not addr or ":" not in addr:
        return False
    try:
        return ipaddress.ip_address(addr.split("%", 1)[0]).ipv4_mapped is not None
    except (ValueError, AttributeError):
        return False


def _safe_close(sock: Any) -> None:
    try:
        sock.close()
    except Exception:  # noqa: BLE001
        pass


__all__ = [
    "TcpProber", "INTERVAL_S", "BACKOFF_INTERVAL_S", "TIMEOUT_S", "REFUSALS_BEFORE_BACKOFF",
    "TIMEOUTS_BEFORE_NOTE", "RESOLVE_INTERVAL_S", "LINGER_RST", "IN_PROGRESS", "REASON_NO_AAAA", "is_v4_mapped",
]
