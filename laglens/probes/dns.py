"""DNS timing probe (SPEC_FULL §5.8): hand-built UDP queries to each resolver target.

One supervised thread drives every target of kind ``dns`` (``dns_gw``,
``dns_cf4``, ``dns_cf6`` when present). Each query is a fresh non-blocking UDP
socket (random source port, random 16-bit id) and the loop multiplexes the
outstanding queries with ``select`` so a slow resolver never delays the others.

Per query the probe records a :class:`~laglens.state.Sample` of kind
``KIND_DNS`` whose ``value`` is the RTT in microseconds, the response RCODE in
the extra bits of ``flags`` (``with_extra``), ``F_ERROR`` when the answer was
truncated (TC bit) and ``F_LOST`` after the 3 s timeout. Names rotate through
``targets.dns_names``, with every 10th query of a resolver aimed at a random
label under ``laglens-test.example.com`` so the resolver has to recurse.

A resolver that times out 5 times in a row is marked ``reason='unreachable'``
(it keeps being probed; a ``dns_fail`` note is raised once) and the reason is
cleared when it answers again. A separate helper thread times
``getaddrinfo('xboxlive.com')`` every 30 s (what applications see); the
result is published as ``sys_ms`` in ``state.latest('dns')``.
"""
from __future__ import annotations

import logging
import random
import select
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from laglens.state import F_ERROR, F_LOADTEST, F_LOST, KIND_DNS, Sample, Target, with_extra
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.dns")

QTYPE_A = 1
QTYPE_AAAA = 28
QCLASS_IN = 1
FLAGS_RD = 0x0100  # standard query, recursion desired
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

INTERVAL_S = 3.0
TIMEOUT_S = 3.0
RECURSION_EVERY = 10
UNREACHABLE_AFTER = 5
SYS_RESOLVE_INTERVAL_S = 30.0
SYS_RESOLVE_NAME = "xboxlive.com"
TEST_ZONE = "laglens-test.example.com"
DEFAULT_NAMES = ["xboxlive.com", "hbomax.com", "cloudflare.com"]
MAX_SELECT_WAIT_S = 0.25
RECV_SIZE = 4096


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------
def encode_name(name: str) -> bytes:
    """Encode a dotted name as DNS labels (``b"\\x03foo\\x03com\\x00"``)."""
    out = bytearray()
    for label in name.strip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("label too long: %r" % label)
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def build_query(qid: int, name: str, qtype: int) -> bytes:
    """A standard recursive query: header, one question, no other sections."""
    header = struct.pack(">HHHHHH", qid & 0xFFFF, FLAGS_RD, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, QCLASS_IN)


def parse_response(data: bytes) -> Optional[Dict[str, int]]:
    """Parse the header of a DNS message.

    Returns ``{'id', 'qr', 'tc', 'rcode', 'ancount', 'qdcount'}`` or ``None``
    when the datagram is shorter than a DNS header.
    """
    if len(data) < 12:
        return None
    qid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    return {
        "id": qid,
        "qr": (flags >> 15) & 1,
        "tc": (flags >> 9) & 1,
        "rcode": flags & 0x0F,
        "qdcount": qd,
        "ancount": an,
    }


def random_test_name(rng: Optional[random.Random] = None) -> str:
    """``<8 random hex>.laglens-test.example.com`` (never cached, forces recursion)."""
    r = rng or random
    return "%08x.%s" % (r.getrandbits(32), TEST_ZONE)


# ---------------------------------------------------------------------------
# Prober
# ---------------------------------------------------------------------------
class _Pending:
    __slots__ = ("sock", "target", "qid", "qname", "qtype", "sent_mono", "ts_ms", "deadline", "seq", "flags")

    def __init__(self, sock: Any, target: Target, qid: int, qname: str, qtype: int, sent_mono: float,
                 ts_ms: int, deadline: float, seq: int, flags: int) -> None:
        self.sock = sock
        self.target = target
        self.qid = qid
        self.qname = qname
        self.qtype = qtype
        self.sent_mono = sent_mono
        self.ts_ms = ts_ms
        self.deadline = deadline
        self.seq = seq
        self.flags = flags


class _TargetState:
    __slots__ = ("next_due", "seq", "queries", "timeouts", "unreachable", "last")

    def __init__(self, next_due: float) -> None:
        self.next_due = next_due
        self.seq = 0
        self.queries = 0
        self.timeouts = 0
        self.unreachable = False
        self.last: Optional[dict] = None


class DnsProber:
    """Probe every ``dns`` target once per 3 s with hand-built UDP queries.

    Injectable for tests: ``sock_factory(family, type)``, ``select_fn``,
    ``clock`` (monotonic), ``wall`` (unix time), ``getaddrinfo`` and ``rng``.
    """

    def __init__(
        self,
        ctx: Any,
        sock_factory: Callable[..., Any] = socket.socket,
        select_fn: Callable[..., Any] = select.select,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        getaddrinfo: Callable[..., Any] = socket.getaddrinfo,
        rng: Optional[random.Random] = None,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.sock_factory = sock_factory
        self.select_fn = select_fn
        self.clock = clock
        self.wall = wall
        self.getaddrinfo = getaddrinfo
        self.rng = rng or random.Random()
        cfg = getattr(ctx, "cfg", None) or {}
        names = (cfg.get("targets", {}) or {}).get("dns_names") or DEFAULT_NAMES
        self.names: List[str] = [n for n in names if isinstance(n, str) and n] or list(DEFAULT_NAMES)
        self.interval_s = INTERVAL_S
        self.timeout_s = TIMEOUT_S
        self._targets: Dict[str, _TargetState] = {}
        self._pending: Dict[int, _Pending] = {}  # fileno -> pending
        self._lock = threading.Lock()
        self.sys_ms: Optional[float] = None
        self.sys_ok: Optional[bool] = None
        self._sys_t: Optional[float] = None
        self.thread: Optional[threading.Thread] = None
        self.sys_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.thread = start_thread("dns", self._loop, self.state)
        self.sys_thread = start_thread("dns_sys", self._sys_loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        for t in (self.thread, self.sys_thread):
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

    def _sys_loop(self) -> None:
        """Time ``getaddrinfo`` every 30 s so the dashboard shows what apps see."""
        stop = self.state.stop_event
        while not stop.is_set():
            self.measure_system_resolver()
            if stop.wait(SYS_RESOLVE_INTERVAL_S):
                break

    # --------------------------------------------------------------- targets
    def _dns_targets(self) -> List[Target]:
        try:
            return [t for t in self.state.targets_list() if t.kind == "dns"]
        except Exception:  # noqa: BLE001
            log.exception("cannot list targets")
            return []

    def _ensure_states(self, targets: List[Target], now: float) -> None:
        n = max(1, len(targets))
        for i, t in enumerate(targets):
            if t.key not in self._targets:
                # stagger first sends so resolvers are not hit in the same instant
                self._targets[t.key] = _TargetState(now + (i * self.interval_s / n))

    # ------------------------------------------------------------------ step
    def step(self) -> None:
        """One scheduler iteration: send what is due, expire timeouts, read replies.

        Blocks at most ``MAX_SELECT_WAIT_S`` in ``select``; tests call it directly.
        """
        now = self.clock()
        targets = self._dns_targets()
        self._ensure_states(targets, now)
        for t in targets:
            ts = self._targets[t.key]
            if now >= ts.next_due:
                ts.next_due = now + self.interval_s
                if t.enabled and t.addr:
                    self._send(t, ts, now)
        self._expire(now)
        wait = self._wait_for(now)
        readable: List[Any] = []
        if self._pending:
            socks = [p.sock for p in self._pending.values()]
            try:
                readable, _w, _x = self.select_fn(socks, [], [], wait)
            except (OSError, ValueError) as exc:
                log.warning("select failed: %s", exc)
                self._close_all()
                readable = []
        elif wait > 0:
            self.state.stop_event.wait(wait)
        for s in readable:
            self._read(s)

    def _wait_for(self, now: float) -> float:
        nxt = now + MAX_SELECT_WAIT_S
        for ts in self._targets.values():
            nxt = min(nxt, ts.next_due)
        for p in self._pending.values():
            nxt = min(nxt, p.deadline)
        return max(0.0, min(MAX_SELECT_WAIT_S, nxt - now))

    # ------------------------------------------------------------------ send
    def _pick_question(self, ts: _TargetState) -> Tuple[str, int]:
        ts.queries += 1
        qtype = QTYPE_A if ts.queries % 2 else QTYPE_AAAA
        if ts.queries % RECURSION_EVERY == 0:
            return random_test_name(self.rng), qtype
        return self.names[(ts.queries - 1) % len(self.names)], qtype

    def _send(self, t: Target, ts: _TargetState, now: float) -> None:
        qname, qtype = self._pick_question(ts)
        qid = self.rng.getrandbits(16)
        pkt = build_query(qid, qname, qtype)
        fam = socket.AF_INET6 if t.family == 6 else socket.AF_INET
        port = t.port or 53
        addr = (t.addr, port, 0, 0) if t.family == 6 else (t.addr, port)
        ts.seq += 1
        flags = F_LOADTEST if self._loadtest_running() else 0
        sock = None
        try:
            sock = self.sock_factory(fam, socket.SOCK_DGRAM)
            sock.setblocking(False)
            ts_ms = int(self.wall() * 1000)
            sent_mono = self.clock()
            sock.sendto(pkt, addr)
        except OSError as exc:
            if sock is not None:
                _safe_close(sock)
            errno_ = exc.errno or 0
            log.debug("dns %s send failed: %s", t.key, exc)
            self._emit(Sample(int(self.wall() * 1000), t.id, KIND_DNS, flags | F_ERROR, ts.seq, errno_))
            self._record(t, ts, rtt_ms=None, rcode=None, ok=False, timed_out=False)
            return
        self._pending[sock.fileno()] = _Pending(sock, t, qid, qname, qtype, sent_mono, ts_ms,
                                               sent_mono + self.timeout_s, ts.seq, flags)

    # ------------------------------------------------------------------ recv
    def _read(self, sock: Any) -> None:
        p = self._pending.get(sock.fileno())
        if p is None:
            _safe_close(sock)
            return
        try:
            data, _peer = sock.recvfrom(RECV_SIZE)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            # ICMP port unreachable surfaces here as ECONNREFUSED on some stacks
            now = self.clock()
            del self._pending[sock.fileno()]
            _safe_close(sock)
            ts = self._targets.get(p.target.key)
            errno_ = exc.errno or 0
            self._emit(Sample(p.ts_ms, p.target.id, KIND_DNS, p.flags | F_ERROR, p.seq, errno_))
            if ts is not None:
                self._record(p.target, ts, rtt_ms=None, rcode=None, ok=False, timed_out=False, now=now)
            return
        hdr = parse_response(data)
        if hdr is None or hdr["id"] != p.qid or not hdr["qr"]:
            return  # not ours (spoof/stray); keep waiting
        now = self.clock()
        rtt_us = max(0, int(round((now - p.sent_mono) * 1e6)))
        del self._pending[sock.fileno()]
        _safe_close(sock)
        flags = with_extra(p.flags, hdr["rcode"])
        if hdr["tc"]:
            flags |= F_ERROR
        self._emit(Sample(p.ts_ms, p.target.id, KIND_DNS, flags, p.seq, rtt_us))
        ts = self._targets.get(p.target.key)
        if ts is not None:
            self._record(p.target, ts, rtt_ms=rtt_us / 1000.0, rcode=hdr["rcode"], ok=not hdr["tc"],
                         timed_out=False, now=now)

    def _expire(self, now: float) -> None:
        for fd in [fd for fd, p in self._pending.items() if now >= p.deadline]:
            p = self._pending.pop(fd)
            _safe_close(p.sock)
            self._emit(Sample(p.ts_ms, p.target.id, KIND_DNS, p.flags | F_LOST, p.seq, -1))
            ts = self._targets.get(p.target.key)
            if ts is not None:
                self._record(p.target, ts, rtt_ms=None, rcode=None, ok=False, timed_out=True, now=now)

    # ----------------------------------------------------------- bookkeeping
    def _record(self, t: Target, ts: _TargetState, rtt_ms: Optional[float], rcode: Optional[int], ok: bool,
                timed_out: bool, now: Optional[float] = None) -> None:
        if timed_out:
            ts.timeouts += 1
            if ts.timeouts >= UNREACHABLE_AFTER and not ts.unreachable:
                ts.unreachable = True
                log.warning("dns %s: %d consecutive timeouts; marking unreachable", t.key, ts.timeouts)
                self._set_reason(t.key, "unreachable")
                try:
                    self.state.raise_note("dns_fail", target=t.id, severity=2,
                                          note="resolver %s did not answer %d queries in a row" % (t.addr, ts.timeouts))
                except Exception:  # noqa: BLE001
                    log.exception("raise_note failed")
        else:
            ts.timeouts = 0
            if ts.unreachable:
                ts.unreachable = False
                log.info("dns %s: answering again", t.key)
                self._set_reason(t.key, None)
        ts.last = {"rtt_ms": round(rtt_ms, 3) if rtt_ms is not None else None, "rcode": rcode, "ok": bool(ok)}
        self._publish_latest()

    def _set_reason(self, key: str, reason: Optional[str]) -> None:
        try:
            self.state.set_target_state(key, reason=reason)
        except Exception:  # noqa: BLE001
            log.exception("set_target_state failed")

    def _publish_latest(self) -> None:
        row: Dict[str, Any] = {}
        for key, ts in self._targets.items():
            if ts.last is not None:
                row[key] = dict(ts.last)
        with self._lock:
            row["sys_ms"] = self.sys_ms
            row["sys_ok"] = self.sys_ok
        row["t"] = self.wall()
        try:
            self.state.set_latest("dns", row)
        except Exception:  # noqa: BLE001
            log.exception("set_latest failed")

    def measure_system_resolver(self) -> Optional[float]:
        """Time one ``getaddrinfo(SYS_RESOLVE_NAME)``; stores ``sys_ms`` (None on failure)."""
        t0 = self.clock()
        ok = True
        try:
            self.getaddrinfo(SYS_RESOLVE_NAME, None)
        except (socket.gaierror, OSError, UnicodeError) as exc:
            ok = False
            log.debug("system resolver failed: %s", exc)
        except Exception:  # noqa: BLE001
            ok = False
            log.exception("system resolver call failed")
        ms = (self.clock() - t0) * 1000.0
        with self._lock:
            self.sys_ms = round(ms, 2) if ok else None
            self.sys_ok = ok
            self._sys_t = self.wall()
        self._publish_latest()
        return self.sys_ms

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
            _safe_close(p.sock)
        self._pending.clear()


def _safe_close(sock: Any) -> None:
    try:
        sock.close()
    except Exception:  # noqa: BLE001
        pass


__all__ = [
    "DnsProber", "build_query", "parse_response", "encode_name", "random_test_name",
    "QTYPE_A", "QTYPE_AAAA", "QCLASS_IN", "FLAGS_RD", "INTERVAL_S", "TIMEOUT_S", "RECURSION_EVERY",
    "UNREACHABLE_AFTER", "SYS_RESOLVE_INTERVAL_S", "SYS_RESOLVE_NAME", "TEST_ZONE",
]
