"""Path discovery, hop roles, route-change notes and the episode sweep (SPEC_FULL §5.3, §4.8).

``Tracer(ctx)`` runs in one supervised thread:

* **when**: at start (after the engine is up), every ``path.discover_interval_s``
  (30 min), when the default gateway changes and when ``isp_hop4`` stops
  answering for 5 minutes; ``rediscover()`` queues one asynchronously.
* **what**: TTL 1..``path.max_ttl`` toward ``1.1.1.1`` and
  ``2606:4700:4700::1111`` (v6 skipped without a v6 default route), 2 probes
  per TTL 150 ms apart, 1.5 s timeout. Methods in order: **native** (macOS: a
  dedicated DGRAM ICMP socket with ``IP_TTL``/``IPV6_UNICAST_HOPS``; the
  TTL-exceeded datagram arrives via ``recvfrom`` with ``addr`` = hop and is
  matched on the quoted inner id + seq; Linux: ``IP_RECVERR``/``IPV6_RECVERR``
  on the dedicated socket, ``recvmsg(MSG_ERRQUEUE)``, offender = hop), then
  ``tracepath -n -m N``, then the ``ping -t``/``-m`` TTL trick, then
  ``traceroute -n -q1 -w1 -m N`` (``mtr -n -r -c1`` as a last resort).
* **roles**: ``gw`` (TTL 1; must equal the default gateway, else a
  ``path_anomaly`` note), ``isp_hop`` (first hop past the gateway outside
  the LAN prefix, any address incl. 10.60.x.x), ``mid_hop`` (first public hop
  after ``isp_hop`` whose median RTT is ≥ 5 ms above it and that answers
  direct echo ≥ 3/5; else the first public hop answering direct echo; else
  none). A role hop that answers ≥ 3 of 5 direct echoes becomes a continuously
  probed target (``isp_hop4`` / ``mid_hop4`` / ``isp_hop6``, rate
  ``hop_rate_hz``) through ``state.add_target`` + ``targets.save_targets``;
  hops that do not answer are listed but not probed, with the reason recorded.
* **rDNS** is looked up in a worker thread joined for 2 s (informational).
* every discovery writes one ``path.jsonl`` row per destination; a hop-list
  change raises ``route_change`` (old/new) and bumps ``state.path['changes']``.
* ``sweep(reason)``: one asynchronous round (1 probe per TTL) toward 1.1.1.1,
  rate-limited to one per 60 s, stored into the newest open episode's
  ``.sweep`` and into ``path.jsonl`` with ``"sweep": true``.
* ``current()`` is the ``GET /api/path`` body; ``state.path`` mirrors it.
"""
from __future__ import annotations

import ipaddress
import logging
import random
import re
import select
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from statistics import median
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple

from laglens import targets as targetsmod
from laglens.probes import pingbin
from laglens.probes.icmp import (
    COOKIE,
    IDENT,
    PKIND_TTL,
    REPLIES_HAVE_IP_HEADER,
    build_echo,
    enable_recverr,
    errqueue_is_time_exceeded,
    errqueue_is_unreachable,
    open_icmp_socket,
    parse_errqueue,
    parse_payload,
    parse_reply,
    set_ttl,
    sockaddr_for,
)
from laglens.state import Target
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.path")

DST4 = "1.1.1.1"
DST6 = "2606:4700:4700::1111"
DEFAULT_MAX_TTL = 12
DEFAULT_INTERVAL_S = 1800
PROBES_PER_TTL = 2
PROBE_GAP_S = 0.15
PROBE_SPACING_S = 0.01
PROBE_TIMEOUT_S = 1.5
ECHO_CHECK_N = 5
ECHO_CHECK_MIN = 3
MID_HOP_DELTA_MS = 5.0
MAX_MID_CANDIDATES = 6
RDNS_JOIN_S = 2.0
SWEEP_MIN_INTERVAL_S = 60.0
ROUTE_POLL_S = 60.0
ISP_SILENT_S = 300.0
ENGINE_WAIT_S = 15.0
HISTORY_KEEP = 20
#: Payload ``target_id`` of tracer probes (never a real target id, which is ≤ 255).
TRACER_TARGET = 0xFFFF
CMD_TIMEOUT_S = 25.0
#: Linux only; absent from ``socket`` on macOS (the value is Linux's, used only on the errqueue path).
MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)

ROLE_KEYS = {4: (("isp_hop", "isp_hop4"), ("mid_hop", "mid_hop4")), 6: (("isp_hop", "isp_hop6"),)}

_seq_lock = threading.Lock()
_seq_counter = random.SystemRandom().randrange(0, 0xFFFF)


def _next_seq() -> int:
    global _seq_counter
    with _seq_lock:
        _seq_counter = (_seq_counter + 1) & 0xFFFF
        return _seq_counter


# ---------------------------------------------------------------------------
# Hops
# ---------------------------------------------------------------------------
@dataclass
class Hop:
    """One TTL level of a trace."""

    ttl: int
    ip: Optional[str] = None
    rtt: List[Optional[float]] = field(default_factory=list)  # ms per probe, None = no answer
    rdns: Optional[str] = None
    reached: bool = False  # the destination itself answered at this TTL
    unreachable: bool = False  # a destination-unreachable came back from ``ip``

    @property
    def median_ms(self) -> Optional[float]:
        vals = [v for v in self.rtt if v is not None]
        return float(median(vals)) if vals else None

    @property
    def loss_pct(self) -> int:
        if not self.rtt:
            return 100
        return int(round(100.0 * sum(1 for v in self.rtt if v is None) / len(self.rtt)))

    def to_dict(self) -> dict:
        d = {"ttl": self.ttl, "ip": self.ip, "rdns": self.rdns, "rtt": list(self.rtt)}
        if self.reached:
            d["reached"] = True
        if self.unreachable:
            d["unreachable"] = True
        return d


def _ip_or_none(tok: str) -> Optional[str]:
    tok = tok.strip().strip("()[],")
    try:
        ipaddress.ip_address(tok.split("%")[0])
    except ValueError:
        return None
    return tok


def _is_global(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return bool(ipaddress.ip_address(ip.split("%")[0]).is_global)
    except ValueError:
        return False


def _is_link_local(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return bool(ipaddress.ip_address(ip.split("%")[0]).is_link_local)
    except ValueError:
        return False


def _same_ip(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    try:
        return ipaddress.ip_address(a.split("%")[0]) == ipaddress.ip_address(b.split("%")[0])
    except ValueError:
        return a == b


def _same_iid(a: Optional[str], b: Optional[str]) -> bool:
    """Two IPv6 addresses sharing the 64-bit interface identifier (one router's link-local and global address).

    The TTL-1 responder of a v6 trace is usually the gateway's *global*
    address while the default route names its link-local one.
    """
    if not a or not b:
        return False
    try:
        ia = ipaddress.ip_address(a.split("%")[0])
        ib = ipaddress.ip_address(b.split("%")[0])
    except ValueError:
        return False
    if ia.version != 6 or ib.version != 6:
        return False
    return ia.packed[8:] == ib.packed[8:]


def _finish(results: Dict[int, Hop], max_ttl: int) -> List[Hop]:
    """Hop list 1..last, truncated after the first TTL that reached the destination.

    TTLs missing from ``results`` *between* answering hops are listed as
    "no answer"; TTLs after the last one present are not listed at all (a
    command's output stops at the destination without saying "reached";
    the native tracer pre-populates every TTL it probed, so its silent
    trailing hops are kept).
    """
    last = max((ttl for ttl in results if 1 <= ttl <= max_ttl), default=0)
    hops: List[Hop] = []
    for ttl in range(1, last + 1):
        h = results.get(ttl) or Hop(ttl)
        hops.append(h)
        if h.reached or h.unreachable:
            break
    return hops


def mark_reached(hops: Sequence[Hop], dst: str) -> List[Hop]:
    """Flag the hop whose address is ``dst`` as the destination (command parsers cannot know it)."""
    out = list(hops)
    for h in out:
        if h.ip and _same_ip(h.ip, dst):
            h.reached = True
    return out


# ---------------------------------------------------------------------------
# Command-output parsers (fallback methods)
# ---------------------------------------------------------------------------
_TRACEPATH_RE = re.compile(r"^\s*(\d+)\??:\s+(\S+)\s+(?:\S+\s+)??([\d.]+)ms(.*)$")
_TRACEPATH_NOREPLY_RE = re.compile(r"^\s*(\d+)\??:\s+no reply")
_PING_EXCEEDED_RE = re.compile(r"\bfrom\s+([0-9a-fA-F.:%]+?)[:,]?\s+.*?(time to live exceeded|time exceeded|hop limit)", re.I)
_PING_REPLY_RE = re.compile(r"bytes from\s+([0-9a-fA-F.:%]+?)[:,]\s.*?time[=<]\s*([\d.]+)\s*ms", re.I)
_TRACEROUTE_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_MS_RE = re.compile(r"([\d.]+)\s*ms")
_MTR_RE = re.compile(r"^\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%?\s+(\d+)\s+([\d.]+)")  # ``???`` rows print no ``%``


def parse_tracepath(text: str, max_ttl: int = DEFAULT_MAX_TTL) -> List[Hop]:
    """``tracepath -n -m N`` output → hops (several lines per TTL = several probes)."""
    results: Dict[int, Hop] = {}
    for line in (text or "").splitlines():
        if "[LOCALHOST]" in line or line.strip().startswith("Resume:"):
            continue
        m = _TRACEPATH_NOREPLY_RE.match(line)
        if m:
            ttl = int(m.group(1))
            if 1 <= ttl <= max_ttl:
                results.setdefault(ttl, Hop(ttl)).rtt.append(None)
            continue
        m = _TRACEPATH_RE.match(line)
        if not m:
            continue
        ttl = int(m.group(1))
        if not 1 <= ttl <= max_ttl:
            continue
        ip = _ip_or_none(m.group(2))
        h = results.setdefault(ttl, Hop(ttl))
        if ip and h.ip is None:
            h.ip = ip
        try:
            h.rtt.append(float(m.group(3)))
        except ValueError:
            h.rtt.append(None)
        if "reached" in m.group(4):
            h.reached = True
    return _finish(results, max_ttl) if results else []


def parse_ping_ttl(text: str) -> Tuple[Optional[str], Optional[float], bool]:
    """One ``ping -c1 -t/-m TTL`` run → ``(ip, rtt_ms, reached)``.

    Linux: ``From 10.60.12.1 icmp_seq=1 Time to live exceeded``; macOS:
    ``36 bytes from 10.0.0.1: Time to live exceeded``; a normal reply line
    (``64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.3 ms``) means the
    destination was reached.
    """
    for line in (text or "").splitlines():
        m = _PING_REPLY_RE.search(line)
        if m:
            try:
                return _ip_or_none(m.group(1)), float(m.group(2)), True
            except ValueError:
                return _ip_or_none(m.group(1)), None, True
        m = _PING_EXCEEDED_RE.search(line)
        if m:
            return _ip_or_none(m.group(1)), None, False
    return None, None, False


def parse_traceroute(text: str, max_ttl: int = DEFAULT_MAX_TTL) -> List[Hop]:
    """``traceroute -n -q1 -w1 -m N`` output → hops (first responder per line)."""
    results: Dict[int, Hop] = {}
    for line in (text or "").splitlines():
        if line.lower().startswith("traceroute"):
            continue
        m = _TRACEROUTE_LINE_RE.match(line)
        if not m:
            continue
        ttl = int(m.group(1))
        if not 1 <= ttl <= max_ttl:
            continue
        rest = m.group(2)
        h = results.setdefault(ttl, Hop(ttl))
        ip = None
        for tok in rest.split():
            cand = _ip_or_none(tok)
            if cand:
                ip = cand
                break
        if ip and h.ip is None:
            h.ip = ip
        rtts = [float(x) for x in _MS_RE.findall(rest)]
        stars = rest.count("*")
        h.rtt.extend(rtts)
        h.rtt.extend([None] * stars)
        if not h.rtt:
            h.rtt.append(None)
    return _finish(results, max_ttl) if results else []


def parse_mtr(text: str, max_ttl: int = DEFAULT_MAX_TTL) -> List[Hop]:
    """``mtr -n -r -c1`` report → hops (``???`` = no answer)."""
    results: Dict[int, Hop] = {}
    for line in (text or "").splitlines():
        m = _MTR_RE.match(line)
        if not m:
            continue
        ttl = int(m.group(1))
        if not 1 <= ttl <= max_ttl:
            continue
        ip = _ip_or_none(m.group(2))
        h = results.setdefault(ttl, Hop(ttl))
        if ip:
            h.ip = ip
            try:
                loss = float(m.group(3))
            except ValueError:
                loss = 0.0
            h.rtt.append(None if loss >= 100.0 else float(m.group(5)))
        else:
            h.rtt.append(None)
    return _finish(results, max_ttl) if results else []


# ---------------------------------------------------------------------------
# Native TTL probing
# ---------------------------------------------------------------------------
def _default_waiter(sock: Any, timeout: float) -> bool:
    try:
        r, _, _ = select.select([sock], [], [], max(0.0, timeout))
    except (OSError, ValueError):
        return False
    return bool(r)


class _Probe:
    __slots__ = ("seq", "ttl", "idx", "t_send", "done")

    def __init__(self, seq: int, ttl: int, idx: int, t_send: float) -> None:
        self.seq = seq
        self.ttl = ttl
        self.idx = idx
        self.t_send = t_send
        self.done = False


class NativeTracer:
    """TTL probing on a dedicated DGRAM ICMP socket (macOS datagrams / Linux errqueue)."""

    def __init__(
        self,
        family: int,
        platform_name: Optional[str] = None,
        socket_factory: Callable[[int], Any] = open_icmp_socket,
        clock: Callable[[], float] = time.monotonic,
        waiter: Callable[[Any, float], bool] = _default_waiter,
        ident: int = IDENT,
        cookie: int = COOKIE,
        nametoindex: Optional[Callable[[str], int]] = None,
        has_ip_header: Optional[bool] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self.family = 6 if family == 6 else 4
        self.platform_name = platform_name or ("linux" if sys.platform.startswith("linux") else "darwin")
        #: Set by the owner at shutdown: a running trace / echo check returns promptly with what it has.
        self._stop = stop_event if stop_event is not None else threading.Event()
        self.linux = self.platform_name == "linux"
        self._socket_factory = socket_factory
        self._clock = clock
        self._waiter = waiter
        self.ident = ident & 0xFFFF
        self.cookie = cookie
        self._nametoindex = nametoindex
        self.has_ip_header = (not self.linux) if has_ip_header is None else bool(has_ip_header)
        self.sock: Any = None
        self.method = "errqueue" if self.linux else "native"
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------ socket
    def open(self) -> None:
        """Open the socket (and enable the error queue on Linux); raises ``OSError``."""
        s = self._socket_factory(self.family)
        if self.linux:
            try:
                enable_recverr(s, self.family)
            except OSError:
                s.close()
                raise
        self.sock = s

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:  # noqa: BLE001
                pass
            self.sock = None

    def _sockaddr(self, addr: str) -> Tuple[Any, ...]:
        if self._nametoindex is not None:
            return sockaddr_for(addr, self.family, nametoindex=self._nametoindex)
        return sockaddr_for(addr, self.family)

    # -------------------------------------------------------------- probes
    def _aborted(self) -> bool:
        """Shutdown requested or the socket closed under a running loop."""
        return self._stop.is_set() or self.sock is None

    def _send(self, dst_sockaddr: Tuple[Any, ...], ttl: int, probe: _Probe) -> bool:
        if self.sock is None:
            return False
        try:
            set_ttl(self.sock, self.family, ttl)
            pkt = build_echo(self.family, probe.seq, TRACER_TARGET, int(self._clock() * 1e9), kind=PKIND_TTL,
                             extra=ttl & 0xFF, ident=self.ident, cookie=self.cookie)
            self.sock.sendto(pkt, dst_sockaddr)
            return True
        except OSError as exc:
            self.last_error = "send ttl %d: %s" % (ttl, exc)
            return False

    def _seq_from_errdata(self, data: bytes) -> Optional[int]:
        """The probe seq quoted back by the Linux error queue (ICMP header or bare payload)."""
        if len(data) >= 8 and data[0] in (8, 128):
            p = parse_payload(data[8:])
            if p is not None and p.matches(self.cookie):
                return p.seq & 0xFFFF
            return int.from_bytes(data[6:8], "big")
        p = parse_payload(data)
        if p is not None and p.matches(self.cookie):
            return p.seq & 0xFFFF
        return None

    def _reap(self, pend: Dict[int, _Probe], on_hop: Callable[[_Probe, Optional[str], float, str], None]) -> None:
        """Drain everything receivable right now (non-blocking)."""
        now = self._clock()
        if self.sock is None:
            return
        if self.linux:
            for _ in range(64):
                try:
                    data, anc, _flags, _addr = self.sock.recvmsg(2048, 512, MSG_ERRQUEUE)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError as exc:
                    self.last_error = "errqueue: %s" % exc
                    break
                seq = self._seq_from_errdata(data)
                info = parse_errqueue(anc, self.family)
                if seq is None or info is None:
                    continue
                probe = pend.get(seq)
                if probe is None or probe.done:
                    continue
                if errqueue_is_time_exceeded(self.family, info):
                    on_hop(probe, info.offender, now, "exceeded")
                elif errqueue_is_unreachable(self.family, info):
                    on_hop(probe, info.offender, now, "unreachable")
                else:
                    on_hop(probe, None, now, "error")
        for _ in range(64):
            try:
                buf, addr = self.sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                break
            except OSError as exc:
                self.last_error = "recv: %s" % exc
                break
            reply = parse_reply(self.family, buf, self.has_ip_header)
            if reply is None:
                continue
            src = addr[0] if addr else None
            if reply.is_echo_reply:
                p = reply.payload
                if p is None or not p.matches(self.cookie) or p.target_id != TRACER_TARGET:
                    continue
                probe = pend.get(p.seq & 0xFFFF)
                if probe is not None and not probe.done:
                    on_hop(probe, src, now, "reached")
            elif reply.is_time_exceeded or reply.is_unreachable:
                inner = reply.inner
                if inner is None:
                    continue
                if inner.payload is not None:
                    if not inner.payload.matches(self.cookie) or inner.payload.target_id != TRACER_TARGET:
                        continue
                    seq = inner.payload.seq & 0xFFFF
                elif inner.ident == self.ident:
                    seq = inner.seq
                else:
                    continue
                probe = pend.get(seq)
                if probe is not None and not probe.done:
                    on_hop(probe, src, now, "exceeded" if reply.is_time_exceeded else "unreachable")

    def trace(self, dst: str, max_ttl: int = DEFAULT_MAX_TTL, probes: int = PROBES_PER_TTL, gap_s: float = PROBE_GAP_S,
              timeout_s: float = PROBE_TIMEOUT_S, spacing_s: float = PROBE_SPACING_S) -> List[Hop]:
        """One trace toward ``dst``: ``probes`` per TTL, ``gap_s`` apart; ``timeout_s`` after the last send."""
        if self.sock is None:
            self.open()
        dst_sa = self._sockaddr(dst)
        results: Dict[int, Hop] = {}
        for ttl in range(1, max_ttl + 1):
            results[ttl] = Hop(ttl, rtt=[None] * probes)
        t0 = self._clock()
        plan: List[Tuple[float, int, int]] = []
        for idx in range(probes):
            for ttl in range(1, max_ttl + 1):
                plan.append((t0 + idx * gap_s + (ttl - 1) * spacing_s, ttl, idx))
        plan.sort()
        pend: Dict[int, _Probe] = {}
        reached_ttl: List[int] = []

        def on_hop(probe: _Probe, ip: Optional[str], now: float, what: str) -> None:
            probe.done = True
            h = results[probe.ttl]
            if ip and h.ip is None:
                h.ip = ip
            h.rtt[probe.idx] = round((now - probe.t_send) * 1000.0, 2)
            if what == "reached":
                h.reached = True
                reached_ttl.append(probe.ttl)
            elif what == "unreachable":
                h.unreachable = True

        deadline = plan[-1][0] + timeout_s if plan else t0
        i = 0
        while not self._aborted():
            now = self._clock()
            while i < len(plan) and plan[i][0] <= now:
                _t, ttl, idx = plan[i]
                i += 1
                if reached_ttl and ttl > min(reached_ttl):
                    continue  # past the destination: pointless
                probe = _Probe(_next_seq(), ttl, idx, self._clock())
                if self._send(dst_sa, ttl, probe):
                    pend[probe.seq] = probe
            outstanding = any(not p.done for p in pend.values())
            if i >= len(plan) and (not outstanding or now >= deadline):
                break
            next_t = plan[i][0] if i < len(plan) else deadline
            wait = min(next_t, deadline) - now
            if self._waiter(self.sock, max(0.0, min(wait, 0.25))):
                self._reap(pend, on_hop)
        self._reap(pend, on_hop)
        return _finish(results, max_ttl)

    def echo_check(self, ip: str, n: int = ECHO_CHECK_N, spacing_s: float = 0.1, timeout_s: float = PROBE_TIMEOUT_S) -> int:
        """Send ``n`` direct echoes (TTL 64) to ``ip``; return how many replied."""
        if self.sock is None:
            self.open()
        sa = self._sockaddr(ip)
        pend: Dict[int, _Probe] = {}
        got = {"n": 0}

        def on_hop(probe: _Probe, src: Optional[str], now: float, what: str) -> None:
            probe.done = True
            if what == "reached":
                got["n"] += 1

        t0 = self._clock()
        sent = 0
        deadline = t0 + (n - 1) * spacing_s + timeout_s
        while not self._aborted():
            now = self._clock()
            while sent < n and now >= t0 + sent * spacing_s:
                probe = _Probe(_next_seq(), 64, sent, self._clock())
                if self._send(sa, 64, probe):
                    pend[probe.seq] = probe
                sent += 1
            if sent >= n and (got["n"] >= n or now >= deadline or not any(not p.done for p in pend.values())):
                break
            next_t = t0 + sent * spacing_s if sent < n else deadline
            wait = min(next_t, deadline) - now
            if self._waiter(self.sock, max(0.0, min(wait, 0.25))):
                self._reap(pend, on_hop)
        self._reap(pend, on_hop)
        return got["n"]


# ---------------------------------------------------------------------------
# Command fallbacks
# ---------------------------------------------------------------------------
class CommandTracer:
    """``tracepath`` → ``ping`` TTL trick → ``traceroute`` → ``mtr`` through ``platform.run``."""

    def __init__(self, platform: Any, platform_name: Optional[str] = None) -> None:
        self.platform = platform
        self.platform_name = platform_name or getattr(platform, "name", "generic")
        self.darwin = self.platform_name == "darwin"
        self.errors: List[str] = []

    def _has(self, name: str) -> bool:
        if name.startswith("/"):
            return bool(self.platform.exists(name))
        return bool(self.platform.which(name))

    def tracepath(self, dst: str, family: int, max_ttl: int) -> List[Hop]:
        if not self._has("tracepath"):
            return []
        argv = ["tracepath", "-n", "-m", str(max_ttl), dst]
        out = self.platform.run(argv, timeout=CMD_TIMEOUT_S)
        if not out:
            self.errors.append("tracepath: no output")
            return []
        return parse_tracepath(out, max_ttl)

    def _ping_argv(self, dst: str, family: int, ttl: int) -> Optional[List[str]]:
        if self.darwin:
            if family == 6:
                return ["/sbin/ping6", "-n", "-c", "1", "-h", str(ttl), dst] if self._has("/sbin/ping6") else None
            return ["/sbin/ping", "-n", "-c", "1", "-m", str(ttl), "-t", "1", dst] if self._has("/sbin/ping") else None
        if not self._has("ping"):
            return None
        argv = ["ping"]
        if family == 6:
            argv.append("-6")
        return argv + ["-n", "-c", "1", "-t", str(ttl), "-W", "1", dst]

    def ping_ttl(self, dst: str, family: int, max_ttl: int) -> List[Hop]:
        if self._ping_argv(dst, family, 1) is None:
            return []
        results: Dict[int, Hop] = {}
        any_answer = False
        for ttl in range(1, max_ttl + 1):
            argv = self._ping_argv(dst, family, ttl)
            res = self.platform.run_rc(argv, timeout=3.0) if argv else None
            text = (res[1] + "\n" + res[2]) if res else ""
            ip, rtt, reached = parse_ping_ttl(text)
            h = Hop(ttl, ip=ip, rtt=[rtt if ip else None], reached=reached)
            results[ttl] = h
            if ip:
                any_answer = True
            if reached:
                break
        if not any_answer:
            self.errors.append("ping TTL trick: no hop answered")
            return []
        return _finish(results, max_ttl)

    def traceroute(self, dst: str, family: int, max_ttl: int) -> List[Hop]:
        if self.darwin:
            binary = "/usr/sbin/traceroute6" if family == 6 else "/usr/sbin/traceroute"
            if not self._has(binary):
                binary = "traceroute6" if family == 6 else "traceroute"
                if not self._has(binary):
                    return []
            argv = [binary, "-n", "-q", "1", "-w", "1", "-m", str(max_ttl), dst]
        else:
            if not self._has("traceroute"):
                return []
            argv = ["traceroute"] + (["-6"] if family == 6 else []) + ["-n", "-q", "1", "-w", "1", "-m", str(max_ttl), dst]
        res = self.platform.run_rc(argv, timeout=CMD_TIMEOUT_S)
        if not res or not (res[1] or "").strip():
            self.errors.append("traceroute: no output")
            return []
        return parse_traceroute(res[1], max_ttl)

    def mtr(self, dst: str, family: int, max_ttl: int) -> List[Hop]:
        if not self._has("mtr"):
            return []
        argv = ["mtr", "-n", "-r", "-c", "1", "-m", str(max_ttl)] + (["-6"] if family == 6 else ["-4"]) + [dst]
        out = self.platform.run(argv, timeout=CMD_TIMEOUT_S)
        if not out:
            self.errors.append("mtr: no output")
            return []
        return parse_mtr(out, max_ttl)

    def trace(self, dst: str, family: int, max_ttl: int) -> Tuple[List[Hop], Optional[str]]:
        """First fallback that yields at least one answering hop → ``(hops, method)``."""
        for name, fn in (("tracepath", self.tracepath), ("ping_ttl", self.ping_ttl), ("traceroute", self.traceroute),
                         ("mtr", self.mtr)):
            try:
                hops = fn(dst, family, max_ttl)
            except Exception as exc:  # noqa: BLE001
                self.errors.append("%s: %s" % (name, exc))
                continue
            if any(h.ip for h in hops):
                return _finish({h.ttl: h for h in mark_reached(hops, dst)}, max_ttl), name
        return [], None

    def echo_check(self, ip: str, family: int, n: int = ECHO_CHECK_N) -> Optional[int]:
        """Direct-echo count via the ping binary; ``None`` when no binary is usable."""
        binary = pingbin.find_ping_binary(self.platform, family)
        if not binary:
            return None
        if self.darwin:
            argv = [binary, "-n", "-c", str(n), "-i", "0.2", ip]
        else:
            argv = [binary] + (["-6"] if family == 6 else []) + ["-n", "-c", str(n), "-i", "0.2", "-W", "1", ip]
        res = self.platform.run_rc(argv, timeout=n * 0.2 + 4.0)
        if res is None:
            return None
        summary = pingbin.parse_ping_summary(res[1] + "\n" + res[2])
        return summary[1] if summary else 0


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
@dataclass
class RoleResult:
    roles: Dict[str, Optional[str]] = field(default_factory=dict)  # role -> ip
    info: Dict[str, dict] = field(default_factory=dict)  # role -> details
    anomalies: List[str] = field(default_factory=list)  # → path_anomaly notes
    reasons: List[str] = field(default_factory=list)  # informational (chip text), no note


def assign_roles(
    hops: Sequence[Hop],
    family: int,
    gateway: Optional[str],
    lan_net: Optional[Any],
    echo_check: Callable[[str], Optional[int]],
    max_mid_candidates: int = MAX_MID_CANDIDATES,
    prefer_mid: Optional[str] = None,
) -> RoleResult:
    """Assign ``gw`` / ``isp_hop`` / ``mid_hop`` (v4) or ``gw6`` / ``isp_hop6`` (v6) per SPEC §5.3.

    ``echo_check(ip)`` returns the number of replies to 5 direct echoes (or
    ``None`` when no method is available, which counts as "not probed").
    ``prefer_mid`` is the previous discovery's mid hop: it is kept while it
    is still a candidate on the path and still answers direct echo, so a
    noisy two-sample median cannot move the target every 30 minutes.
    """
    res = RoleResult()
    sfx = "6" if family == 6 else ""
    gw_role = "gw" + sfx
    isp_role = "isp_hop" + sfx
    mid_role = "mid_hop" + sfx
    cache: Dict[str, Optional[int]] = {}

    def check(ip: str) -> Optional[int]:
        if ip not in cache:
            try:
                cache[ip] = echo_check(ip)
            except Exception as exc:  # noqa: BLE001
                log.warning("path: echo check of %s failed: %s", ip, exc)
                cache[ip] = None
        return cache[ip]

    def is_gateway(ip: Optional[str]) -> bool:
        if _same_ip(ip, gateway):
            return True
        return family == 6 and bool(gateway) and _same_iid(ip, gateway)

    def in_lan(ip: Optional[str]) -> bool:
        if not ip:
            return False
        if _is_link_local(ip) or is_gateway(ip):
            return True
        if lan_net is not None:
            try:
                return ipaddress.ip_address(ip.split("%")[0]) in lan_net
            except ValueError:
                return False
        return False

    first = hops[0] if hops else None
    gw_ip = first.ip if first else None
    res.roles[gw_role] = gw_ip
    res.info[gw_role] = {"ip": gw_ip, "ttl": 1, "median_ms": first.median_ms if first else None}
    if gw_ip is None:
        if gateway:
            # The gateway answers direct echo (it is probed as gw4/gw6) but sent no TTL-exceeded: some
            # routers rate-limit ICMP errors or never emit them. Not an anomaly; assume the default gateway.
            res.roles[gw_role] = gateway
            res.info[gw_role] = {"ip": gateway, "ttl": 1, "median_ms": None, "assumed": True,
                                 "reason": "gateway sent no TTL-exceeded; assumed from the default route"}
            res.reasons.append("IPv%d: first hop did not answer TTL-1 probes; assuming the default gateway %s"
                               % (family, gateway))
        else:
            res.anomalies.append("the first hop did not answer TTL-1 probes")
    elif gateway and not is_gateway(gw_ip):
        res.anomalies.append("first hop %s is not your gateway %s — VPN or wrong interface?" % (gw_ip, gateway))

    isp: Optional[Hop] = None
    for h in hops:
        if h.ttl == 1 and (in_lan(h.ip) or h.ip is None):
            continue
        if h.ip and not in_lan(h.ip):
            isp = h
            break
    if isp is None:
        res.roles[isp_role] = None
        res.info[isp_role] = {"ip": None, "probed": False, "reason": "no hop past the gateway answered"}
    else:
        replies = check(isp.ip or "")
        probed = replies is not None and replies >= ECHO_CHECK_MIN
        res.roles[isp_role] = isp.ip
        res.info[isp_role] = {
            "ip": isp.ip, "ttl": isp.ttl, "median_ms": isp.median_ms, "echo_replies": replies, "probed": probed,
            "reason": None if probed else ("hop does not answer direct echo (%s/%d)" % (replies if replies is not None else "?", ECHO_CHECK_N)),
        }

    if family == 6:
        return res

    mid: Optional[Hop] = None
    mid_reason = "mid-path hop: none found"
    sticky = False
    if isp is not None:
        cands = [h for h in hops if h.ttl > isp.ttl and h.ip and _is_global(h.ip) and not h.reached][:max_mid_candidates]
        isp_med = isp.median_ms
        if prefer_mid:
            for h in cands:
                if _same_ip(h.ip, prefer_mid):
                    r = check(h.ip or "")
                    if r is not None and r >= ECHO_CHECK_MIN:
                        mid = h
                        sticky = True
                    break
        for h in cands:
            if mid is not None:
                break
            med = h.median_ms
            if med is None or (isp_med is not None and med < isp_med + MID_HOP_DELTA_MS):
                continue
            r = check(h.ip or "")
            if r is not None and r >= ECHO_CHECK_MIN:
                mid = h
                break
        if mid is None:
            for h in cands:
                r = check(h.ip or "")
                if r is not None and r >= ECHO_CHECK_MIN:
                    mid = h
                    mid_reason = "no public hop ≥ 5 ms past the ISP hop answers echo; using the first that answers"
                    break
    if mid is None:
        res.roles[mid_role] = None
        res.info[mid_role] = {"ip": None, "probed": False, "reason": mid_reason}
    else:
        res.roles[mid_role] = mid.ip
        res.info[mid_role] = {"ip": mid.ip, "ttl": mid.ttl, "median_ms": mid.median_ms, "echo_replies": cache.get(mid.ip or ""),
                              "probed": True, "reason": None if mid_reason.startswith("mid-path") else mid_reason}
        if sticky:
            res.info[mid_role]["kept"] = True
    return res


def path_changed(old_hops: Optional[Sequence[dict]], new_hops: Sequence[Hop], old_roles: Optional[dict], new_roles: dict) -> bool:
    """Whether the hop list / role addresses changed between two discoveries of one destination.

    A hop that answers in one run and not in the other is *not* a change
    (flaky routers must not spam ``route_change``); two answering addresses
    at the same TTL that differ, or a role whose address moved, are.
    """
    if old_hops is None:
        return False
    new_ips = [h.ip for h in new_hops if h.ip]
    for role, ip in (new_roles or {}).items():
        old_ip = (old_roles or {}).get(role)
        if ip and old_ip and not _same_ip(ip, old_ip):
            if role.startswith("mid_hop") and any(_same_ip(old_ip, x) for x in new_ips):
                continue  # the mid hop was re-picked along an unchanged path: a measurement choice, not a route change
            return True
    old_by_ttl = {int(h.get("ttl", 0)): h.get("ip") for h in old_hops if isinstance(h, dict)}
    for h in new_hops:
        o = old_by_ttl.get(h.ttl)
        if h.ip and o and not _same_ip(h.ip, o):
            return True
    return False


# ---------------------------------------------------------------------------
# Tracer component
# ---------------------------------------------------------------------------
class Tracer:
    """Path discovery component (INTERFACES §10.2)."""

    def __init__(
        self,
        ctx: Any,
        native_factory: Optional[Callable[[int], NativeTracer]] = None,
        command_tracer: Optional[CommandTracer] = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        rdns: Callable[[str], Any] = socket.gethostbyaddr,
        engine_wait_s: float = ENGINE_WAIT_S,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.platform = ctx.platform
        self.cfg: dict = ctx.cfg or {}
        pcfg = self.cfg.get("path", {}) or {}
        self.max_ttl = int(pcfg.get("max_ttl", DEFAULT_MAX_TTL) or DEFAULT_MAX_TTL)
        self.interval_s = float(pcfg.get("discover_interval_s", DEFAULT_INTERVAL_S) or DEFAULT_INTERVAL_S)
        self.sweep_enabled = bool(pcfg.get("sweep_on_episode", True))
        self.hop_rate_hz = float(self.cfg.get("hop_rate_hz", 2) or 2)
        self.platform_name = getattr(self.platform, "name", None) or ("linux" if sys.platform.startswith("linux") else "darwin")
        self._clock = clock
        self._wall = wall
        self._rdns = rdns
        self.engine_wait_s = engine_wait_s
        self._stop = threading.Event()
        self._native_factory = native_factory or (
            lambda fam: NativeTracer(fam, self.platform_name, clock=clock, stop_event=self._stop))
        self._cmd = command_tracer or CommandTracer(self.platform, self.platform_name)
        self._native: Dict[int, Optional[NativeTracer]] = {4: None, 6: None}
        self._native_error: Dict[int, Optional[str]] = {4: None, 6: None}

        self._lock = threading.RLock()
        self._jobs: Deque[Tuple[str, str]] = deque()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.running = False
        self._next_discovery = 0.0
        self._last_sweep_at: Optional[float] = None
        self._last_route_poll = 0.0
        self._last_isp_rediscover = 0.0
        self._isp_added_at: Optional[float] = None
        self._gateway: Optional[str] = (getattr(ctx, "route", None) or {}).get("gateway")
        self._gateway6: Optional[str] = (getattr(ctx, "route", None) or {}).get("gateway6")
        self._prev: Dict[str, dict] = {}  # dst -> last discovery row
        self.doc: dict = {
            "v4": [], "v6": [], "roles": {}, "role_info": {}, "discovered_at": None, "changes": 0, "history": [],
            "method": None, "method6": None, "running": False, "last_sweep": None, "errors": {}, "next_discovery": None,
            "destinations": {"4": DST4, "6": DST6}, "reasons": [],
        }
        self._seed_from_store()
        self._publish_doc()

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._thread = start_thread("tracer", self._loop, self.state, stop_event=self._stop)

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()  # a running native trace / echo check returns at its next wait (≤ 0.25 s)
        self._wake.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout)
        for fam in (4, 6):
            nt = self._native.get(fam)
            if nt is not None:
                nt.close()

    def rediscover(self, reason: str = "api") -> bool:
        """Queue a discovery; ``False`` if one is already running."""
        with self._lock:
            if self.running or any(j[0] == "discover" for j in self._jobs):
                return False
            self._jobs.append(("discover", reason))
        self._wake.set()
        return True

    def sweep(self, reason: str = "episode") -> bool:
        """Queue one sweep round (rate-limited 1/60 s); ``False`` if skipped."""
        if not self.sweep_enabled:
            return False
        now = self._clock()
        with self._lock:
            if self._last_sweep_at is not None and now - self._last_sweep_at < SWEEP_MIN_INTERVAL_S:
                return False
            if any(j[0] == "sweep" for j in self._jobs):
                return False
            self._last_sweep_at = now
            self._jobs.append(("sweep", reason))
        self._wake.set()
        return True

    def current(self) -> dict:
        """The ``GET /api/path`` body."""
        with self._lock:
            d = dict(self.doc)
            d["v4"] = [dict(h) for h in self.doc.get("v4", [])]
            d["v6"] = [dict(h) for h in self.doc.get("v6", [])]
            d["roles"] = dict(self.doc.get("roles", {}))
            d["role_info"] = {k: dict(v) for k, v in self.doc.get("role_info", {}).items()}
            d["history"] = list(self.doc.get("history", []))
            d["running"] = self.running
            return d

    # ------------------------------------------------------------------ loop
    def _loop(self) -> None:
        st = self.state
        self._wait_for_engine()
        with self._lock:
            if not any(j[0] == "discover" for j in self._jobs):
                self._jobs.appendleft(("discover", "start"))
        while not st.stop_event.is_set() and not self._stop.is_set():
            job = None
            with self._lock:
                if self._jobs:
                    job = self._jobs.popleft()
            if job is None:
                self._wake.wait(1.0)
                self._wake.clear()
                self._periodic()
                continue
            kind, reason = job
            try:
                if kind == "discover":
                    self.discover(reason)
                elif kind == "sweep":
                    self.run_sweep(reason)
            except Exception:  # noqa: BLE001 - a failed discovery must not kill the thread
                if self._stop.is_set() or st.stop_event.is_set():
                    log.info("tracer: %s (%s) interrupted by shutdown", kind, reason)
                else:
                    log.exception("tracer: %s (%s) failed", kind, reason)
                with self._lock:
                    self.running = False

    def _wait_for_engine(self) -> None:
        deadline = self._clock() + self.engine_wait_s
        while self._clock() < deadline and not self._stop.is_set() and not self.state.stop_event.is_set():
            if self.ctx.component("engine") is not None:
                return
            self._stop.wait(0.25)

    def _periodic(self) -> None:
        now = self._clock()
        if self._next_discovery and now >= self._next_discovery:
            self.rediscover("interval")
            self._next_discovery = now + self.interval_s
        if now - self._last_route_poll >= ROUTE_POLL_S:
            self._last_route_poll = now
            try:
                route = self.platform.default_route() or {}
            except Exception:  # noqa: BLE001
                route = {}
            gw = route.get("gateway")
            gw6 = route.get("gateway6")
            if gw and self._gateway and not _same_ip(gw, self._gateway):
                log.warning("tracer: default gateway changed %s → %s", self._gateway, gw)
                self._gateway = gw
                self._gateway6 = gw6
                self.rediscover("gateway change")
            elif gw and not self._gateway:
                self._gateway = gw
                self._gateway6 = gw6
        t = self.state.target("isp_hop4")
        if t is not None and t.enabled and now - self._last_isp_rediscover >= ISP_SILENT_S:
            last = self.state.last_sample(t.id, received_only=True)
            ref = last.ts_ms / 1000.0 if last is not None else self._isp_added_at
            if ref is not None and self._wall() - ref >= ISP_SILENT_S:
                self._last_isp_rediscover = now
                self.rediscover("isp_hop4 silent for 5 min")

    # ------------------------------------------------------------- helpers
    def _seed_from_store(self) -> None:
        """On resume, reuse the last ``path.jsonl`` rows for history and change detection."""
        try:
            rows = self.store.read_json("path")
        except Exception:  # noqa: BLE001
            rows = []
        discoveries = [r for r in rows if isinstance(r, dict) and not r.get("sweep")]
        for r in discoveries:
            dst = r.get("dst")
            if dst:
                self._prev[dst] = r
        self.doc["history"] = discoveries[-HISTORY_KEEP:]
        if discoveries:
            last = discoveries[-1]
            self.doc["discovered_at"] = last.get("t")
            self.doc["changes"] = int(self.state.path.get("changes", 0) or 0)

    def _publish_doc(self) -> None:
        with self._lock:
            snap = self.current()
        try:
            with self.state.lock:
                self.state.path = snap
            self.state.set_latest("path", {
                "discovered_at": snap.get("discovered_at"), "changes": snap.get("changes"), "roles": snap.get("roles"),
                "method": snap.get("method"),
            })
        except Exception:  # noqa: BLE001
            log.exception("tracer: cannot publish state.path")

    def _route(self) -> dict:
        route = dict(getattr(self.ctx, "route", None) or {})
        try:
            fresh = self.platform.default_route() or {}
        except Exception:  # noqa: BLE001
            fresh = {}
        for k, v in fresh.items():
            if v is not None:
                route[k] = v
        if route.get("gateway"):
            self._gateway = route["gateway"]
        if route.get("gateway6"):
            self._gateway6 = route["gateway6"]
        return route

    @staticmethod
    def _lan_net(route: dict) -> Optional[Any]:
        lan_ip = route.get("lan_ip")
        plen = route.get("prefixlen")
        if lan_ip and plen:
            try:
                return ipaddress.ip_network("%s/%d" % (lan_ip, int(plen)), strict=False)
            except ValueError:
                return None
        return None

    def _native_for(self, fam: int) -> Optional[NativeTracer]:
        nt = self._native.get(fam)
        if nt is not None:
            return nt
        if self._native_error.get(fam):
            return None
        try:
            nt = self._native_factory(fam)
            nt.open()
        except OSError as exc:
            self._native_error[fam] = "native TTL probing unavailable (IPv%d): %s" % (fam, exc)
            log.warning("tracer: %s; using command fallbacks", self._native_error[fam])
            return None
        self._native[fam] = nt
        return nt

    def _trace(self, fam: int, dst: str, probes: int = PROBES_PER_TTL) -> Tuple[List[Hop], Optional[str], List[str]]:
        errors: List[str] = []
        nt = self._native_for(fam)
        native_hops: List[Hop] = []
        if nt is not None:
            try:
                native_hops = mark_reached(nt.trace(dst, self.max_ttl, probes=probes), dst)
            except OSError as exc:
                errors.append("native: %s" % exc)
                nt.close()
                self._native[fam] = None
            if any(h.ip for h in native_hops):
                return native_hops, nt.method, errors
            errors.append("native: no hop answered%s" % ((" (%s)" % nt.last_error) if nt.last_error else ""))
        elif self._native_error.get(fam):
            errors.append(self._native_error[fam] or "")
        self._cmd.errors = []
        hops, method = self._cmd.trace(dst, fam, self.max_ttl)
        errors.extend(self._cmd.errors)
        if method:
            return hops, method, errors
        return native_hops, (nt.method if nt is not None else None), errors

    def _echo_check(self, fam: int, ip: str) -> Optional[int]:
        nt = self._native_for(fam)
        if nt is not None:
            try:
                return nt.echo_check(ip)
            except OSError as exc:
                log.warning("tracer: native echo check of %s failed: %s", ip, exc)
        return self._cmd.echo_check(ip, fam)

    def _rdns_lookup(self, ips: List[str]) -> Dict[str, Optional[str]]:
        out: Dict[str, Optional[str]] = {}
        if not ips:
            return out

        def worker() -> None:
            for ip in ips:
                try:
                    out[ip] = self._rdns(ip.split("%")[0])[0]
                except Exception:  # noqa: BLE001 - herror/gaierror/timeout
                    out[ip] = None

        t = threading.Thread(target=worker, name="tracer-rdns", daemon=True)
        t.start()
        t.join(RDNS_JOIN_S)
        return dict(out)

    @staticmethod
    def _label(role: str, ip: str, rdns: Optional[str]) -> str:
        if role == "isp_hop":
            name = "Comcast" if rdns and "comcast" in rdns.lower() else "ISP"
            return "%s hop %s" % (name, ip)
        return "Mid-path hop %s" % ip

    def _apply_targets(self, fam: int, roles: RoleResult, rdns: Dict[str, Optional[str]]) -> None:
        """Add / update / disable the hop targets for the roles of one family."""
        st = self.state
        added = False
        for role, key in ROLE_KEYS.get(fam, ()):
            ip = roles.roles.get(role + ("6" if fam == 6 else ""))
            info = roles.info.get(role + ("6" if fam == 6 else ""), {})
            existing = st.target(key)
            if ip and info.get("probed"):
                label = self._label(role, ip, rdns.get(ip))
                if existing is None:
                    st.add_target(Target(id=-1, key=key, role=role, addr=ip, family=fam, kind="icmp", label=label,
                                         rate_hz=self.hop_rate_hz, mode="direct", extra={"rdns": rdns.get(ip)}))
                    added = True
                    log.info("tracer: probing %s as %s (%s)", ip, key, label)
                else:
                    st.set_target_state(key, enabled=True, reason=None, addr=ip, label=label, rate_hz=self.hop_rate_hz,
                                        family=fam, extra={"rdns": rdns.get(ip)})
                if role == "isp_hop" and fam == 4:
                    self._isp_added_at = self._wall()
                info["target"] = key
            elif existing is not None and existing.enabled:
                reason = info.get("reason") or ("hop not found in the path" if not ip else "hop does not answer direct echo")
                st.set_target_state(key, enabled=False, reason=reason)
                info["target"] = key
            elif ip and not info.get("probed"):
                log.info("tracer: %s %s listed but not probed: %s", role, ip, info.get("reason"))
        if added:
            targetsmod.save_targets(st, self.store)

    # ----------------------------------------------------------- discovery
    def discover(self, reason: str = "manual") -> Optional[dict]:
        """Run a full discovery now (synchronously); ``None`` if one is already running."""
        with self._lock:
            if self.running:
                return None
            self.running = True
            self.doc["running"] = True
        t_start = self._wall()
        log.info("tracer: discovery (%s)", reason)
        try:
            route = self._route()
            lan_net = self._lan_net(route)
            new_doc_roles: Dict[str, Optional[str]] = {}
            new_info: Dict[str, dict] = {}
            errors: Dict[str, Any] = {}
            reasons: List[str] = []
            rows: List[dict] = []
            methods: Dict[int, Optional[str]] = {4: None, 6: None}
            hops_json: Dict[int, List[dict]] = {4: [], 6: []}
            changes = 0
            for fam, dst in ((4, DST4), (6, DST6)):
                if self._stop.is_set():
                    break
                if fam == 6 and not route.get("gateway6"):
                    reasons.append("IPv6 path skipped: no IPv6 default route")
                    continue
                hops, method, errs = self._trace(fam, dst)
                if errs:
                    errors[str(fam)] = errs
                gateway = route.get("gateway") if fam == 4 else (route.get("gateway6") or "").split("%")[0] or None
                prev = self._prev.get(dst)
                prev_mid = ((prev or {}).get("roles") or {}).get("mid_hop") if fam == 4 else None
                roles = assign_roles(hops, fam, gateway, lan_net if fam == 4 else None,
                                     lambda ip, _f=fam: self._echo_check(_f, ip), prefer_mid=prev_mid)
                rd = self._rdns_lookup([h.ip for h in hops if h.ip])
                for h in hops:
                    if h.ip:
                        h.rdns = rd.get(h.ip)
                self._apply_targets(fam, roles, rd)
                for a in roles.anomalies:
                    self.state.raise_note("path_anomaly", severity=2, note=a, family=fam, dst=dst)
                    log.warning("tracer: %s", a)
                for r in roles.reasons:
                    reasons.append(r)
                    log.info("tracer: %s", r)
                changed = path_changed(prev.get("hops") if prev else None, hops, prev.get("roles") if prev else None,
                                       roles.roles)
                if changed:
                    changes += 1
                    old_ips = [h.get("ip") for h in (prev or {}).get("hops", [])]
                    new_ips = [h.ip for h in hops]
                    self.state.raise_note("route_change", severity=2, note="path to %s changed" % dst, old=old_ips,
                                          new=new_ips, dst=dst, family=fam)
                    log.warning("tracer: route to %s changed: %s → %s", dst, old_ips, new_ips)
                row = {
                    "t": round(self._wall(), 3), "dst": dst, "family": fam, "hops": [h.to_dict() for h in hops],
                    "roles": dict(roles.roles), "changed": bool(changed), "method": method, "reason": reason,
                }
                if not method:
                    row["error"] = "; ".join(errs) or "no TTL-probe method worked"
                self._prev[dst] = row
                rows.append(row)
                methods[fam] = method
                hops_json[fam] = row["hops"]
                new_doc_roles.update(roles.roles)
                new_info.update(roles.info)
                if not any(h.ip for h in hops):
                    reasons.append("IPv%d: no hop answered (%s)" % (fam, "; ".join(errs) or "no method"))
                try:
                    self.store.append_json("path", row)
                except Exception:  # noqa: BLE001
                    log.exception("tracer: cannot write path.jsonl")
            with self._lock:
                d = self.doc
                if hops_json[4] or methods[4]:
                    d["v4"] = hops_json[4]
                    d["method"] = methods[4]
                if hops_json[6] or methods[6]:
                    d["v6"] = hops_json[6]
                    d["method6"] = methods[6]
                if new_doc_roles:
                    d["roles"] = new_doc_roles
                    d["role_info"] = new_info
                d["discovered_at"] = t_start
                d["changes"] = int(d.get("changes", 0)) + changes
                d["history"] = (d.get("history", []) + rows)[-HISTORY_KEEP:]
                d["errors"] = errors
                d["reasons"] = reasons
                d["last_reason"] = reason
                self._next_discovery = self._clock() + self.interval_s
                d["next_discovery"] = self._wall() + self.interval_s
        finally:
            with self._lock:
                self.running = False
                self.doc["running"] = False
            self._publish_doc()
        return self.current()

    # --------------------------------------------------------------- sweep
    def run_sweep(self, reason: str = "episode", probes: int = 1) -> Optional[dict]:
        """One round toward 1.1.1.1 (synchronous); stored into the newest open episode."""
        with self._lock:
            if self.running:
                return None
            self.running = True
        try:
            hops, method, errs = self._trace(4, DST4, probes=probes)
            doc = {
                "t": round(self._wall(), 3), "dst": DST4,
                "hops": [{"ttl": h.ttl, "ip": h.ip, "rtt": list(h.rtt), "loss": h.loss_pct} for h in hops],
                "method": method, "reason": reason,
            }
            try:
                eps = self.state.open_episodes()
                if eps:
                    ep = eps[-1]
                    with self.state.lock:
                        ep.sweep = {"dst": DST4, "hops": doc["hops"], "t": doc["t"], "method": method}
                    doc["episode"] = ep.id
            except Exception:  # noqa: BLE001
                log.exception("tracer: cannot attach sweep to the episode")
            row = dict(doc)
            row["sweep"] = True
            try:
                self.store.append_json("path", row)
            except Exception:  # noqa: BLE001
                log.exception("tracer: cannot write the sweep row")
            with self._lock:
                self.doc["last_sweep"] = doc
            return doc
        finally:
            with self._lock:
                self.running = False
            self._publish_doc()


__all__ = [
    "Hop", "parse_tracepath", "parse_ping_ttl", "parse_traceroute", "parse_mtr", "NativeTracer", "CommandTracer",
    "RoleResult", "assign_roles", "path_changed", "mark_reached", "Tracer", "DST4", "DST6", "TRACER_TARGET", "ECHO_CHECK_MIN",
    "ECHO_CHECK_N", "MID_HOP_DELTA_MS", "SWEEP_MIN_INTERVAL_S",
]
