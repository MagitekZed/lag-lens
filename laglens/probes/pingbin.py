"""Ping-binary fallback backend (SPEC_FULL §5.1 "Fallback backend").

Used per address family when the unprivileged DGRAM ICMP socket cannot be
opened (``PermissionError`` / ``EACCES`` / ``EPROTONOSUPPORT``). One
``ping`` subprocess per target:

* Linux (iputils): ``ping -n -O -i <interval> -W 2 -D <ip>`` (``-6`` for v6);
* macOS: ``/sbin/ping -n -i <interval> <ip>`` / ``/sbin/ping6 -n -i <interval> <ip6>``.

The reply lines (``icmp_seq=N ... time=X ms``) give the RTT. Loss is a
**sequence gap older than** ``timeout_ms`` (2 s by default) on both OSes:
iputils' ``no answer yet for icmp_seq=N`` (printed 250 ms after a send,
before the next one) and macOS' ``Request timeout for icmp_seq N`` are
parsed and counted but are only *hints* — a reply can still arrive — so the
lost verdict is always the timeout sweep, exactly like the socket engine. A
reply that arrives after the lost verdict and within ``late_window_ms`` is a
second sample flagged ``F_LATE``.

Every sample carries ``F_FALLBACK``. Trains, big packets and TTL kinds do
not exist on this backend (deferred in v1 anyway). The engine's ``emit``
callback finalises the common flags (``F_LOADTEST``, ``F_XBOX_ASLEEP``,
``F_STALL``), the slot and the store write.

Send times are estimated: ping sends seq ``N`` at ``anchor + N × interval``;
``anchor`` is refined from every reply (``recv − rtt − N × interval``), and
before the first reply it is the spawn time. The first sequence number is
learnt from the first line that carries one (macOS counts from 0, iputils
from 1) so the gap sweep never invents a lost seq 0 on Linux.

A seq that was declared lost and whose late window has passed is *settled*:
a reply that still turns up for it is dropped (it is neither a fresh receive
nor a late one), exactly like the socket engine forgets its pending entry.

The subprocess is restarted (backoff 1 → 30 s) if it exits; ``stop()``
terminates the children.
"""
from __future__ import annotations

import errno
import logging
import os
import re
import select
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from laglens.state import F_ERROR, F_FALLBACK, F_LATE, F_LOST, KIND_ICMP, Sample, Target
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.pingbin")

DEFAULT_INTERVAL_S = 0.25
MIN_INTERVAL_S = 0.2  # unprivileged iputils/macOS floor
DEFAULT_TIMEOUT_S = 2.0
DEFAULT_LATE_WINDOW_S = 10.0
RESTART_BACKOFF_MIN_S = 1.0
RESTART_BACKOFF_MAX_S = 30.0
HEALTHY_RUN_S = 60.0
READ_CHUNK = 4096
MAX_LINE = 4096

_TS_RE = re.compile(r"^\[(\d+(?:\.\d+)?)\]\s*")
_REPLY_RE = re.compile(r"icmp_seq[= ](\d+).*?\btime[=<]\s*([\d.]+)\s*ms", re.I)
_NO_ANSWER_RE = re.compile(r"no answer yet for icmp_seq[= ](\d+)", re.I)
_TIMEOUT_RE = re.compile(r"Request timeout for icmp_seq[= ](\d+)", re.I)
_FROM_ERR_RE = re.compile(r"^From (\S+?):?\s+icmp_seq[= ](\d+)\s+(.+?)\s*$", re.I)
_SENDTO_RE = re.compile(r"sendto:\s*(.+?)\s*$", re.I)
_SUMMARY_RE = re.compile(r"(\d+) packets transmitted,\s*(\d+)(?: packets)? received", re.I)
_DUP = "(DUP!)"

_ERR_TEXT_ERRNO = (
    ("host unreachable", errno.EHOSTUNREACH),
    ("no route to host", errno.EHOSTUNREACH),
    ("host is down", errno.EHOSTDOWN),
    ("net unreachable", errno.ENETUNREACH),
    ("network unreachable", errno.ENETUNREACH),
    ("port unreachable", errno.ECONNREFUSED),
    ("prohibited", errno.EACCES),
    ("time to live exceeded", errno.ETIMEDOUT),
    ("time exceeded", errno.ETIMEDOUT),
    ("frag needed", errno.EMSGSIZE),
    ("packet too big", errno.EMSGSIZE),
)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
@dataclass
class PingLine:
    """One parsed line of ``ping`` output."""

    kind: str  # 'reply' | 'dup' | 'noanswer' | 'timeout' | 'error' | 'sendto' | 'summary'
    seq: Optional[int] = None
    rtt_ms: Optional[float] = None
    ts: Optional[float] = None  # iputils ``-D`` receive timestamp (unix s)
    errno: Optional[int] = None
    text: str = ""


def _errno_for(text: str) -> int:
    low = text.lower()
    for needle, code in _ERR_TEXT_ERRNO:
        if needle in low:
            return code
    return errno.EIO


def parse_ping_line(line: str) -> Optional[PingLine]:
    """Classify a ``ping`` output line (iputils or macOS/BSD); ``None`` if uninteresting.

    Handles ``[ts] 64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms``
    (iputils ``-D``), ``16 bytes from 2606:…, icmp_seq=0 hlim=57 time=12.3 ms``
    (macOS ping6), ``no answer yet for icmp_seq=5`` (iputils ``-O``),
    ``Request timeout for icmp_seq 3`` (macOS), ``From 10.0.0.1 icmp_seq=1
    Destination Host Unreachable`` (iputils), ``ping: sendto: No route to
    host`` and the final ``N packets transmitted, M received`` summary.
    """
    s = line.strip()
    if not s:
        return None
    ts: Optional[float] = None
    m = _TS_RE.match(s)
    if m:
        try:
            ts = float(m.group(1))
        except ValueError:
            ts = None
        s = s[m.end():]
    m = _REPLY_RE.search(s)
    if m and "from" in s.lower():
        try:
            seq = int(m.group(1))
            rtt = float(m.group(2))
        except ValueError:
            return None
        return PingLine("dup" if _DUP in s else "reply", seq=seq, rtt_ms=rtt, ts=ts, text=s)
    m = _NO_ANSWER_RE.search(s)
    if m:
        return PingLine("noanswer", seq=int(m.group(1)), ts=ts, text=s)
    m = _TIMEOUT_RE.search(s)
    if m:
        return PingLine("timeout", seq=int(m.group(1)), ts=ts, text=s)
    m = _FROM_ERR_RE.match(s)
    if m:
        return PingLine("error", seq=int(m.group(2)), ts=ts, errno=_errno_for(m.group(3)), text=s)
    m = _SENDTO_RE.search(s)
    if m and s.lower().startswith("ping"):
        return PingLine("sendto", errno=_errno_for(m.group(1)), text=s)
    m = _SUMMARY_RE.search(s)
    if m:
        return PingLine("summary", text=s)
    return None


def parse_ping_summary(text: str) -> Optional[Tuple[int, int]]:
    """``(transmitted, received)`` from a ``ping`` run's summary line, or ``None``."""
    m = _SUMMARY_RE.search(text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


# ---------------------------------------------------------------------------
# Binaries / argv
# ---------------------------------------------------------------------------
def find_ping_binary(platform: Any, family: int) -> Optional[str]:
    """Path of the ping binary for ``family`` on this platform, or ``None``."""
    name = getattr(platform, "name", "generic")
    if name == "darwin":
        cand = "/sbin/ping6" if family == 6 else "/sbin/ping"
        if platform.exists(cand):
            return cand
        found = platform.which("ping6" if family == 6 else "ping")
        return found
    found = platform.which("ping")
    if found:
        return found
    if family == 6:
        return platform.which("ping6")
    return None


def ping_argv(platform_name: str, addr: str, family: int, interval_s: float = DEFAULT_INTERVAL_S,
              timeout_s: float = DEFAULT_TIMEOUT_S, binary: Optional[str] = None) -> List[str]:
    """The continuous ``ping`` command line for one target.

    Linux (iputils): ``ping [-6] -n -O -i I -W T -D <ip>``; macOS:
    ``/sbin/ping -n -i I <ip>`` or ``/sbin/ping6 -n -i I <ip6>``.
    """
    interval = max(MIN_INTERVAL_S, float(interval_s))
    ival = ("%.3f" % interval).rstrip("0").rstrip(".")
    if platform_name == "darwin":
        if family == 6:
            return [binary or "/sbin/ping6", "-n", "-i", ival, addr]
        return [binary or "/sbin/ping", "-n", "-i", ival, addr]
    argv = [binary or "ping"]
    if family == 6:
        argv.append("-6")
    argv += ["-n", "-O", "-i", ival, "-W", str(int(round(timeout_s))), "-D", addr]
    return argv


def _default_read_wait(fd: int, timeout: float) -> bool:
    try:
        r, _, _ = select.select([fd], [], [], timeout)
    except (OSError, ValueError):
        return False
    return bool(r)


# ---------------------------------------------------------------------------
# One target
# ---------------------------------------------------------------------------
class PingProcess:
    """One ``ping`` child for one target: parsing, loss/late accounting, restart."""

    def __init__(
        self,
        target: Target,
        argv: List[str],
        emit: Callable[[Sample], None],
        spawn: Callable[..., Any] = subprocess.Popen,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        interval_s: float = DEFAULT_INTERVAL_S,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        late_window_s: float = DEFAULT_LATE_WINDOW_S,
        read_wait: Callable[[int, float], bool] = _default_read_wait,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self.target = target
        self.argv = list(argv)
        self.emit = emit
        self._spawn = spawn
        self._clock = clock
        self._wall = wall
        self.interval_s = max(MIN_INTERVAL_S, float(interval_s))
        self.timeout_s = float(timeout_s)
        self.late_window_s = float(late_window_s)
        self._read_wait = read_wait
        self._stop = stop_event or threading.Event()
        self.proc: Any = None
        self.thread: Optional[threading.Thread] = None
        self.restarts = 0
        self.lines = 0
        self.errors = 0
        self.hints = 0
        self.sent_estimate = 0
        self.received = 0
        self.lost = 0
        self.late = 0
        self.last_error: Optional[str] = None
        self._reset(self._clock())

    # ------------------------------------------------------------ accounting
    def _reset(self, now: float) -> None:
        self.anchor_mono = now
        self._seen: Dict[int, float] = {}  # settled seqs (received, errored, or lost past the late window)
        self._lost: Dict[int, float] = {}  # seq -> send time (mono); lost, reply still possible
        self._cursor = 0
        self._base_seq: Optional[int] = None  # first seq this child uses (0 macOS, 1 iputils)
        self._partial = b""

    def _learn_base(self, seq: int) -> None:
        """The first seq-bearing line tells where ping's numbering starts."""
        if self._base_seq is None:
            self._base_seq = seq
            if self._cursor < seq and not self._seen and not self._lost:
                self._cursor = seq
        elif seq < self._base_seq:
            self._base_seq = seq

    def send_mono(self, seq: int) -> float:
        return self.anchor_mono + seq * self.interval_s

    def _ts_ms(self, seq: int, now_mono: float, now_wall: float) -> int:
        return int(round((now_wall - (now_mono - self.send_mono(seq))) * 1000))

    def _sample(self, seq: int, flags: int, value: int, now_mono: float, now_wall: float) -> Sample:
        return Sample(ts_ms=self._ts_ms(seq, now_mono, now_wall), target_id=self.target.id, kind=KIND_ICMP,
                      flags=flags | F_FALLBACK, seq=seq, value=value)

    def handle_line(self, line: str, now_mono: Optional[float] = None, now_wall: Optional[float] = None) -> Optional[Sample]:
        """Account one output line; returns the sample it produced (also emitted), if any."""
        now = self._clock() if now_mono is None else now_mono
        wall_now = self._wall() if now_wall is None else now_wall
        self.lines += 1
        pl = parse_ping_line(line)
        if pl is None:
            return None
        if pl.kind == "reply":
            seq = int(pl.seq or 0)
            rtt_s = (pl.rtt_ms or 0.0) / 1000.0
            self._learn_base(seq)
            if seq in self._lost:
                t_send = self._lost.pop(seq)
                self._seen[seq] = now  # settled either way
                if now - t_send <= self.late_window_s:
                    self.late += 1
                    s = self._sample(seq, F_LATE, int(round(rtt_s * 1e6)), now, wall_now)
                    self.emit(s)
                    return s
                return None
            if seq in self._seen:
                return None
            # refine the send-time anchor from this (timely) reply
            self.anchor_mono = now - rtt_s - seq * self.interval_s
            self._seen[seq] = now
            self.received += 1
            s = self._sample(seq, 0, int(round(rtt_s * 1e6)), now, wall_now)
            self.emit(s)
            return s
        if pl.kind == "dup":
            return None
        if pl.kind in ("noanswer", "timeout"):
            self.hints += 1  # a reply may still come; the sweep decides
            if pl.seq is not None:
                self._learn_base(int(pl.seq))
            return None
        if pl.kind == "error":
            seq = int(pl.seq or 0)
            self._learn_base(seq)
            self.errors += 1
            self.last_error = pl.text
            if seq in self._seen or seq in self._lost:
                return None
            self._seen[seq] = now
            s = self._sample(seq, F_ERROR, int(pl.errno or errno.EIO), now, wall_now)
            self.emit(s)
            return s
        if pl.kind == "sendto":
            self.errors += 1
            self.last_error = pl.text
        return None

    def sweep(self, now_mono: Optional[float] = None, now_wall: Optional[float] = None) -> List[Sample]:
        """Declare gaps older than ``timeout_s`` lost; forget lost seqs past the late window."""
        now = self._clock() if now_mono is None else now_mono
        wall_now = self._wall() if now_wall is None else now_wall
        out: List[Sample] = []
        expected = int((now - self.anchor_mono) // self.interval_s)
        if expected < 0:
            expected = -1
        self.sent_estimate = max(self.sent_estimate, expected + 1)
        while self._cursor <= expected:
            seq = self._cursor
            if seq in self._seen:
                self._cursor += 1
                continue
            t_send = self.send_mono(seq)
            if now - t_send < self.timeout_s:
                break
            self._lost[seq] = t_send
            self.lost += 1
            s = self._sample(seq, F_LOST, -1, now, wall_now)
            self.emit(s)
            out.append(s)
            self._cursor += 1
        # a lost seq whose late window has passed is settled: a reply for it is dropped from now on
        if self._lost:
            for seq in [k for k, t in self._lost.items() if now - t > self.late_window_s]:
                del self._lost[seq]
                self._seen[seq] = now
        if len(self._seen) > 4096:
            floor = self._cursor - 2048
            for seq in [k for k in self._seen if k < floor]:
                del self._seen[seq]
        return out

    # --------------------------------------------------------------- process
    def _spawn_child(self) -> Any:
        return self._spawn(self.argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           bufsize=0)

    def _feed(self, chunk: bytes) -> None:
        data = self._partial + chunk
        while True:
            nl = data.find(b"\n")
            if nl < 0:
                break
            line = data[:nl]
            data = data[nl + 1:]
            try:
                self.handle_line(line[:MAX_LINE].decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001 - one odd line must not kill the reader
                log.exception("pingbin %s: bad line %r", self.target.key, line[:120])
        self._partial = data[-MAX_LINE:]

    def run(self) -> None:
        """Thread body: spawn, read, sweep; restart with backoff if the child exits."""
        backoff = RESTART_BACKOFF_MIN_S
        while not self._stop.is_set():
            started = self._clock()
            self._reset(started)
            try:
                self.proc = self._spawn_child()
            except (OSError, ValueError) as exc:
                self.last_error = "cannot start %s: %s" % (self.argv[0], exc)
                log.warning("pingbin %s: %s; retry in %.0f s", self.target.key, self.last_error, backoff)
                self.restarts += 1
                if self._stop.wait(backoff):
                    break
                backoff = min(backoff * 2, RESTART_BACKOFF_MAX_S)
                continue
            fd = self.proc.stdout.fileno()
            while not self._stop.is_set():
                if self._read_wait(fd, min(0.25, self.interval_s)):
                    try:
                        chunk = os.read(fd, READ_CHUNK)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        break
                    self._feed(chunk)
                self.sweep()
            self._terminate(self.proc, 1.0)
            if self._stop.is_set():
                break
            rc = self.proc.poll()
            self.restarts += 1
            if self._clock() - started >= HEALTHY_RUN_S:
                backoff = RESTART_BACKOFF_MIN_S
            log.warning("pingbin %s: ping exited (rc=%s); restarting in %.0f s", self.target.key, rc, backoff)
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2, RESTART_BACKOFF_MAX_S)

    @staticmethod
    def _terminate(proc: Any, timeout: float) -> None:
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout)
                except Exception:  # noqa: BLE001 - subprocess.TimeoutExpired or a fake
                    try:
                        proc.kill()
                        proc.wait(0.5)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass

    def start(self, state: Any) -> None:
        self.thread = start_thread("pingbin-%s" % self.target.key, self.run, state, stop_event=self._stop, engine=True)

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._terminate(self.proc, min(1.0, timeout))
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout)

    def stats(self) -> dict:
        return {
            "key": self.target.key, "argv": self.argv, "restarts": self.restarts, "lines": self.lines,
            "received": self.received, "lost": self.lost, "late": self.late, "errors": self.errors,
            "last_error": self.last_error, "alive": bool(self.proc is not None and self.proc.poll() is None),
        }


# ---------------------------------------------------------------------------
# Per-family manager
# ---------------------------------------------------------------------------
class PingBackend:
    """Keeps one :class:`PingProcess` per enabled target of one address family.

    ``sync(targets)`` is called by the engine every second with the enabled
    ICMP targets of the family; processes are started for new targets,
    restarted when the address changed and stopped for targets that left.
    """

    name = "pingbin"

    def __init__(
        self,
        ctx: Any,
        family: int,
        emit: Callable[[Sample], None],
        binary: Optional[str] = None,
        spawn: Callable[..., Any] = subprocess.Popen,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        platform_name: Optional[str] = None,
        read_wait: Callable[[int, float], bool] = _default_read_wait,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.family = family
        self.emit = emit
        self.binary = binary
        self._spawn = spawn
        self._clock = clock
        self._wall = wall
        self._read_wait = read_wait
        self.platform_name = platform_name or getattr(ctx.platform, "name", "generic")
        cfg = ctx.cfg or {}
        self.timeout_s = float(cfg.get("timeout_ms", 2000) or 2000) / 1000.0
        self.late_window_s = float(cfg.get("late_window_ms", 10000) or 10000) / 1000.0
        self.procs: Dict[int, PingProcess] = {}
        self._stopped = False
        self._lock = threading.Lock()

    def _argv(self, t: Target) -> List[str]:
        rate = float(t.rate_hz or 4.0)
        interval = 1.0 / rate if rate > 0 else DEFAULT_INTERVAL_S
        return ping_argv(self.platform_name, t.addr or "", t.family, interval_s=interval, timeout_s=self.timeout_s,
                         binary=self.binary)

    def sync(self, targets: Iterable[Target]) -> None:
        """Start/stop children so exactly the given enabled targets are pinged."""
        if self._stopped:
            return
        want: Dict[int, Target] = {}
        for t in targets:
            if t.enabled and t.addr and t.family == self.family and t.kind == "icmp":
                want[t.id] = t
        with self._lock:
            for tid in [tid for tid in self.procs if tid not in want]:
                p = self.procs.pop(tid)
                p.stop(0.5)
                log.info("pingbin: stopped %s", p.target.key)
            for tid, t in want.items():
                argv = self._argv(t)
                cur = self.procs.get(tid)
                if cur is not None and cur.argv == argv:
                    continue
                if cur is not None:
                    cur.stop(0.5)
                p = PingProcess(
                    t, argv, self.emit, spawn=self._spawn, clock=self._clock, wall=self._wall,
                    interval_s=1.0 / float(t.rate_hz or 4.0), timeout_s=self.timeout_s,
                    late_window_s=self.late_window_s, read_wait=self._read_wait,
                )
                self.procs[tid] = p
                p.start(self.state)
                log.info("pingbin: started %s: %s", t.key, " ".join(argv))

    def stop(self, timeout: float = 2.0) -> None:
        """Terminate every child and join the reader threads."""
        self._stopped = True
        with self._lock:
            procs = list(self.procs.values())
            self.procs.clear()
        for p in procs:
            p.stop(max(0.2, timeout / max(1, len(procs))))

    def stats(self) -> dict:
        with self._lock:
            procs = list(self.procs.values())
        return {
            "family": self.family, "binary": self.binary, "processes": len(procs),
            "restarts": sum(p.restarts for p in procs), "lines": sum(p.lines for p in procs),
            "targets": [p.stats() for p in procs],
        }


__all__ = [
    "PingLine", "parse_ping_line", "parse_ping_summary", "find_ping_binary", "ping_argv", "PingProcess",
    "PingBackend", "DEFAULT_INTERVAL_S", "DEFAULT_TIMEOUT_S", "DEFAULT_LATE_WINDOW_S",
]
