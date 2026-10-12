"""On-demand bufferbloat load test (SPEC_FULL S7; BUILD_PLAN §1): idle / down / up / recover.

Each phase lasts ``loadtest.phase_s`` seconds. ``down`` runs
``loadtest.threads`` parallel HTTPS GETs of
``https://speed.cloudflare.com/__down?bytes=100000000`` that are streamed and
discarded until the phase ends; ``up`` runs parallel POSTs of random bytes
(8 MB bodies, repeated) to ``https://speed.cloudflare.com/__up``. Per phase
the throughput (Mb/s) and the latency p50/p95 of the reference targets
``inet4_cf`` / ``inet4_g`` (from ``state.raw_window``) are recorded; the grade
is derived from the added median latency under load: A < 15 ms, B < 40,
C < 100, D < 250, else F.

The test refuses to start while an episode is open (``EpisodeOpen``) unless
forced, and while another run is in progress (``LoadTestBusy``). While it
runs ``state.loadtest`` is ``{"running", "phase", "elapsed_s", "live", "last"}``
(the ``GET /api/loadtest`` body), ``loadtest`` is published for SSE, a
``loadtest_phase`` note is raised at every phase start and the result row
(SPEC_FULL §6.7 ``loadtests.jsonl``) is stored at the end.

``run_cli(cfg)`` runs the same sequence headlessly; without the probe engine
it measures latency with the ping binary through the platform layer.
"""
from __future__ import annotations

import http.client
import logging
import os
import re
import threading
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("laglens.loadtest")

PHASES = ("idle", "down", "up", "recover")
LOAD_PHASES = ("down", "up")
DOWN_URL = "https://speed.cloudflare.com/__down?bytes=100000000"
UP_URL = "https://speed.cloudflare.com/__up"
UP_BODY_BYTES = 8 * 1024 * 1024
CHUNK = 64 * 1024
HTTP_TIMEOUT_S = 10.0
REFERENCE_KEYS = ("inet4_cf", "inet4_g")
GRADES = ((15.0, "A"), (40.0, "B"), (100.0, "C"), (250.0, "D"))
_PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


class LoadTestBusy(Exception):
    """A load test is already running."""


class EpisodeOpen(Exception):
    """An episode is open; pass ``force=True`` to run anyway."""


def grade_for(added_ms: Optional[float]) -> Optional[str]:
    """Letter grade for the added latency under load (``None`` when unknown)."""
    if added_ms is None:
        return None
    for limit, letter in GRADES:
        if added_ms < limit:
            return letter
    return "F"


def _pct(values: Sequence[float], p: float) -> Optional[float]:
    if not values:
        return None
    vs = sorted(values)
    if len(vs) == 1:
        return round(vs[0], 2)
    k = (len(vs) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(vs) - 1)
    return round(vs[lo] + (vs[hi] - vs[lo]) * (k - lo), 2)


def latency_summary(rtts: Sequence[float]) -> Dict[str, Any]:
    return {"p50": _pct(rtts, 50), "p95": _pct(rtts, 95), "n": len(rtts)}


# ---------------------------------------------------------------------------
# HTTP transfer (real); tests inject a fake with the same two methods
# ---------------------------------------------------------------------------
class HttpTransfer:
    """Streams downloads/uploads over ``http.client`` until ``stop()`` says so."""

    def __init__(self, timeout: float = HTTP_TIMEOUT_S) -> None:
        self.timeout = timeout
        self._blob = os.urandom(CHUNK)

    def _conn(self, url: str) -> Tuple[Any, str]:
        u = urllib.parse.urlsplit(url)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        if u.scheme == "http":
            conn: Any = http.client.HTTPConnection(u.hostname or "", u.port or 80, timeout=self.timeout)
        else:
            conn = http.client.HTTPSConnection(u.hostname or "", u.port or 443, timeout=self.timeout)
        return conn, path

    def download(self, url: str, stop: Callable[[], bool], on_bytes: Callable[[int], None]) -> None:
        while not stop():
            conn, path = self._conn(url)
            try:
                conn.request("GET", path, headers={"User-Agent": "LagLens/1.0"})
                resp = conn.getresponse()
                while not stop():
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    on_bytes(len(chunk))
            except (OSError, http.client.HTTPException) as exc:
                log.debug("loadtest: download error: %s", exc)
                if not stop():
                    time.sleep(0.5)
            finally:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass

    def upload(self, url: str, stop: Callable[[], bool], on_bytes: Callable[[int], None]) -> None:
        while not stop():
            conn, path = self._conn(url)
            try:
                conn.putrequest("POST", path)
                conn.putheader("User-Agent", "LagLens/1.0")
                conn.putheader("Content-Type", "application/octet-stream")
                conn.putheader("Content-Length", str(UP_BODY_BYTES))
                conn.endheaders()
                sent = 0
                while sent < UP_BODY_BYTES and not stop():
                    n = min(CHUNK, UP_BODY_BYTES - sent)
                    conn.send(self._blob[:n])
                    sent += n
                    on_bytes(n)
                if sent >= UP_BODY_BYTES:
                    resp = conn.getresponse()
                    resp.read(4096)
            except (OSError, http.client.HTTPException) as exc:
                log.debug("loadtest: upload error: %s", exc)
                if not stop():
                    time.sleep(0.5)
            finally:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass


# ---------------------------------------------------------------------------
# Latency sources
# ---------------------------------------------------------------------------
def state_latency_source(state: Any) -> Callable[[float, float], List[float]]:
    """RTTs (ms) of the reference targets in ``[t_from, t_to)`` from the raw ring."""

    def source(t_from: float, t_to: float) -> List[float]:
        out: List[float] = []
        for key in REFERENCE_KEYS:
            t = state.target(key)
            if t is None:
                continue
            for s in state.raw_window(t.id, t_from, t_to):
                if s.received and s.value >= 0:
                    out.append(s.value / 1000.0)
        return out

    return source


class PingSampler:
    """Headless latency source: ``ping -c 1`` through the platform layer at ~4 Hz."""

    def __init__(self, platform: Any, targets: Sequence[str] = ("1.1.1.1", "8.8.8.8"), rate_hz: float = 4.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.platform = platform
        self.targets = list(targets)
        self.period = 1.0 / max(0.5, rate_hz)
        self._clock = clock
        self._samples: List[Tuple[float, Optional[float]]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.errors = 0

    def argv(self, target: str) -> List[str]:
        if self.platform.name == "darwin":
            return ["ping", "-n", "-c", "1", "-t", "1", target]
        if ":" in target:
            return ["ping", "-6", "-n", "-c", "1", "-W", "1", target]
        return ["ping", "-n", "-c", "1", "-W", "1", target]

    def once(self, target: str) -> Optional[float]:
        out = self.platform.run(self.argv(target), timeout=3.0)
        if not out:
            self.errors += 1
            return None
        m = _PING_TIME_RE.search(out)
        return float(m.group(1)) if m else None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="loadtest-ping", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(3.0)

    def _loop(self) -> None:
        i = 0
        while not self._stop.is_set():
            t = self._clock()
            target = self.targets[i % len(self.targets)]
            i += 1
            try:
                rtt = self.once(target)
            except Exception:  # noqa: BLE001
                rtt = None
            with self._lock:
                self._samples.append((t, rtt))
            rest = self.period - (self._clock() - t)
            if rest > 0:
                self._stop.wait(rest)

    def rtts(self, t_from: float, t_to: float) -> List[float]:
        with self._lock:
            return [r for t, r in self._samples if r is not None and t_from <= t < t_to]


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------
class LoadTest:
    """``LoadTest(ctx)``; ``.start(force)``, ``.stop()``, ``.status()``, ``.run_sync()``."""

    name = "loadtest"

    def __init__(self, ctx: Any, transfer: Optional[Any] = None,
                 latency_source: Optional[Callable[[float, float], List[float]]] = None,
                 clock: Callable[[], float] = time.time, wait: Optional[Callable[[float], None]] = None,
                 on_phase: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.cfg = ctx.cfg or {}
        lcfg = self.cfg.get("loadtest") or {}
        try:
            self.phase_s = max(1.0, float(lcfg.get("phase_s", 20)))
        except (TypeError, ValueError):
            self.phase_s = 20.0
        try:
            self.threads = max(1, int(lcfg.get("threads", 4)))
        except (TypeError, ValueError):
            self.threads = 4
        self.transfer = transfer or HttpTransfer()
        self.latency = latency_source or state_latency_source(self.state)
        self._clock = clock
        self._wait = wait or (lambda s: self.state.stop_event.wait(s))
        self._on_phase = on_phase
        self._lock = threading.Lock()
        self._abort = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._seq = 0
        self.id: Optional[str] = None
        self.last: Optional[Dict[str, Any]] = None
        self._bytes = 0
        self._bytes_lock = threading.Lock()

    # ----------------------------------------------------------------- API
    def status(self) -> Dict[str, Any]:
        """The ``GET /api/loadtest`` body."""
        with self.state.lock:
            d = dict(self.state.loadtest or {})
        d.setdefault("running", False)
        d.setdefault("phase", None)
        d.setdefault("elapsed_s", 0)
        d.setdefault("live", None)
        d.setdefault("last", self.last)
        return d

    def start(self, force: bool = False) -> Dict[str, Any]:
        """Start the test in a background thread; raises ``LoadTestBusy`` / ``EpisodeOpen``."""
        with self._lock:
            if self._running:
                raise LoadTestBusy("load test already running")
            if not force and self.state.open_episodes():
                raise EpisodeOpen("an episode is open")
            self._running = True
            self._abort.clear()
            self._seq += 1
            self.id = "lt-%d" % self._seq
            # Mark it running before the thread exists so GET /api/loadtest agrees with the
            # LoadTestBusy answer of a second POST that arrives before the first phase starts.
            self._set_state(running=True, phase=None, elapsed_s=0, live=None)
            self._thread = threading.Thread(target=self._thread_body, name="loadtest", daemon=True)
            self._thread.start()
        return {"ok": True, "id": self.id, "phases": list(PHASES), "eta_s": int(self.phase_s * len(PHASES))}

    def stop(self, timeout: float = 5.0) -> None:
        """Abort a running test (no-op otherwise)."""
        self._abort.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout)

    def _thread_body(self) -> None:
        try:
            self.run_sync()
        except Exception:  # noqa: BLE001 - never let the thread die loudly
            log.exception("loadtest: run failed")
            self._set_state(running=False, phase=None, live=None, error="run failed")
        finally:
            with self._lock:
                self._running = False

    # --------------------------------------------------------------- engine
    def _set_state(self, **kv: Any) -> Dict[str, Any]:
        with self.state.lock:
            d = dict(self.state.loadtest or {})
            d.update(kv)
            d.setdefault("last", self.last)
            d["id"] = self.id
            self.state.loadtest = d
        try:
            self.state.publish("loadtest", {"phase": d.get("phase"), "live": d.get("live"), "running": d.get("running"),
                                            "elapsed_s": d.get("elapsed_s"), "id": self.id})
        except Exception:  # noqa: BLE001
            pass
        return d

    def _count(self, n: int) -> None:
        with self._bytes_lock:
            self._bytes += n

    def _workers(self, phase: str, stop: Callable[[], bool]) -> List[threading.Thread]:
        if phase not in LOAD_PHASES:
            return []
        fn = self.transfer.download if phase == "down" else self.transfer.upload
        url = DOWN_URL if phase == "down" else UP_URL

        def body() -> None:
            try:
                fn(url, stop, self._count)
            except Exception:  # noqa: BLE001
                log.debug("loadtest: worker error", exc_info=True)

        out = []
        for i in range(self.threads):
            t = threading.Thread(target=body, name="loadtest-%s-%d" % (phase, i), daemon=True)
            t.start()
            out.append(t)
        return out

    def run_sync(self) -> Dict[str, Any]:
        """Run the four phases in the calling thread and return the ``loadtests.jsonl`` row."""
        if self.id is None:
            self._seq += 1
            self.id = "lt-%d" % self._seq
        with self._lock:
            self._running = True
        t0 = self._clock()
        phases: Dict[str, Dict[str, Any]] = {}
        aborted = False
        try:
            for phase in PHASES:
                if self._abort.is_set() or self.state.stop_event.is_set():
                    aborted = True
                    break
                phases[phase] = self._phase(phase, t0)
                if self._abort.is_set():
                    aborted = True
                    break
        finally:
            with self._lock:
                self._running = False
        t1 = self._clock()
        idle_p50 = (phases.get("idle") or {}).get("p50")
        added: Dict[str, Optional[float]] = {}
        for ph in LOAD_PHASES:
            p50 = (phases.get(ph) or {}).get("p50")
            added[ph] = round(p50 - idle_p50, 1) if (p50 is not None and idle_p50 is not None) else None
        worst = [v for v in added.values() if v is not None]
        grade = grade_for(max(worst)) if worst and not aborted else None
        row = {"t0": round(t0, 3), "t1": round(t1, 3), "id": self.id, "phases": phases, "grade": grade, "added_ms": added,
               "aborted": aborted, "phase_s": self.phase_s, "threads": self.threads}
        self.last = row
        self._set_state(running=False, phase=None, elapsed_s=round(t1 - t0, 1), live=None, last=row)
        if not aborted:
            try:
                self.store.append_json("loadtests", row)
            except Exception:  # noqa: BLE001
                log.debug("loadtest: append_json failed", exc_info=True)
        log.info("loadtest %s: grade %s, added %s", self.id, grade, added)
        return row

    def _phase(self, phase: str, t0: float) -> Dict[str, Any]:
        start = self._clock()
        end = start + self.phase_s
        with self._bytes_lock:
            self._bytes = 0
        self._set_state(running=True, phase=phase, elapsed_s=round(start - t0, 1), live={"mbps": None, "p95": None})
        try:
            self.state.raise_note("loadtest_phase", t=start, severity=1, note="load test phase %s" % phase, phase=phase, id=self.id)
        except Exception:  # noqa: BLE001
            pass

        def stop() -> bool:
            return self._abort.is_set() or self.state.stop_event.is_set() or self._clock() >= end

        workers = self._workers(phase, stop)
        last_pub = start
        while not stop():
            self._wait(0.25)
            now = self._clock()
            if now - last_pub >= 1.0:
                last_pub = now
                with self._bytes_lock:
                    b = self._bytes
                el = max(0.001, now - start)
                live = {"mbps": round(b * 8.0 / el / 1e6, 1) if phase in LOAD_PHASES else None,
                        "p95": _pct(self.latency(start, now), 95)}
                self._set_state(running=True, phase=phase, elapsed_s=round(now - t0, 1), live=live)
        for w in workers:
            w.join(5.0)
        finish = self._clock()
        with self._bytes_lock:
            b = self._bytes
        dur = max(0.001, finish - start)
        res: Dict[str, Any] = latency_summary(self.latency(start, finish))
        if phase in LOAD_PHASES:
            res["mbps"] = round(b * 8.0 / dur / 1e6, 1)
            res["bytes"] = b
        res["dur_s"] = round(dur, 1)
        if self._on_phase is not None:
            try:
                self._on_phase(phase, res)
            except Exception:  # noqa: BLE001
                pass
        return res


# ---------------------------------------------------------------------------
# Headless CLI
# ---------------------------------------------------------------------------
class _NullStore:
    def __init__(self) -> None:
        self.rows: List[Tuple[str, dict]] = []

    def append_json(self, name: str, obj: dict) -> None:
        self.rows.append((name, obj))


class _CliContext:
    def __init__(self, cfg: dict, state: Any, platform: Any) -> None:
        self.cfg = cfg
        self.state = state
        self.store = _NullStore()
        self.platform = platform
        self.components: Dict[str, Any] = {}

    def component(self, name: str) -> Optional[Any]:
        return self.components.get(name)


def format_table(row: Dict[str, Any]) -> str:
    """Human-readable result table for ``--loadtest``."""
    lines = ["%-8s %10s %9s %9s %6s" % ("PHASE", "Mb/s", "p50 ms", "p95 ms", "n")]
    for ph in PHASES:
        r = (row.get("phases") or {}).get(ph) or {}
        mb = r.get("mbps")
        lines.append("%-8s %10s %9s %9s %6s" % (ph, ("%.1f" % mb) if mb is not None else "-",
                                               _fmt(r.get("p50")), _fmt(r.get("p95")), r.get("n", 0)))
    added = row.get("added_ms") or {}
    lines.append("added latency under load: down %s ms, up %s ms" % (_fmt(added.get("down")), _fmt(added.get("up"))))
    lines.append("grade: %s%s" % (row.get("grade") or "n/a", " (aborted)" if row.get("aborted") else ""))
    return "\n".join(lines)


def _fmt(v: Any) -> str:
    return ("%.1f" % v) if isinstance(v, (int, float)) else "-"


def run_cli(cfg: dict, platform: Optional[Any] = None, transfer: Optional[Any] = None,
            sampler: Optional[Any] = None, out: Callable[[str], Any] = print, state: Optional[Any] = None,
            clock: Callable[[], float] = time.time) -> int:
    """Headless load test: prints a phase line as each phase ends and the result table."""
    from laglens.state import State

    if platform is None:
        from laglens.platform import get_platform

        platform = get_platform()
    st = state or State(cfg=cfg)
    ctx = _CliContext(cfg, st, platform)
    own_sampler = sampler is None
    if own_sampler:
        sampler = PingSampler(platform, clock=clock)
        sampler.start()

    def on_phase(phase: str, res: Dict[str, Any]) -> None:
        out("%-8s done: %s Mb/s, p50 %s ms, p95 %s ms (%d samples)" % (
            phase, _fmt(res.get("mbps")), _fmt(res.get("p50")), _fmt(res.get("p95")), res.get("n", 0)))

    lt = LoadTest(ctx, transfer=transfer, latency_source=sampler.rtts, clock=clock, on_phase=on_phase,
                  wait=lambda s: st.stop_event.wait(s))
    out("Lag Lens load test: %d phases x %.0f s (%d threads); latency via %s" % (
        len(PHASES), lt.phase_s, lt.threads, "ping binary" if own_sampler else "engine"))
    try:
        row = lt.run_sync()
    except KeyboardInterrupt:
        lt.stop()
        out("aborted")
        return 1
    finally:
        if own_sampler:
            sampler.stop()
    out(format_table(row))
    if own_sampler and getattr(sampler, "errors", 0) and not any((row["phases"].get(p) or {}).get("n") for p in PHASES):
        out("warning: no latency samples (ping binary failed); grade unavailable")
    return 0 if row and not row.get("aborted") else 1


__all__ = ["LoadTest", "LoadTestBusy", "EpisodeOpen", "HttpTransfer", "PingSampler", "state_latency_source",
           "grade_for", "latency_summary", "format_table", "run_cli", "PHASES", "DOWN_URL", "UP_URL"]
