"""Reusable smoke harness for the detection engine (detector, classify, verdict, marks, ticker, health).

Feeds synthetic sample streams through ``State`` → ``Ticker`` (or a bare
``Detector``) under a fake clock, with fakes for the tracer / DOCSIS
components the detector calls when an episode opens. Imported by
``test_detector*.py``, ``test_ticker*.py``, ``test_classify*.py``,
``test_matrix*.py``, ``test_verdict*.py`` and ``test_marks*.py`` (unittest
discovery puts ``tests/`` on ``sys.path``; ``test_detector_base`` re-exports
these names for older imports).

Building blocks:

* :class:`Session` — ``State`` + ``Store`` in a temp dir, the ladder targets
  of a real home run (gw4, gw6, xbox, isp_hop4, mid_hop4, four internet
  anycasts, a DNS and a TCP probe), ``emit()`` for one sample and
  ``stream()`` for a regular ICMP stream with per-sample hooks.
* :func:`make_ticker` — a :class:`laglens.engine.ticker.Ticker` on the
  session's fake clock (``tick(t)`` is called directly; no thread).
* :func:`feed` — the smoke loop: emit the samples of every wall second and
  tick once per second, exactly as the live engine + ticker do.
* :func:`fault` — a loss / RTT hook factory for the common fault shapes
  (``lost`` set of keys in a time window, ``slow`` keys with an RTT delta).
* :func:`run_episode` — stream a clean baseline, then a fault, then quiet
  until the episode closes; returns the closed episodes.
"""
import os
import random
import shutil
import sys
import tempfile
from argparse import Namespace
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import config as configmod  # noqa: E402
from laglens.state import (  # noqa: E402
    F_ERROR,
    F_LATE,
    F_LOADTEST,
    F_LOST,
    F_STALL,
    KIND_CDN_CONNECT,
    KIND_CDN_TTFB,
    KIND_DNS,
    KIND_ICMP,
    KIND_TCP,
    Episode,
    Sample,
    State,
    Target,
)
from laglens.store import Store  # noqa: E402

#: 2026-10-11 19:00:00 local-ish; a multiple of 5 so the slot grid starts at t0.
T0 = 1_760_223_600.0

#: key -> (role, addr, family, kind, rate_hz, p50 ms)
LADDER = [
    ("gw4", "gateway", "10.0.0.1", 4, "icmp", 4.0, 1.0),
    ("gw6", "gateway", "fe80::1", 6, "icmp", 4.0, 1.2),
    ("xbox", "xbox", "10.0.0.23", 4, "icmp", 4.0, 0.8),
    ("isp_hop4", "isp_hop", "10.60.12.1", 4, "icmp", 2.0, 12.0),
    ("mid_hop4", "mid_hop", "11.0.5.1", 4, "icmp", 2.0, 16.0),
    ("inet4_cf", "anycast", "1.1.1.1", 4, "icmp", 4.0, 14.0),
    ("inet4_g", "anycast", "8.8.8.8", 4, "icmp", 4.0, 15.0),
    ("inet6_cf", "anycast", "2606:4700:4700::1111", 6, "icmp", 4.0, 14.5),
    ("inet6_g", "anycast", "2001:4860:4860::8888", 6, "icmp", 4.0, 15.5),
    ("dns_gw", "dns", "10.0.0.1", 4, "dns", 1 / 3.0, 5.0),
    ("tcp_cf4", "tcp", "1.1.1.1", 4, "tcp", 0.5, 18.0),
]
P50 = {row[0]: row[6] for row in LADDER}
KIND_OF = {"icmp": KIND_ICMP, "dns": KIND_DNS, "tcp": KIND_TCP, "cdn": KIND_CDN_TTFB}
ICMP_KEYS = [row[0] for row in LADDER if row[4] == "icmp"]
INTERNET = ("inet4_cf", "inet4_g", "inet6_cf", "inet6_g")
BEYOND_GW = ("isp_hop4", "mid_hop4") + INTERNET


class FakeClock:
    """A settable wall clock."""

    def __init__(self, t: float = T0) -> None:
        self.t = float(t)

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> float:
        self.t += dt
        return self.t

    def set(self, t: float) -> None:
        self.t = float(t)


class FakePlatform:
    name = "darwin"

    def __init__(self) -> None:
        self.calls: List[str] = []

    def terminal_app_name(self) -> str:
        return "Terminal"


class FakeTracer:
    """Records ``sweep()`` calls (the detector asks for one when an episode opens)."""

    def __init__(self) -> None:
        self.sweeps: List[str] = []

    def sweep(self, reason: str) -> bool:
        self.sweeps.append(reason)
        return True


class FakeDocsis:
    def __init__(self) -> None:
        self.refreshes = 0

    def refresh(self) -> bool:
        self.refreshes += 1
        return True


class Ctx:
    """A minimal AppContext double (cfg, state, store, platform, component())."""

    def __init__(self, cfg: dict, state: State, store: Optional[Store], platform=None) -> None:
        self.cfg = cfg
        self.state = state
        self.store = store
        self.platform = platform or FakePlatform()
        self.args = Namespace(no_docsis=False, no_igd=False)
        self.components: Dict[str, object] = {}
        self.root = Path(".")

    def component(self, name: str):
        return self.components.get(name)


class FakeUsage:
    def __init__(self, free_mb: float = 50_000) -> None:
        self.free = int(free_mb * 1024 * 1024)
        self.total = self.free * 2
        self.used = self.free


def make_cfg(**over) -> dict:
    cfg = configmod.deep_merge(configmod.DEFAULTS, over)
    cfg.setdefault("_warnings", [])
    return cfg


class Session:
    """State + Store in a temp dir with a fake clock and the ladder targets."""

    def __init__(self, t0: float = T0, cfg: Optional[dict] = None, keys=None, with_store: bool = True) -> None:
        self.cfg = cfg or make_cfg()
        self.clock = FakeClock(t0)
        self.state = State(t0, "20261011-190000", cfg=self.cfg)
        self.state.clock = self.clock
        self.tmp: Optional[Path] = None
        self.store: Optional[Store] = None
        if with_store:
            self.tmp = Path(tempfile.mkdtemp(prefix="laglens-detect-"))
            self.store = Store(self.tmp / "20261011-190000", self.cfg, disk_usage=lambda p: FakeUsage())
        self.ctx = Ctx(self.cfg, self.state, self.store)
        self.tracer = FakeTracer()
        self.docsis = FakeDocsis()
        self.ctx.components["tracer"] = self.tracer
        self.ctx.components["docsis"] = self.docsis
        self.ids: Dict[str, int] = {}
        self.seq: Dict[str, int] = {}
        self.rng = random.Random(7)
        self.published: List = []
        self.state.subscribe(lambda n, o: self.published.append((n, o)))
        for row in LADDER:
            key, role, addr, fam, kind, rate, _ = row
            if keys is not None and key not in keys:
                continue
            t = self.state.add_target(Target(id=-1, key=key, role=role, addr=addr, family=fam, kind=kind, label=key, rate_hz=rate))
            self.ids[key] = t.id
            self.seq[key] = 0
        if "xbox" in self.ids:
            # what the Xbox collector reports once the console answers: only an awake console's loss counts
            self.state.xbox = {"ip": "10.0.0.23", "state": "awake", "source": "icmp", "link_mbps": None}

    def close(self) -> None:
        if self.store is not None:
            try:
                self.store.stop(timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
        if self.tmp is not None:
            shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ targets
    def add_target(self, key: str, role: str, addr: str, family: int = 4, kind: str = "icmp", rate_hz: float = 4.0,
                   p50_ms: float = 20.0, **fields) -> Target:
        """Add a target outside the default ladder (e.g. a CDN probe) and register its baseline p50."""
        t = self.state.add_target(Target(id=-1, key=key, role=role, addr=addr, family=family, kind=kind, label=key,
                                         rate_hz=rate_hz, **fields))
        self.ids[key] = t.id
        self.seq[key] = 0
        P50.setdefault(key, p50_ms)
        return t

    # ------------------------------------------------------------ samples
    def emit(self, key: str, ts: float, rtt_ms: Optional[float] = None, lost: bool = False, late: bool = False,
             error: Optional[int] = None, flags: int = 0, kind: Optional[int] = None) -> Sample:
        tid = self.ids[key]
        target = self.state.targets[tid]
        k = KIND_OF[target.kind] if kind is None else kind
        self.seq[key] += 1
        f = flags
        value = int(round((rtt_ms if rtt_ms is not None else P50[key]) * 1000))
        if lost:
            f |= F_LOST
            value = -1
        elif error is not None:
            f |= F_ERROR
            value = int(error)
        if late:
            f |= F_LATE
        s = Sample(ts_ms=int(round(ts * 1000)), target_id=tid, kind=k, flags=f, seq=self.seq[key], value=value)
        self.state.add_sample(s)
        if self.store is not None:
            self.store.append_sample(s)
        return s

    def stream(self, t_from: float, t_to: float, keys=None, jitter_ms: float = 0.3,
               lost: Optional[Callable[[str, float], bool]] = None,
               rtt: Optional[Callable[[str, float, float], float]] = None,
               late: Optional[Callable[[str, float], bool]] = None,
               flags: Optional[Callable[[str, float], int]] = None) -> int:
        """Emit a regular ICMP stream for ``keys`` in ``[t_from, t_to)``; hooks decide loss/RTT per sample."""
        n = 0
        for key in (keys or [k for k in self.ids if self.state.targets[self.ids[k]].kind == "icmp"]):
            target = self.state.targets[self.ids[key]]
            if target.kind != "icmp" or not target.enabled:
                continue
            step = 1.0 / float(target.rate_hz)
            offset = (target.id * 23 % 200) / 1000.0
            t = t_from
            while t < t_to:
                ts = t + offset
                base = P50[key] + self.rng.uniform(-jitter_ms, jitter_ms)
                r = rtt(key, ts, base) if rtt else base
                is_lost = bool(lost and lost(key, ts))
                fl = flags(key, ts) if flags else 0
                self.emit(key, ts, rtt_ms=r, lost=is_lost, flags=fl)
                if late and late(key, ts):
                    self.emit(key, ts, rtt_ms=r + 2500.0, late=True)
                t += step
                n += 1
        return n

    # ------------------------------------------------------------ queries
    def events(self, type_: Optional[str] = None, key: Optional[str] = None):
        tid = self.ids.get(key) if key else None
        return [e for e in self.state.events if (type_ is None or e.type == type_) and (tid is None or e.target == tid)]

    def episodes(self) -> List[Episode]:
        return [e for e in self.state.episodes if e.id]

    def closed_episodes(self) -> List[Episode]:
        return [e for e in self.episodes() if e.t1 is not None]

    def rows(self, name: str) -> List[dict]:
        if self.store is None:
            return []
        self.store.flush()
        return self.store.read_json(name)

    def published_names(self) -> List[str]:
        return [n for n, _ in self.published]

    def key_of(self, tid: Optional[int]) -> Optional[str]:
        t = self.state.target_by_id(tid) if tid is not None else None
        return t.key if t else None


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------
def make_ticker(s: Session):
    """A :class:`Ticker` on the session's fake clock; ``.tick(t)`` is driven by the tests."""
    from laglens.engine.ticker import Ticker
    return Ticker(s.ctx, clock=s.clock, wait=lambda d: True)


def run_ticks(ticker, clock: FakeClock, until: float, step: float = 1.0) -> int:
    """Advance the fake clock one second at a time, calling ``ticker.tick(t)`` at each new second."""
    n = 0
    last = None
    while clock.t < until:
        clock.advance(step)
        t = int(clock.t)
        if last is None or t > last:
            ticker.tick(t, clock.t)
            last = t
            n += 1
    return n


def run_detector(det, clock: FakeClock, until: float) -> int:
    n = 0
    while clock.t < until:
        clock.advance(1.0)
        det.step(int(clock.t))
        n += 1
    return n


def feed(s: Session, tick: Callable[[int], None], t_from: float, t_to: float, keys=None,
         lost: Optional[Callable[[str, float], bool]] = None,
         rtt: Optional[Callable[[str, float, float], float]] = None,
         late: Optional[Callable[[str, float], bool]] = None,
         flags: Optional[Callable[[str, float], int]] = None,
         jitter_ms: float = 0.3, per_second: Optional[Callable[[float], None]] = None,
         loadtest: Optional[Sequence[float]] = None) -> int:
    """The smoke loop: for every wall second emit its samples, set the clock, tick.

    ``tick`` is ``ticker.tick`` or ``detector.step``. ``per_second(t)`` runs
    after the samples of second ``t`` were emitted (raise notes, set latest
    rows, emit DNS/TCP samples by hand...). ``loadtest=(t0, t1)`` flags the
    samples of that window ``F_LOADTEST`` and keeps ``state.loadtest`` in step
    with the wall clock, as the engine and the load-test module do. Returns
    the number of ticks.
    """
    n = 0
    t = float(int(t_from))
    lt0, lt1 = (float(loadtest[0]), float(loadtest[1])) if loadtest else (0.0, 0.0)

    def flags_with_lt(key: str, ts: float) -> int:
        f = flags(key, ts) if flags else 0
        if loadtest and lt0 <= ts < lt1:
            f |= F_LOADTEST
        return f

    while t < t_to:
        if loadtest:
            running = lt0 <= t < lt1
            last = {"t0": lt0, "t1": lt1, "id": "lt-1"} if t >= lt1 else None
            with s.state.lock:
                s.state.loadtest = {"running": running, "last": last}
        s.stream(t, t + 1.0, keys=keys, lost=lost, rtt=rtt, late=late, flags=flags_with_lt if loadtest else flags,
                 jitter_ms=jitter_ms)
        if per_second is not None:
            per_second(t)
        s.clock.set(t + 1.0)
        tick(int(t + 1.0))
        t += 1.0
        n += 1
    return n


def fault(lost_keys: Iterable[str] = (), t_from: float = 0.0, t_to: float = 0.0,
          slow_keys: Iterable[str] = (), slow_ms: float = 0.0, slow_from: Optional[float] = None,
          slow_to: Optional[float] = None, loss_fraction: float = 1.0, seed: int = 11):
    """``(lost_hook, rtt_hook)`` for keys lost in ``[t_from, t_to)`` and keys slowed by ``slow_ms``."""
    lost_set: Set[str] = set(lost_keys)
    slow_set: Set[str] = set(slow_keys)
    s_from = t_from if slow_from is None else slow_from
    s_to = t_to if slow_to is None else slow_to
    rng = random.Random(seed)

    def lost(key: str, ts: float) -> bool:
        if key in lost_set and t_from <= ts < t_to:
            return loss_fraction >= 1.0 or rng.random() < loss_fraction
        return False

    def rtt(key: str, ts: float, base: float) -> float:
        if key in slow_set and s_from <= ts < s_to:
            return base + slow_ms
        return base

    return lost, rtt


def run_episode(s: Session, tick: Callable[[int], None], baseline_s: float = 70.0, fault_s: float = 3.0,
                quiet_s: float = 20.0, lost_keys: Iterable[str] = (), slow_keys: Iterable[str] = (), slow_ms: float = 0.0,
                keys=None, loss_fraction: float = 1.0, late: Optional[Callable[[str, float], bool]] = None,
                flags: Optional[Callable[[str, float], int]] = None,
                per_second: Optional[Callable[[float], None]] = None, t_start: Optional[float] = None,
                loadtest: Optional[Sequence[float]] = None) -> List[Episode]:
    """Clean baseline → one fault window → quiet; returns the closed episodes. ``s.fault_t0`` holds the fault start."""
    start = s.clock.t if t_start is None else t_start
    f0 = start + baseline_s
    f1 = f0 + fault_s
    s.fault_t0, s.fault_t1 = f0, f1  # type: ignore[attr-defined]
    lost, rtt = fault(lost_keys, f0, f1, slow_keys, slow_ms, loss_fraction=loss_fraction)
    feed(s, tick, start, f1 + quiet_s, keys=keys, lost=lost, rtt=rtt, late=late, flags=flags, per_second=per_second,
         loadtest=loadtest)
    return s.closed_episodes()


def ntp_row(direction: str = "upstream", share: float = 0.81, d_offset: float = 25.0, d_rtt: float = 60.0, t: float = T0) -> dict:
    """An ``ntp`` latest row in the aux-probes shape (per-server ``cf``/``g`` + combined direction/share)."""
    per = {"rtt": 34.0 + d_rtt, "offset": 70.0 + d_offset, "d_rtt": d_rtt, "d_offset": d_offset, "share": share,
           "direction": direction, "n": 12}
    return {"cf": dict(per), "g": dict(per), "direction": direction, "share": share, "t": t}


__all__ = ["T0", "LADDER", "P50", "KIND_OF", "ICMP_KEYS", "INTERNET", "BEYOND_GW", "FakeClock", "FakePlatform",
           "FakeTracer", "FakeDocsis", "Ctx", "FakeUsage", "make_cfg", "Session", "make_ticker", "run_ticks",
           "run_detector", "feed", "fault", "run_episode", "ntp_row", "F_LOST", "F_LATE", "F_ERROR", "F_STALL",
           "F_LOADTEST", "KIND_ICMP", "KIND_DNS", "KIND_TCP", "KIND_CDN_TTFB", "KIND_CDN_CONNECT", "Sample", "State",
           "Target", "Episode"]
