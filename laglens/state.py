"""Shared in-memory state: targets, samples, rollups, events, episodes, marks.

This module is the contract every other module imports (BUILD_PLAN §3.1).
It holds **no I/O**: probes call :meth:`State.add_sample`, the ticker closes
seconds and 5 s windows through :mod:`laglens.engine.rollup`, the HTTP server
serves :meth:`State.snapshot` and SSE listeners use
:meth:`State.subscribe`.

Thread safety: one ``threading.RLock`` guards every mutation; critical
sections are short and never call out (callbacks registered with
:meth:`State.subscribe` run *outside* the lock).

Rings kept in RAM (SPEC_FULL §3.3):

* raw samples per target, 15 minutes;
* 1 s rollups per target, 2 hours;
* 5 s rollups per target and 5 s collector rows, 24 hours;
* per 250 ms slot bitmasks of target ids lost/late in that slot (consumed by
  the 5 s window close, kept ~15 min for the matrix).

Slot indices count 250 ms slots from ``slot_origin_ms``, which is ``t0``
rounded *down* to the 5 s grid, so the 20 slots of a wall-aligned 5 s window
start exactly at the window's ``t`` (SPEC_FULL §6.3) and slot 0 starts at
most 5 s before the session ``t0``.
"""
import threading
import time
from array import array
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

from laglens.version import __version__

# ---------------------------------------------------------------------------
# Sample kinds and flags (SPEC_FULL §6.1)
# ---------------------------------------------------------------------------
KIND_ICMP = 0
KIND_ICMP_BIG = 1  # deferred (reserved)
KIND_TRAIN = 2  # deferred (reserved)
KIND_TTL = 3
KIND_NTP = 4
KIND_STUN = 5  # deferred (reserved)
KIND_DNS = 6
KIND_TCP = 7
KIND_CDN_CONNECT = 8
KIND_CDN_TTFB = 9

KIND_NAMES: Dict[int, str] = {
    KIND_ICMP: "icmp",
    KIND_ICMP_BIG: "icmp_big",
    KIND_TRAIN: "train",
    KIND_TTL: "ttl",
    KIND_NTP: "ntp",
    KIND_STUN: "stun",
    KIND_DNS: "dns",
    KIND_TCP: "tcp",
    KIND_CDN_CONNECT: "cdn_connect",
    KIND_CDN_TTFB: "cdn_ttfb",
}

F_LOST = 1
F_LATE = 2
F_ERROR = 4
F_STALL = 8
F_LOADTEST = 16
F_FALLBACK = 32
F_XBOX_ASLEEP = 64
#: bits 8–15 carry extra data: DNS rcode (kind 6), TTL (kind 3), train index.
F_EXTRA_SHIFT = 8
F_EXTRA_MASK = 0xFF00

#: Kinds whose samples sit on the 250 ms slot grid and feed the simultaneity
#: matrix. TTL-expiry probes are off-grid by design (SPEC_FULL §5.3).
ON_GRID_KINDS = frozenset({KIND_ICMP, KIND_ICMP_BIG})

SLOT_MS = 250
#: Slot indices are relative to ``t0`` rounded down to this grid (the 5 s window).
SLOT_GRID_MS = 5000
RAW_RING_S = 15 * 60
RING1_LEN = 2 * 3600
RING5_LEN = 24 * 3600 // 5
SLOT_RING_S = RAW_RING_S
MAX_TARGET_ID = 255  # u8 in samples.bin
MATRIX_MAX_ID = 31  # bits 0–31 of the slot bitmask

#: Status pill vocabulary (SPEC_FULL §8.2).
STATUS_STARTING = "STARTING"
STATUS_WARMUP = "WARMUP"
STATUS_OK = "OK"
STATUS_TROUBLE = "TROUBLE"
STATUS_RECENT = "RECENT"
STATUS_LOADTEST = "LOADTEST"
STATUS_GAP = "GAP"
STATUS_DEGRADED = "DEGRADED"
STATUS_STOPPED = "STOPPED"

LATEST_KINDS = ("iface", "host", "wifi", "wan", "docsis", "igd", "xbox", "ntp", "dns", "cdn", "path")
ROW5_KINDS = ("iface", "host", "wifi", "wan", "ntp", "docsis", "xbox", "slots")

#: Sentinel for "argument not passed" (``State.set_target_state(reason=...)``).
_UNSET: Any = object()


def extra_of(flags: int) -> int:
    """Return the extra byte (bits 8–15) of a sample's flags."""
    return (flags & F_EXTRA_MASK) >> F_EXTRA_SHIFT


def with_extra(flags: int, extra: int) -> int:
    """Return ``flags`` with bits 8–15 set to ``extra`` (0–255)."""
    return (flags & ~F_EXTRA_MASK) | ((extra & 0xFF) << F_EXTRA_SHIFT)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class Target:
    """A probe destination. ``id`` is the stable index used in samples.bin."""

    id: int
    key: str  # 'gw4', 'inet4_cf', 'tcp_xbl_auth4', ...
    role: str  # gateway|xbox|isp_hop|mid_hop|anycast|ntp|stun|dns|tcp|tcp_xbl|tcp_game|cdn
    addr: Optional[str]  # None when the name could not be resolved yet
    family: int  # 4 or 6
    kind: str  # 'icmp' | 'dns' | 'tcp' | 'ntp' | 'cdn'
    label: str
    rate_hz: float = 4.0
    backend: str = "socket"  # 'socket' | 'pingbin'
    mode: str = "direct"  # 'direct' | 'ttl_expiry'
    enabled: bool = True
    reason: Optional[str] = None
    port: int = 0
    extra: dict = field(default_factory=dict)  # e.g. {'name': ..., 'url': ...}

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Target":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    @property
    def on_grid(self) -> bool:
        return self.kind == "icmp" and self.mode == "direct"


@dataclass
class Sample:
    """One probe result (SPEC_FULL §6.1)."""

    ts_ms: int  # wall clock ms (UTC) at SEND
    target_id: int
    kind: int  # KIND_*
    flags: int  # F_* bits; bits 8–15 extra
    seq: int
    value: int  # rtt_us; -1 lost; errno if F_ERROR
    slot: int = 0  # 250 ms slot index since session t0 (0 for off-grid kinds)

    @property
    def lost(self) -> bool:
        return bool(self.flags & F_LOST)

    @property
    def late(self) -> bool:
        return bool(self.flags & F_LATE)

    @property
    def error(self) -> bool:
        return bool(self.flags & F_ERROR)

    @property
    def received(self) -> bool:
        """A normal (not lost/late/error) reply carrying an RTT."""
        return not (self.flags & (F_LOST | F_LATE | F_ERROR))

    @property
    def rtt_ms(self) -> Optional[float]:
        return self.value / 1000.0 if self.received or self.late else None

    def to_row(self) -> list:
        """``[ts_ms, id, kind, flags, value_us]`` as served by ``/api/samples``."""
        return [self.ts_ms, self.target_id, self.kind, self.flags, self.value]


@dataclass
class Event:
    """A detected symptom or informational event (SPEC_FULL §6.4)."""

    id: str
    t0: float
    t1: Optional[float]
    type: str
    target: Optional[int]
    severity: int
    peak: dict = field(default_factory=dict)
    episode: Optional[str] = None
    stall: bool = False
    source: str = "auto"
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Episode:
    """An episode (SPEC_FULL §6.5). ``cls`` is serialised as ``"class"``."""

    id: str
    t0: float
    t1: Optional[float] = None
    dur_s: Optional[float] = None
    targets: List[int] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    cls: str = "unknown"
    subclass: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    alt: Optional[dict] = None
    locus: Optional[dict] = None
    direction: str = "n/a"
    xbox_state: str = "unknown"
    activity: str = "idle"
    host_tags: List[str] = field(default_factory=list)
    comcast_relevant: bool = True
    sweep: Optional[dict] = None
    docsis: Optional[dict] = None
    marks: List[str] = field(default_factory=list)
    onset_order: List[str] = field(default_factory=list)
    size_loss_ratio: Dict[str, float] = field(default_factory=dict)
    wan: Optional[dict] = None
    xb7_cpu_only: bool = False

    @property
    def open(self) -> bool:
        return self.t1 is None

    def to_dict(self, brief: bool = False) -> dict:
        """Full JSON object; ``brief`` drops ``sweep`` and ``docsis`` (§10.2)."""
        d = asdict(self)
        d["class"] = d.pop("cls")
        if brief:
            d.pop("sweep", None)
            d.pop("docsis", None)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Episode":
        d = dict(d)
        if "class" in d:
            d["cls"] = d.pop("class")
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Mark:
    """A "Lag happened" press (SPEC_FULL §6.6)."""

    id: str
    t_pressed: float
    offset_s: float
    t_est: float
    activity: str = "idle"
    note: str = ""
    source: str = "dashboard"
    episode: Optional[str] = None
    assessment: Optional[str] = None
    snapshot: Optional[str] = None  # 'marks/<id>.json' once written

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Rollup:
    """Per-target rollup over 1 s or 5 s (ms floats; ``None`` when nothing received)."""

    t: int  # unix s, start of window
    id: int  # target id
    n: int  # probes sent (lost + err + received)
    lost: int
    late: int
    err: int
    min: Optional[float]
    p50: Optional[float]
    p95: Optional[float]
    max: Optional[float]
    jit: Optional[float]
    stall: int
    big_n: int = 0
    big_lost: int = 0

    def to_row(self) -> dict:
        """The ``rollups.jsonl`` probe row (SPEC_FULL §6.3)."""
        return asdict(self)

    @property
    def loss_pct(self) -> Optional[float]:
        return (100.0 * self.lost / self.n) if self.n else None

    @property
    def received(self) -> int:
        return max(0, self.n - self.lost - self.err)

    def merge(self, other: "Rollup") -> None:
        """Fold ``other`` (same ``t`` and ``id``) into this rollup in place.

        Used when samples for an already-closed second arrive late (a lost
        verdict at send+``timeout_ms``, a late reply up to ``late_window_ms``):
        counts add up exactly; ``min``/``max`` are exact; ``p50``/``p95``/
        ``jit`` are combined as a weighted average by received count (an
        approximation, since the raw RTTs are no longer available).
        """
        a_recv = self.received
        b_recv = other.received
        self.n += other.n
        self.lost += other.lost
        self.late += other.late
        self.err += other.err
        self.stall += other.stall
        self.big_n += other.big_n
        self.big_lost += other.big_lost
        if other.min is not None:
            self.min = other.min if self.min is None else min(self.min, other.min)
        if other.max is not None:
            self.max = other.max if self.max is None else max(self.max, other.max)
        for attr in ("p50", "p95", "jit"):
            a = getattr(self, attr)
            b = getattr(other, attr)
            if b is None:
                continue
            if a is None or a_recv + b_recv == 0:
                setattr(self, attr, b)
            else:
                setattr(self, attr, round((a * a_recv + b * b_recv) / float(a_recv + b_recv), 2))


# ---------------------------------------------------------------------------
# Accumulators
# ---------------------------------------------------------------------------
class SecondAcc:
    """Per-target accumulator for one wall-clock second (filled by add_sample)."""

    __slots__ = ("n", "lost", "late", "err", "stall", "rtts", "late_rtts", "big_n", "big_lost")

    def __init__(self) -> None:
        self.n = 0
        self.lost = 0
        self.late = 0
        self.err = 0
        self.stall = 0
        self.rtts: List[float] = []  # received RTTs in ms, in arrival order
        self.late_rtts: List[float] = []
        self.big_n = 0
        self.big_lost = 0


class TargetTotals:
    """Session-long counters per target (for ``/api/stats?window=session``)."""

    __slots__ = ("sent", "lost", "late", "err", "stall", "rtts_us", "run", "max_run", "first_ts", "last_ts")

    def __init__(self) -> None:
        self.sent = 0
        self.lost = 0
        self.late = 0
        self.err = 0
        self.stall = 0
        self.rtts_us = array("I")
        self.run = 0  # current consecutive-lost run
        self.max_run = 0
        self.first_ts = 0
        self.last_ts = 0


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
class State:
    """Process-wide shared state. All public methods are thread-safe."""

    def __init__(self, t0: Optional[float] = None, session_id: str = "", cfg: Optional[dict] = None) -> None:
        self.lock = threading.RLock()
        self.t0: float = time.time() if t0 is None else float(t0)
        self.t0_ms: int = int(round(self.t0 * 1000))
        #: Origin of the 250 ms slot grid: ``t0`` rounded down to the 5 s grid.
        self.slot_origin_ms: int = (self.t0_ms // SLOT_GRID_MS) * SLOT_GRID_MS
        self.session_id: str = session_id
        self.cfg: dict = cfg or {}
        self.label: Optional[str] = (cfg or {}).get("label")
        self.resumed_count: int = 0
        self.version: str = __version__

        self.targets: Dict[int, Target] = {}
        self.by_key: Dict[str, Target] = {}

        self._raw: Dict[int, Deque[Sample]] = {}
        self._acc: Dict[int, Dict[int, SecondAcc]] = {}  # second -> target id -> acc
        self._r1: Dict[int, Deque[Rollup]] = {}
        self._r5: Dict[int, Deque[Rollup]] = {}
        self._rows5: Dict[str, Deque[dict]] = {k: deque(maxlen=RING5_LEN) for k in ROW5_KINDS}
        self._slot_lost: Dict[int, int] = {}
        self._slot_late: Dict[int, int] = {}
        self.totals: Dict[int, TargetTotals] = {}
        self.sample_count: int = 0

        self._collectors: Dict[str, dict] = {}
        self._latest: Dict[str, dict] = {}

        self.events: List[Event] = []
        self.episodes: List[Episode] = []
        self.marks: List[Mark] = []
        self.tags: List[dict] = []  # activity spans {t0, t1, activity, source}
        self._event_seq = 0
        self._episode_seq = 0
        self._mark_seq = 0

        self.activity: dict = {"current": "idle", "since": self.t0}
        self.verdict: dict = {
            "text": "",
            "confidence": "low",
            "top": [],
            "comcast": "",
            "next": [],
            "marks": {"total": 0, "linked": 0},
        }
        self.doctor: List[dict] = []
        self.path: dict = {"v4": [], "v6": [], "discovered_at": None, "changes": 0}
        self.loadtest: dict = {"running": False, "last": None}
        self.disk: dict = {"free_mb": None, "session_mb": 0, "writing": True}
        self.host: dict = {}
        self.xbox: dict = {"ip": None, "state": "unknown", "source": None, "link_mbps": None}
        self.update: dict = {"available": False, "latest": None}
        self.matrix: dict = {"pairs": {}, "locus_counts": {}}
        #: Running sums behind ``matrix["pairs"]`` (``{"both": {"A|B": n}, "b_lost": {"A|B": n}}``),
        #: filled by ``laglens.engine.classify.accumulate_matrix``; not part of any API body.
        self.matrix_acc: dict = {"both": {}, "b_lost": {}}
        #: Episodes shorter than the 1.5 s minimum (SPEC §7.4 "blips"): counted, never stored as rows.
        self.blips: int = 0
        self.w5m: Dict[int, dict] = {}  # per-target 5 min stats, refreshed by the ticker

        self.stop_event = threading.Event()
        self.stop_reason: str = "unknown"
        self.status: str = STATUS_STARTING
        self.pill: str = "Checking your setup…"
        self.headline: dict = {"answer": "unknown", "text": "Can't tell yet", "action": ""}
        self.health: dict = {"now": None, "session": None}
        self.sse_clients: int = 0
        self.port: Optional[int] = None

        self._subscribers: List[Callable[[str, Any], None]] = []
        self._notes: List[dict] = []  # discrete occurrences reported by producers; drained by the detector
        #: Wall-clock source behind :meth:`now`; tests replace it with a fake (``state.clock = lambda: t``).
        self.clock: Callable[[], float] = time.time

    # ------------------------------------------------------------------ time
    def now(self) -> float:
        """Current unix time from :attr:`clock` (``time.time`` unless a test injected a fake)."""
        return self.clock()

    def elapsed(self, now: Optional[float] = None) -> float:
        return (self.now() if now is None else now) - self.t0

    def slot_for(self, ts_ms: int) -> int:
        """250 ms slot index of a wall-clock ms timestamp (0 before the origin).

        Slots are counted from :attr:`slot_origin_ms` (``t0`` rounded down to
        the 5 s grid), so a wall-aligned 5 s window ``[t, t+5)`` covers
        exactly slots ``slot_for(t*1000) .. +19``.
        """
        d = ts_ms - self.slot_origin_ms
        return d // SLOT_MS if d > 0 else 0

    def slot_time(self, slot: int) -> float:
        """Wall-clock seconds at the start of ``slot``."""
        return (self.slot_origin_ms + slot * SLOT_MS) / 1000.0

    # --------------------------------------------------------------- targets
    def add_target(self, t: Target) -> Target:
        """Register a target. ``id < 0`` or an id already in use gets the next free id."""
        with self.lock:
            if t.id is None or t.id < 0 or (t.id in self.targets and self.targets[t.id].key != t.key):
                t.id = self.next_target_id()
            if t.id > MAX_TARGET_ID:
                raise ValueError("too many targets (max %d)" % (MAX_TARGET_ID + 1))
            old = self.by_key.get(t.key)
            if old is not None and old.id != t.id:
                self.targets.pop(old.id, None)
            self.targets[t.id] = t
            self.by_key[t.key] = t
            self._raw.setdefault(t.id, deque())
            self._r1.setdefault(t.id, deque(maxlen=RING1_LEN))
            self._r5.setdefault(t.id, deque(maxlen=RING5_LEN))
            self.totals.setdefault(t.id, TargetTotals())
        self.publish("target", t.to_dict())
        return t

    def next_target_id(self) -> int:
        with self.lock:
            return (max(self.targets) + 1) if self.targets else 0

    def target(self, key: str) -> Optional[Target]:
        with self.lock:
            return self.by_key.get(key)

    def target_by_id(self, tid: int) -> Optional[Target]:
        with self.lock:
            return self.targets.get(tid)

    def targets_list(self) -> List[Target]:
        with self.lock:
            return [self.targets[k] for k in sorted(self.targets)]

    def set_target_state(self, key: str, enabled: Optional[bool] = None, reason: Any = _UNSET, **kv) -> None:
        """Update ``enabled``/``reason``/other fields of a target and publish it.

        Only the arguments actually passed change: omitting ``reason`` leaves
        the current reason untouched (pass ``reason=None`` to clear it), so a
        caller that only refreshes ``addr`` cannot wipe a ``'cannot resolve'``
        reason while the target stays disabled.
        """
        with self.lock:
            t = self.by_key.get(key)
            if t is None:
                return
            if enabled is not None:
                t.enabled = enabled
            if reason is not _UNSET:
                t.reason = reason
            for k, v in kv.items():
                if hasattr(t, k):
                    setattr(t, k, v)
            d = t.to_dict()
        self.publish("target", d)

    # --------------------------------------------------------------- samples
    def add_sample(self, s: Sample) -> None:
        """Record a probe result: raw ring, 1 s accumulators, slot bitmasks, totals."""
        with self.lock:
            tid = s.target_id
            ring = self._raw.get(tid)
            if ring is None:
                ring = deque()
                self._raw[tid] = ring
                self._r1.setdefault(tid, deque(maxlen=RING1_LEN))
                self._r5.setdefault(tid, deque(maxlen=RING5_LEN))
            if s.kind in ON_GRID_KINDS and s.slot == 0:
                s.slot = self.slot_for(s.ts_ms)
            ring.append(s)
            cutoff = s.ts_ms - RAW_RING_S * 1000
            while ring and ring[0].ts_ms < cutoff:
                ring.popleft()
            self.sample_count += 1

            sec = s.ts_ms // 1000
            per_sec = self._acc.get(sec)
            if per_sec is None:
                per_sec = {}
                self._acc[sec] = per_sec
            acc = per_sec.get(tid)
            if acc is None:
                acc = SecondAcc()
                per_sec[tid] = acc

            tot = self.totals.get(tid)
            if tot is None:
                tot = TargetTotals()
                self.totals[tid] = tot
            if not tot.first_ts:
                tot.first_ts = s.ts_ms
            tot.last_ts = max(tot.last_ts, s.ts_ms)

            on_grid = s.kind in ON_GRID_KINDS and tid <= MATRIX_MAX_ID
            if s.flags & F_LATE:
                acc.late += 1
                tot.late += 1
                if s.value >= 0:
                    acc.late_rtts.append(s.value / 1000.0)
                if on_grid:
                    self._slot_late[s.slot] = self._slot_late.get(s.slot, 0) | (1 << tid)
            else:
                acc.n += 1
                tot.sent += 1
                if s.kind == KIND_ICMP_BIG:
                    acc.big_n += 1
                if s.flags & F_LOST:
                    acc.lost += 1
                    tot.lost += 1
                    tot.run += 1
                    if tot.run > tot.max_run:
                        tot.max_run = tot.run
                    if s.kind == KIND_ICMP_BIG:
                        acc.big_lost += 1
                    if on_grid:
                        self._slot_lost[s.slot] = self._slot_lost.get(s.slot, 0) | (1 << tid)
                elif s.flags & F_ERROR:
                    acc.err += 1
                    tot.err += 1
                    tot.run = 0
                else:
                    acc.rtts.append(s.value / 1000.0)
                    tot.run = 0
                    if s.value >= 0:
                        tot.rtts_us.append(min(s.value, 0xFFFFFFFF))
                if s.flags & F_STALL:
                    acc.stall += 1
                    tot.stall += 1
            if on_grid and len(self._slot_lost) > (SLOT_RING_S * 1000 // SLOT_MS) * 2:
                self._prune_slots(s.slot - SLOT_RING_S * 1000 // SLOT_MS)

    def _prune_slots(self, before_slot: int) -> None:
        for d in (self._slot_lost, self._slot_late):
            for k in [k for k in d if k < before_slot]:
                del d[k]

    def raw_window(self, target_id: int, t_from: float, t_to: float) -> List[Sample]:
        """Samples of one target with ``t_from <= ts < t_to`` (unix s), oldest first."""
        lo = int(t_from * 1000)
        hi = int(t_to * 1000)
        with self.lock:
            ring = self._raw.get(target_id)
            if not ring:
                return []
            out: List[Sample] = []
            for s in reversed(ring):
                if s.ts_ms >= hi:
                    continue
                if s.ts_ms < lo:
                    break
                out.append(s)
        out.reverse()
        return out

    def raw_all(self, t_from: float, t_to: float, target_ids: Optional[Iterable[int]] = None) -> List[Sample]:
        """Samples of several targets in a window, sorted by ``ts_ms``."""
        with self.lock:
            ids = list(target_ids) if target_ids is not None else list(self._raw)
        out: List[Sample] = []
        for tid in ids:
            out.extend(self.raw_window(tid, t_from, t_to))
        out.sort(key=lambda s: s.ts_ms)
        return out

    def last_sample(self, target_id: int, received_only: bool = True) -> Optional[Sample]:
        with self.lock:
            ring = self._raw.get(target_id)
            if not ring:
                return None
            if not received_only:
                return ring[-1]
            for s in reversed(ring):
                if s.received:
                    return s
            return None

    # ---------------------------------------------------- accumulator hand-off
    def take_accumulators(self, before_sec: int) -> Dict[int, Dict[int, SecondAcc]]:
        """Remove and return every per-second accumulator with ``second < before_sec``."""
        with self.lock:
            keys = [k for k in self._acc if k < before_sec]
            keys.sort()
            return {k: self._acc.pop(k) for k in keys}

    def pending_seconds(self) -> List[int]:
        with self.lock:
            return sorted(self._acc)

    def slots(self, slot_from: int, count: int, late: bool = False) -> List[int]:
        """``count`` bitmasks starting at ``slot_from`` (non-destructive)."""
        src = self._slot_late if late else self._slot_lost
        with self.lock:
            return [src.get(slot_from + i, 0) for i in range(count)]

    def prune_slots(self, before_slot: int) -> None:
        with self.lock:
            self._prune_slots(before_slot)

    # --------------------------------------------------------------- rollups
    def add_rollup(self, res: int, r: Rollup) -> None:
        """Store a rollup in the 1 s (2 h) or 5 s (24 h) ring, keeping it time-ordered.

        If the ring already holds a rollup for the same ``(t, id)`` (samples for
        an already-closed second arrived late) the new one is *merged* into it
        (:meth:`Rollup.merge`) instead of appending a duplicate row; a rollup
        older than the ring's tail is inserted at its time position.
        """
        with self.lock:
            ring = (self._r1 if res == 1 else self._r5).setdefault(
                r.id, deque(maxlen=RING1_LEN if res == 1 else RING5_LEN)
            )
            if not ring or ring[-1].t < r.t:
                ring.append(r)
                return
            # Late arrival: walk back from the tail (bounded by how late a
            # sample can be, so this stays O(late_window / res)).
            pos = len(ring)
            for existing in reversed(ring):
                if existing.t == r.t:
                    existing.merge(r)
                    return
                if existing.t < r.t:
                    break
                pos -= 1
            if pos >= len(ring):
                ring.append(r)
            else:
                ring.insert(pos, r)

    def rollups(
        self, res: int, t_from: float, t_to: float, target_ids: Optional[Iterable[int]] = None
    ) -> Dict[int, List[Rollup]]:
        """Rollups with ``t_from <= t < t_to`` per target; ``res`` 1 or 5."""
        if res not in (1, 5):
            raise ValueError("res must be 1 or 5")
        src = self._r1 if res == 1 else self._r5
        with self.lock:
            ids = list(target_ids) if target_ids is not None else sorted(src)
            out: Dict[int, List[Rollup]] = {}
            for tid in ids:
                ring = src.get(tid)
                if not ring:
                    out[tid] = []
                    continue
                # Rings are time-ordered: scan back from the tail and stop at
                # t_from so a short window costs O(window), not O(ring).
                sel: List[Rollup] = []
                for r in reversed(ring):
                    if r.t >= t_to:
                        continue
                    if r.t < t_from:
                        break
                    sel.append(r)
                sel.reverse()
                out[tid] = sel
        return out

    def last_rollup(self, res: int, target_id: int) -> Optional[Rollup]:
        src = self._r1 if res == 1 else self._r5
        with self.lock:
            ring = src.get(target_id)
            return ring[-1] if ring else None

    def add_row5(self, kind: str, row: dict) -> None:
        """Keep a 5 s collector row (``{'t':..,'iface':{...}}``) in the 24 h ring."""
        with self.lock:
            ring = self._rows5.get(kind)
            if ring is None:
                ring = deque(maxlen=RING5_LEN)
                self._rows5[kind] = ring
            ring.append(row)

    def rows5(self, kind: str, t_from: float, t_to: float) -> List[dict]:
        with self.lock:
            ring = self._rows5.get(kind)
            if not ring:
                return []
            sel: List[dict] = []
            for r in reversed(ring):
                t = r.get("t", 0)
                if t >= t_to:
                    continue
                if t < t_from:
                    break
                sel.append(r)
        sel.reverse()
        return sel

    # ------------------------------------------------------------ collectors
    def set_collector(self, name: str, status: str, reason: Optional[str] = None, **kv) -> None:
        """Update the status registry entry for ``name`` and publish on change."""
        now = self.now()
        with self.lock:
            cur = self._collectors.get(name)
            changed = cur is None or cur.get("status") != status or cur.get("reason") != reason
            entry = dict(cur or {})
            if changed or "since" not in entry:
                entry["since"] = now
            entry["status"] = status
            entry["reason"] = reason
            entry.update(kv)
            self._collectors[name] = entry
            snap = dict(entry)
        if changed:
            snap["name"] = name
            self.publish("collector", snap)

    def collectors(self) -> Dict[str, dict]:
        with self.lock:
            return {k: dict(v) for k, v in self._collectors.items()}

    def collector(self, name: str) -> Optional[dict]:
        with self.lock:
            v = self._collectors.get(name)
            return dict(v) if v else None

    # ---------------------------------------------------------------- latest
    def latest(self, kind: str) -> Optional[dict]:
        with self.lock:
            v = self._latest.get(kind)
            return dict(v) if v is not None else None

    def set_latest(self, kind: str, row: dict) -> None:
        with self.lock:
            self._latest[kind] = dict(row)

    # ------------------------------------------------------------ notes
    def raise_note(self, type: str, t: Optional[float] = None, target: Optional[int] = None,
                   severity: int = 1, note: str = "", **peak: Any) -> dict:
        """Report a discrete occurrence (route change, link flap, modem log line, WAN IP change...).

        Producers (probes, collectors, tracer) never create Event objects themselves: they call
        raise_note() and the detector drains the queue once per second with drain_notes() and
        turns each note into an Event (with episode attachment and de-duplication). ``peak``
        becomes the Event's ``peak`` dict. Returns the queued note (a plain dict).
        """
        d = {"type": str(type), "t": float(t) if t is not None else self.now(), "target": target,
             "severity": int(severity), "note": note, "peak": dict(peak)}
        with self.lock:
            self._notes.append(d)
            if len(self._notes) > 10000:          # never grow without bound if nothing drains
                del self._notes[:-10000]
        return d

    def drain_notes(self) -> List[dict]:
        """Return and clear every queued note (oldest first). Used by the detector each tick."""
        with self.lock:
            out = self._notes
            self._notes = []
        return out

    # ------------------------------------------------ events/episodes/marks
    def next_event_id(self) -> str:
        with self.lock:
            self._event_seq += 1
            return "ev-%06d" % self._event_seq

    def next_episode_id(self) -> str:
        with self.lock:
            self._episode_seq += 1
            return "ep-%06d" % self._episode_seq

    def next_mark_id(self) -> str:
        with self.lock:
            self._mark_seq += 1
            return "mk-%d" % self._mark_seq

    def seed_ids(self, events: int = 0, episodes: int = 0, marks: int = 0) -> None:
        """On resume: continue numbering after the ids already on disk."""
        with self.lock:
            self._event_seq = max(self._event_seq, events)
            self._episode_seq = max(self._episode_seq, episodes)
            self._mark_seq = max(self._mark_seq, marks)

    def add_event(self, ev: Event) -> Event:
        with self.lock:
            self.events.append(ev)
            if len(self.events) > 20000:
                del self.events[:1000]
        self.publish("event", ev.to_dict())
        return ev

    def add_episode(self, ep: Episode) -> Episode:
        with self.lock:
            self.episodes.append(ep)
        self.publish("episode_open", ep.to_dict(brief=True))
        return ep

    def episode(self, ep_id: str) -> Optional[Episode]:
        with self.lock:
            for ep in reversed(self.episodes):
                if ep.id == ep_id:
                    return ep
        return None

    def open_episodes(self) -> List[Episode]:
        with self.lock:
            return [e for e in self.episodes if e.t1 is None]

    def add_mark(self, m: Mark) -> Mark:
        with self.lock:
            self.marks.append(m)
        self.publish("mark", m.to_dict())
        return m

    def mark(self, mark_id: str) -> Optional[Mark]:
        with self.lock:
            for m in reversed(self.marks):
                if m.id == mark_id:
                    return m
        return None

    def set_activity(self, activity: str, source: str = "dashboard", label: Optional[str] = None) -> dict:
        now = self.now()
        with self.lock:
            if self.tags and self.tags[-1].get("t1") is None:
                self.tags[-1]["t1"] = now
            tag = {"t0": now, "t1": None, "activity": activity, "source": source}
            if label:
                tag["label"] = label
            self.tags.append(tag)
            self.activity = {"current": activity, "since": now}
            if label:
                self.activity["label"] = label
            snap = dict(self.activity)
        self.publish("activity", snap)
        return snap

    def activity_spans(self, activity: str) -> List[Tuple[float, float]]:
        """Closed/open spans ``(t0, t1)`` tagged with ``activity`` (open → now)."""
        now = self.now()
        with self.lock:
            return [(t["t0"], t["t1"] if t["t1"] is not None else now) for t in self.tags if t["activity"] == activity]

    # -------------------------------------------------------------- status
    def set_status(self, status: str, pill: Optional[str] = None, headline: Optional[dict] = None) -> None:
        with self.lock:
            self.status = status
            if pill is not None:
                self.pill = pill
            if headline is not None:
                self.headline = dict(headline)

    # ------------------------------------------------------------ snapshot
    def _target_snapshot(self, t: Target, now: float) -> dict:
        d = t.to_dict()
        last = self.last_sample(t.id)
        d["last"] = {"rtt": last.rtt_ms, "t": last.ts_ms / 1000.0} if last else None
        d["w5m"] = self.w5m.get(t.id)
        ring = self._r1.get(t.id)
        spark: List[Optional[float]] = []
        if ring:
            cutoff = int(now) - 60
            for r in reversed(ring):
                if r.t < cutoff or len(spark) >= 60:
                    break
                spark.append(r.p50)
            spark.reverse()
        d["spark"] = spark
        return d

    def snapshot(self) -> dict:
        """The ``GET /api/state`` JSON (SPEC_FULL §10.2 minus deferred keys)."""
        now = self.now()
        with self.lock:
            targets = [self._target_snapshot(self.targets[k], now) for k in sorted(self.targets)]
            episodes_open = [e.id for e in self.episodes if e.t1 is None]
            recent = [e.to_dict(brief=True) for e in self.episodes[-20:]]
            marks_recent = [m.to_dict() for m in self.marks[-10:]]
            snap = {
                "version": self.version,
                "session": {
                    "id": self.session_id,
                    "started": self.t0,
                    "label": self.label,
                    "resumed_count": self.resumed_count,
                    "elapsed_s": round(now - self.t0, 1),
                },
                "state": self.status,
                "pill": self.pill,
                "headline": dict(self.headline),
                "health": dict(self.health),
                "host": dict(self.host),
                "targets": targets,
                "xbox": dict(self.xbox),
                "collectors": {k: dict(v) for k, v in self._collectors.items()},
                "path": dict(self.path),
                "activity": dict(self.activity),
                "activities": [str(a) for a in ((self.cfg or {}).get("activities") or []) if isinstance(a, str)],
                "episodes_open": episodes_open,
                "episodes_recent": recent,
                "marks_recent": marks_recent,
                "verdict": dict(self.verdict),
                "loadtest": dict(self.loadtest),
                "doctor": list(self.doctor),
                "disk": dict(self.disk),
                "update": dict(self.update),
                "token_required": True,
                "sse_clients": self.sse_clients,
                "now": now,
            }
        return snap

    def tick_payload(self, now: Optional[float] = None) -> dict:
        """The SSE ``tick`` event body (SPEC_FULL §10.3), built from rings."""
        now = self.now() if now is None else now
        with self.lock:
            targets: Dict[str, dict] = {}
            for tid in sorted(self.targets):
                last = self.last_sample(tid, received_only=False)
                r1 = self._r1.get(tid)
                last_r = r1[-1] if r1 else None
                w = self.w5m.get(tid) or {}
                targets[str(tid)] = {
                    "rtt": last.rtt_ms if last else None,
                    "lost": last_r.lost if last_r else 0,
                    "late": last_r.late if last_r else 0,
                    "p95_5m": w.get("p95"),
                    "loss_5m": w.get("loss_pct"),
                }
            slot_now = self.slot_for(int(now * 1000))
            host_row = self._latest.get("host") or {}
            stall = bool(host_row.get("stall"))
            payload = {
                "t": now,
                "state": self.status,
                "pill": self.pill,
                "headline": dict(self.headline),
                "health": self.health.get("now"),
                "targets": targets,
                "iface": self._latest.get("iface"),
                "wan": self._latest.get("wan"),
                "xbox": self.xbox.get("state"),
                "stall": bool(stall),
                "slots_lost": [self._slot_lost.get(slot_now - 4 + i, 0) for i in range(4)],
            }
        return payload

    # ------------------------------------------------------------- pub/sub
    def subscribe(self, cb: Callable[[str, Any], None]) -> Callable[[], None]:
        """Register ``cb(name, obj)``; returns an unsubscribe function."""
        with self.lock:
            self._subscribers.append(cb)

        def unsubscribe() -> None:
            with self.lock:
                try:
                    self._subscribers.remove(cb)
                except ValueError:
                    pass

        return unsubscribe

    def unsubscribe(self, cb: Callable[[str, Any], None]) -> None:
        with self.lock:
            try:
                self._subscribers.remove(cb)
            except ValueError:
                pass

    def publish(self, name: str, obj: Any) -> None:
        """Fan ``(name, obj)`` out to subscribers outside the lock; errors are swallowed."""
        with self.lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(name, obj)
            except Exception:  # noqa: BLE001 - a bad listener must not hurt publishers
                pass

    # ------------------------------------------------------------- helpers
    def request_stop(self, reason: str = "api", publish: bool = True) -> None:
        """Set ``stop_event`` (first caller wins ``stop_reason``) and publish ``stopping``.

        ``publish=False`` only sets the fields: use it from contexts where
        running subscriber callbacks is unsafe (a signal handler); the
        shutdown sequence publishes ``stopping`` itself.
        """
        with self.lock:
            if not self.stop_event.is_set():
                self.stop_reason = reason
        self.stop_event.set()
        if publish:
            self.publish("stopping", {"reason": reason})


__all__ = [
    "KIND_ICMP", "KIND_ICMP_BIG", "KIND_TRAIN", "KIND_TTL", "KIND_NTP", "KIND_STUN", "KIND_DNS", "KIND_TCP",
    "KIND_CDN_CONNECT", "KIND_CDN_TTFB", "KIND_NAMES",
    "F_LOST", "F_LATE", "F_ERROR", "F_STALL", "F_LOADTEST", "F_FALLBACK", "F_XBOX_ASLEEP",
    "F_EXTRA_SHIFT", "F_EXTRA_MASK", "extra_of", "with_extra", "ON_GRID_KINDS", "SLOT_MS", "SLOT_GRID_MS",
    "RAW_RING_S", "RING1_LEN", "RING5_LEN", "MAX_TARGET_ID", "MATRIX_MAX_ID",
    "STATUS_STARTING", "STATUS_WARMUP", "STATUS_OK", "STATUS_TROUBLE", "STATUS_RECENT", "STATUS_LOADTEST",
    "STATUS_GAP", "STATUS_DEGRADED", "STATUS_STOPPED", "LATEST_KINDS", "ROW5_KINDS",
    "Target", "Sample", "Event", "Episode", "Mark", "Rollup", "SecondAcc", "TargetTotals", "State",
]
