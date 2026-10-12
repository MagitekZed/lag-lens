"""Episode classification: simultaneity matrix, loss locus and the ordered rules.

Inputs per episode (SPEC_FULL §7.5–7.6): the affected set (targets with a
symptom event), per-target loss % and Δp95 against the 10 min baseline
before the episode, the loss locus from the 250 ms slot bitmasks, the NTP
direction, host exoneration tags, the Xbox state, IGD/host transmit rates,
DOCSIS correlations, TCP vs ICMP agreement and v4/v6 agreement.

:func:`classify` mutates the :class:`laglens.state.Episode` it is given:
``cls``, ``subclass``, ``confidence``, ``evidence``, ``alt``, ``locus``,
``direction``, ``xb7_cpu_only``, ``targets``, ``host_tags``,
``comcast_relevant``, ``wan``, ``xbox_state``, ``activity``, ``onset_order``
and ``size_loss_ratio``.

Rules run in the exact order of §7.6 (rule 12 ``nat_stateful`` is not in
v1); the first full match wins. ``alt`` is the best *near miss* among the
other rules (the one with most of its conditions satisfied) together with
the conditions that failed, so the evidence card can say why the runner-up
was rejected. Confidence = base + boosts, −0.2 when only one independent
signal supports the class, capped at 0.95.

Everything here reads :class:`laglens.state.State` rings only (raw ring,
rollups, 5 s collector rows, events); it never blocks and never raises
(a failure leaves the episode ``unknown`` with the error in the evidence).
"""
import logging
import math
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from laglens.engine.rollup import percentile
from laglens.state import (
    F_ERROR,
    F_LATE,
    F_LOADTEST,
    F_LOST,
    F_STALL,
    F_XBOX_ASLEEP,
    KIND_ICMP_BIG,
    MATRIX_MAX_ID,
    Episode,
    Event,
    Sample,
    State,
    Target,
)

log = logging.getLogger("laglens.classify")

#: The ladder (SPEC §7.5): shallow → deep. Targets on the same level are siblings.
LADDER: List[List[str]] = [["gw4"], ["xbox", "isp_hop4", "isp_hop6"], ["mid_hop4"], ["inet4_cf", "inet4_g", "inet6_cf", "inet6_g"]]
#: the first Comcast hop: IPv4 when it answers pings, else the IPv6 one (Comcast's 10.60.x.x hop often ignores echo)
COMCAST_HOP_KEYS = ("isp_hop4", "isp_hop6")
LADDER_KEYS: List[str] = [k for level in LADDER for k in level]
DEPTH: Dict[str, int] = {k: i for i, level in enumerate(LADDER) for k in level}
INTERNET_KEYS = ("inet4_cf", "inet4_g", "inet6_cf", "inet6_g")
HOP_ROLES = ("isp_hop", "mid_hop")
#: Event types that exonerate the host (SPEC §7.3).
HOST_TAG_TYPES = ("host_stall", "monitor_gap", "wifi_drop", "wifi_roam", "iface_errors", "link_flap", "self_load",
                  "vpn_route", "clock_jump")
#: Types whose overlap is measured as a share of the episode (the others count when they touch it).
HOST_COVER_TYPES = ("host_stall", "monitor_gap")
SYMPTOM_TYPES = ("latency_spike", "loss_burst", "late_burst", "jitter", "probe_error", "dns_slow", "dns_fail",
                 "tcp_slow", "tcp_timeout", "cdn_slow")
LOSS_TYPES = ("loss_burst", "tcp_timeout", "dns_fail")
DOCSIS_CORR_TYPES = ("docsis_t3", "docsis_t4", "docsis_drw", "docsis_uncorr")
V6_HEALTH_TYPES = ("v6_gw_stale", "v6_route_expired", "v6_prefix_change")
LOCUS_SHARE = 0.7
CONF_CAP = 0.95
SINGLE_SIGNAL_PENALTY = 0.2
#: Noise floors (ms) by role (SPEC §7.1).
FLOOR_BY_ROLE = {"gateway": 10.0, "xbox": 10.0, "isp_hop": 25.0, "mid_hop": 25.0}
DEFAULT_FLOOR = 30.0
CLEAN_LOSS_PCT = 2.0
AFFECTED_LOSS_PCT = 10.0
MAX_MATRIX_SLOTS = 2400  # 10 min


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def floor_for(role: str, mad: Optional[float] = None) -> float:
    """Noise floor for a role; gateway/xbox use ``max(10 ms, 5·MAD)``."""
    base = FLOOR_BY_ROLE.get(role, DEFAULT_FLOOR)
    if role in ("gateway", "xbox") and mad is not None:
        return max(base, 5.0 * mad)
    return base


def label_of(t: Target) -> str:
    """Human label used in evidence strings."""
    addr = t.addr or "?"
    if t.role == "gateway":
        return "gateway %s" % addr if t.family == 4 else "IPv6 gateway"
    if t.role == "xbox":
        return "Xbox %s" % addr
    if t.role == "isp_hop":
        return "Comcast hop %s" % addr
    if t.role == "mid_hop":
        return "mid-path hop %s" % addr
    if t.role == "anycast":
        return addr
    return t.label or t.key


def confidence_band(conf: float) -> str:
    """``low (<0.5) / medium (<0.75) / high``."""
    if conf < 0.5:
        return "low"
    if conf < 0.75:
        return "medium"
    return "high"


def _fmt_pct(v: Optional[float]) -> str:
    if v is None:
        return "n/a"
    return "%d%%" % int(round(v)) if abs(v - round(v)) < 0.05 else "%.1f%%" % v


def _fmt_ms(v: Optional[float]) -> str:
    if v is None:
        return "n/a"
    return "%+d ms" % int(round(v))


def _local_hour(t: float) -> int:
    return time.localtime(t).tm_hour


def _overlap(a0: float, a1: float, b0: float, b1: float) -> float:
    return max(0.0, min(a1, b1) - max(a0, b0))


# ---------------------------------------------------------------------------
# Simultaneity matrix and loss locus (§7.5)
# ---------------------------------------------------------------------------
def ladder_targets(state: State) -> Tuple[Dict[str, Target], List[str]]:
    """Ladder targets usable on the slot grid and the excluded ones (with a reason)."""
    usable: Dict[str, Target] = {}
    excluded: List[str] = []
    for key in LADDER_KEYS:
        t = state.target(key)
        if t is None:
            continue
        if not t.enabled:
            excluded.append("%s (disabled: %s)" % (key, t.reason or "no reason"))
        elif not t.on_grid:
            excluded.append("%s (off-grid: %s mode)" % (key, t.mode if t.kind == "icmp" else t.kind))
        elif t.id > MATRIX_MAX_ID:
            excluded.append("%s (id %d beyond the bitmask)" % (key, t.id))
        else:
            usable[key] = t
    return usable, excluded


def slot_sets(state: State, t0: float, t1: float) -> Tuple[Dict[str, Set[int]], Dict[str, Set[int]], Dict[str, Target], List[str], int]:
    """Per ladder key the slots *lost* and the slots *probed* inside ``[t0, t1]``.

    Built from the raw ring (a late reply turns its slot from lost into late,
    SPEC §5.1); when the ring no longer holds the window, the ``state.slots``
    bitmasks give the lost slots and every slot counts as probed. Returns
    ``(lost, probed, usable, excluded, slot_count)``.
    """
    slot_from = state.slot_for(int(math.floor(t0 * 1000)))
    slot_to = state.slot_for(int(math.ceil(t1 * 1000)))
    count = max(1, min(MAX_MATRIX_SLOTS, slot_to - slot_from + 1))
    usable, excluded = ladder_targets(state)
    lost: Dict[str, Set[int]] = {}
    probed: Dict[str, Set[int]] = {}
    masks: Optional[List[int]] = None
    for key, t in usable.items():
        samples = state.raw_window(t.id, t0, t1 + 0.001)
        l_set: Set[int] = set()
        p_set: Set[int] = set()
        late_set: Set[int] = set()
        for s in samples:
            slot = s.slot - slot_from
            if slot < 0 or slot >= count:
                continue
            if s.flags & F_LATE:
                late_set.add(slot)
            else:
                p_set.add(slot)
                if s.flags & F_LOST:
                    l_set.add(slot)
        if not samples:
            if masks is None:
                masks = state.slots(slot_from, count)
            bit = 1 << t.id
            l_set = {i for i, m in enumerate(masks) if m & bit}
            p_set = set(range(count))
        lost[key] = l_set - late_set
        probed[key] = p_set
    return lost, probed, usable, excluded, count


def matrix_from_sets(lost: Dict[str, Set[int]], probed: Dict[str, Set[int]]) -> Tuple[Dict[str, float], Optional[str]]:
    """``cond[A|B] = P(A lost | B lost, A probed)`` for shallow|deep pairs and the locus key.

    The locus is the shallowest ladder key lost in ≥ 70 % of the slots where any
    deeper key was lost (among the slots the shallow key was probed in);
    ``"internet"`` when only the deepest level lost packets; ``None`` when nothing
    on the ladder was lost.
    """
    keys = [k for k in LADDER_KEYS if k in lost]
    cond: Dict[str, float] = {}
    for a in keys:
        for b in keys:
            if DEPTH[a] >= DEPTH[b]:
                continue
            denom = lost[b] & probed.get(a, lost[b])
            if denom:
                cond["%s|%s" % (a, b)] = round(len(lost[a] & denom) / float(len(denom)), 2)
    shallowest: Optional[str] = None
    for key in keys:
        any_deeper: Set[int] = set()
        for d in keys:
            if DEPTH[d] > DEPTH[key]:
                any_deeper |= lost[d]
        denom = any_deeper & probed.get(key, any_deeper)
        if not denom:
            continue
        if len(lost[key] & denom) / float(len(denom)) >= LOCUS_SHARE:
            shallowest = key
            break
    if shallowest is None and any(lost.get(k) for k in INTERNET_KEYS):
        shallowest = "internet"
    return cond, shallowest


def compute_matrix(state: State, t0: float, t1: float) -> dict:
    """Conditional loss ``cond[A|B]`` and the loss locus over the slots of ``[t0, t1]``.

    Returns ``{"shallowest", "cond": {"A|B": p}, "slots", "lost_slots": {key: n},
    "excluded": [...], "sentence"}``. ``shallowest`` is the locus key, ``"internet"``
    when only the deepest level lost packets, or ``None`` when nothing on the
    ladder was lost. Pairs are ordered shallow|deep and conditioned on the
    slots the shallow target was probed in (a 2 Hz hop is probed in every
    other slot).
    """
    lost, probed, usable, excluded, count = slot_sets(state, t0, t1)
    cond, shallowest = matrix_from_sets(lost, probed)
    lost_counts = {k: len(v) for k, v in lost.items() if v}
    sentence = locus_sentence(state, shallowest, cond, lost_counts, usable, excluded)
    return {
        "shallowest": shallowest,
        "cond": cond,
        "slots": count,
        "lost_slots": lost_counts,
        "excluded": excluded,
        "sentence": sentence,
    }


def locus_sentence(state: State, shallowest: Optional[str], cond: Dict[str, float], lost_counts: Dict[str, int],
                   usable: Dict[str, Target], excluded: Sequence[str]) -> str:
    """The §6.5 locus sentence, e.g. *loss locus: Comcast hop (lost in 91% of slots where 1.1.1.1 was lost; gateway 2%)*."""
    tail = ""
    if excluded:
        tail = "; excluded from the matrix: " + ", ".join(excluded)
    if shallowest is None:
        return "loss locus: none (no ladder target lost packets in the same slots)" + tail
    if shallowest == "internet":
        parts = ["%s %d slots" % (label_of(usable[k]), lost_counts[k]) for k in INTERNET_KEYS if k in lost_counts]
        return "loss locus: internet only (%s; nothing shallower lost in those slots)%s" % (", ".join(parts), tail)
    deeper = [k for k in lost_counts if DEPTH.get(k, 0) > DEPTH[shallowest]]
    if not deeper:
        return "loss locus: %s (only target with loss)%s" % (label_of(usable[shallowest]), tail)
    ref = max(deeper, key=lambda k: lost_counts[k])
    share = cond.get("%s|%s" % (shallowest, ref), 0.0)
    extra = ""
    gw = cond.get("gw4|%s" % ref)
    if shallowest != "gw4" and gw is not None:
        extra = "; gateway %d%%" % int(round(gw * 100))
    return "loss locus: %s (lost in %d%% of slots where %s was lost%s)%s" % (
        label_of(usable[shallowest]), int(round(share * 100)), label_of(usable[ref]), extra, tail)


def accumulate_matrix(state: State, matrix: dict, t0: float, t1: float) -> None:
    """Fold an episode's matrix into ``state.matrix`` (pairs as running means, locus counts)."""
    lost, probed, _, _, _ = slot_sets(state, t0, t1)
    with state.lock:
        acc = state.matrix_acc
        both = acc.setdefault("both", {})
        b_lost = acc.setdefault("b_lost", {})
        for a in lost:
            for b in lost:
                if DEPTH[a] >= DEPTH[b]:
                    continue
                denom = lost[b] & probed.get(a, lost[b])
                if not denom:
                    continue
                k = "%s|%s" % (a, b)
                both[k] = both.get(k, 0) + len(lost[a] & denom)
                b_lost[k] = b_lost.get(k, 0) + len(denom)
        pairs = {k: round(both[k] / float(b_lost[k]), 2) for k in b_lost if b_lost[k]}
        counts = dict(state.matrix.get("locus_counts", {}))
        if matrix.get("shallowest"):
            key = matrix["shallowest"]
            counts[key] = counts.get(key, 0) + 1
        state.matrix = {"pairs": pairs, "locus_counts": counts}


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------
class TargetView:
    """Per-target numbers for one episode."""

    __slots__ = ("target", "sent", "lost", "late", "err", "p50", "p95", "max", "base_p50", "base_p95", "base_mad",
                 "events", "symptom", "affected", "floor", "big_ratio")

    def __init__(self, target: Target) -> None:
        self.target = target
        self.sent = 0
        self.lost = 0
        self.late = 0
        self.err = 0
        self.p50: Optional[float] = None
        self.p95: Optional[float] = None
        self.max: Optional[float] = None
        self.base_p50: Optional[float] = None
        self.base_p95: Optional[float] = None
        self.base_mad: Optional[float] = None
        self.events: List[Event] = []
        self.symptom = False  # a severity ≥ 2 symptom event
        self.affected = False
        self.floor = DEFAULT_FLOOR
        self.big_ratio: Optional[float] = None

    @property
    def key(self) -> str:
        return self.target.key

    @property
    def loss_pct(self) -> Optional[float]:
        return (100.0 * self.lost / self.sent) if self.sent else None

    @property
    def d_p95(self) -> Optional[float]:
        if self.p95 is None or self.base_p95 is None:
            return None
        return self.p95 - self.base_p95

    @property
    def has_loss(self) -> bool:
        lp = self.loss_pct
        return (lp is not None and lp >= CLEAN_LOSS_PCT and self.lost >= 2) or any(e.type in LOSS_TYPES for e in self.events)

    @property
    def has_latency(self) -> bool:
        d = self.d_p95
        return any(e.type in ("latency_spike", "jitter", "tcp_slow", "dns_slow") for e in self.events) or (
            d is not None and d >= self.floor)

    @property
    def clean(self) -> bool:
        """No symptom, loss under 2 % and no p95 inflation beyond the noise floor."""
        if self.affected:
            return False
        lp = self.loss_pct
        if lp is not None and lp >= CLEAN_LOSS_PCT and self.lost >= 2:
            return False
        d = self.d_p95
        return d is None or d < self.floor

    @property
    def known(self) -> bool:
        return self.sent > 0

    def describe(self) -> str:
        """``gateway 10.0.0.1: 0% loss, +1 ms``."""
        lp = self.loss_pct
        if not self.known:
            return "%s: no samples" % label_of(self.target)
        if self.p95 is None:
            return "%s: %s loss, no replies" % (label_of(self.target), _fmt_pct(lp))
        return "%s: %s loss, %s" % (label_of(self.target), _fmt_pct(lp), _fmt_ms(self.d_p95))


class Features:
    """Everything the rules look at, computed once per :func:`classify` call."""

    def __init__(self) -> None:
        self.t0 = 0.0
        self.t1 = 0.0
        self.dur = 0.0
        self.views: Dict[str, TargetView] = {}
        self.by_id: Dict[int, TargetView] = {}
        self.events: List[Event] = []
        self.nearby: List[Event] = []  # events of any type within ±60 s
        self.host_cover = 0.0
        self.host_tags: List[str] = []
        self.on_wifi = False
        self.wifi_event = False
        self.link_event = False
        self.loadtest = False
        self.xbox_state = "unknown"
        self.xbox_link_mbps: Optional[int] = None
        self.direction = "n/a"
        self.ntp_share: Optional[float] = None
        self.ntp_dtheta: Optional[float] = None
        self.docsis_events: List[Event] = []
        self.docsis_flags: List[str] = []
        self.docsis_uncorr: Optional[int] = None
        self.docsis_uncorr_ch: Optional[str] = None
        self.wan_tx: Optional[float] = None
        self.wan_rx: Optional[float] = None
        self.wan_trusted = False
        self.host_tx: Optional[float] = None
        self.up_mbps = 25.0
        self.matrix: dict = {}
        self.reset_events: List[Event] = []
        self.v6_events: List[Event] = []
        self.evening = False
        self.late_dominates = False
        self.activity = "idle"

    # ---- convenience
    def view(self, key: str) -> Optional[TargetView]:
        return self.views.get(key)

    def affected_keys(self) -> List[str]:
        return [k for k, v in self.views.items() if v.affected]

    def affected_roles(self, *roles: str) -> List[TargetView]:
        return [v for v in self.views.values() if v.affected and v.target.role in roles]

    def internet_views(self) -> List[TargetView]:
        return [v for k, v in self.views.items() if k in INTERNET_KEYS and v.known]

    def beyond_gateway(self) -> List[TargetView]:
        """Direct ICMP targets past the gateway (hops + internet), known this episode."""
        return [v for v in self.views.values() if v.known and v.target.kind == "icmp"
                and v.target.role in ("isp_hop", "mid_hop", "anycast")]

    def comcast_hop(self) -> Optional[TargetView]:
        """The probed first Comcast hop (IPv4 preferred, else IPv6); ``None`` when neither has samples."""
        for key in COMCAST_HOP_KEYS:
            v = self.views.get(key)
            if v is not None and v.known:
                return v
        return None

    def is_clean(self, key: str) -> Optional[bool]:
        """True/False, or ``None`` when the target is absent or has no samples."""
        v = self.views.get(key)
        if v is None or not v.known:
            return None
        return v.clean


def _baseline(samples: Iterable[Sample]) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    rtts = sorted(s.value / 1000.0 for s in samples
                  if not (s.flags & (F_LOST | F_LATE | F_ERROR | F_STALL | F_LOADTEST | F_XBOX_ASLEEP)))
    if not rtts:
        return None, None, None
    p50 = percentile(rtts, 50)
    mad = percentile(sorted(abs(x - p50) for x in rtts), 50) if p50 is not None else None
    return p50, percentile(rtts, 95), mad


def _fill_view(view: TargetView, samples: Sequence[Sample], baseline: Sequence[Sample]) -> None:
    rtts: List[float] = []
    big_n = big_lost = small_n = small_lost = 0
    for s in samples:
        if s.flags & F_LATE:
            view.late += 1
            continue
        if view.target.role == "xbox" and s.flags & F_XBOX_ASLEEP:
            continue
        view.sent += 1
        is_big = s.kind == KIND_ICMP_BIG
        if is_big:
            big_n += 1
        else:
            small_n += 1
        if s.flags & F_LOST:
            view.lost += 1
            if is_big:
                big_lost += 1
            else:
                small_lost += 1
        elif s.flags & F_ERROR:
            view.err += 1
        else:
            rtts.append(s.value / 1000.0)
    srt = sorted(rtts)
    view.p50 = percentile(srt, 50)
    view.p95 = percentile(srt, 95)
    view.max = srt[-1] if srt else None
    view.base_p50, view.base_p95, view.base_mad = _baseline(baseline)
    view.floor = floor_for(view.target.role, view.base_mad)
    if big_n and small_n:
        small_rate = small_lost / float(small_n)
        big_rate = big_lost / float(big_n)
        if small_rate > 0:
            view.big_ratio = round(big_rate / small_rate, 2)
        elif big_rate > 0:
            view.big_ratio = 99.0


def _ntp_direction(rows: Sequence[dict]) -> Tuple[str, Optional[float], Optional[float]]:
    """Direction from NTP rows (SPEC §5.6) tolerating several producer layouts.

    Accepts the aux-probes row (``{"cf": {...}, "g": {...}, "direction", "share"}``
    with per-server ``share`` / ``d_offset`` / ``d_rtt``), per-server
    ``{"upstream_share": ..}`` or ``{"d_theta_ms", "d_rtt_ms"}``
    (``offset_shift_ms`` / ``rtt_shift_ms`` as synonyms). Returns
    ``(direction, share, d_theta_ms)``; the row with the largest RTT shift wins.
    """
    best: Tuple[str, Optional[float], Optional[float]] = ("n/a", None, None)
    best_rtt = -1.0
    for row in rows:
        if not isinstance(row, dict):
            continue
        direction = row.get("direction")
        shares: List[float] = []
        dthetas: List[float] = []
        drtt_max = 0.0
        for key, val in row.items():
            if not isinstance(val, dict):
                continue
            share = val.get("upstream_share", val.get("share"))
            dth = val.get("d_theta_ms", val.get("offset_shift_ms", val.get("d_offset")))
            drt = val.get("d_rtt_ms", val.get("rtt_shift_ms", val.get("d_rtt")))
            if share is None and dth is not None and drt is not None and drt >= 20:
                share = 0.5 + float(dth) / float(drt)
            if share is not None:
                try:
                    shares.append(float(share))
                except (TypeError, ValueError):
                    continue
                if dth is not None:
                    try:
                        dthetas.append(float(dth))
                    except (TypeError, ValueError):
                        pass
                if drt is not None:
                    try:
                        drtt_max = max(drtt_max, abs(float(drt)))
                    except (TypeError, ValueError):
                        pass
        if isinstance(direction, str) and direction:
            share = row.get("share", row.get("upstream_share"))
            if share is None and shares:
                share = sum(shares) / len(shares)
            if share is not None:
                try:
                    share = round(float(share), 2)
                except (TypeError, ValueError):
                    share = None
            dth = sum(dthetas) / len(dthetas) if dthetas else row.get("d_theta_ms")
            if direction == "n/a" and not shares and share is None:
                continue  # the producer has no baseline yet: not a measurement
            cand = (direction, share, dth)
            rtt_w = drtt_max if drtt_max > 0 else 0.0
        elif shares:
            if len(shares) >= 2 and max(shares) - min(shares) > 0.2:
                direction = "mixed"
            else:
                mean = sum(shares) / len(shares)
                direction = "upstream" if mean >= 0.7 else ("downstream" if mean <= 0.3 else "symmetric")
            cand = (direction, round(sum(shares) / len(shares), 2), (sum(dthetas) / len(dthetas)) if dthetas else None)
            rtt_w = drtt_max
        else:
            continue
        if rtt_w >= best_rtt:
            best_rtt = rtt_w
            best = cand
    return best


def _rows_in(state: State, kind: str, t_from: float, t_to: float) -> List[dict]:
    rows = state.rows5(kind, t_from, t_to)
    out = []
    for r in rows:
        inner = r.get(kind)
        if isinstance(inner, dict):
            out.append(inner)
    return out


def _max_of(rows: Iterable[dict], key: str) -> Optional[float]:
    best: Optional[float] = None
    for r in rows:
        v = r.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            best = float(v) if best is None else max(best, float(v))
    return best


def extract_features(ep: Episode, ctx: Any, now: Optional[float] = None) -> Features:
    """Compute the :class:`Features` of ``ep`` from the state rings."""
    state: State = ctx.state
    cfg = getattr(ctx, "cfg", None) or {}
    now = state.now() if now is None else now
    f = Features()
    f.t0 = ep.t0
    f.t1 = ep.t1 if ep.t1 is not None else now
    f.dur = max(0.0, f.t1 - f.t0)
    f.up_mbps = float((cfg.get("link") or {}).get("up_mbps", 25) or 25)
    f.activity = ep.activity or "idle"
    with state.lock:
        all_events = list(state.events)
        targets = list(state.targets.values())
        xbox_info = dict(state.xbox)
        host = dict(state.host)
        loadtest = dict(state.loadtest)
    docsis_latest = state.latest("docsis") or {}
    igd_latest = state.latest("igd") or {}
    wan_latest = state.latest("wan") or {}
    iface_latest = state.latest("iface") or {}
    ntp_latest = state.latest("ntp") or {}
    member_ids = set(ep.events)
    f.events = [e for e in all_events if e.id in member_ids]
    f.nearby = [e for e in all_events if e.t0 <= f.t1 + 60 and (e.t1 if e.t1 is not None else now) >= f.t0 - 60]

    # ---- per-target views
    saw_loadtest_samples = False
    for t in targets:
        if not t.enabled and t.id not in ep.targets:
            continue
        view = TargetView(t)
        samples = state.raw_window(t.id, f.t0, f.t1 + 0.25)
        baseline = state.raw_window(t.id, f.t0 - 600, f.t0)
        if t.role == "xbox" and xbox_info.get("since"):
            cut = float(xbox_info["since"]) * 1000.0  # samples of the previous address do not describe this console
            samples = [s for s in samples if s.ts_ms >= cut]
            baseline = [s for s in baseline if s.ts_ms >= cut]
        _fill_view(view, samples, baseline)
        if not saw_loadtest_samples and any(s.flags & F_LOADTEST for s in samples):
            saw_loadtest_samples = True
        f.views[t.key] = view
        f.by_id[t.id] = view
    for e in f.events:
        if e.target is None:
            continue
        v = f.by_id.get(e.target)
        if v is None:
            continue
        v.events.append(e)
        if e.type in SYMPTOM_TYPES and e.severity >= 2:
            v.symptom = True
    for v in f.views.values():
        lp = v.loss_pct
        stats_affected = (lp is not None and lp >= AFFECTED_LOSS_PCT and v.lost >= 2) or (
            v.d_p95 is not None and v.d_p95 >= max(v.floor, (v.base_p50 or 0.0)) and v.d_p95 >= v.floor)
        v.affected = v.symptom or (v.target.id in ep.targets) or stats_affected

    # ---- host exoneration (§7.3)
    cover = 0.0
    tags: List[str] = []
    for e in f.nearby:
        if e.type not in HOST_TAG_TYPES:
            continue
        e_t1 = e.t1 if e.t1 is not None else now
        if e.type in HOST_COVER_TYPES:
            ov = _overlap(f.t0, f.t1, e.t0, e_t1)
            cover += ov
            if ov > 0 and e.type not in tags:
                tags.append(e.type)
        elif _overlap(f.t0 - 5, f.t1 + 5, e.t0, e_t1 + 0.001) > 0 or abs(e.t0 - f.t0) <= 5:
            if e.type not in tags:
                tags.append(e.type)
            if e.type in ("wifi_drop", "wifi_roam"):
                f.wifi_event = True
            if e.type in ("link_flap", "iface_errors"):
                f.link_event = True
    f.host_cover = (cover / f.dur) if f.dur > 0 else (1.0 if cover > 0 else 0.0)
    if f.host_cover <= 0.5:
        tags = [t for t in tags if t not in HOST_COVER_TYPES]
    f.host_tags = tags
    f.on_wifi = bool(host.get("wifi"))

    # ---- loadtest window
    f.loadtest = any(bool(e.peak.get("loadtest")) for e in f.events) or (
        bool(loadtest.get("running")) and ep.t1 is None)
    last = loadtest.get("last") if isinstance(loadtest.get("last"), dict) else None
    if last and isinstance(last.get("t0"), (int, float)):
        lt0 = float(last["t0"])
        lt1 = float(last.get("t1") or (lt0 + 120))
        if _overlap(f.t0, f.t1, lt0, lt1) > 0:
            f.loadtest = True
    if saw_loadtest_samples:
        f.loadtest = True

    # ---- xbox
    f.xbox_state = ep.xbox_state if ep.xbox_state != "unknown" else str(xbox_info.get("state") or "unknown")
    lm = xbox_info.get("link_mbps")
    f.xbox_link_mbps = int(lm) if isinstance(lm, (int, float)) and not isinstance(lm, bool) else None

    # ---- direction (NTP)
    ntp_rows = _rows_in(state, "ntp", f.t0 - 5, f.t1 + 5)
    if ntp_latest:
        ntp_rows.append(ntp_latest)
    f.direction, f.ntp_share, f.ntp_dtheta = _ntp_direction(ntp_rows)

    # ---- DOCSIS correlation
    f.docsis_events = [e for e in f.nearby if e.type in DOCSIS_CORR_TYPES]
    flags = docsis_latest.get("flags")
    f.docsis_flags = [str(x) for x in flags] if isinstance(flags, list) else []
    if isinstance(ep.docsis, dict):
        pre = ep.docsis.get("pre_uncorr") or {}
        post = ep.docsis.get("post_uncorr") or {}
        if isinstance(pre, dict) and isinstance(post, dict):
            best_ch, best_delta = None, 0
            for ch, after in post.items():
                try:
                    delta = int(after) - int(pre.get(ch, after))
                except (TypeError, ValueError):
                    continue
                if delta > best_delta:
                    best_ch, best_delta = str(ch), delta
            if best_ch is not None:
                f.docsis_uncorr, f.docsis_uncorr_ch = best_delta, best_ch
    if f.docsis_uncorr is None:
        for e in f.docsis_events:
            if e.type == "docsis_uncorr":
                d = e.peak.get("delta", e.peak.get("uncorr_delta"))
                if isinstance(d, (int, float)) and not isinstance(d, bool):
                    f.docsis_uncorr = int(d)
                    ch = e.peak.get("ch", e.peak.get("channel"))
                    per = e.peak.get("per_channel")
                    if ch is None and isinstance(per, dict) and per:
                        # the DOCSIS collector reports {channel: delta}: name the worst channel
                        try:
                            ch, worst = max(per.items(), key=lambda kv: float(kv[1] or 0))
                            if isinstance(worst, (int, float)) and worst > 0:
                                f.docsis_uncorr = int(worst)
                        except (TypeError, ValueError):
                            ch = None
                    f.docsis_uncorr_ch = str(ch) if ch is not None else "?"
                    break
    f.reset_events = [e for e in f.nearby if e.type in ("xb7_reset", "link_flap", "docsis_reboot")]
    f.v6_events = [e for e in all_events if e.type in V6_HEALTH_TYPES and abs(e.t0 - f.t0) <= 300]

    # ---- WAN / host transmit
    wan_rows = _rows_in(state, "wan", f.t0 - 5, f.t1 + 5)
    trusted_rows = [r for r in wan_rows if r.get("trusted")]
    f.wan_trusted = bool(igd_latest.get("trusted")) or bool(wan_latest.get("trusted")) or bool(trusted_rows)
    tx_candidates = [r for r in (trusted_rows or [])]
    if igd_latest.get("trusted"):
        tx_candidates.append(igd_latest)
    if wan_latest.get("trusted"):
        tx_candidates.append(wan_latest)
    if not tx_candidates:
        # untrusted counters are still shown as evidence; only `wan_trusted` lets them prove anything
        tx_candidates = list(wan_rows) + [r for r in (igd_latest, wan_latest) if r]
    f.wan_tx = _max_of(tx_candidates, "tx_mbps")
    f.wan_rx = _max_of(tx_candidates, "rx_mbps")
    iface_rows = _rows_in(state, "iface", f.t0 - 5, f.t1 + 5)
    if iface_latest:
        iface_rows.append(iface_latest)
    f.host_tx = _max_of(iface_rows, "tx_mbps")
    if ep.wan is None and (f.wan_tx is not None or f.wan_rx is not None):
        ep.wan = {"tx_mbps_max": f.wan_tx, "rx_mbps_max": f.wan_rx, "trusted": f.wan_trusted}

    # ---- matrix
    try:
        f.matrix = compute_matrix(state, f.t0, f.t1)
    except Exception as exc:  # noqa: BLE001 - never let the matrix kill classification
        log.exception("matrix failed for %s", ep.id)
        f.matrix = {"shallowest": None, "cond": {}, "slots": 0, "lost_slots": {}, "excluded": [],
                    "sentence": "loss locus: unavailable (%s)" % exc}

    f.evening = 19 <= _local_hour(f.t0) <= 22
    sym = [e for e in f.events if e.type in SYMPTOM_TYPES and e.severity >= 2]
    late = [e for e in sym if e.type == "late_burst"]
    f.late_dominates = bool(late) and len(late) >= len(sym) - len(late)
    return f


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
class RuleResult:
    """Outcome of one rule: full match or the list of failed conditions."""

    __slots__ = ("name", "ok", "confidence", "subclass", "evidence", "failed", "signals", "checked", "info", "extra")

    def __init__(self, name: str) -> None:
        self.name = name
        self.ok = False
        self.confidence = 0.0
        self.subclass: Optional[str] = None
        self.evidence: List[str] = []
        self.failed: List[str] = []
        self.signals: Set[str] = set()
        self.checked = 0
        self.info = False
        self.extra: Dict[str, Any] = {}

    def need(self, cond: bool, why: str) -> bool:
        """Record a condition; returns it."""
        self.checked += 1
        if not cond:
            self.failed.append(why)
        return cond

    @property
    def score(self) -> float:
        if self.checked == 0:
            return 0.0
        return (self.checked - len(self.failed)) / float(self.checked)


def _n_affected_internet(f: Features) -> int:
    return sum(1 for v in f.internet_views() if v.affected)


def _all_clean(views: Iterable[TargetView]) -> bool:
    return all(v.clean for v in views)


def rule_probe_host(f: Features) -> RuleResult:
    r = RuleResult("probe_host")
    cover_pct = int(round(100 * f.host_cover))
    r.need(f.host_cover > 0.5, "host_stall/monitor_gap covers %d%% (< 50%%)" % cover_pct)
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.9
    r.evidence.append("probe host stalled or paused for %d%% of the episode" % cover_pct)
    r.signals.update(["host"])
    return r


def rule_probe_wifi(f: Features) -> RuleResult:
    r = RuleResult("probe_wifi")
    r.need(f.wifi_event, "no wifi_drop/wifi_roam within ±5 s")
    r.need(f.on_wifi, "probe host is not on Wi-Fi")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.8
    r.evidence.append("Wi-Fi drop/roam on the probe host coincided with the episode")
    r.signals.update(["wifi_event", "on_wifi"])
    return r


def rule_loadtest(f: Features) -> RuleResult:
    r = RuleResult("loadtest")
    r.need(f.loadtest, "not inside a load-test window")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 1.0
    r.evidence.append("inside a load-test window (self-inflicted)")
    r.signals.update(["loadtest", "window"])
    return r


def rule_probe_link(f: Features) -> RuleResult:
    r = RuleResult("probe_link")
    gw = f.view("gw4")
    xb = f.view("xbox")
    both_lost = bool(gw and xb and f.xbox_state == "awake" and gw.has_loss and xb.has_loss and gw.affected and xb.affected)
    r.need(f.link_event or both_lost, "no link_flap/iface_errors and not (Xbox lost and gateway lost)")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.8
    if f.link_event:
        r.evidence.append("link flap / interface errors on the probe host coincided with the episode")
        r.signals.add("link")
    if both_lost and gw is not None and xb is not None:
        r.evidence.append("gateway and Xbox lost packets together (%s, %s)" % (_fmt_pct(gw.loss_pct), _fmt_pct(xb.loss_pct)))
        r.signals.add("lan_loss")
    return r


def rule_probe_wifi_link(f: Features) -> RuleResult:
    """Probe host on Wi-Fi and the GATEWAY itself degraded together with everything beyond it.

    The gateway is the first hop; when the probe host is on Wi-Fi the radio link is the only
    segment shared by the gateway probe and every deeper target, so a gateway latency rise (or
    loss) that everything beyond it echoes is the probe host's Wi-Fi, not the path. Loss-free
    inflation is the typical airtime-contention signature (``wifi_latency``); shared loss is
    ``wifi_loss`` unless there is XB7 reset evidence (then rule_xb7_gateway owns it).
    """
    r = RuleResult("probe_wifi")
    gw = f.view("gw4")
    if not r.need(f.on_wifi, "probe host is not on Wi-Fi"):
        return r  # a wired host never gets this rule as a near miss either (score 0)
    r.need(gw is not None and gw.known and gw.affected, "gateway not affected (or not probed)")
    beyond = f.beyond_gateway()
    affected_beyond = [v for v in beyond if v.affected]
    r.need(bool(affected_beyond), "nothing beyond the gateway was affected")
    if r.failed or gw is None:
        return r
    if not gw.has_loss:
        r.need(gw.has_latency, "gateway shows neither loss nor a latency rise")
        r.need(not any(v.has_loss for v in beyond), "targets beyond the gateway lost packets while the gateway did not")
        if r.failed:
            return r
        r.ok = True
        r.subclass = "wifi_latency"
        r.confidence = 0.6
        r.evidence.append("probe host is on Wi-Fi and the gateway itself slowed (%s) together with %d target(s) beyond it"
                          % (gw.describe(), len(affected_beyond)))
    else:
        r.need(not f.reset_events, "XB7 reset evidence present (link flap / WAN change / reboot)")
        if r.failed:
            return r
        r.ok = True
        r.subclass = "wifi_loss"
        r.confidence = 0.5
        r.evidence.append("probe host is on Wi-Fi and the gateway lost packets (%s) together with %d target(s) beyond it"
                          % (gw.describe(), len(affected_beyond)))
    r.evidence.append("the Wi-Fi link is the only segment shared by the gateway and the internet probes: "
                      "weak evidence for the path; wire this computer to the XB7 to confirm")
    r.signals.update(["on_wifi", "gw_affected", "beyond_affected"])
    r.extra["host_tag"] = r.subclass
    return r


def rule_xbox_lan(f: Features) -> RuleResult:
    r = RuleResult("xbox_lan")
    xb = f.view("xbox")
    r.need(xb is not None and xb.known and xb.affected, "Xbox not affected (or not probed)")
    r.need(f.xbox_state == "awake", "Xbox not awake (asleep or not yet seen answering)")
    gw_clean = f.is_clean("gw4")
    r.need(gw_clean is not False, "gateway not clean")
    beyond = [v for v in f.beyond_gateway()]
    r.need(_all_clean(beyond), "targets beyond the gateway affected: %s" % ", ".join(v.key for v in beyond if not v.clean))
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.7
    r.signals.update(["xbox_loss", "beyond_clean"])
    assert xb is not None
    r.evidence.append("only the Xbox was affected: %s" % xb.describe())
    if (xb.big_ratio is not None and xb.big_ratio > 3) or f.xbox_link_mbps == 100:
        r.confidence = 0.9
        if xb.big_ratio is not None and xb.big_ratio > 3:
            r.evidence.append("big-packet loss ratio %.1f on the Xbox (cable/port signature)" % xb.big_ratio)
            r.signals.add("size")
        if f.xbox_link_mbps == 100:
            r.evidence.append("Xbox negotiated 100 Mb/s (expected 1000)")
            r.signals.add("link_speed")
    return r


def gw4_inflation(f: Features) -> Tuple[bool, Optional[float], Optional[float]]:
    """The xb7_cpu discriminator: gw4 Δp95 = X and Comcast-hop Δp95 < X/2 (X above the floor)."""
    gw = f.view("gw4")
    hop = f.comcast_hop()
    if gw is None or hop is None or gw.d_p95 is None or hop.d_p95 is None:
        return False, gw.d_p95 if gw else None, hop.d_p95 if hop else None
    x = gw.d_p95
    held = x >= gw.floor and hop.d_p95 < x / 2.0 and not gw.has_loss
    return held, x, hop.d_p95


def rule_xb7_cpu(f: Features) -> RuleResult:
    r = RuleResult("xb7_cpu")
    r.info = True
    gw = f.view("gw4")
    lat_only = bool(gw and gw.affected and gw.has_latency and not gw.has_loss)
    beyond = f.beyond_gateway()
    cond1 = lat_only and _all_clean(beyond)
    held, x, hop_d = gw4_inflation(f)
    cond2 = held and lat_only
    r.need(gw is not None and gw.known, "gateway not probed")
    r.need(lat_only, "gateway shows loss or no latency symptom")
    r.need(cond1 or cond2, "beyond-gateway targets affected and no gateway-only inflation (gw Δp95 %s, hop Δp95 %s)"
           % (_fmt_ms(x), _fmt_ms(hop_d)))
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.6
    r.signals.add("gw_latency")
    assert gw is not None
    r.evidence.append("gateway latency rose (%s) without loss" % gw.describe())
    if cond1:
        r.evidence.append("everything beyond the gateway stayed clean")
        r.signals.add("beyond_clean")
    if cond2:
        r.evidence.append("gateway Δp95 %s vs Comcast hop Δp95 %s: the XB7 answers slower than it forwards" % (_fmt_ms(x), _fmt_ms(hop_d)))
        r.signals.add("inflation")
    r.evidence.append("XB7 CPU busy, not a path fault")
    return r


def rule_xb7_gateway(f: Features) -> RuleResult:
    r = RuleResult("xb7_gateway")
    gw = f.view("gw4")
    r.need(gw is not None and gw.known and gw.has_loss and gw.affected, "gateway shows no loss")
    beyond = [v for v in f.beyond_gateway()]
    r.need(bool(beyond), "no targets beyond the gateway")
    r.need(all(v.has_loss for v in beyond), "not everything beyond the gateway lost packets: %s clean"
           % ", ".join(v.key for v in beyond if not v.has_loss))
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.6
    r.signals.update(["gw_loss", "beyond_loss"])
    assert gw is not None
    r.evidence.append("gateway lost packets: %s; everything beyond it lost too" % gw.describe())
    if f.reset_events:
        r.confidence = 0.9
        kinds = sorted({e.type for e in f.reset_events})
        r.evidence.append("corroborated by %s within ±60 s" % ", ".join(kinds))
        r.signals.add("reset")
    return r


def rule_upstream_delay(f: Features) -> RuleResult:
    """Delay in the upload direction past the modem when the household upload cannot be measured.

    The modem's upload queue and Comcast's upstream look the same from a parallel probe: the XB7
    answers normally, the first Comcast hop and everything past it slow down together, NTP says the
    extra time is on the way out. With verified gateway counters the two can be told apart (rules 8
    and 10); without them the honest answer names both, with the experiment that separates them.
    """
    r = RuleResult("upstream_delay")
    if not r.need(f.direction == "upstream", "delay not in the upload direction (NTP direction %s)" % f.direction):
        return r  # not a near miss for episodes without an upload-direction delay (score 0)
    gw_clean = f.is_clean("gw4")
    r.need(gw_clean is not False, "gateway not clean" if gw_clean is False else "gateway not probed")
    hop = f.comcast_hop()
    r.need(bool(hop and hop.affected), "Comcast hop not affected" if hop else "Comcast hop not probed")
    n_inet = _n_affected_internet(f)
    r.need(n_inet >= 2, "only %d internet target(s) affected (< 2)" % n_inet)
    beyond = f.beyond_gateway()
    r.need(all((v.loss_pct or 0.0) <= 2.0 for v in beyond), "loss above 2% past the gateway (a line fault pattern)")
    r.need(not f.docsis_events, "the modem logged DOCSIS events (line fault evidence)")
    r.need(not f.wan_trusted, "household upload is measurable (verified gateway counters)")
    host_hot = f.host_tx is not None and f.host_tx > 0.6 * f.up_mbps
    r.need(not host_hot, "this computer was uploading heavily (upload_saturation by this host)")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.6
    r.signals.update(["hop", "ntp"])
    assert hop is not None
    r.evidence.append("the XB7 answered normally while the first Comcast hop and everything past it slowed down: %s" % hop.describe())
    if f.ntp_share is not None:
        r.evidence.append("NTP: the extra delay is on the way out (upload direction, share %.2f)" % f.ntp_share)
    r.evidence.append("household upload is not measurable on this gateway (its traffic counters are not reliable), so a "
                      "device uploading at home (a game-clip upload, a cloud backup, a camera) and Comcast's upstream look "
                      "the same from here")
    v4 = [v for k, v in f.views.items() if k in ("inet4_cf", "inet4_g") and v.known]
    v6 = [v for k, v in f.views.items() if k in ("inet6_cf", "inet6_g") and v.known]
    if v4 and v6 and any(v.affected for v in v4) and any(v.affected for v in v6):
        r.signals.add("v4v6")
        r.evidence.append("IPv4 and IPv6 targets agree")
    return r


def rule_docsis_access(f: Features) -> RuleResult:
    r = RuleResult("docsis_access")
    gw_clean = f.is_clean("gw4")
    r.need(gw_clean is not False, "gateway not clean" if gw_clean is False else "gateway not probed")
    hop = f.comcast_hop()
    locus = f.matrix.get("shallowest")
    hop_aff = bool(hop and hop.affected)
    r.need(hop_aff or locus in COMCAST_HOP_KEYS, "Comcast hop not affected and loss locus is %s" % (locus or "none"))
    n_inet = _n_affected_internet(f)
    r.need(n_inet >= 2, "only %d internet target(s) affected (< 2)" % n_inet)
    # a uniform latency rise with upload evidence and no loss is rule 10's pattern, not a line fault
    # (a guard, counted as a failed condition only when it fires so the near-miss score stays comparable)
    if not r.failed and upload_signature(f).ok:
        r.need(False, "uniform latency inflation without loss plus upload evidence (upload_saturation)")
    if r.failed:
        return r
    r.ok = True
    conf = 0.6
    r.signals.update(["inet_loss", "hop"])
    if hop_aff and hop is not None:
        r.evidence.append("Comcast hop affected: %s" % hop.describe())
    if locus in COMCAST_HOP_KEYS:
        r.signals.add("locus")
    v4 = [v for k, v in f.views.items() if k in ("inet4_cf", "inet4_g") and v.known]
    v6 = [v for k, v in f.views.items() if k in ("inet6_cf", "inet6_g") and v.known]
    if v4 and v6 and any(v.affected for v in v4) and any(v.affected for v in v6):
        conf += 0.15
        r.evidence.append("IPv4 and IPv6 targets agree")
        r.signals.add("v4v6")
    if f.docsis_events:
        conf += 0.15
        r.signals.add("docsis")
    if f.direction == "upstream":
        conf += 0.1
        r.signals.add("ntp")
    # subclasses
    beyond = f.beyond_gateway()
    gw = f.view("gw4")
    gw_flat = gw is not None and (gw.d_p95 is None or gw.d_p95 < 5.0)
    all_beyond_loss = bool(beyond) and all(v.has_loss for v in beyond if v.target.role == "anycast") and n_inet >= 2
    if all_beyond_loss and 0.6 <= f.dur <= 4.0 and gw_flat:
        r.subclass = "t3_signature"
        conf = max(conf, 0.8)
        r.evidence.append("all-beyond-gateway loss burst of %.1f s with the gateway RTT flat (T3 signature)" % f.dur)
        if any(e.type == "docsis_t3" for e in f.docsis_events):
            conf = 0.95
    elif (hop is not None and hop.big_ratio is not None and hop.big_ratio > 3) or any(e.type == "docsis_uncorr" for e in f.docsis_events):
        r.subclass = "rf_plant"
        if hop is not None and hop.big_ratio is not None and hop.big_ratio > 3:
            r.evidence.append("big-packet loss ratio %.1f on the Comcast hop (RF plant signature)" % hop.big_ratio)
            r.signals.add("size")
    elif (f.direction == "upstream" and f.wan_trusted and f.wan_tx is not None and f.wan_tx < 0.3 * f.up_mbps
          and all((v.loss_pct or 0.0) <= 2.0 for v in beyond)):
        r.subclass = "upstream"
        r.evidence.append("delay in the upload direction while the household upload was low (%.1f of %.0f Mb/s, verified "
                          "counter): Comcast's upstream" % (f.wan_tx, f.up_mbps))
    elif f.dur >= 120 and all(not v.has_loss for v in beyond) and f.evening:
        r.subclass = "congestion"
        r.evidence.append("sustained latency rise for %d s with little loss in the evening (congestion signature)" % int(f.dur))
    r.confidence = conf
    return r


def rule_comcast_network(f: Features) -> RuleResult:
    r = RuleResult("comcast_network")
    r.need(f.is_clean("gw4") is not False, "gateway not clean")
    hop_v = f.comcast_hop()
    hop_clean = hop_v.clean if hop_v is not None else None
    r.need(hop_clean is True, "Comcast hop not clean" if hop_clean is False else "Comcast hop not probed")
    mid = f.view("mid_hop4")
    r.need(bool(mid and mid.affected), "mid-path hop not affected" if mid else "mid-path hop not probed")
    n_inet = _n_affected_internet(f)
    r.need(n_inet >= 2, "only %d internet target(s) affected (< 2)" % n_inet)
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.6
    r.signals.update(["mid_hop", "inet_loss"])
    assert mid is not None
    r.evidence.append("mid-path hop affected while gateway and Comcast hop stayed clean: %s" % mid.describe())
    return r


def upload_signature(f: Features) -> RuleResult:
    """The rule-10 conditions as a :class:`RuleResult` (shared with rule 8, which must not eat them).

    Uniform latency inflation on every target past the gateway (spread < 30 %),
    loss ≤ 2 %, gateway flat, and one of: trusted WAN tx > 70 % of ``up_mbps``,
    host tx > 60 %, NTP direction upstream with Δθ ≥ 10 ms, late bursts dominate.
    ``r.extra`` carries ``inflated``, ``wan_hot``, ``host_hot``, ``ntp_up``.
    """
    r = RuleResult("upload_saturation")
    beyond = f.beyond_gateway()
    inflated = [v for v in beyond if v.d_p95 is not None and v.d_p95 >= v.floor]
    r.need(bool(beyond) and len(inflated) == len(beyond), "not every beyond-gateway target shows latency inflation (%d of %d)"
           % (len(inflated), len(beyond)))
    spread_ok = False
    if inflated:
        ds = [v.d_p95 for v in inflated if v.d_p95 is not None]
        top = max(ds)
        spread_ok = top > 0 and (top - min(ds)) / top < 0.3
    r.need(spread_ok, "RTT inflation not uniform (spread ≥ 30%)")
    loss_ok = all((v.loss_pct or 0.0) <= 2.0 for v in beyond)
    r.need(loss_ok, "loss above 2% on a beyond-gateway target")
    gw = f.view("gw4")
    gw_flat = gw is None or not gw.known or (gw.d_p95 is None or gw.d_p95 < gw.floor)
    r.need(gw_flat, "gateway RTT not flat")
    wan_hot = f.wan_trusted and f.wan_tx is not None and f.wan_tx > 0.7 * f.up_mbps
    host_hot = f.host_tx is not None and f.host_tx > 0.6 * f.up_mbps
    ntp_up = f.direction == "upstream" and f.ntp_dtheta is not None and abs(f.ntp_dtheta) >= 10
    # a verified, low household upload refutes saturation: then the upload-direction delay is Comcast's (rule 8)
    wan_low = f.wan_trusted and f.wan_tx is not None and f.wan_tx < 0.3 * f.up_mbps
    indirect = (ntp_up or f.late_dominates) and not wan_low
    r.need(wan_hot or host_hot or indirect,
           "no upload evidence (WAN tx %s, host tx %s, direction %s, late bursts %s)"
           % ("%.1f Mb/s" % f.wan_tx if f.wan_tx is not None else "n/a",
              "%.1f Mb/s" % f.host_tx if f.host_tx is not None else "n/a", f.direction,
              "dominate" if f.late_dominates else "do not dominate"))
    r.ok = not r.failed
    r.extra = {"inflated": inflated, "wan_hot": wan_hot, "host_hot": host_hot, "ntp_up": ntp_up}
    return r


def rule_upload_saturation(f: Features) -> RuleResult:
    r = upload_signature(f)
    if r.failed:
        return r
    inflated = r.extra["inflated"]
    wan_hot, host_hot, ntp_up = r.extra["wan_hot"], r.extra["host_hot"], r.extra["ntp_up"]
    r.ok = True
    r.confidence = 0.6
    r.signals.add("uniform_inflation")
    r.evidence.append("uniform latency inflation on every target past the gateway (%s)"
                      % ", ".join("%s %s" % (v.key, _fmt_ms(v.d_p95)) for v in inflated))
    if host_hot:
        r.subclass = "by_this_host"
        r.confidence = 0.85
        r.evidence.append("host tx %.1f Mb/s of %.0f (%.0f%%)" % (f.host_tx or 0, f.up_mbps, 100 * (f.host_tx or 0) / f.up_mbps))
        r.signals.add("host_tx")
    elif wan_hot:
        r.subclass = "by_other_device"
        r.confidence = 0.85
        r.evidence.append("WAN tx %.1f Mb/s of %.0f (%.0f%%, trusted IGD counters)" % (f.wan_tx or 0, f.up_mbps, 100 * (f.wan_tx or 0) / f.up_mbps))
        r.signals.add("wan_tx")
    else:
        r.subclass = "inferred"
        if ntp_up:
            r.evidence.append("NTP direction upstream (Δθ %+.0f ms)" % (f.ntp_dtheta or 0))
            r.signals.add("ntp")
        if f.late_dominates:
            r.evidence.append("late replies dominate the symptoms (queueing, not loss)")
            r.signals.add("late")
    return r


def rule_ip_family(f: Features) -> RuleResult:
    r = RuleResult("ipv6_only")
    v4 = [v for k, v in f.views.items() if k in ("inet4_cf", "inet4_g") and v.known]
    v6 = [v for k, v in f.views.items() if k in ("inet6_cf", "inet6_g") and v.known]
    n4 = sum(1 for v in v4 if v.affected)
    n6 = sum(1 for v in v6 if v.affected)
    v4_aff = n4 > 0
    v6_aff = n6 > 0
    r.need(bool(v4) and bool(v6), "both address families must be probed")
    r.need(v4_aff != v6_aff, "both families affected" if (v4_aff and v6_aff) else "neither family affected")
    # "the family" must be affected, not one destination of it (that is rule 14): ≥ 2 targets, or all it has
    if v6_aff and not v4_aff:
        r.need(n6 >= 2 or n6 == len(v6), "only 1 of %d IPv6 targets affected (single destination?)" % len(v6))
        r.need(_all_clean(v4), "IPv4 twins not clean")
    elif v4_aff and not v6_aff:
        r.name = "ipv4_only"
        r.need(n4 >= 2 or n4 == len(v4), "only 1 of %d IPv4 targets affected (single destination?)" % len(v4))
        r.need(_all_clean(v6), "IPv6 twins not clean")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.7
    r.signals.update(["family_split", "twins_clean"])
    if r.name == "ipv6_only":
        r.evidence.append("only IPv6 targets affected (%s); IPv4 twins clean" % ", ".join(v.describe() for v in v6 if v.affected))
        for e in f.v6_events:
            r.evidence.append("IPv6 health event %s at %s" % (e.type, time.strftime("%H:%M:%S", time.localtime(e.t0))))
            r.signals.add("v6_health")
    else:
        r.evidence.append("only IPv4 targets affected (%s); IPv6 twins clean" % ", ".join(v.describe() for v in v4 if v.affected))
    return r


def rule_internet(f: Features) -> RuleResult:
    r = RuleResult("internet")
    inet = f.internet_views()
    aff = [v for v in inet if v.affected]
    others = [v for v in f.views.values() if v.affected and v.target.key not in INTERNET_KEYS]
    r.need(bool(aff), "no internet target affected")
    r.need(not others, "non-internet targets affected: %s" % ", ".join(v.key for v in others))
    fams = {v.target.family for v in aff}
    r.need(fams == {4, 6}, "only one address family affected")
    hops = [v for k, v in f.views.items() if k in ("isp_hop4", "isp_hop6", "mid_hop4") and v.known]
    r.need(_all_clean(hops), "a hop is not clean")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.5
    r.signals.update(["inet_only", "hops_clean"] if hops else ["inet_only"])
    r.evidence.append("only the internet targets were affected (%s); hops clean" % ", ".join(v.describe() for v in aff))
    return r


def rule_single_destination(f: Features) -> RuleResult:
    r = RuleResult("single_destination")
    aff = f.affected_keys()
    anycast = [k for k in aff if f.views[k].target.role == "anycast"]
    r.need(len(anycast) == 1, "%d anycast destinations affected (need exactly 1)" % len(anycast))
    r.need(len(aff) == len(anycast), "other targets affected too: %s" % ", ".join(k for k in aff if k not in anycast))
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.4
    r.signals.add("single")
    r.evidence.append("exactly one destination affected: %s; likely not your problem" % f.views[anycast[0]].describe())
    return r


def rule_hop_rate_limit(f: Features) -> RuleResult:
    r = RuleResult("hop_rate_limit")
    r.info = True
    hops = f.affected_roles("isp_hop", "mid_hop")
    r.need(bool(hops), "no intermediate hop affected")
    deeper = [v for v in f.views.values() if v.known and v.target.role == "anycast"]
    r.need(_all_clean(deeper), "deeper targets affected")
    others = [v for v in f.views.values() if v.affected and v.target.role not in HOP_ROLES]
    r.need(not others, "non-hop targets affected: %s" % ", ".join(v.key for v in others))
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.9
    r.signals.update(["hop_only", "deeper_clean"])
    r.evidence.append("only an intermediate hop lost packets (%s); deeper targets clean, so the hop is rate-limiting its own replies"
                      % ", ".join(v.describe() for v in hops))
    return r


def rule_dns(f: Features) -> RuleResult:
    r = RuleResult("dns")
    aff = [f.views[k] for k in f.affected_keys()]
    r.need(bool(aff) and all(v.target.kind == "dns" for v in aff), "affected targets are not all DNS probes")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.7
    r.signals.add("dns")
    r.evidence.append("only DNS probes were affected: %s" % ", ".join(v.target.label for v in aff))
    return r


def rule_cdn(f: Features) -> RuleResult:
    r = RuleResult("cdn")
    aff = [f.views[k] for k in f.affected_keys()]
    r.need(bool(aff) and all(v.target.kind == "cdn" for v in aff), "affected targets are not all CDN probes")
    if r.failed:
        return r
    r.ok = True
    r.confidence = 0.5
    r.signals.add("cdn")
    r.evidence.append("only CDN fetches were slow: %s" % ", ".join(v.target.label for v in aff))
    return r


def rule_unknown(f: Features) -> RuleResult:
    r = RuleResult("unknown")
    r.ok = True
    r.confidence = 0.3
    r.signals.add("none")
    r.evidence.append("no rule matched the pattern")
    return r


RULES = [rule_probe_host, rule_probe_wifi, rule_loadtest, rule_probe_link, rule_probe_wifi_link, rule_xbox_lan, rule_xb7_cpu,
         rule_xb7_gateway, rule_upstream_delay, rule_docsis_access, rule_comcast_network, rule_upload_saturation, rule_ip_family,
         rule_internet, rule_single_destination, rule_hop_rate_limit, rule_dns, rule_cdn, rule_unknown]
INFO_CLASSES = frozenset({"xb7_cpu", "hop_rate_limit"})


def common_evidence(f: Features) -> List[str]:
    """The per-target lines, locus, direction, DOCSIS and traffic lines every episode gets."""
    out: List[str] = []
    for key in LADDER_KEYS:
        v = f.views.get(key)
        if v is not None and v.known:
            out.append(v.describe())
    for v in f.views.values():
        if v.affected and v.target.key not in LADDER_KEYS and v.known:
            out.append(v.describe())
    if f.matrix.get("sentence"):
        out.append(f.matrix["sentence"])
    if f.direction != "n/a":
        share = " (share %.2f)" % f.ntp_share if f.ntp_share is not None else ""
        out.append("NTP direction: %s%s" % (f.direction, share))
    for e in f.docsis_events:
        when = time.strftime("%H:%M:%S", time.localtime(e.t0))
        off = e.t0 - f.t0
        name = {"docsis_t3": "T3 time-out", "docsis_t4": "T4 time-out", "docsis_drw": "dynamic range window",
                "docsis_uncorr": "uncorrectable burst"}.get(e.type, e.type)
        out.append("XB7 log: %s at %s (%+d s)" % (name, when, int(round(off))))
    if f.docsis_uncorr is not None and f.docsis_uncorr > 0:
        out.append("uncorrectables +%d on DS ch %s during episode" % (f.docsis_uncorr, f.docsis_uncorr_ch or "?"))
    if f.wan_tx is not None:
        out.append("WAN tx %.1f Mb/s of %.0f (%s)" % (f.wan_tx, f.up_mbps, "trusted" if f.wan_trusted else "untrusted"))
    if f.host_tx is not None:
        out.append("host tx %.1f Mb/s" % f.host_tx)
    if f.host_tags:
        out.append("host tags: %s" % ", ".join(f.host_tags))
    if f.xbox_state == "asleep":
        out.append("Xbox asleep during the episode")
    return out


def onset_order(f: Features) -> List[str]:
    """Keys by first symptomatic time (event ``t0``), earliest first."""
    first: Dict[str, float] = {}
    for v in f.views.values():
        times = [e.t0 for e in v.events if e.type in SYMPTOM_TYPES]
        if times:
            first[v.key] = min(times)
    return [k for k, _ in sorted(first.items(), key=lambda kv: kv[1])]


def classify(ep: Episode, ctx: Any, now: Optional[float] = None) -> None:
    """Fill the classification fields of ``ep`` in place (never raises)."""
    try:
        f = extract_features(ep, ctx, now)
        _apply(ep, f, ctx)
    except Exception as exc:  # noqa: BLE001 - classification must never break the detector
        log.exception("classify failed for %s", ep.id)
        ep.cls = "unknown"
        ep.confidence = 0.3
        ep.evidence = ["classification failed: %s: %s" % (type(exc).__name__, exc)]
        ep.alt = None


def _apply(ep: Episode, f: Features, ctx: Any) -> None:
    results: List[RuleResult] = []
    chosen: Optional[RuleResult] = None
    for rule in RULES:
        try:
            res = rule(f)
        except Exception as exc:  # noqa: BLE001
            log.exception("rule %s failed", getattr(rule, "__name__", rule))
            res = RuleResult(getattr(rule, "__name__", "rule").replace("rule_", ""))
            res.failed.append("rule error: %s" % exc)
            res.checked = 1
        results.append(res)
        if res.ok and chosen is None:
            chosen = res
    if chosen is None:
        chosen = results[-1]
    conf = chosen.confidence
    if len(chosen.signals) <= 1 and chosen.name != "unknown":
        conf -= SINGLE_SIGNAL_PENALTY
    conf = max(0.05, min(CONF_CAP, conf))
    ep.cls = chosen.name
    ep.subclass = chosen.subclass
    ep.confidence = round(conf, 2)
    ep.evidence = common_evidence(f) + chosen.evidence
    if len(chosen.signals) <= 1 and chosen.name != "unknown":
        ep.evidence.append("single signal: confidence reduced by 0.2")
    # alternative: the best near miss (or a later full match)
    best: Optional[RuleResult] = None
    for res in results:
        if res is chosen or res.name == "unknown" or res.checked == 0:
            continue
        if best is None or res.score > best.score:
            best = res
    if best is not None and best.score > 0:
        if best.ok:
            why = "outranked by %s (earlier rule)" % chosen.name
        else:
            why = "; ".join(best.failed)
        ep.alt = {"class": best.name, "why_rejected": why}
    else:
        ep.alt = None
    ep.locus = {"shallowest": f.matrix.get("shallowest"), "cond": dict(f.matrix.get("cond", {})),
                "slots": f.matrix.get("slots", 0), "excluded": list(f.matrix.get("excluded", []))}
    ep.direction = f.direction
    ep.xb7_cpu_only = bool(gw4_inflation(f)[0])
    host_tag = chosen.extra.get("host_tag") if chosen.ok else None
    if host_tag and host_tag not in f.host_tags:
        f.host_tags.append(host_tag)
    ep.host_tags = list(f.host_tags)
    ep.comcast_relevant = not f.host_tags
    ep.xbox_state = f.xbox_state
    ep.activity = f.activity
    affected_ids = sorted({v.target.id for v in f.views.values() if v.affected} | set(ep.targets))
    ep.targets = affected_ids
    ep.onset_order = onset_order(f) or ep.onset_order
    ep.size_loss_ratio = {v.key: v.big_ratio for v in f.views.values() if v.big_ratio is not None}
    if ep.t1 is not None:
        try:
            accumulate_matrix(ctx.state, f.matrix, f.t0, f.t1)
        except Exception:  # noqa: BLE001
            log.exception("matrix accumulation failed")


__all__ = ["LADDER", "LADDER_KEYS", "COMCAST_HOP_KEYS", "DEPTH", "INTERNET_KEYS", "HOST_TAG_TYPES", "SYMPTOM_TYPES", "INFO_CLASSES",
           "compute_matrix", "accumulate_matrix", "slot_sets", "matrix_from_sets", "locus_sentence", "ladder_targets",
           "extract_features",
           "Features", "TargetView", "RuleResult", "RULES", "classify", "confidence_band", "floor_for", "label_of",
           "common_evidence", "onset_order", "gw4_inflation", "upload_signature"]
