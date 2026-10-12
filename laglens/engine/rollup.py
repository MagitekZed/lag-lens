"""Rollups: close 1 s accumulators, build 5 s window rows, percentiles, stats.

Called by the ticker (``engine/ticker.py``) once per second:

* :func:`close_second` turns the per-second accumulators that
  :meth:`laglens.state.State.add_sample` filled into 1 s :class:`Rollup`
  objects (kept 2 h in RAM);
* :func:`close_window5` builds the 5 s rows for ``rollups.jsonl`` from the raw
  ring (exact percentiles), including the ``slots`` bitmask row and the latest
  collector rows, and stores the 5 s rollups in the 24 h ring.

**The ticker must lag behind wall time.** Samples are keyed by SEND time but
a probe's verdict is only known at send + ``timeout_ms`` (lost) or up to
send + ``late_window_ms`` (late reply). At tick ``t`` the ticker therefore
closes seconds ``< t - second_close_lag_s(cfg)`` (``ceil(timeout_ms/1000) +
1``, 3 s by default) and the 5 s window ``[t - WINDOW5_LAG_S - 5, t -
WINDOW5_LAG_S)`` i.e. ``close_window5(state, t - 10)`` (``late_window_ms``
= 10 s), so lost probes are counted in the window they were sent in. A
sample that still lands in an already-closed second is merged into the
existing 1 s rollup by :meth:`laglens.state.State.add_rollup` rather than
producing a duplicate row.

Helpers: :func:`percentile` (linear interpolation, matches
``statistics.quantiles(method='inclusive')``), :func:`jitter` (mean absolute
difference of consecutive received RTTs, SPEC_FULL §5.12),
:func:`window_stats` / :func:`stats` (``/api/stats`` shapes, SPEC_FULL §7.8).
"""
import math
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from laglens.state import (
    KIND_ICMP_BIG,
    F_ERROR,
    F_LATE,
    F_LOST,
    F_STALL,
    ROW5_KINDS,
    Rollup,
    Sample,
    SecondAcc,
    State,
)

WINDOW5_S = 5
SLOTS_PER_WINDOW = 20
COLLECTOR_ROW_KINDS = ("iface", "host", "wifi", "wan", "ntp", "docsis", "xbox")
#: How far behind wall time the 5 s window close runs (= ``late_window_ms``):
#: at tick ``t`` (multiple of 5) the ticker calls ``close_window5(state, t - WINDOW5_LAG_S)``.
WINDOW5_LAG_S = 10


def second_close_lag_s(cfg: Optional[dict] = None, timeout_ms: Optional[int] = None) -> int:
    """Seconds the 1 s close lags wall time: ``ceil(timeout_ms / 1000) + 1``.

    At tick ``t`` the ticker calls ``close_second(state, t - second_close_lag_s(cfg))``
    so every probe sent in a second has reached its lost/received verdict
    (``timeout_ms`` after send) before that second is rolled up.
    """
    if timeout_ms is None:
        timeout_ms = int((cfg or {}).get("timeout_ms", 2000) or 2000)
    return int(math.ceil(max(0, timeout_ms) / 1000.0)) + 1


# ---------------------------------------------------------------------------
# Math helpers
# ---------------------------------------------------------------------------
def percentile(sorted_values: Sequence[float], p: float) -> Optional[float]:
    """``p``-th percentile (0–100) of an ascending sequence, linear interpolation.

    Equivalent to ``statistics.quantiles(values, n=100, method='inclusive')``
    for integer ``p``. Returns ``None`` for an empty sequence.
    """
    n = len(sorted_values)
    if n == 0:
        return None
    if n == 1:
        return float(sorted_values[0])
    h = (n - 1) * (p / 100.0)
    lo = int(math.floor(h))
    hi = min(lo + 1, n - 1)
    frac = h - lo
    return float(sorted_values[lo]) + (float(sorted_values[hi]) - float(sorted_values[lo])) * frac


def jitter(rtts: Sequence[float]) -> Optional[float]:
    """Mean absolute difference of consecutive values; ``None`` if fewer than 2."""
    if len(rtts) < 2:
        return None
    total = 0.0
    for a, b in zip(rtts, rtts[1:]):
        total += abs(b - a)
    return total / (len(rtts) - 1)


def _r(v: Optional[float], nd: int = 2) -> Optional[float]:
    return None if v is None else round(v, nd)


# ---------------------------------------------------------------------------
# 1 s rollups
# ---------------------------------------------------------------------------
def rollup_from_acc(t: int, tid: int, acc: SecondAcc) -> Rollup:
    """Build a 1 s :class:`Rollup` from a :class:`SecondAcc`."""
    rtts = sorted(acc.rtts)
    return Rollup(
        t=t,
        id=tid,
        n=acc.n,
        lost=acc.lost,
        late=acc.late,
        err=acc.err,
        min=_r(rtts[0]) if rtts else None,
        p50=_r(percentile(rtts, 50)),
        p95=_r(percentile(rtts, 95)),
        max=_r(rtts[-1]) if rtts else None,
        jit=_r(jitter(acc.rtts)),
        stall=acc.stall,
        big_n=acc.big_n,
        big_lost=acc.big_lost,
    )


def close_second(state: State, t: int) -> List[Rollup]:
    """Close every accumulated second strictly before ``t`` (unix s).

    Produces one :class:`Rollup` per (second, target) with activity, stores
    each in the 1 s ring and returns them oldest first. The ticker passes
    ``t = now - second_close_lag_s(cfg)``; a second that receives samples
    after it was closed (late replies) is closed again on the next call and
    :meth:`State.add_rollup` merges that rollup into the existing one, so the
    1 s ring never holds two rows for the same ``(t, id)``.
    """
    out: List[Rollup] = []
    taken = state.take_accumulators(int(t))
    for sec in sorted(taken):
        per_target = taken[sec]
        for tid in sorted(per_target):
            acc = per_target[tid]
            if acc.n == 0 and acc.late == 0:
                continue
            r = rollup_from_acc(sec, tid, acc)
            state.add_rollup(1, r)
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# 5 s window
# ---------------------------------------------------------------------------
def rollup_from_samples(t: int, tid: int, samples: Iterable[Sample]) -> Rollup:
    """Aggregate raw samples of one target into a :class:`Rollup` starting at ``t``."""
    n = lost = late = err = stall = big_n = big_lost = 0
    rtts: List[float] = []
    for s in samples:
        if s.flags & F_LATE:
            late += 1
            continue
        n += 1
        if s.kind == KIND_ICMP_BIG:
            big_n += 1
        if s.flags & F_LOST:
            lost += 1
            if s.kind == KIND_ICMP_BIG:
                big_lost += 1
        elif s.flags & F_ERROR:
            err += 1
        else:
            rtts.append(s.value / 1000.0)
        if s.flags & F_STALL:
            stall += 1
    srt = sorted(rtts)
    return Rollup(
        t=t,
        id=tid,
        n=n,
        lost=lost,
        late=late,
        err=err,
        min=_r(srt[0]) if srt else None,
        p50=_r(percentile(srt, 50)),
        p95=_r(percentile(srt, 95)),
        max=_r(srt[-1]) if srt else None,
        jit=_r(jitter(rtts)),
        stall=stall,
        big_n=big_n,
        big_lost=big_lost,
    )


def close_window5(state: State, t: int) -> List[dict]:
    """Build the ``rollups.jsonl`` rows for the 5 s window starting at ``t``.

    ``t`` should be a multiple of 5 (the ticker aligns it) and lie
    ``WINDOW5_LAG_S`` behind wall time so lost/late verdicts are in. The 20
    ``slots`` bitmasks start exactly at ``t`` because the slot grid origin is
    5 s-aligned (:attr:`State.slot_origin_ms`). Returns, in order:
    one probe row per target that had samples, the ``slots`` row
    (``{"t", "slots": [u32×20], "late_slots": [u32×20]}``) and one row per
    collector kind with a fresh ``latest`` value (``{"t", "<kind>": {...}}``).
    The 5 s rollups and the rows are also pushed into the 24 h rings.
    """
    t = int(t)
    rows: List[dict] = []
    for target in state.targets_list():
        samples = state.raw_window(target.id, t, t + WINDOW5_S)
        if not samples:
            continue
        r = rollup_from_samples(t, target.id, samples)
        state.add_rollup(5, r)
        rows.append(r.to_row())

    first_slot = state.slot_for(t * 1000)
    slot_row = {
        "t": t,
        "slots": state.slots(first_slot, SLOTS_PER_WINDOW),
        "late_slots": state.slots(first_slot, SLOTS_PER_WINDOW, late=True),
    }
    state.add_row5("slots", slot_row)
    rows.append(slot_row)
    # Keep ~15 min of slots for the matrix; drop older ones.
    state.prune_slots(first_slot - (15 * 60 * 1000) // 250)

    for kind in COLLECTOR_ROW_KINDS:
        latest = state.latest(kind)
        if not latest:
            continue
        row = {"t": t, kind: latest}
        state.add_row5(kind, row)
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
def longest_outage(samples: Iterable[Sample], rate_hz: float) -> float:
    """Longest run of consecutive lost probes, in seconds (run / rate)."""
    run = best = 0
    for s in samples:
        if s.flags & F_LATE:
            continue
        if s.flags & F_LOST:
            run += 1
            if run > best:
                best = run
        else:
            run = 0
    return (best / rate_hz) if rate_hz > 0 else float(best)


def window_stats(samples: Sequence[Sample], rate_hz: float = 4.0) -> dict:
    """Per-target stats over raw samples (the ``/api/stats`` target shape)."""
    sent = lost = late = err = 0
    rtts: List[float] = []
    big_n = big_lost = 0
    for s in samples:
        if s.flags & F_LATE:
            late += 1
            continue
        sent += 1
        if s.kind == KIND_ICMP_BIG:
            big_n += 1
        if s.flags & F_LOST:
            lost += 1
            if s.kind == KIND_ICMP_BIG:
                big_lost += 1
        elif s.flags & F_ERROR:
            err += 1
        else:
            rtts.append(s.value / 1000.0)
    srt = sorted(rtts)
    loss_pct = (100.0 * lost / sent) if sent else None
    big_ratio = None
    if big_n and sent - big_n > 0:
        small_loss = (lost - big_lost) / float(sent - big_n)
        big_loss = big_lost / float(big_n)
        big_ratio = round(big_loss / small_loss, 2) if small_loss > 0 else (None if big_loss == 0 else 99.0)
    return {
        "sent": sent,
        "lost": lost,
        "late": late,
        "err": err,
        "loss_pct": _r(loss_pct, 2),
        "late_pct": _r(100.0 * late / sent, 2) if sent else None,
        "min": _r(srt[0]) if srt else None,
        "p50": _r(percentile(srt, 50)),
        "p95": _r(percentile(srt, 95)),
        "p99": _r(percentile(srt, 99)),
        "max": _r(srt[-1]) if srt else None,
        "jitter": _r(jitter(rtts)),
        "longest_outage_s": round(longest_outage(samples, rate_hz), 2),
        "big_loss_ratio": big_ratio,
    }


def _stats_from_rollups(rollups: Sequence[Rollup], rate_hz: float) -> dict:
    """Approximate stats from 1 s rollups (used beyond the 15 min raw ring)."""
    sent = sum(r.n for r in rollups)
    lost = sum(r.lost for r in rollups)
    late = sum(r.late for r in rollups)
    err = sum(r.err for r in rollups)
    p50s = sorted(r.p50 for r in rollups if r.p50 is not None)
    p95s = sorted(r.p95 for r in rollups if r.p95 is not None)
    maxs = sorted(r.max for r in rollups if r.max is not None)
    mins = [r.min for r in rollups if r.min is not None]
    jits = [r.jit for r in rollups if r.jit is not None]
    run = best = 0
    for r in rollups:
        if r.n and r.lost == r.n:
            run += r.lost
            best = max(best, run)
        else:
            run = 0
    return {
        "sent": sent,
        "lost": lost,
        "late": late,
        "err": err,
        "loss_pct": _r(100.0 * lost / sent, 2) if sent else None,
        "late_pct": _r(100.0 * late / sent, 2) if sent else None,
        "min": _r(min(mins)) if mins else None,
        "p50": _r(percentile(p50s, 50)),
        "p95": _r(percentile(p95s, 95)),
        "p99": _r(percentile(maxs, 99)),
        "max": _r(maxs[-1]) if maxs else None,
        "jitter": _r(sum(jits) / len(jits)) if jits else None,
        "longest_outage_s": round(best / rate_hz, 2) if rate_hz else float(best),
        "big_loss_ratio": None,
        "approx": True,
    }


def _session_stats(state: State, tid: int, rate_hz: float) -> dict:
    tot = state.totals.get(tid)
    if tot is None:
        return window_stats([], rate_hz)
    srt = sorted(tot.rtts_us)
    sent = tot.sent
    return {
        "sent": sent,
        "lost": tot.lost,
        "late": tot.late,
        "err": tot.err,
        "loss_pct": _r(100.0 * tot.lost / sent, 2) if sent else None,
        "late_pct": _r(100.0 * tot.late / sent, 2) if sent else None,
        "min": _r(srt[0] / 1000.0) if srt else None,
        "p50": _r((percentile(srt, 50) or 0) / 1000.0) if srt else None,
        "p95": _r((percentile(srt, 95) or 0) / 1000.0) if srt else None,
        "p99": _r((percentile(srt, 99) or 0) / 1000.0) if srt else None,
        "max": _r(srt[-1] / 1000.0) if srt else None,
        "jitter": None,
        "longest_outage_s": round(tot.max_run / rate_hz, 2) if rate_hz else float(tot.max_run),
        "big_loss_ratio": None,
    }


def _in_spans(t: float, spans: Sequence[Tuple[float, float]]) -> bool:
    for a, b in spans:
        if a <= t < b:
            return True
    return False


def stats(state: State, window: str = "session", activity: str = "all", now: Optional[float] = None) -> dict:
    """``GET /api/stats`` body: per-target stats, health, matrix.

    ``window`` is ``'session'``, ``'1h'`` or ``'5m'``. Windows inside the raw
    ring (≤ 15 min) use exact percentiles; ``'1h'`` uses the 1 s rollup ring
    (approximate, flagged ``approx``); ``'session'`` uses the session-long
    counters and RTT array. ``activity`` filters to the tagged spans (raw or
    rollup based; session totals then fall back to the 2 h rollup ring).
    """
    now = state.now() if now is None else now
    spans: Optional[List[Tuple[float, float]]] = None
    if activity != "all":
        spans = state.activity_spans(activity)
    out: Dict[str, dict] = {}
    for target in state.targets_list():
        rate = target.rate_hz or 1.0
        if window == "5m":
            samples = state.raw_window(target.id, now - 300, now)
            if spans is not None:
                samples = [s for s in samples if _in_spans(s.ts_ms / 1000.0, spans)]
            out[str(target.id)] = window_stats(samples, rate)
        elif window == "1h" or (window == "session" and spans is not None):
            span_s = 3600 if window == "1h" else 7200
            rl = state.rollups(1, now - span_s, now, [target.id]).get(target.id, [])
            if spans is not None:
                rl = [r for r in rl if _in_spans(r.t, spans)]
            out[str(target.id)] = _stats_from_rollups(rl, rate)
        else:
            out[str(target.id)] = _session_stats(state, target.id, rate)
        episodes = 0
        for ep in state.episodes:
            if target.id in ep.targets:
                episodes += 1
        out[str(target.id)]["episodes"] = episodes
    return {
        "window": window,
        "activity": activity,
        "targets": out,
        "health": dict(state.health),
        "matrix": dict(state.matrix),
    }


def w5m_for(state: State, now: Optional[float] = None) -> Dict[int, dict]:
    """Refresh ``state.w5m`` (the per-target 5 min block of ``/api/state``)."""
    now = state.now() if now is None else now
    result: Dict[int, dict] = {}
    for target in state.targets_list():
        samples = state.raw_window(target.id, now - 300, now)
        ws = window_stats(samples, target.rate_hz or 1.0)
        result[target.id] = {
            "p50": ws["p50"],
            "p95": ws["p95"],
            "loss_pct": ws["loss_pct"],
            "late_pct": ws["late_pct"],
            "jitter": ws["jitter"],
        }
    with state.lock:
        state.w5m = result
    return result


__all__ = [
    "percentile", "jitter", "rollup_from_acc", "close_second", "rollup_from_samples", "close_window5",
    "longest_outage", "window_stats", "stats", "w5m_for", "WINDOW5_S", "SLOTS_PER_WINDOW", "ROW5_KINDS",
    "WINDOW5_LAG_S", "second_close_lag_s",
]
