"""Health score (SPEC_FULL §7.8).

``health = 100 − min(40, 20·loss%) − min(25, max(0, p95−p50−10)/4) − min(15, jitter/2)
          − min(20, episode_minutes/6) − min(20, 40·xbox_loss% while AWAKE)``

computed over the *reference set* (``inet4_cf``, ``inet4_g``, ``inet6_cf``,
``inet6_g`` and ``isp_hop4`` when it is probed directly), excluding
host-stall seconds (``F_STALL`` samples) and load-test windows
(``F_LOADTEST`` samples). ``loss%`` and ``xbox_loss%`` are percentages
(``3.0`` = 3 %), so ``20·loss%`` reaches the 40-point cap at 2 % loss.

:func:`window_health` works from the raw ring (any window inside the last 15
minutes, normally the last 5 minutes); :func:`session_health` uses the
session-long counters and RTT arrays in :class:`laglens.state.State`.
"""
import logging
from typing import List, Optional, Sequence

from laglens.engine.rollup import jitter, percentile
from laglens.state import F_ERROR, F_LATE, F_LOADTEST, F_LOST, F_STALL, F_XBOX_ASLEEP, Sample, State, Target

log = logging.getLogger("laglens.health")

REFERENCE_KEYS = ("inet4_cf", "inet4_g", "inet6_cf", "inet6_g")
#: Episodes shorter than this never count (SPEC §7.4 "blips").
MIN_EPISODE_S = 1.5
#: Episode classes that are artefacts of the monitor itself, not path faults.
NON_PATH_CLASSES = frozenset({"loadtest", "probe_host", "xb7_cpu", "hop_rate_limit"})


def reference_targets(state: State) -> List[Target]:
    """The reference set: the four internet anycast targets plus a *direct* ``isp_hop4``."""
    out: List[Target] = []
    for key in REFERENCE_KEYS:
        t = state.target(key)
        if t is not None and t.enabled:
            out.append(t)
    hop = state.target("isp_hop4")
    if hop is not None and hop.enabled and hop.mode == "direct":
        out.append(hop)
    return out


def score(loss_pct: float, p50: Optional[float], p95: Optional[float], jitter_ms: Optional[float],
          episode_minutes: float, xbox_loss_pct: Optional[float]) -> float:
    """The §7.8 formula, clamped to 0–100 and rounded to one decimal."""
    h = 100.0
    h -= min(40.0, 20.0 * max(0.0, loss_pct))
    if p50 is not None and p95 is not None:
        h -= min(25.0, max(0.0, p95 - p50 - 10.0) / 4.0)
    if jitter_ms is not None:
        h -= min(15.0, max(0.0, jitter_ms) / 2.0)
    h -= min(20.0, max(0.0, episode_minutes) / 6.0)
    if xbox_loss_pct is not None:
        h -= min(20.0, 40.0 * max(0.0, xbox_loss_pct))
    return round(max(0.0, min(100.0, h)), 1)


def _usable(s: Sample) -> bool:
    """A primary sample outside host stalls and load tests."""
    return not (s.flags & (F_LATE | F_STALL | F_LOADTEST))


def episode_minutes(state: State, t_from: float, t_to: float, now: Optional[float] = None) -> float:
    """Minutes of episode time (≥ 1.5 s, path faults only) overlapping ``[t_from, t_to)``."""
    now = state.now() if now is None else now
    total = 0.0
    with state.lock:
        episodes = list(state.episodes)
    for ep in episodes:
        if ep.cls in NON_PATH_CLASSES:
            continue
        t1 = ep.t1 if ep.t1 is not None else now
        if t1 - ep.t0 < MIN_EPISODE_S:
            continue
        lo = max(ep.t0, t_from)
        hi = min(t1, t_to)
        if hi > lo:
            total += hi - lo
    return total / 60.0


def window_health(state: State, t_from: float, t_to: float, now: Optional[float] = None) -> Optional[float]:
    """Health over the raw ring window ``[t_from, t_to)``; ``None`` without data."""
    now = state.now() if now is None else now
    sent = lost = 0
    rtts: List[float] = []
    jits: List[float] = []
    for t in reference_targets(state):
        samples = [s for s in state.raw_window(t.id, t_from, t_to) if _usable(s)]
        if not samples:
            continue
        received: List[float] = []
        for s in samples:
            sent += 1
            if s.flags & F_LOST:
                lost += 1
            elif not (s.flags & F_ERROR):
                received.append(s.value / 1000.0)
        rtts.extend(received)
        j = jitter(received)
        if j is not None:
            jits.append(j)
    if sent == 0:
        return None
    srt = sorted(rtts)
    xbox_loss: Optional[float] = None
    xbox = state.target("xbox")
    if xbox is not None and xbox.enabled:
        xs = [s for s in state.raw_window(xbox.id, t_from, t_to) if _usable(s) and not (s.flags & F_XBOX_ASLEEP)]
        if xs:
            xbox_loss = 100.0 * sum(1 for s in xs if s.flags & F_LOST) / len(xs)
    return score(
        loss_pct=100.0 * lost / sent,
        p50=percentile(srt, 50),
        p95=percentile(srt, 95),
        jitter_ms=(sum(jits) / len(jits)) if jits else None,
        episode_minutes=episode_minutes(state, t_from, t_to, now),
        xbox_loss_pct=xbox_loss,
    )


def session_health(state: State, now: Optional[float] = None) -> Optional[float]:
    """Health over the whole session from the session-long counters (stall seconds approximated)."""
    now = state.now() if now is None else now
    sent = lost = 0
    rtts: List[int] = []
    jits: List[float] = []
    with state.lock:
        totals = {tid: tot for tid, tot in state.totals.items()}
    for t in reference_targets(state):
        tot = totals.get(t.id)
        if tot is None or tot.sent == 0:
            continue
        # Stall seconds cannot be excluded exactly from session counters: subtract the stalled samples.
        sent += max(0, tot.sent - tot.stall)
        lost += tot.lost
        rtts.extend(tot.rtts_us)
        r1 = state.rollups(1, now - 7200, now, [t.id]).get(t.id, [])
        js = [r.jit for r in r1 if r.jit is not None and r.stall == 0]
        if js:
            jits.append(sum(js) / len(js))
    if sent == 0:
        return None
    srt = sorted(rtts)
    p50 = percentile(srt, 50)
    p95 = percentile(srt, 95)
    xbox_loss: Optional[float] = None
    xbox = state.target("xbox")
    if xbox is not None:
        tot = totals.get(xbox.id)
        if tot is not None and tot.sent:
            xbox_loss = 100.0 * tot.lost / tot.sent
    return score(
        loss_pct=100.0 * lost / sent,
        p50=(p50 / 1000.0) if p50 is not None else None,
        p95=(p95 / 1000.0) if p95 is not None else None,
        jitter_ms=(sum(jits) / len(jits)) if jits else None,
        episode_minutes=episode_minutes(state, state.t0, now, now),
        xbox_loss_pct=xbox_loss,
    )


def refresh(state: State, now: Optional[float] = None, session: bool = True) -> dict:
    """Recompute ``state.health`` (``{"now": 5 min score, "session": session score}``)."""
    now = state.now() if now is None else now
    h_now = window_health(state, now - 300, now, now)
    with state.lock:
        cur = dict(state.health)
    cur["now"] = h_now
    if session:
        cur["session"] = session_health(state, now)
    with state.lock:
        state.health = cur
    return cur


__all__ = ["REFERENCE_KEYS", "MIN_EPISODE_S", "NON_PATH_CLASSES", "reference_targets", "score",
           "episode_minutes", "window_health", "session_health", "refresh"]
