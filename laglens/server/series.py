"""``GET /api/series`` body: aligned, null-padded arrays over a fixed time grid.

:func:`build_series` turns the per-target rollup rings of
:class:`laglens.state.State` (1 s ring: 2 h, 5 s ring: 24 h), the 5 s
collector rows (``state.rows5``) and, for ranges older than what RAM holds,
``rollups.jsonl`` (``store.read_json('rollups')``) into the shape of
SPEC_FULL §10.2:

```
{"res":5,"from":..,"to":..,"t":[...],
 "targets":{"0":{"p50":[..],"p95":[..],"max":[..],"lost":[..],"late":[..],"n":[..],"jit":[..]}},
 "iface":{...},"wan":{...},"wifi":{...},"docsis":{...},"ntp":{...},
 "segments":{"lan":[..],"docsis":[..],"comcast":[..],"internet":[..]},
 "slots_lost":[[...]],"xbox_state":[...],"stall":[...]}
```

Every array has exactly ``len(t)`` entries; a grid point without data is
``null``. ``res=1`` is only accepted for ranges of at most two hours
(:data:`MAX_RES1_SPAN_S`); the HTTP layer maps the ``ValueError`` to 400.

Segments (SPEC_FULL §8.3, timeline 4) are 10 s medians of the 5 s / 1 s
``p50`` values along the ladder ``gw4 → isp_hop4 → mid_hop4 → inet``:
``lan = gw4``, ``docsis = isp_hop4 − gw4``, ``comcast = mid_hop4 − isp_hop4``,
``internet = inet − mid_hop4``, each clamped to ``≥ 0``. When a rung is not
probed (no ``mid_hop4`` target, say) the next deeper segment is measured
against the nearest shallower rung that exists, so ``internet`` becomes
``inet − isp_hop4``; a segment whose own rung is missing is ``null``.
"""
from __future__ import annotations

import logging
import statistics
from typing import Any, Dict, Iterable, List, Optional, Sequence

from laglens.state import Rollup, State

log = logging.getLogger("laglens.server.series")

MAX_RES1_SPAN_S = 2 * 3600
#: Hard cap on grid points per response (24 h at 1 s would be 86 400).
MAX_POINTS = 200_000
SEGMENT_BUCKET_S = 10
TARGET_KEYS = ("p50", "p95", "max", "lost", "late", "n", "jit")
#: Rows of ``rollups.jsonl`` that carry collector data (SPEC_FULL §6.3).
COLLECTOR_KINDS = ("iface", "wan", "wifi", "docsis", "ntp", "xbox", "host", "slots")
IFACE_KEYS = ("rx_mbps", "tx_mbps", "err", "drop", "carrier_changes", "mcast_pps")
WAN_KEYS = ("rx_mbps", "tx_mbps")
WIFI_KEYS = ("rssi", "noise")
DOCSIS_KEYS = ("ds_snr_min", "us_pwr_max", "uncorr_delta")
INET_KEYS = ("inet4_cf", "inet4_g", "inet6_cf", "inet6_g")


def _state_of(ctx_or_state: Any) -> State:
    st = getattr(ctx_or_state, "state", None)
    return st if isinstance(st, State) else ctx_or_state


def _num(v: Any) -> Optional[float]:
    """A finite number or ``None`` (JSON-safe)."""
    if isinstance(v, bool) or v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f != f or f in (float("inf"), float("-inf")):
        return None
    return f


def _grid(t_from: float, t_to: float, res: int) -> List[int]:
    start = (int(t_from) // res) * res
    end = int(t_to)
    if end <= start:
        return [start]
    return list(range(start, end, res))


def _index_of(t: Any, start: int, res: int, n: int) -> int:
    """Grid index of a row timestamp or ``-1`` when it falls outside the grid."""
    try:
        tt = int(float(t))
    except (TypeError, ValueError):
        return -1
    i = (tt - start) // res
    return i if 0 <= i < n else -1


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------
def _file_rows(store: Any, t_from: float, t_to: float) -> List[dict]:
    """Rows of ``rollups.jsonl`` with ``t_from <= t < t_to`` (empty without a store)."""
    if store is None or not hasattr(store, "read_json"):
        return []
    try:
        rows = store.read_json("rollups")
    except Exception:  # noqa: BLE001 - a torn file must not break the dashboard
        log.debug("rollups.jsonl unreadable", exc_info=True)
        return []
    out: List[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        t = _num(r.get("t"))
        if t is None or t < t_from or t >= t_to:
            continue
        out.append(r)
    return out


def _ring_oldest(state: State, res: int, ids: Iterable[int]) -> Optional[int]:
    """Oldest rollup time held in RAM across ``ids`` (``None`` when the ring is empty)."""
    oldest: Optional[int] = None
    with state.lock:
        src = state._r1 if res == 1 else state._r5  # noqa: SLF001 - read-only peek under the lock
        for tid in ids:
            ring = src.get(tid)
            if ring:
                t = ring[0].t
                oldest = t if oldest is None else min(oldest, t)
    return oldest


def _needs_file(state: State, res: int, t_from: float, ids: Iterable[int]) -> bool:
    if res != 5:
        return False
    oldest = _ring_oldest(state, res, ids)
    return oldest is None or t_from < oldest


# ---------------------------------------------------------------------------
# per-target arrays
# ---------------------------------------------------------------------------
def _target_arrays(n: int) -> Dict[str, List[Optional[float]]]:
    return {k: [None] * n for k in TARGET_KEYS}


def _fill_target(arrs: Dict[str, list], i: int, r: Rollup) -> None:
    arrs["p50"][i] = r.p50
    arrs["p95"][i] = r.p95
    arrs["max"][i] = r.max
    arrs["lost"][i] = r.lost
    arrs["late"][i] = r.late
    arrs["n"][i] = r.n
    arrs["jit"][i] = r.jit


def _fill_target_row(arrs: Dict[str, list], i: int, row: dict) -> None:
    if arrs["n"][i] is not None:  # RAM wins over the file
        return
    arrs["p50"][i] = _num(row.get("p50"))
    arrs["p95"][i] = _num(row.get("p95"))
    arrs["max"][i] = _num(row.get("max"))
    arrs["lost"][i] = int(_num(row.get("lost")) or 0)
    arrs["late"][i] = int(_num(row.get("late")) or 0)
    arrs["n"][i] = int(_num(row.get("n")) or 0)
    arrs["jit"][i] = _num(row.get("jit"))


# ---------------------------------------------------------------------------
# collector arrays
# ---------------------------------------------------------------------------
def _collector_rows(state: State, kind: str, t_from: float, t_to: float, file_rows: Sequence[dict]) -> List[dict]:
    """``{'t':..,'<kind>':{...}}`` rows from the RAM ring, then the file for older times."""
    ram = state.rows5(kind, t_from, t_to)
    if not file_rows:
        return ram
    seen = {int(float(r.get("t", 0))) for r in ram if _num(r.get("t")) is not None}
    extra = [r for r in file_rows if kind in r and isinstance(r.get(kind), (dict, list)) and int(float(r["t"])) not in seen]
    return extra + ram


def _collector_series(rows: Sequence[dict], kind: str, keys: Sequence[str], start: int, res: int, n: int,
                      derived: Optional[Dict[str, Any]] = None) -> Dict[str, list]:
    out: Dict[str, list] = {k: [None] * n for k in keys}
    for row in rows:
        i = _index_of(row.get("t"), start, res, n)
        if i < 0:
            continue
        body = row.get(kind)
        if not isinstance(body, dict):
            continue
        for k in keys:
            if derived and k in derived:
                out[k][i] = _num(derived[k](body))
            else:
                out[k][i] = _num(body.get(k))
    return out


def _sum_keys(body: dict, keys: Sequence[str]) -> Optional[float]:
    vals = [_num(body.get(k)) for k in keys]
    vals = [v for v in vals if v is not None]
    return sum(vals) if vals else None


def _ntp_offset(body: dict) -> Optional[float]:
    vals = []
    for srv in body.values():
        if isinstance(srv, dict):
            v = _num(srv.get("offset"))
            if v is not None:
                vals.append(v)
    return sum(vals) / len(vals) if vals else None


def _ntp_rtt(body: dict) -> Optional[float]:
    vals = []
    for srv in body.values():
        if isinstance(srv, dict):
            v = _num(srv.get("rtt"))
            if v is not None:
                vals.append(v)
    return min(vals) if vals else None


def _ntp_series(rows: Sequence[dict], start: int, res: int, n: int) -> Dict[str, list]:
    raw = _collector_series(rows, "ntp", ("offset", "rtt"), start, res, n,
                            derived={"offset": _ntp_offset, "rtt": _ntp_rtt})
    offsets = raw["offset"]
    base = next((v for v in offsets if v is not None), None)
    shift = [None if v is None or base is None else round(v - base, 3) for v in offsets]
    return {"offset_shift": shift, "offset": offsets, "rtt": raw["rtt"]}


def _slots_series(rows: Sequence[dict], start: int, res: int, n: int) -> List[Optional[list]]:
    out: List[Optional[list]] = [None] * n
    per_sec = 1000 // 250
    for row in rows:
        slots = row.get("slots")
        if not isinstance(slots, list):
            continue
        t = _num(row.get("t"))
        if t is None:
            continue
        masks = [int(_num(v) or 0) for v in slots]
        if res >= 5:
            i = _index_of(t, start, res, n)
            if i >= 0:
                out[i] = masks
        else:
            for sec in range(5):
                i = _index_of(int(t) + sec, start, res, n)
                if i >= 0:
                    out[i] = masks[sec * per_sec:(sec + 1) * per_sec]
    return out


def _xbox_series(rows: Sequence[dict], start: int, res: int, n: int) -> List[Optional[str]]:
    out: List[Optional[str]] = [None] * n
    for row in rows:
        i = _index_of(row.get("t"), start, res, n)
        body = row.get("xbox")
        if i >= 0 and isinstance(body, dict):
            s = body.get("state")
            out[i] = str(s) if s is not None else None
    return out


def _stall_of(body: dict) -> Optional[int]:
    if body.get("stall") is not None:
        return 1 if body.get("stall") else 0
    late = _num(body.get("late_ms_max"))
    gap = _num(body.get("loop_gap_ms"))
    if late is None and gap is None:
        return None
    return 1 if (late or 0) > 50 or (gap or 0) > 200 else 0


def _stall_series(rows: Sequence[dict], start: int, res: int, n: int) -> List[Optional[int]]:
    out: List[Optional[int]] = [None] * n
    for row in rows:
        i = _index_of(row.get("t"), start, res, n)
        body = row.get("host")
        if i >= 0 and isinstance(body, dict):
            out[i] = _stall_of(body)
    return out


# ---------------------------------------------------------------------------
# segments
# ---------------------------------------------------------------------------
def _bucket_medians(values: Sequence[Optional[float]], t: Sequence[int], bucket_s: int) -> List[Optional[float]]:
    """Per-grid-point median of ``values`` over the ``bucket_s`` bucket each point falls in."""
    n = len(values)
    out: List[Optional[float]] = [None] * n
    if n == 0:
        return out
    groups: Dict[int, List[float]] = {}
    for i in range(n):
        v = values[i]
        if v is None:
            continue
        groups.setdefault(t[i] // bucket_s, []).append(v)
    med = {b: statistics.median(vs) for b, vs in groups.items()}
    for i in range(n):
        out[i] = med.get(t[i] // bucket_s)
    return out


def _diff_clamped(deep: Sequence[Optional[float]], shallow: Sequence[Optional[float]]) -> List[Optional[float]]:
    out: List[Optional[float]] = []
    for a, b in zip(deep, shallow):
        if a is None or b is None:
            out.append(None)
        else:
            out.append(round(max(0.0, a - b), 2))
    return out


def segments(targets: Dict[str, Dict[str, list]], key_to_id: Dict[str, int], t: Sequence[int],
             bucket_s: int = SEGMENT_BUCKET_S) -> Dict[str, list]:
    """Build the ``segments`` block from per-target ``p50`` arrays (see module doc)."""
    n = len(t)

    def med(key: str) -> Optional[List[Optional[float]]]:
        tid = key_to_id.get(key)
        if tid is None:
            return None
        arrs = targets.get(str(tid))
        if not arrs:
            return None
        return _bucket_medians(arrs["p50"], t, bucket_s)

    gw = med("gw4")
    isp = med("isp_hop4")
    mid = med("mid_hop4")
    inet = None
    for k in INET_KEYS:
        inet = med(k)
        if inet is not None:
            break
    empty = [None] * n
    lan = [None if v is None else round(v, 2) for v in gw] if gw is not None else list(empty)
    docsis = _diff_clamped(isp, gw) if (isp is not None and gw is not None) else list(empty)
    comcast = _diff_clamped(mid, isp) if (mid is not None and isp is not None) else list(empty)
    shallower = mid if mid is not None else (isp if isp is not None else gw)
    internet = _diff_clamped(inet, shallower) if (inet is not None and shallower is not None) else list(empty)
    return {"lan": lan, "docsis": docsis, "comcast": comcast, "internet": internet}


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def build_series(ctx_or_state: Any, store: Any, t_from: float, t_to: float, res: int,
                 target_ids: Optional[Iterable[int]] = None) -> dict:
    """Return the ``GET /api/series`` body for ``[t_from, t_to)`` at ``res`` seconds.

    ``ctx_or_state`` is an :class:`AppContext` or a :class:`State`; ``store``
    may be ``None`` (RAM only). Raises ``ValueError`` for a bad ``res``, an
    inverted range, ``res=1`` over more than two hours or a grid beyond
    :data:`MAX_POINTS`.
    """
    state = _state_of(ctx_or_state)
    res = int(res)
    if res not in (1, 5):
        raise ValueError("res must be 1 or 5")
    t_from = float(t_from)
    t_to = float(t_to)
    if t_to < t_from:
        raise ValueError("'to' must not be before 'from'")
    if res == 1 and (t_to - t_from) > MAX_RES1_SPAN_S:
        raise ValueError("res=1 is limited to ranges of 2 h or less")
    if (t_to - t_from) / res > MAX_POINTS:
        raise ValueError("range too large for this resolution")

    t = _grid(t_from, t_to, res)
    n = len(t)
    start = t[0]
    grid_to = start + n * res  # covers the last grid cell entirely

    if target_ids is None:
        ids = [tg.id for tg in state.targets_list()]
    else:
        ids = [int(i) for i in target_ids]
    key_to_id = {tg.key: tg.id for tg in state.targets_list()}

    targets: Dict[str, Dict[str, list]] = {}
    ram = state.rollups(res, start, grid_to, ids)
    for tid in ids:
        arrs = _target_arrays(n)
        for r in ram.get(tid, []):
            i = _index_of(r.t, start, res, n)
            if i >= 0:
                _fill_target(arrs, i, r)
        targets[str(tid)] = arrs

    file_rows: List[dict] = []
    if _needs_file(state, res, start, ids):
        file_rows = _file_rows(store, start, grid_to)
        wanted = set(ids)
        for row in file_rows:
            tid = row.get("id")
            if not isinstance(tid, int) or tid not in wanted or "n" not in row:
                continue
            i = _index_of(row.get("t"), start, res, n)
            if i >= 0:
                _fill_target_row(targets[str(tid)], i, row)

    rows_by_kind = {k: _collector_rows(state, k, start, grid_to, file_rows) for k in COLLECTOR_KINDS}
    iface = _collector_series(rows_by_kind["iface"], "iface", IFACE_KEYS, start, res, n, derived={
        "err": lambda b: _sum_keys(b, ("rx_err", "tx_err")),
        "drop": lambda b: _sum_keys(b, ("rx_drop", "tx_drop")),
    })
    wan = _collector_series(rows_by_kind["wan"], "wan", WAN_KEYS, start, res, n)
    wifi = _collector_series(rows_by_kind["wifi"], "wifi", WIFI_KEYS, start, res, n)
    docsis = _collector_series(rows_by_kind["docsis"], "docsis", DOCSIS_KEYS, start, res, n)
    ntp = _ntp_series(rows_by_kind["ntp"], start, res, n)

    return {
        "res": res,
        "from": t_from,
        "to": t_to,
        "t": t,
        "targets": targets,
        "iface": iface,
        "wan": wan,
        "wifi": wifi,
        "docsis": docsis,
        "ntp": ntp,
        "segments": segments(targets, key_to_id, t),
        "slots_lost": _slots_series(rows_by_kind["slots"], start, res, n),
        "xbox_state": _xbox_series(rows_by_kind["xbox"], start, res, n),
        "stall": _stall_series(rows_by_kind["host"], start, res, n),
    }


__all__ = ["build_series", "segments", "MAX_RES1_SPAN_S", "MAX_POINTS", "SEGMENT_BUCKET_S", "TARGET_KEYS"]
