"""Detection: baselines, symptoms, notes → events, hop corroboration, episodes.

:class:`Detector` is driven by the ticker once per second with
``step(t)``. It works ``second_close_lag_s(cfg)`` seconds behind wall time
(the *edge*) so every sample it looks at already has its lost/late verdict
(SPEC_FULL §7.2 "evaluated each 1 s tick over the last few seconds of raw
samples"). All timestamps on events and episodes are sample (send) times,
never tick times.

Per tick:

1. drain the producer notes (``state.drain_notes()``) into events (dedupe per
   type/target within a rate limit, §7.2 severities, docsis within ±60 s of an
   episode attached as correlation, everything else within ±5 s as members);
2. recompute the per-target baselines every 5 s (rolling 10 min p50 + MAD
   from the raw ring, baseline jitter = median of the 1 s jitters);
3. evaluate the symptoms of every enabled target on the samples newer than
   the per-target cursor: ``latency_spike``, ``loss_burst`` (gateway/Xbox need
   3 in 8), ``late_burst``, ``jitter``, ``probe_error``, ``dns_slow/dns_fail``,
   ``tcp_slow/tcp_timeout``, ``cdn_slow``; hop symptoms start informational
   (severity 1) and are upgraded when a deeper target shows a symptom in the
   same or the next 250 ms slot;
4. ``host_stall`` from ``F_STALL`` samples or the host collector's latest row, and ``link_down``
   while this computer's own link has no carrier (no episode opens inside that span);
5. the ``xb7_reset`` composite rule;
6. close events whose end rule fired (an updated row goes to ``events.jsonl``);
7. episodes (§7.4): open on a severity ≥ 2 symptom on a non-hop target (or a
   corroborated hop), join when the last symptom was < 5 s ago, register
   (id, row, ``episode_open``, tracer sweep, DOCSIS refresh, mark linking)
   once the symptom span reaches 1.5 s, close after 10 s of quiet (shorter
   ones are *blips*: ``state.blips`` counts them), split at 10 min, collapse
   into an ``unstable_period`` when more than 30 episodes opened in 10 min.

Only this module creates :class:`laglens.state.Event` objects (INTERFACES
§10.1). Nothing here blocks, and every external call (tracer, docsis) is
guarded so a missing or failing component cannot stop detection.
"""
import logging
import os
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from laglens.engine import classify as classifymod
from laglens.engine.rollup import jitter as jitter_of, percentile, second_close_lag_s
from laglens.state import (
    F_ERROR,
    F_LATE,
    F_LOADTEST,
    F_LOST,
    F_STALL,
    F_XBOX_ASLEEP,
    KIND_CDN_TTFB,
    Episode,
    Event,
    Mark,
    Sample,
    State,
    Target,
    extra_of,
)

log = logging.getLogger("laglens.detector")

HOP_ROLES = ("isp_hop", "mid_hop")
SYMPTOM_TYPES = classifymod.SYMPTOM_TYPES
#: Severity by note type (SPEC §7.2); unknown types keep the producer's severity.
SEVERITY_BY_NOTE: Dict[str, int] = {
    "monitor_gap": 1, "host_stall": 1, "iface_errors": 2, "link_flap": 3, "self_load": 2, "wan_saturated": 2,
    "wifi_drop": 2, "wifi_roam": 2, "docsis_t3": 3, "docsis_t4": 3, "docsis_drw": 3, "docsis_ranging": 2,
    "docsis_uncorr": 3, "docsis_power_snr": 2, "docsis_partial": 3, "docsis_reboot": 4, "xb7_reset": 4,
    "route_change": 2, "path_anomaly": 2, "wan_ip_change": 2, "v6_prefix_change": 1, "nat_mapping_change": 1,
    "v6_gw_stale": 2, "v6_route_expired": 2, "vpn_route": 2, "dhcp_renew": 1, "clock_jump": 2,
    "collector_error": 1, "loadtest_phase": 1, "probe_error": 2, "cdn_slow": 2, "dns_fail": 3, "tcp_timeout": 3,
    "mark": 1,
}
#: Same type + target within this many seconds → merged into the previous event (count++).
RATE_LIMIT_BY_NOTE: Dict[str, float] = {
    "iface_errors": 60.0, "wifi_roam": 30.0, "wifi_drop": 10.0, "self_load": 30.0, "wan_saturated": 30.0,
    "docsis_uncorr": 60.0, "docsis_power_snr": 300.0, "docsis_partial": 300.0, "collector_error": 60.0,
    "nat_mapping_change": 30.0, "mark": 0.0, "loadtest_phase": 0.0,
}
DEFAULT_NOTE_RATE_LIMIT_S = 5.0
#: Note types the probes raise that the detector also derives from samples: one per-target limiter for both.
NOTE_SHARED_LIMITS: Dict[str, float] = {"probe_error": 60.0, "dns_fail": 30.0, "tcp_timeout": 30.0, "cdn_slow": 120.0}
WARMUP_LOSS_S = 15.0
MIN_BASELINE_N = 20
MIN_EPISODE_S = 1.5
EPISODE_JOIN_S = 5.0
EPISODE_QUIET_S = 10.0
UNSTABLE_QUIET_S = 60.0
EPISODE_MAX_S = 600.0
UNSTABLE_COUNT = 30
UNSTABLE_WINDOW_S = 600.0
EVENT_ATTACH_S = 5.0
DOCSIS_ATTACH_S = 60.0
MARK_LINK_S = 60.0
EVENT_MAX_OPEN_S = 600.0
#: The host collector reads the link every 10 s, so the carrier went down up to this long before it was seen.
LINK_LEAD_S = 10.0
#: After the link is back, DHCP, ARP and IPv6 router adverts take a while: the span lasts this much longer.
LINK_SETTLE_S = 30.0
PROBE_ERROR_RATE_S = 60.0
POINT_RATE_S = 30.0
CDN_RATE_S = 120.0
EPISODE_UPDATE_S = 10.0
RESET_CANDIDATE_TTL_S = 600.0
RESET_CORROBORATORS = ("link_flap", "route_change", "wan_ip_change", "docsis_reboot", "igd_uptime_drop",
                       "docsis_uptime_drop")
HOST_STALL_LATE_MS = 50
HOST_STALL_GAP_MS = 200


class Baseline:
    """Rolling 10 min baseline of one target (SPEC §7.1)."""

    __slots__ = ("p50", "mad", "p95", "jit", "n", "session_p50", "computed_at")

    def __init__(self) -> None:
        self.p50: Optional[float] = None
        self.mad: Optional[float] = None
        self.p95: Optional[float] = None
        self.jit: Optional[float] = None
        self.n = 0
        self.session_p50: Optional[float] = None
        self.computed_at = 0.0

    @property
    def ready(self) -> bool:
        return self.p50 is not None and self.mad is not None and self.n >= MIN_BASELINE_N

    def to_dict(self) -> dict:
        return {"p50": self.p50, "mad": self.mad, "p95": self.p95, "jitter": self.jit, "n": self.n,
                "session_p50": self.session_p50}


def baseline_from_samples(samples: Sequence[Sample], jitters: Sequence[float] = ()) -> Baseline:
    """Build a :class:`Baseline` from raw samples (valid RTTs only) and 1 s jitters."""
    b = Baseline()
    rtts = sorted(s.value / 1000.0 for s in samples
                  if not (s.flags & (F_LOST | F_LATE | F_ERROR | F_STALL | F_LOADTEST | F_XBOX_ASLEEP)))
    b.n = len(rtts)
    if rtts:
        b.p50 = percentile(rtts, 50)
        b.p95 = percentile(rtts, 95)
        b.mad = percentile(sorted(abs(x - (b.p50 or 0.0)) for x in rtts), 50)
    js = sorted(float(j) for j in jitters if j is not None)
    if js:
        b.jit = percentile(js, 50)
    return b


def baseline_for(state: State, tid: int, t: float, span_s: float = 600.0) -> Baseline:
    """Baseline of target ``tid`` over the ``span_s`` before ``t`` (raw ring + 1 s rollups), earlier episodes
    left out (:func:`laglens.engine.classify.quiet_baseline`) so a bad stretch does not raise "normal"."""
    window = state.raw_window(tid, t - span_s, t)
    target = state.target_by_id(tid)
    samples = classifymod.quiet_baseline(state, target, t, span_s, window=window) if target is not None else window
    if len(samples) < len(window):
        jitters: List[float] = []  # the rollups include the episodes: per-second jitter from the quiet samples
    else:
        rl = state.rollups(1, t - span_s, t, [tid]).get(tid, [])
        jitters = [r.jit for r in rl if r.jit is not None]
    if not jitters and samples:
        # no 1 s rollups yet (bare detector, offline rebuild): per-second jitter straight from the raw ring
        by_sec: Dict[int, List[float]] = {}
        for s in samples:
            if s.received and not (s.flags & (F_STALL | F_LOADTEST | F_XBOX_ASLEEP)):
                by_sec.setdefault(s.ts_ms // 1000, []).append(s.value / 1000.0)
        for rtts in by_sec.values():
            j = jitter_of(rtts)
            if j is not None:
                jitters.append(j)
    return baseline_from_samples(samples, jitters)


def spike_threshold(b: Baseline, role: str) -> float:
    """``max(p50 + 5·MAD, 2·p50, p50 + floor)`` (SPEC §7.2)."""
    p50 = b.p50 or 0.0
    mad = b.mad or 0.0
    return max(p50 + 5.0 * mad, 2.0 * p50, p50 + classifymod.floor_for(role, mad))


def loss_severity(length_s: float) -> int:
    if length_s < 1.0:
        return 2
    if length_s <= 5.0:
        return 3
    if length_s <= 30.0:
        return 4
    return 5


def spike_severity(excess_ms: float) -> int:
    if excess_ms < 50:
        return 2
    if excess_ms < 150:
        return 3
    if excess_ms < 400:
        return 4
    return 5


class _Track:
    """Bookkeeping of the episode being built (pending until it lasts 1.5 s)."""

    def __init__(self, t0: float) -> None:
        self.ep = Episode(id="", t0=round(t0, 3))
        self.members: List[Event] = []
        self.registered = False
        self.closed = False
        self.unstable = False
        self.last_symptom = t0
        self.last_row = 0.0
        self.dirty = False

    def add(self, ev: Event) -> None:
        if ev in self.members:
            return
        self.members.append(ev)
        if self.registered:
            ev.episode = self.ep.id
            if ev.id not in self.ep.events:
                self.ep.events.append(ev.id)
            if ev.target is not None and ev.target not in self.ep.targets:
                self.ep.targets.append(ev.target)
                self.ep.targets.sort()
        self.dirty = True


class Detector:
    """Symptom, event and episode detection (INTERFACES §10.2 ``Detector(ctx)``; ``.step(t)``)."""

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self.state: State = ctx.state
        self.store = getattr(ctx, "store", None)
        self.cfg: dict = getattr(ctx, "cfg", None) or {}
        self.lag = second_close_lag_s(self.cfg)
        self.warmup_s = float(self.cfg.get("warmup_s", 60) or 0)
        self.baselines: Dict[int, Baseline] = {}
        self._base_t: Optional[float] = None
        self._session_t: Optional[float] = None
        self._open: Dict[Tuple[int, str], Event] = {}
        self._last_t: Dict[str, float] = {}
        self._cursor: Dict[int, int] = {}
        self._late_cursor: Dict[int, int] = {}
        self._err_cursor: Dict[int, int] = {}
        self._spike_run: Dict[int, Tuple[int, float, float]] = {}  # tid -> (run, t0, rtt_max)
        self._tcp_run: Dict[int, Tuple[int, float, float]] = {}
        self._cdn_run: Dict[int, Tuple[int, float]] = {}
        self._point_last: Dict[Tuple[Optional[int], str], float] = {}
        self._note_last: Dict[Tuple[str, Optional[int]], Event] = {}
        self._recent: List[Event] = []
        self._new_events: List[Event] = []
        self._track: Optional[_Track] = None
        self._closed_tracks: List[_Track] = []
        self._uptime: Dict[str, Optional[float]] = {"igd": None, "docsis": None}
        self._corr_times: List[Tuple[str, float]] = []
        self._dark: Dict[str, Optional[float]] = {"inet": None, "gw": None}
        self._reset_cands: List[dict] = []
        self._link_spans: List[List[Optional[float]]] = []  # [t0, t1 or None] of each link_down
        self.blips = 0
        self.verdict_due = False
        self.edge: Optional[float] = None
        self.errors = 0

    # ------------------------------------------------------------------ API
    def step(self, t: int) -> None:
        """One detection pass for tick ``t`` (evaluates samples older than ``t - lag``)."""
        edge = float(t) - self.lag
        self.edge = edge
        loadtest = bool(self.state.loadtest.get("running"))
        for name, fn in (
            ("notes", lambda: self._drain_notes(edge)),
            ("baselines", lambda: self._update_baselines(edge)),
            ("symptoms", lambda: self._eval_targets(edge, loadtest)),
            ("host_stall", lambda: self._eval_host_stall(edge)),
            ("link", lambda: self._eval_link(edge)),
            ("hops", lambda: self._corroborate_hops(edge)),
            ("xb7_reset", lambda: self._xb7_reset(edge)),
            ("close", lambda: self._close_events(edge)),
            ("episodes", lambda: self._episodes(edge, loadtest)),
        ):
            try:
                fn()
            except Exception:  # noqa: BLE001 - one failing stage must not stop the others
                self.errors += 1
                log.exception("detector stage %s failed at t=%d", name, t)
        self._new_events = []

    def finalize(self, t: Optional[float] = None) -> None:
        """Close every open event and the current episode (shutdown)."""
        t = self.state.now() if t is None else float(t)
        for key in list(self._open):
            ev = self._open[key]
            self._close_event(key, max(ev.t0, min(t, self._last_t.get(ev.id, t))))
        tr = self._track
        if tr is not None and not tr.closed:
            self._refresh_last_symptom(tr)
            self._close_track(tr, t)

    def link_down(self) -> bool:
        """Whether this computer's own link is down (or has not settled since it came back)."""
        return (-1, "link_down") in self._open

    def open_episode(self) -> Optional[Episode]:
        """The registered open episode, if any."""
        tr = self._track
        if tr is not None and tr.registered and not tr.closed:
            return tr.ep
        return None

    def baseline(self, tid: int) -> Optional[Baseline]:
        return self.baselines.get(tid)

    def stats(self) -> dict:
        return {"blips": self.blips, "open_events": len(self._open), "errors": self.errors,
                "episode_open": self.open_episode() is not None, "edge": self.edge}

    # ------------------------------------------------------------ helpers
    def _store_row(self, name: str, obj: dict) -> None:
        store = self.store
        if store is None:
            return
        try:
            store.append_json(name, obj)
        except Exception:  # noqa: BLE001
            log.exception("cannot append %s row", name)

    def _publish(self, name: str, obj: Any) -> None:
        try:
            self.state.publish(name, obj)
        except Exception:  # noqa: BLE001
            log.exception("publish %s failed", name)

    def _interval(self, target: Target) -> float:
        return 1.0 / float(target.rate_hz or 1.0)

    def _elapsed(self, edge: float) -> float:
        return edge - self.state.t0

    def _open_event(self, type_: str, target: Optional[Target], t0: float, severity: int, peak: dict,
                    loadtest: bool, t1: Optional[float] = None, note: str = "", stall: bool = False) -> Event:
        ev = Event(id=self.state.next_event_id(), t0=round(t0, 3), t1=None if t1 is None else round(t1, 3),
                   type=type_, target=target.id if target is not None else None, severity=severity,
                   peak=dict(peak), stall=stall, source="auto", note=note)
        if loadtest:
            ev.peak["loadtest"] = True
        if target is not None and target.role in HOP_ROLES and type_ in SYMPTOM_TYPES:
            ev.peak["base_severity"] = severity
            ev.peak["corroborated"] = False
            ev.severity = 1
        self.state.add_event(ev)
        self._store_row("events", ev.to_dict())
        tid = target.id if target is not None else -1
        if t1 is None:
            self._open[(tid, type_)] = ev
            self._last_t[ev.id] = t0
        else:
            self._last_t[ev.id] = t1
        self._recent.append(ev)
        if len(self._recent) > 300:
            del self._recent[:100]
        self._new_events.append(ev)
        return ev

    def _close_event(self, key: Tuple[int, str], t1: float) -> None:
        ev = self._open.pop(key, None)
        if ev is None:
            return
        ev.t1 = round(max(ev.t0, t1), 3)
        if ev.type == "loss_burst" or ev.type == "late_burst":
            base = loss_severity(ev.t1 - ev.t0) if ev.type == "loss_burst" else 2
            self._set_severity(ev, base)
        self._store_row("events", ev.to_dict())
        self._publish("event", ev.to_dict())

    def _set_severity(self, ev: Event, base: int) -> None:
        """Set the severity honouring the hop "informational unless corroborated" rule."""
        if "base_severity" in ev.peak:
            ev.peak["base_severity"] = base
            ev.severity = base if ev.peak.get("corroborated") else 1
        else:
            ev.severity = base

    def _rate_ok(self, key: Tuple[Optional[int], str], t: float, limit: float) -> bool:
        last = self._point_last.get(key)
        if last is not None and t - last < limit:
            return False
        self._point_last[key] = t
        return True

    # -------------------------------------------------------------- notes
    def _drain_notes(self, edge: float) -> None:
        notes = self.state.drain_notes()
        if not notes:
            return
        loadtest = bool(self.state.loadtest.get("running"))
        for n in notes:
            try:
                self._note_to_event(n, loadtest)
            except Exception:  # noqa: BLE001
                log.exception("bad note %r", n)

    def _note_to_event(self, n: dict, loadtest: bool) -> Optional[Event]:
        typ = str(n.get("type") or "note")
        t = float(n.get("t") or self.state.now())
        target = n.get("target")
        peak = dict(n.get("peak") or {})
        note = str(n.get("note") or "")
        sev = SEVERITY_BY_NOTE.get(typ, int(n.get("severity") or 1))
        key = (typ, target)
        limit = RATE_LIMIT_BY_NOTE.get(typ, DEFAULT_NOTE_RATE_LIMIT_S)
        last = self._note_last.get(key)
        if last is not None and limit > 0 and 0 <= t - last.t0 < limit:
            last.peak["count"] = int(last.peak.get("count", 1)) + 1
            last.peak["last_t"] = round(t, 3)
            return None
        if typ in NOTE_SHARED_LIMITS and isinstance(target, int):
            # the probes raise these too (engine: Local Network permission / gw6; dns: dns_fail; tcp: tcp_timeout;
            # cdn: cdn_slow): share the per-target limiter with the detector's own sample-derived rule so one
            # target never gets the same symptom twice from two sources
            if not self._rate_ok((target, typ), t, NOTE_SHARED_LIMITS[typ]):
                return None
            if typ == "probe_error" and n.get("severity") is not None:
                sev = int(n.get("severity") or 1)
        t1 = t
        for k in ("gap_s", "dur_s", "duration_s"):
            v = peak.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                t1 = t + float(v)
                break
        tgt = self.state.target_by_id(target) if isinstance(target, int) else None
        source = str(peak.pop("source", "auto") or "auto")
        ev = Event(id=self.state.next_event_id(), t0=round(t, 3), t1=round(t1, 3), type=typ,
                   target=tgt.id if tgt is not None else (target if isinstance(target, int) else None),
                   severity=sev, peak=peak, stall=(typ in ("host_stall", "monitor_gap")),
                   source=source, note=note)
        if loadtest:
            ev.peak["loadtest"] = True
        if typ == "monitor_gap":
            self._corr_times.append(("monitor_gap", t))
        self.state.add_event(ev)
        self._store_row("events", ev.to_dict())
        self._note_last[key] = ev
        self._last_t[ev.id] = t1
        self._recent.append(ev)
        self._new_events.append(ev)
        if typ in RESET_CORROBORATORS:
            self._corr_times.append((typ, t))
        if typ.startswith("docsis_"):
            self._attach_docsis(ev)
        else:
            self._attach_event(ev)
        return ev

    def _attach_docsis(self, ev: Event) -> None:
        """DOCSIS notes within ±60 s of an episode become a correlation, not a member."""
        entry = {"type": ev.type, "t": ev.t0, "note": ev.note, "peak": dict(ev.peak)}
        for tr in self._tracks_near(ev.t0, DOCSIS_ATTACH_S):
            doc = tr.ep.docsis if isinstance(tr.ep.docsis, dict) else {}
            lst = doc.setdefault("events", [])
            if entry not in lst:
                lst.append(entry)
                lines = doc.setdefault("log_lines", [])
                if ev.note and ev.note not in lines:
                    lines.append(ev.note)
            tr.ep.docsis = doc
            tr.dirty = True
            if tr.closed and tr.registered:
                self._reclassify(tr)

    def _attach_event(self, ev: Event) -> None:
        """Non-symptom events within ±5 s of an episode span join it as members."""
        for tr in self._tracks_near(ev.t0, EVENT_ATTACH_S, t1=ev.t1):
            tr.add(ev)
            if tr.closed and tr.registered:
                if ev.type in classifymod.HOST_TAG_TYPES:
                    self._reclassify(tr)
                else:
                    self._write_episode(tr, "episode_update")

    def _tracks_near(self, t: float, margin: float, t1: Optional[float] = None) -> List[_Track]:
        t1 = t if t1 is None else t1
        out: List[_Track] = []
        cur = self._track
        if cur is not None and not cur.closed:
            end = cur.last_symptom
            if t <= end + margin and t1 >= cur.ep.t0 - margin:
                out.append(cur)
        for tr in self._closed_tracks[-50:]:
            if not tr.registered or tr.ep.t1 is None:
                continue
            if t <= tr.ep.t1 + margin and t1 >= tr.ep.t0 - margin:
                out.append(tr)
        return out

    # ----------------------------------------------------------- baselines
    def _update_baselines(self, edge: float) -> None:
        if self._base_t is not None and edge - self._base_t < 5.0:
            return
        self._base_t = edge
        do_session = self._session_t is None or edge - self._session_t >= 60.0
        if do_session:
            self._session_t = edge
        for t in self.state.targets_list():
            if not t.enabled:
                continue
            b = baseline_for(self.state, t.id, edge)
            b.computed_at = edge
            old = self.baselines.get(t.id)
            if do_session or old is None:
                tot = self.state.totals.get(t.id)
                if tot is not None and len(tot.rtts_us):
                    p = percentile(sorted(tot.rtts_us), 50)
                    b.session_p50 = round(p / 1000.0, 2) if p is not None else None
            elif old is not None:
                b.session_p50 = old.session_p50
            self.baselines[t.id] = b

    # ------------------------------------------------------------ symptoms
    def _eval_targets(self, edge: float, loadtest: bool) -> None:
        for target in self.state.targets_list():
            if not target.enabled:
                continue
            try:
                samples = self.state.raw_window(target.id, edge - 12.0, edge)
                if not samples:
                    continue
                if target.kind == "icmp":
                    self._icmp_symptoms(target, samples, edge, loadtest)
                elif target.kind == "dns":
                    self._dns_symptoms(target, samples, edge, loadtest)
                elif target.kind == "tcp":
                    self._tcp_symptoms(target, samples, edge, loadtest)
                elif target.kind == "cdn":
                    self._cdn_symptoms(target, samples, edge, loadtest)
                self._probe_errors(target, samples, edge, loadtest)
            except Exception:  # noqa: BLE001
                self.errors += 1
                log.exception("symptoms failed for %s", target.key)

    def _new_primary(self, target: Target, samples: Sequence[Sample]) -> Tuple[List[Sample], List[int]]:
        prim = [s for s in samples if not (s.flags & F_LATE)]
        if target.role == "xbox":
            prim = [s for s in prim if not (s.flags & F_XBOX_ASLEEP)]
            since = self.state.xbox.get("since")
            if since:
                prim = [s for s in prim if s.ts_ms >= since * 1000.0]  # the previous address's silence is not this console's
        cursor = self._cursor.get(target.id, -1)
        new_idx = [i for i, s in enumerate(prim) if s.ts_ms > cursor]
        if prim:
            self._cursor[target.id] = prim[-1].ts_ms
        return prim, new_idx

    def _icmp_symptoms(self, target: Target, samples: Sequence[Sample], edge: float, loadtest: bool) -> None:
        if target.role == "xbox" and self.state.xbox.get("state") != "awake":
            return  # asleep, or not yet seen awake (start-up): a silent console is not a fault
        tid = target.id
        prim, new_idx = self._new_primary(target, samples)
        pingbin = target.backend == "pingbin"
        interval = self._interval(target)
        window = 8 + (1 if pingbin else 0)
        consec = 3 + (1 if pingbin else 0)
        need = 3 if target.role in ("gateway", "xbox", "plex_server", "plex_player") else 2
        elapsed = self._elapsed(edge)
        loss_ok = elapsed >= WARMUP_LOSS_S
        b = self.baselines.get(tid)
        lat_ok = elapsed >= self.warmup_s and b is not None and b.ready

        # --- loss_burst
        key = (tid, "loss_burst")
        ev = self._open.get(key)
        for i in new_idx:
            s = prim[i]
            if not (s.flags & F_LOST):
                continue
            if ev is None and loss_ok:
                win = prim[max(0, i - window + 1): i + 1]
                lost_in = [x for x in win if x.flags & F_LOST]
                run = 0
                for x in reversed(win):
                    if x.flags & F_LOST:
                        run += 1
                    else:
                        break
                if len(lost_in) >= need or run >= consec:
                    first = lost_in[0] if len(lost_in) >= need else win[len(win) - run]
                    t0 = first.ts_ms / 1000.0
                    ev = self._open_event("loss_burst", target, t0, 2,
                                          {"lost": len(lost_in), "n": len(win),
                                           "loss_pct": round(100.0 * len(lost_in) / len(win), 1), "last_t": round(s.ts_ms / 1000.0, 3)},
                                          loadtest or any(x.flags & F_LOADTEST for x in lost_in))
            if ev is not None:
                self._last_t[ev.id] = max(self._last_t.get(ev.id, ev.t0), s.ts_ms / 1000.0)
        if ev is not None:
            last = self._last_t.get(ev.id, ev.t0)
            span = [x for x in prim if ev.t0 - 0.001 <= x.ts_ms / 1000.0 <= last + 0.001]
            lost = sum(1 for x in span if x.flags & F_LOST)
            run = best = 0
            for x in span:
                if x.flags & F_LOST:
                    run += 1
                    best = max(best, run)
                else:
                    run = 0
            ev.peak.update({"lost": lost, "n": len(span), "loss_pct": round(100.0 * lost / len(span), 1) if span else 0.0,
                            "longest_run": best, "last_t": round(last, 3)})
            self._set_severity(ev, loss_severity(last + interval - ev.t0))

        # --- latency_spike
        key = (tid, "latency_spike")
        ev = self._open.get(key)
        if lat_ok and b is not None:
            thr = spike_threshold(b, target.role)
            run, run_t0, run_max = self._spike_run.get(tid, (0, 0.0, 0.0))
            for i in new_idx:
                s = prim[i]
                if not s.received or s.flags & (F_STALL | F_LOADTEST):
                    continue  # stalled and load-test samples never make a spike (they still count for loss)
                rtt = s.value / 1000.0
                if rtt > thr:
                    run += 1
                    if run == 1:
                        run_t0, run_max = s.ts_ms / 1000.0, rtt
                    run_max = max(run_max, rtt)
                    if ev is None and run >= consec:
                        ev = self._open_event("latency_spike", target, run_t0, spike_severity(run_max - (b.p50 or 0.0)),
                                              {"rtt_max_ms": round(run_max, 2), "p50_ms": round(b.p50 or 0.0, 2),
                                               "threshold_ms": round(thr, 2), "excess_ms": round(run_max - (b.p50 or 0.0), 2),
                                               "last_t": round(s.ts_ms / 1000.0, 3)}, loadtest)
                    if ev is not None:
                        self._last_t[ev.id] = s.ts_ms / 1000.0
                        if rtt >= float(ev.peak.get("rtt_max_ms", 0)):
                            ev.peak["rtt_max_ms"] = round(rtt, 2)
                            ev.peak["excess_ms"] = round(rtt - (b.p50 or 0.0), 2)
                            self._set_severity(ev, spike_severity(rtt - (b.p50 or 0.0)))
                        ev.peak["last_t"] = round(s.ts_ms / 1000.0, 3)
                else:
                    run, run_t0, run_max = 0, 0.0, 0.0
            self._spike_run[tid] = (run, run_t0, run_max)
        else:
            self._spike_run[tid] = (0, 0.0, 0.0)

        # --- late_burst
        late = [s for s in samples if s.flags & F_LATE]
        lc = self._late_cursor.get(tid, -1)
        new_late = [s for s in late if s.ts_ms > lc]
        if late:
            self._late_cursor[tid] = late[-1].ts_ms
        key = (tid, "late_burst")
        ev = self._open.get(key)
        for s in new_late:
            if ev is None and loss_ok:
                span_ms = int(window * interval * 1000)
                inside = [x for x in late if s.ts_ms - span_ms <= x.ts_ms <= s.ts_ms]
                if len(inside) >= 2:
                    ev = self._open_event("late_burst", target, inside[0].ts_ms / 1000.0, 2,
                                          {"late": len(inside), "n": window, "last_t": round(s.ts_ms / 1000.0, 3)}, loadtest)
            if ev is not None:
                self._last_t[ev.id] = max(self._last_t.get(ev.id, ev.t0), s.ts_ms / 1000.0)
                ev.peak["late"] = max(int(ev.peak.get("late", 0)), len([x for x in late if ev.t0 <= x.ts_ms / 1000.0]))
                ev.peak["last_t"] = round(self._last_t[ev.id], 3)

        # --- jitter
        key = (tid, "jitter")
        ev = self._open.get(key)
        if lat_ok and b is not None and b.jit is not None:
            recent = [s for s in prim if s.ts_ms >= int((edge - 10.0) * 1000)]
            has_loss = any(s.flags & F_LOST for s in recent)
            rtts = [s.value / 1000.0 for s in recent if s.received and not (s.flags & (F_STALL | F_LOADTEST))]
            j = jitter_of(rtts) if len(rtts) >= 8 else None
            thr = max(15.0, 4.0 * b.jit)
            if j is not None:
                if ev is None and j > thr and not has_loss:
                    ev = self._open_event("jitter", target, edge - 10.0, 2,
                                          {"jitter_ms": round(j, 2), "baseline_ms": round(b.jit, 2), "threshold_ms": round(thr, 2),
                                           "last_t": round(edge, 3)}, loadtest)
                    self._last_t[ev.id] = edge
                elif ev is not None:
                    ev.peak["jitter_ms"] = max(float(ev.peak.get("jitter_ms", 0.0)), round(j, 2))
                    if j > 2.0 * b.jit:
                        self._last_t[ev.id] = edge
                        ev.peak["last_t"] = round(edge, 3)

    def _probe_errors(self, target: Target, samples: Sequence[Sample], edge: float, loadtest: bool) -> None:
        errs = [s for s in samples if s.flags & F_ERROR]
        if not errs:
            return
        if target.role == "xbox" and self.state.xbox.get("state") != "awake":
            # a console in rest mode does not answer ARP, so macOS refuses the sends (EHOSTUNREACH): like its
            # silence (see _icmp_symptoms), that is not a fault
            self._err_cursor[target.id] = errs[-1].ts_ms
            return
        cursor = self._err_cursor.get(target.id, -1)
        new = [s for s in errs if s.ts_ms > cursor]
        self._err_cursor[target.id] = errs[-1].ts_ms
        for s in new:
            inside = [x for x in errs if s.ts_ms - 10000 <= x.ts_ms <= s.ts_ms]
            if len(inside) < 3:
                continue
            if not self._rate_ok((target.id, "probe_error"), s.ts_ms / 1000.0, PROBE_ERROR_RATE_S):
                continue
            errno_ = int(s.value)
            platform = getattr(self.ctx, "platform", None)
            is_darwin = getattr(platform, "name", "") == "darwin"
            lan = False
            try:
                from laglens.platform import is_private
                lan = is_private(target.addr)
            except Exception:  # noqa: BLE001
                lan = False
            permission = is_darwin and errno_ == 65 and lan
            if permission:
                app = "your terminal app"
                try:
                    app = platform.terminal_app_name() or app
                except Exception:  # noqa: BLE001
                    pass
                note = ("macOS Local Network permission: allow %s in System Settings > Privacy & Security > Local Network"
                        % app)
                sev = 1
            else:
                try:
                    note = "errno %d (%s)" % (errno_, os.strerror(errno_))
                except (ValueError, OverflowError):
                    note = "errno %d" % errno_
                sev = 2
            self._open_event("probe_error", target, inside[0].ts_ms / 1000.0, sev,
                             {"errno": errno_, "count": len(inside), "permission": permission, "last_t": round(s.ts_ms / 1000.0, 3)},
                             loadtest, t1=s.ts_ms / 1000.0, note=note)

    def _dns_symptoms(self, target: Target, samples: Sequence[Sample], edge: float, loadtest: bool) -> None:
        prim, new_idx = self._new_primary(target, samples)
        if self._elapsed(edge) < WARMUP_LOSS_S:
            return
        for i in new_idx:
            s = prim[i]
            ts = s.ts_ms / 1000.0
            lo = s.ts_ms - 30000
            if s.received and s.value > 500000:
                slow = [x for x in prim if lo <= x.ts_ms <= s.ts_ms and x.received and x.value > 500000]
                if len(slow) >= 2 and self._rate_ok((target.id, "dns_slow"), ts, POINT_RATE_S):
                    self._open_event("dns_slow", target, slow[0].ts_ms / 1000.0, 2,
                                     {"rtt_ms": round(max(x.value for x in slow) / 1000.0, 1), "count": len(slow), "last_t": round(ts, 3)},
                                     loadtest, t1=ts)
            failed = bool(s.flags & F_LOST) or (s.received and extra_of(s.flags) == 2)
            if failed:
                fails = [x for x in prim if lo <= x.ts_ms <= s.ts_ms and (x.flags & F_LOST or (x.received and extra_of(x.flags) == 2))]
                if len(fails) >= 2 and self._rate_ok((target.id, "dns_fail"), ts, POINT_RATE_S):
                    self._open_event("dns_fail", target, fails[0].ts_ms / 1000.0, 3,
                                     {"count": len(fails), "timeouts": sum(1 for x in fails if x.flags & F_LOST),
                                      "servfail": sum(1 for x in fails if not (x.flags & F_LOST)), "last_t": round(ts, 3)},
                                     loadtest, t1=ts)

    def _tcp_symptoms(self, target: Target, samples: Sequence[Sample], edge: float, loadtest: bool) -> None:
        prim, new_idx = self._new_primary(target, samples)
        elapsed = self._elapsed(edge)
        b = self.baselines.get(target.id)
        run, run_t0, run_max = self._tcp_run.get(target.id, (0, 0.0, 0.0))
        for i in new_idx:
            s = prim[i]
            ts = s.ts_ms / 1000.0
            if s.flags & F_LOST:
                run = 0
                if elapsed >= WARMUP_LOSS_S and self._rate_ok((target.id, "tcp_timeout"), ts, POINT_RATE_S):
                    self._open_event("tcp_timeout", target, ts, 3, {"last_t": round(ts, 3)}, loadtest, t1=ts)
                continue
            if not s.received:
                run = 0
                continue
            if b is None or b.p50 is None or elapsed < self.warmup_s or b.n < 5:
                continue
            rtt = s.value / 1000.0
            if rtt > b.p50 + 60.0:
                run += 1
                if run == 1:
                    run_t0, run_max = ts, rtt
                run_max = max(run_max, rtt)
                if run >= 3 and self._rate_ok((target.id, "tcp_slow"), ts, POINT_RATE_S):
                    self._open_event("tcp_slow", target, run_t0, 2,
                                     {"connect_ms": round(run_max, 1), "p50_ms": round(b.p50, 1), "count": run, "last_t": round(ts, 3)},
                                     loadtest, t1=ts)
            else:
                run, run_t0, run_max = 0, 0.0, 0.0
        self._tcp_run[target.id] = (run, run_t0, run_max)

    def _cdn_symptoms(self, target: Target, samples: Sequence[Sample], edge: float, loadtest: bool) -> None:
        prim, new_idx = self._new_primary(target, samples)
        run, run_t0 = self._cdn_run.get(target.id, (0, 0.0))
        for i in new_idx:
            s = prim[i]
            if s.kind != KIND_CDN_TTFB:
                continue
            ts = s.ts_ms / 1000.0
            if (s.received and s.value > 1000000) or (s.flags & F_LOST):
                run += 1
                if run == 1:
                    run_t0 = ts
                if run >= 2 and self._rate_ok((target.id, "cdn_slow"), ts, CDN_RATE_S):
                    # spans the slow run (first slow fetch → this one) so an episode can form around it
                    self._open_event("cdn_slow", target, run_t0, 2,
                                     {"ttfb_ms": round(s.value / 1000.0, 1) if s.received else None, "count": run, "last_t": round(ts, 3)},
                                     loadtest, t1=ts)
            else:
                run, run_t0 = 0, 0.0
        self._cdn_run[target.id] = (run, run_t0)

    # ---------------------------------------------------------- host stall
    def _eval_host_stall(self, edge: float) -> None:
        now = self.state.now()
        host = self.state.latest("host") or {}
        late_ms = host.get("late_ms_max") or 0
        gap_ms = host.get("loop_gap_ms") or 0
        fresh = True
        ht = host.get("t")
        if isinstance(ht, (int, float)) and not isinstance(ht, bool):
            fresh = now - float(ht) <= 3.0
        stalled_t: Optional[float] = None
        if fresh and ((isinstance(late_ms, (int, float)) and late_ms > HOST_STALL_LATE_MS)
                      or (isinstance(gap_ms, (int, float)) and gap_ms > HOST_STALL_GAP_MS)):
            stalled_t = now
        if stalled_t is None:
            for t in self.state.targets_list():
                if not t.enabled or t.kind != "icmp":
                    continue
                for s in self.state.raw_window(t.id, edge - 1.0, edge):
                    if s.flags & F_STALL:
                        stalled_t = s.ts_ms / 1000.0
                        break
                if stalled_t is not None:
                    break
        key = (-1, "host_stall")
        ev = self._open.get(key)
        if stalled_t is not None:
            if ev is None:
                ev = self._open_event("host_stall", None, stalled_t - 1.0, 1,
                                      {"late_ms_max": late_ms, "loop_gap_ms": gap_ms, "last_t": round(stalled_t, 3)},
                                      bool(self.state.loadtest.get("running")), stall=True)
                self._attach_event(ev)
            self._last_t[ev.id] = max(self._last_t.get(ev.id, ev.t0), stalled_t)
            ev.peak["late_ms_max"] = max(float(ev.peak.get("late_ms_max") or 0), float(late_ms or 0))
            ev.peak["loop_gap_ms"] = max(float(ev.peak.get("loop_gap_ms") or 0), float(gap_ms or 0))
            ev.peak["last_t"] = round(self._last_t[ev.id], 3)
        elif ev is not None and now - self._last_t.get(ev.id, ev.t0) >= 2.0:
            self._close_event(key, self._last_t.get(ev.id, ev.t0))

    # ----------------------------------------------------------- link down
    def _eval_link(self, edge: float) -> None:
        """``link_down`` spans the time this computer's own link has no carrier, plus a settle period.

        Every send then fails on this computer (EHOSTUNREACH, ENETUNREACH), which says nothing about the
        router or Comcast: :meth:`_episodes` opens no episode inside the span.
        """
        row = self.state.latest("iface") or {}
        carrier = row.get("carrier")
        now = self.state.now()
        key = (-1, "link_down")
        ev = self._open.get(key)
        if carrier is False:
            if ev is None:
                t0 = now - LINK_LEAD_S
                iface = (self.state.host or {}).get("iface")
                ev = self._open_event("link_down", None, t0, 3, {"iface": iface}, False, stall=True,
                                      note="this computer's network link is down%s" % (" (%s)" % iface if iface else ""))
                self._attach_event(ev)
                self._link_spans.append([t0, None])
                log.info("detector: %s; no episodes until it is back", ev.note)
            ev.peak.pop("up_t", None)
            self._last_t[ev.id] = now
        elif ev is not None and carrier is True:
            up = float(ev.peak.setdefault("up_t", round(now, 3)))
            if now - up >= LINK_SETTLE_S:
                self._close_event(key, up + LINK_SETTLE_S)
                if self._link_spans:
                    self._link_spans[-1][1] = up + LINK_SETTLE_S

    def _in_link_down(self, t: float) -> bool:
        return any(t0 is not None and t0 <= t and (t1 is None or t <= t1) for t0, t1 in self._link_spans[-20:])

    # ------------------------------------------------------- hop evidence
    def _deeper_roles(self, role: str) -> Tuple[str, ...]:
        return ("mid_hop", "anycast") if role == "isp_hop" else ("anycast",)

    def _corroborate_hops(self, edge: float) -> None:
        for ev in list(self._open.values()) + [e for e in self._new_events if e.t1 is not None]:
            if "corroborated" not in ev.peak or ev.peak.get("corroborated"):
                continue
            target = self.state.target_by_id(ev.target) if ev.target is not None else None
            if target is None:
                continue
            need = 2 if target.extra.get("rate_limit_suspected") else 1
            h_last = self._last_t.get(ev.id, ev.t1 if ev.t1 is not None else ev.t0)
            deeper_roles = self._deeper_roles(target.role)
            seen: Set[int] = set()
            for other in list(self._open.values()) + self._recent[-100:]:
                if other.target is None or other.target == ev.target or other.type not in SYMPTOM_TYPES:
                    continue
                if max(other.severity, int(other.peak.get("base_severity", 0))) < 2:
                    continue
                ot = self.state.target_by_id(other.target)
                if ot is None or ot.role not in deeper_roles:
                    continue
                o_last = self._last_t.get(other.id, other.t1 if other.t1 is not None else other.t0)
                if other.t0 <= h_last + 0.25 and o_last >= ev.t0 - 0.25:
                    seen.add(other.target)
            if len(seen) < need and ev.type == "loss_burst":
                s0 = self.state.slot_for(int(ev.t0 * 1000))
                s1 = self.state.slot_for(int(h_last * 1000)) + 1
                masks = self.state.slots(s0, max(1, s1 - s0 + 1))
                deeper_ids = [t.id for t in self.state.targets_list()
                              if t.role in deeper_roles and t.enabled and t.on_grid and t.id <= 31]
                hop_bit = 1 << target.id
                for i, m in enumerate(masks[:-1]):
                    if not (m & hop_bit):
                        continue
                    both = m | masks[i + 1]
                    for d in deeper_ids:
                        if both & (1 << d):
                            seen.add(d)
            if len(seen) >= need:
                ev.peak["corroborated"] = True
                ev.peak["corroborated_by"] = sorted(seen)
                ev.severity = int(ev.peak.get("base_severity", 2))
                self._store_row("events", ev.to_dict())
                self._publish("event", ev.to_dict())
                if ev not in self._new_events:
                    self._new_events.append(ev)

    # ------------------------------------------------------------ xb7 reset
    def _xb7_reset(self, edge: float) -> None:
        now = self.state.now()
        for kind in ("igd", "docsis"):
            row = self.state.latest(kind) or {}
            up = row.get("uptime_s")
            if isinstance(up, (int, float)) and not isinstance(up, bool):
                prev = self._uptime.get(kind)
                if prev is not None and float(up) < prev - 5:
                    self._corr_times.append(("%s_uptime_drop" % kind, now))
                self._uptime[kind] = float(up)
        self._corr_times = [(k, t) for k, t in self._corr_times if now - t <= 900]

        gw = self.state.target("gw4")
        inet = [t for t in self.state.targets_list() if t.enabled and t.kind == "icmp" and t.role == "anycast"]

        def dark(t: Target) -> Optional[bool]:
            prim = [s for s in self.state.raw_window(t.id, edge - 2.0, edge) if not (s.flags & F_LATE)]
            if not prim:
                return None
            return all((s.flags & (F_LOST | F_ERROR)) for s in prim)

        states = [dark(t) for t in inet]
        all_dark = bool(states) and all(s is True for s in states)
        gw_state = dark(gw) if gw is not None and gw.enabled else None
        if all_dark and gw_state is False:
            if self._dark["inet"] is None:
                self._dark["inet"] = edge - 2.0
        else:
            since = self._dark["inet"]
            if since is not None and edge - since >= 15.0:
                self._reset_cands.append({"t0": since, "t1": edge, "pattern": "internet_dark", "done": False})
            self._dark["inet"] = None
        if gw_state is True:
            if self._dark["gw"] is None:
                self._dark["gw"] = edge - 2.0
        else:
            since = self._dark["gw"]
            if since is not None and gw_state is False and edge - since >= 20.0:
                self._reset_cands.append({"t0": since, "t1": edge, "pattern": "gateway_dark", "done": False})
            if gw_state is not None:
                self._dark["gw"] = None

        for cand in self._reset_cands:
            if cand["done"]:
                continue
            corr = [(k, t) for k, t in self._corr_times if cand["t0"] - 60 <= t <= now]
            for e in self._recent[-100:]:
                if e.type in ("link_flap", "route_change", "wan_ip_change", "docsis_reboot") and cand["t0"] - 60 <= e.t0 <= now:
                    corr.append((e.type, e.t0))
            if not corr:
                continue
            cand["done"] = True
            target = gw if gw is not None else None
            ev = self._open_event("xb7_reset", target, cand["t0"], 4,
                                  {"pattern": cand["pattern"], "dark_s": round(cand["t1"] - cand["t0"], 1),
                                   "corroborated_by": sorted({k for k, _ in corr}), "last_t": round(cand["t1"], 3)},
                                  bool(self.state.loadtest.get("running")), t1=cand["t1"])
            self._corr_times.append(("xb7_reset", cand["t0"]))
            self._attach_event(ev)
            for tr in self._closed_tracks[-20:]:
                if tr.registered and tr.ep.t1 is not None and tr.ep.t1 >= cand["t0"] - 60 and tr.ep.t0 <= cand["t1"] + 60:
                    if ev not in tr.members:
                        tr.add(ev)
                    self._reclassify(tr)
        self._reset_cands = [c for c in self._reset_cands if not c["done"] and now - c["t1"] <= RESET_CANDIDATE_TTL_S]

    # ------------------------------------------------------- event closing
    def _close_events(self, edge: float) -> None:
        for key in list(self._open):
            ev = self._open[key]
            tid, typ = key
            if typ == "link_down":
                continue  # closed by _eval_link once the link has settled
            last = self._last_t.get(ev.id, ev.t0)
            target = self.state.target_by_id(tid) if tid >= 0 else None
            interval = self._interval(target) if target is not None else 0.25
            if edge - ev.t0 >= EVENT_MAX_OPEN_S:
                self._close_event(key, last + interval)
                continue
            if typ in ("loss_burst", "late_burst"):
                if edge - last >= 4.0:
                    self._close_event(key, last + interval)
            elif typ == "latency_spike":
                if last > edge - 2.0 or target is None:
                    continue
                b = self.baselines.get(tid)
                end_thr = ((b.p50 or 0.0) + 2.0 * (b.mad or 0.0)) if b is not None else float("inf")
                recent = [s for s in self.state.raw_window(tid, edge - 2.0, edge) if s.received and not (s.flags & F_STALL)]
                if all(s.value / 1000.0 < end_thr for s in recent):
                    self._close_event(key, last + interval)
            elif typ == "jitter":
                if edge - last >= 10.0:
                    self._close_event(key, last)
            elif typ == "host_stall":
                continue  # closed by _eval_host_stall against wall time

    # ------------------------------------------------------------ episodes
    def _refresh_last_symptom(self, tr: _Track) -> None:
        """End of the latest symptom: a closed event's ``t1``, an open one's last symptomatic sample."""
        best = tr.ep.t0
        for e in tr.members:
            if e.type not in SYMPTOM_TYPES:
                continue
            if e.t1 is not None:
                best = max(best, e.t1)
            else:
                best = max(best, self._last_t.get(e.id, e.t0))
        tr.last_symptom = best

    def _eligible(self, ev: Event) -> bool:
        if ev.type not in SYMPTOM_TYPES or ev.target is None or ev.severity < 2:
            return False
        if "corroborated" in ev.peak and not ev.peak.get("corroborated"):
            return False
        return True

    def _episodes(self, edge: float, loadtest: bool) -> None:
        tr = self._track
        cands = sorted([e for e in self._new_events if self._eligible(e) and not self._in_link_down(e.t0)],
                       key=lambda e: e.t0)
        for ev in cands:
            if tr is not None and not tr.closed:
                if ev in tr.members:
                    continue
                self._refresh_last_symptom(tr)
                if ev.t0 <= tr.last_symptom + EPISODE_JOIN_S:
                    tr.add(ev)
                    if tr.registered:
                        self._store_row("events", ev.to_dict())
                    continue
                self._close_track(tr, edge)
                tr = None
            if loadtest:
                ev.peak["loadtest"] = True  # classify() turns this into the `loadtest` class (rule 3)
            tr = _Track(ev.t0)
            tr.add(ev)
            self._track = tr
        if tr is None or tr.closed:
            return
        self._refresh_last_symptom(tr)
        if not tr.registered and tr.last_symptom - tr.ep.t0 >= MIN_EPISODE_S:
            self._register(tr, edge)
        if tr.registered and edge - tr.ep.t0 >= EPISODE_MAX_S:
            still_open = [e for e in tr.members if e.t1 is None]
            self._close_track(tr, edge, t1=tr.ep.t0 + EPISODE_MAX_S)
            nxt = _Track(tr.ep.t0 + EPISODE_MAX_S)
            for e in still_open:
                nxt.add(e)
            nxt.last_symptom = tr.last_symptom
            self._track = nxt
            return
        quiet = edge - tr.last_symptom
        threshold = UNSTABLE_QUIET_S if tr.unstable else EPISODE_QUIET_S
        if quiet >= threshold:
            self._close_track(tr, edge)
            return
        if tr.registered and (tr.dirty or edge - tr.last_row >= EPISODE_UPDATE_S):
            self._classify(tr, edge)
            self._write_episode(tr, "episode_update")
            tr.last_row = edge
            tr.dirty = False

    def _register(self, tr: _Track, edge: float) -> None:
        st = self.state
        ep = tr.ep
        ep.id = st.next_episode_id()
        tr.registered = True
        for e in tr.members:
            e.episode = ep.id
            if e.id not in ep.events:
                ep.events.append(e.id)
            if e.target is not None and e.target not in ep.targets:
                ep.targets.append(e.target)
        ep.targets.sort()
        ep.activity = str(st.activity.get("current") or "idle")
        ep.xbox_state = str(st.xbox.get("state") or "unknown")
        with st.lock:
            recent = sum(1 for e in st.episodes if e.t0 >= edge - UNSTABLE_WINDOW_S)
        if recent + 1 > UNSTABLE_COUNT:
            tr.unstable = True
        self._attach_nearby(tr)
        self._classify(tr, edge)
        for e in tr.members:
            self._store_row("events", e.to_dict())
        st.add_episode(ep)
        self._store_row("episodes", ep.to_dict())
        tr.last_row = edge
        tr.dirty = False
        self._link_marks(tr)
        self._on_open(tr)

    def _attach_nearby(self, tr: _Track) -> None:
        ep = tr.ep
        end = ep.t1 if ep.t1 is not None else tr.last_symptom
        for e in self._recent[-200:]:
            if e in tr.members or e.type in SYMPTOM_TYPES or e.episode is not None:
                continue
            e_t1 = e.t1 if e.t1 is not None else self._last_t.get(e.id, e.t0)
            if e.type.startswith("docsis_"):
                if e.t0 <= end + DOCSIS_ATTACH_S and e_t1 >= ep.t0 - DOCSIS_ATTACH_S:
                    doc = ep.docsis if isinstance(ep.docsis, dict) else {}
                    entry = {"type": e.type, "t": e.t0, "note": e.note, "peak": dict(e.peak)}
                    lst = doc.setdefault("events", [])
                    if entry not in lst:
                        lst.append(entry)
                    ep.docsis = doc
                continue
            if e.t0 <= end + EVENT_ATTACH_S and e_t1 >= ep.t0 - EVENT_ATTACH_S:
                tr.add(e)
                if tr.registered:
                    self._store_row("events", e.to_dict())

    def _classify(self, tr: _Track, edge: float) -> None:
        ep = tr.ep
        classifymod.classify(ep, self.ctx, now=edge)
        if tr.unstable:
            ep.subclass = "unstable_period"
            ep.evidence.append("unstable period: more than %d episodes in 10 min collapsed into one" % UNSTABLE_COUNT)
        ep.onset_order = ep.onset_order or self._onset(tr)

    def _reclassify(self, tr: _Track) -> None:
        if not tr.registered:
            return
        self._classify(tr, tr.ep.t1 if tr.ep.t1 is not None else self.state.now())
        self._write_episode(tr, "episode_update")
        self.verdict_due = True

    def _onset(self, tr: _Track) -> List[str]:
        first: Dict[str, float] = {}
        for e in tr.members:
            if e.type not in SYMPTOM_TYPES or e.target is None:
                continue
            t = self.state.target_by_id(e.target)
            if t is None:
                continue
            if t.key not in first or e.t0 < first[t.key]:
                first[t.key] = e.t0
        return [k for k, _ in sorted(first.items(), key=lambda kv: kv[1])]

    def _write_episode(self, tr: _Track, name: str) -> None:
        row = tr.ep.to_dict()
        self._store_row("episodes", row)
        self._publish(name, tr.ep.to_dict(brief=True))

    def _link_marks(self, tr: _Track) -> None:
        ep = tr.ep
        end = ep.t1 if ep.t1 is not None else tr.last_symptom
        with self.state.lock:
            marks = list(self.state.marks)
        for m in marks:
            if m.episode is not None:
                continue
            if ep.t0 - MARK_LINK_S <= m.t_est <= end + MARK_LINK_S:
                m.episode = ep.id
                if m.id not in ep.marks:
                    ep.marks.append(m.id)
                self._store_row("marks", m.to_dict())
                tr.dirty = True

    def _on_open(self, tr: _Track) -> None:
        ctx = self.ctx
        if tr.ep.cls == "loadtest" or any(e.peak.get("loadtest") for e in tr.members):
            return  # self-inflicted: no sweep, no extra DOCSIS poll, no notification candidate
        tracer = ctx.component("tracer") if hasattr(ctx, "component") else None
        if tracer is not None and hasattr(tracer, "sweep"):
            try:
                tracer.sweep("episode")
            except Exception:  # noqa: BLE001
                log.exception("tracer sweep failed")
        docsis = ctx.component("docsis") if hasattr(ctx, "component") else None
        if docsis is not None and hasattr(docsis, "refresh"):
            try:
                docsis.refresh()
            except Exception:  # noqa: BLE001
                log.exception("docsis refresh failed")
        igd = self.state.latest("igd") or {}
        if igd and tr.ep.wan is None:
            tr.ep.wan = {"tx_mbps_max": igd.get("tx_mbps"), "rx_mbps_max": igd.get("rx_mbps"), "trusted": bool(igd.get("trusted"))}

    def _close_track(self, tr: _Track, edge: float, t1: Optional[float] = None) -> None:
        if tr.closed:
            return
        tr.closed = True
        if self._track is tr:
            self._track = None
        self._refresh_last_symptom(tr)
        end = tr.last_symptom if t1 is None else t1
        end = max(end, tr.ep.t0)
        if not tr.registered:
            if end - tr.ep.t0 < MIN_EPISODE_S:
                self.blips += 1
                with self.state.lock:
                    self.state.blips += 1
                for e in tr.members:
                    e.peak["blip"] = True
                log.debug("blip of %.2f s on %s", end - tr.ep.t0, [e.target for e in tr.members])
                return
            self._register(tr, edge)
        ep = tr.ep
        ep.t1 = round(end, 3)
        ep.dur_s = round(ep.t1 - ep.t0, 2)
        self._attach_nearby(tr)
        self._classify(tr, edge)
        self._link_marks(tr)
        self._write_episode(tr, "episode_close")
        self._closed_tracks.append(tr)
        if len(self._closed_tracks) > 200:
            del self._closed_tracks[:100]
        self.verdict_due = True


__all__ = ["Detector", "Baseline", "baseline_for", "baseline_from_samples", "spike_threshold", "loss_severity",
           "spike_severity", "SEVERITY_BY_NOTE", "RATE_LIMIT_BY_NOTE", "SYMPTOM_TYPES", "MIN_EPISODE_S",
           "EPISODE_QUIET_S", "EPISODE_JOIN_S", "EPISODE_MAX_S", "UNSTABLE_COUNT", "WARMUP_LOSS_S"]
