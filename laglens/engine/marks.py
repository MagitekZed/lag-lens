"""Marks: "Lag happened" presses (SPEC_FULL §6.6, §7.4, §8.4; INTERFACES §10.2).

:class:`MarkService` is used by the HTTP server:

* ``create(offset_s, activity, note, source, t_pressed, replay)`` computes
  ``t_est = (t_pressed or now) − offset_s``, writes the ``marks.jsonl`` row,
  links the nearest episode within ±60 s (the episode's ``marks`` list gets
  the id and an updated episode row is appended), renders the instant
  assessment over ``[t_est − 10 s, t_est + 2 s]`` in the exact sentence
  styles of §8.4, publishes ``mark`` (through ``state.add_mark``), raises a
  ``mark`` note so the detector puts a severity-1 ``mark`` event on the
  timelines, and schedules a snapshot thread that writes
  ``marks/<id>.json`` 30 s later (raw samples ``t_est − 120 … + 30 s`` as
  ``[ts_ms, id, kind, flags, value]`` rows plus the 1 s rollups and the
  iface/wan/wifi/dns/docsis rows of that window) via ``store.write_atomic``
  and sets ``mark.snapshot``.
* ``snapshot(mark_id)`` reads it back (``None`` until written).

The detector may also link marks to episodes that register later (§7.4).
"""
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from laglens.engine.rollup import percentile
from laglens.state import (
    F_ERROR,
    F_LATE,
    F_LOADTEST,
    F_LOST,
    F_STALL,
    F_XBOX_ASLEEP,
    Mark,
    Sample,
    State,
    Target,
)

log = logging.getLogger("laglens.marks")

ASSESS_BEFORE_S = 10.0
ASSESS_AFTER_S = 2.0
LINK_WINDOW_S = 60.0
SNAPSHOT_DELAY_S = 30.0
SNAPSHOT_BEFORE_S = 120.0
SNAPSHOT_AFTER_S = 30.0
NULL_ASSESSMENT = "Nothing abnormal in the last 10 s on any target: likely game-server side or the Xbox itself."
SNAPSHOT_ROW_KINDS = ("iface", "wan", "wifi", "dns", "docsis")
GROUP_ORDER = ("gateway", "xbox", "isp_hop", "mid_hop", "internet")
GROUP_LABELS = {"gateway": "XB7", "xbox": "Xbox", "isp_hop": "Comcast hop", "mid_hop": "mid-path hop", "internet": "internet"}


def _group_of(t: Target) -> Optional[str]:
    if t.kind != "icmp":
        return None
    if t.role in ("gateway",):
        return "gateway" if t.family == 4 else None
    if t.role in ("xbox", "isp_hop", "mid_hop"):
        return t.role
    if t.role == "anycast":
        return "internet"
    return None


def _join(names: Sequence[str]) -> str:
    names = list(names)
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:] if s else s


class GroupAssessment:
    """What one ladder group did inside the assessment window."""

    __slots__ = ("group", "sent", "lost", "first_lost", "last_lost", "rtt_max", "base_p50", "spike", "answered")

    def __init__(self, group: str) -> None:
        self.group = group
        self.sent = 0
        self.lost = 0
        self.first_lost: Optional[float] = None
        self.last_lost: Optional[float] = None
        self.rtt_max: Optional[float] = None
        self.base_p50: Optional[float] = None
        self.spike = False
        self.answered = False

    @property
    def lost_packets(self) -> bool:
        return self.lost >= 2 or (self.sent >= 4 and self.lost / float(self.sent) >= 0.25)

    @property
    def abnormal(self) -> bool:
        return self.lost_packets or self.spike


def assess_window(state: State, t_est: float, before_s: float = ASSESS_BEFORE_S, after_s: float = ASSESS_AFTER_S) -> Tuple[str, Dict[str, GroupAssessment]]:
    """The §8.4 instant assessment sentence over ``[t_est − 10 s, t_est + 2 s]``."""
    t_from, t_to = t_est - before_s, t_est + after_s
    groups: Dict[str, GroupAssessment] = {}
    for t in state.targets_list():
        if not t.enabled:
            continue
        g = _group_of(t)
        if g is None:
            continue
        if t.role == "xbox" and state.xbox.get("state") == "asleep":
            continue
        ga = groups.setdefault(g, GroupAssessment(g))
        samples = [s for s in state.raw_window(t.id, t_from, t_to) if not (s.flags & F_LATE)]
        if t.role == "xbox":
            samples = [s for s in samples if not (s.flags & F_XBOX_ASLEEP)]
        base = sorted(s.value / 1000.0 for s in state.raw_window(t.id, t_from - 600, t_from)
                      if not (s.flags & (F_LOST | F_LATE | F_ERROR | F_STALL | F_LOADTEST | F_XBOX_ASLEEP)))
        p50 = percentile(base, 50)
        mad = percentile(sorted(abs(x - (p50 or 0.0)) for x in base), 50) if base else None
        rtts: List[float] = []
        for s in samples:
            ga.sent += 1
            if s.flags & (F_LOST | F_ERROR):
                ga.lost += 1
                ts = s.ts_ms / 1000.0
                ga.first_lost = ts if ga.first_lost is None else min(ga.first_lost, ts)
                ga.last_lost = ts if ga.last_lost is None else max(ga.last_lost, ts)
            elif not (s.flags & F_STALL):
                ga.answered = True
                rtts.append(s.value / 1000.0)
        if rtts:
            mx = max(rtts)
            ga.rtt_max = mx if ga.rtt_max is None else max(ga.rtt_max, mx)
            if p50 is not None:
                ga.base_p50 = p50 if ga.base_p50 is None else min(ga.base_p50, p50)
                floor = 10.0 if g in ("gateway", "xbox") else (25.0 if g in ("isp_hop", "mid_hop") else 30.0)
                thr = max(p50 + 5.0 * (mad or 0.0), 2.0 * p50, p50 + floor)
                if sum(1 for r in rtts if r > thr) >= 2:
                    ga.spike = True
    present = [g for g in GROUP_ORDER if g in groups and groups[g].sent > 0]
    lost_groups = [g for g in present if groups[g].lost_packets]
    spike_groups = [g for g in present if groups[g].spike and g not in lost_groups]
    fine_groups = [g for g in present if g not in lost_groups and g not in spike_groups and groups[g].answered]
    if not lost_groups and not spike_groups:
        return NULL_ASSESSMENT, groups
    parts: List[str] = []
    if lost_groups:
        first = min(groups[g].first_lost for g in lost_groups if groups[g].first_lost is not None)
        last = max(groups[g].last_lost for g in lost_groups if groups[g].last_lost is not None)
        dur = max(1, int(round(last - first + 0.25)))
        names = _join([GROUP_LABELS[g] for g in lost_groups])
        if lost_groups == present:
            names = "Everything including the XB7" if "gateway" in present else names
        verb = "stopped answering" if lost_groups == ["xbox"] else "lost packets"
        parts.append("%s %s for %d s starting %s" % (_cap(names), verb, dur, time.strftime("%H:%M:%S", time.localtime(first))))
    if spike_groups:
        g0 = spike_groups[0]
        ga = groups[g0]
        names = _join([GROUP_LABELS[g] for g in spike_groups])
        base = " (normally %d ms)" % int(round(ga.base_p50)) if ga.base_p50 is not None else ""
        parts.append("%s latency rose to %d ms%s" % (_cap(names), int(round(ga.rtt_max or 0)), base))
    sentence = "; ".join(parts)
    if fine_groups:
        sentence += "; %s answered normally" % _join([GROUP_LABELS[g] for g in fine_groups])
    return sentence + ".", groups


class MarkService:
    """``MarkService(ctx)``: create marks, assess them, link episodes, write snapshots."""

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self.state: State = ctx.state
        self.store = getattr(ctx, "store", None)
        self.snapshot_delay_s = SNAPSHOT_DELAY_S
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------- create
    def create(self, offset_s: float = 0.0, activity: Optional[str] = None, note: str = "", source: str = "dashboard",
               t_pressed: Optional[float] = None, replay: bool = False) -> Mark:
        """Record a press; returns the :class:`Mark` (already published and stored)."""
        st = self.state
        now = st.now()
        try:
            offset = max(0.0, float(offset_s or 0.0))
        except (TypeError, ValueError):
            offset = 0.0
        pressed = now
        if t_pressed is not None:
            try:
                pressed = float(t_pressed)
            except (TypeError, ValueError):
                pressed = now
        t_est = pressed - offset
        act = activity or str(st.activity.get("current") or "idle")
        mark = Mark(id=st.next_mark_id(), t_pressed=round(pressed, 3), offset_s=offset, t_est=round(t_est, 3),
                    activity=act, note=str(note or ""), source=str(source or "dashboard"))
        try:
            mark.assessment, _ = assess_window(st, t_est)
        except Exception as exc:  # noqa: BLE001
            log.exception("assessment failed for %s", mark.id)
            mark.assessment = "Assessment unavailable: %s" % exc
        try:
            self._link_episode(mark, now)
        except Exception:  # noqa: BLE001
            log.exception("episode link failed for %s", mark.id)
        st.add_mark(mark)
        self._row(mark)
        try:
            st.raise_note("mark", t=t_est, severity=1, note=mark.note or ("mark %s" % mark.id), mark=mark.id,
                          activity=act, source=mark.source, replay=bool(replay))
        except Exception:  # noqa: BLE001
            log.exception("mark note failed")
        self._schedule_snapshot(mark)
        return mark

    def _row(self, mark: Mark) -> None:
        if self.store is None:
            return
        try:
            self.store.append_json("marks", mark.to_dict())
        except Exception:  # noqa: BLE001
            log.exception("cannot append marks row")

    def _link_episode(self, mark: Mark, now: float) -> None:
        st = self.state
        with st.lock:
            episodes = [e for e in st.episodes if e.id]
        best = None
        best_d = None
        for ep in episodes:
            t1 = ep.t1 if ep.t1 is not None else now
            if mark.t_est < ep.t0:
                d = ep.t0 - mark.t_est
            elif mark.t_est > t1:
                d = mark.t_est - t1
            else:
                d = 0.0
            if d <= LINK_WINDOW_S and (best_d is None or d < best_d):
                best, best_d = ep, d
        if best is None:
            return
        mark.episode = best.id
        if mark.id not in best.marks:
            best.marks.append(mark.id)
        if self.store is not None:
            try:
                self.store.append_json("episodes", best.to_dict())
            except Exception:  # noqa: BLE001
                log.exception("cannot append episode row")
        st.publish("episode_update", best.to_dict(brief=True))

    # ----------------------------------------------------------- snapshot
    def _schedule_snapshot(self, mark: Mark) -> None:
        th = threading.Thread(target=self._snapshot_body, args=(mark,), name="mark-%s" % mark.id, daemon=True)
        with self._lock:
            self._threads = [t for t in self._threads if t.is_alive()]
            self._threads.append(th)
        th.start()

    def _snapshot_body(self, mark: Mark) -> None:
        try:
            self.state.stop_event.wait(self.snapshot_delay_s)
            self.write_snapshot(mark)
        except Exception:  # noqa: BLE001
            log.exception("snapshot failed for %s", mark.id)

    def snapshot_document(self, mark: Mark) -> dict:
        """Build the ``marks/<id>.json`` object from the rings."""
        st = self.state
        t_from, t_to = mark.t_est - SNAPSHOT_BEFORE_S, mark.t_est + SNAPSHOT_AFTER_S
        rows = [s.to_row() for s in st.raw_all(t_from, t_to)]
        rollups: List[dict] = []
        for tid, rl in st.rollups(1, t_from, t_to).items():
            rollups.extend(r.to_row() for r in rl)
        rollups.sort(key=lambda r: (r["t"], r["id"]))
        doc: Dict[str, Any] = {
            "id": mark.id,
            "mark": mark.to_dict(),
            "from_ms": int(t_from * 1000),
            "to_ms": int(t_to * 1000),
            "columns": ["ts_ms", "id", "kind", "flags", "value"],
            "rows": rows,
            "rollups": rollups,
            "written_at": st.now(),
        }
        for kind in SNAPSHOT_ROW_KINDS:
            got = st.rows5(kind, t_from, t_to)
            if not got:
                latest = st.latest(kind)
                got = [{"t": int(st.now()), kind: latest, "latest": True}] if latest else []
            doc[kind] = got
        return doc

    def write_snapshot(self, mark: Mark) -> Optional[str]:
        """Write ``marks/<id>.json`` atomically and set ``mark.snapshot``."""
        if self.store is None:
            return None
        name = "marks/%s.json" % mark.id
        doc = self.snapshot_document(mark)
        self.store.write_atomic(name, json.dumps(doc, separators=(",", ":"), ensure_ascii=False) + "\n")
        mark.snapshot = name
        self._row(mark)
        self.state.publish("mark", mark.to_dict())
        return name

    def snapshot(self, mark_id: str) -> Optional[dict]:
        """The snapshot JSON of a mark, or ``None`` when not written yet."""
        if self.store is None:
            return None
        path = self.store.path("marks/%s.json" % mark_id)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def wait(self, timeout: float = 5.0) -> None:
        """Join pending snapshot threads (tests / shutdown)."""
        with self._lock:
            threads = list(self._threads)
        for th in threads:
            th.join(timeout)

    def stop(self, timeout: float = 2.0) -> None:
        self.wait(timeout)


__all__ = ["MarkService", "assess_window", "GroupAssessment", "NULL_ASSESSMENT", "LINK_WINDOW_S", "SNAPSHOT_DELAY_S",
           "SNAPSHOT_BEFORE_S", "SNAPSHOT_AFTER_S"]
