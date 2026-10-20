"""The 1 Hz wall-aligned ticker (INTERFACES §2, BUILD_PLAN §3.3).

Once per second at ``t = int(now)`` :meth:`Ticker.tick`:

1. detects a *monitor gap* (the tick is more than 2 s late: sleep, a
   stall, a resume) and raises a ``monitor_gap`` note;
2. ``close_second(state, t - second_close_lag_s(cfg))`` — closes every
   accumulated second whose probes all have their lost/received verdict;
3. for every pending 5 s window ``w ≤ t - WINDOW5_LAG_S`` (normally exactly
   one when ``t % 5 == 0``, more after a gap): ``rows =
   close_window5(state, w)`` → ``store.append_json('rollups', row)`` for each
   row → ``state.publish('rollup5', rows)``;
4. ``Detector.step(t)``;
5. every 30 s (and when an episode closed) ``compute_verdict(ctx)`` (which
   also writes ``comcast_evidence.txt``) and ``publish('verdict', ...)`` on
   change;
6. ``rollup.w5m_for(state)``, the health score into ``state.health``;
7. status / pill / headline (SPEC §8.2) through ``state.set_status``;
8. ``state.publish('tick', state.tick_payload())``.

``close_final()`` closes everything still pending at shutdown (seconds,
windows, open events/episodes, a last verdict) before ``store.flush()``.
``replay(samples)`` drives the same pipeline from stored samples for the
offline ``--report DIR`` rebuild.

The loop runs under :func:`laglens.supervisor.start_thread` and stops on
``state.stop_event``; every stage is guarded so one failure never skips the
others and never crashes the thread.
"""
import logging
import math
import time
from typing import Any, Callable, Iterable, List, Optional

from laglens.engine import health as healthmod
from laglens.engine import rollup as rollupmod
from laglens.engine import verdict as verdictmod
from laglens.engine.detector import Detector
from laglens.engine.rollup import WINDOW5_LAG_S, WINDOW5_S, close_second, close_window5, second_close_lag_s, w5m_for
from laglens.state import (
    STATUS_DEGRADED,
    STATUS_GAP,
    STATUS_LOADTEST,
    STATUS_OK,
    STATUS_RECENT,
    STATUS_TROUBLE,
    STATUS_WARMUP,
    Sample,
    State,
)
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.ticker")

VERDICT_INTERVAL_S = 30
HEALTH_INTERVAL_S = 5
RECENT_S = 600.0
GAP_LATE_S = 2.0
GAP_SHOW_S = 30.0
#: Collector ``disabled`` reasons that are configuration choices, not degradation.
CHOICE_REASONS = ("not configured", "password not set", "disabled by", "disabled in config", "enabled is false",
                  "wired interface", "no ipv6", "not supported", "start with --")
TROUBLE_PHRASES = {
    "docsis_access": "packets lost past your gateway (cable line)",
    "comcast_network": "packets lost in Comcast's network",
    "xb7_gateway": "your XB7 gateway stopped answering",
    "xbox_lan": "the Xbox stopped answering",
    "plex_server": "the Plex server stopped answering",
    "plex_player": "the Plex player stopped answering",
    "home_lan": "the Plex server and player dropped together",
    "probe_link": "this computer's link dropped",
    "probe_wifi": "this computer's Wi-Fi dropped",
    "probe_host": "this computer stalled",
    "upload_saturation": "upload saturation",
    "upstream_delay": "upload delay past your modem",
    "ipv6_only": "IPv6 trouble",
    "ipv4_only": "IPv4 trouble",
    "internet": "packets lost on the internet side",
    "single_destination": "one destination unreachable",
    "hop_rate_limit": "a hop rate-limiting (informational)",
    "xb7_cpu": "XB7 slow to answer (informational)",
    "dns": "DNS failing",
    "cdn": "CDN slow",
    "loadtest": "load test",
    "unknown": "trouble on the path",
}
RECENT_PHRASES = {
    "docsis_access": "Comcast hop", "comcast_network": "Comcast network", "xb7_gateway": "XB7 gateway",
    "xbox_lan": "Xbox LAN", "plex_server": "Plex server", "plex_player": "Plex player", "home_lan": "home network",
    "probe_link": "this computer's link", "probe_wifi": "this computer's Wi-Fi",
    "probe_host": "this computer", "upload_saturation": "upload saturation", "upstream_delay": "upload delay", "ipv6_only": "IPv6",
    "ipv4_only": "IPv4", "internet": "internet", "single_destination": "one destination", "dns": "DNS", "cdn": "CDN",
    "hop_rate_limit": "hop rate limit", "xb7_cpu": "XB7 CPU", "loadtest": "load test", "unknown": "unclassified",
}


def _floor5(t: float) -> int:
    return int(math.floor(t / 5.0)) * 5


class Ticker:
    """``Ticker(ctx)``: ``.start()``, ``.stop(timeout)``, ``.tick(t)``, ``.close_final()``."""

    def __init__(self, ctx: Any, clock: Optional[Callable[[], float]] = None,
                 wait: Optional[Callable[[float], bool]] = None) -> None:
        self.ctx = ctx
        self.state: State = ctx.state
        self.store = getattr(ctx, "store", None)
        self.cfg: dict = getattr(ctx, "cfg", None) or {}
        self.clock: Callable[[], float] = clock or self.state.now
        self.wait: Callable[[float], bool] = wait or self.state.stop_event.wait
        self.lag = second_close_lag_s(self.cfg)
        self.warmup_s = float(self.cfg.get("warmup_s", 60) or 0)
        self.detector = Detector(ctx)
        self.thread = None
        self._last_t: Optional[int] = None
        self._last_wall: Optional[float] = None
        self._next_window: int = _floor5(self.state.t0)
        self._next_verdict: Optional[int] = None
        self._next_health: Optional[int] = None
        self._gap_until: float = 0.0
        self._last_verdict_sig: Optional[str] = None
        self._final_done = False
        self.ticks = 0
        self.errors = 0

    # ------------------------------------------------------------ thread
    def start(self) -> None:
        self.thread = start_thread("ticker", self._loop, self.state, engine=True)

    def stop(self, timeout: float = 2.0) -> None:
        th = self.thread
        if th is not None:
            th.join(timeout)

    def _loop(self) -> None:
        st = self.state
        while not st.stop_event.is_set():
            now = self.clock()
            t = int(now)
            if self._last_t is None or t > self._last_t:
                self.tick(t, now)
            now = self.clock()
            delay = (int(now) + 1) - now + 0.01
            if self.wait(max(0.01, delay)):
                break

    # -------------------------------------------------------------- tick
    def tick(self, t: int, now: Optional[float] = None) -> None:
        """Run the per-second pipeline for wall second ``t``."""
        st = self.state
        now = self.clock() if now is None else now
        t = int(t)
        self.ticks += 1
        stages = (
            ("gap", lambda: self._monitor_gap(t, now)),
            ("second", lambda: close_second(st, t - self.lag)),
            ("window5", lambda: self._windows(t)),
            ("detector", lambda: self.detector.step(t)),
            ("verdict", lambda: self._verdict(t, now)),
            ("w5m", lambda: w5m_for(st, now)),
            ("health", lambda: self._health(t, now)),
            ("status", lambda: self._status(now)),
            ("publish", lambda: st.publish("tick", st.tick_payload(now))),
        )
        for name, fn in stages:
            try:
                fn()
            except Exception:  # noqa: BLE001 - never let one stage stop the tick
                self.errors += 1
                log.exception("ticker stage %s failed at t=%d", name, t)
        self._last_t = t
        self._last_wall = now

    def _monitor_gap(self, t: int, now: float) -> None:
        if self._last_t is None:
            return
        expected = self._last_t + 1
        late = now - expected
        if late > GAP_LATE_S:
            gap = now - (self._last_wall if self._last_wall is not None else expected)
            log.warning("monitor gap: tick %.1f s late", late)
            self.state.raise_note("monitor_gap", t=self._last_wall if self._last_wall is not None else float(expected),
                                  severity=1, note="monitor paused %.0f s" % gap, gap_s=round(gap, 1), reason="tick late")
            self._gap_until = now + GAP_SHOW_S

    def _windows(self, t: int) -> List[List[dict]]:
        """Close every pending 5 s window up to ``t - WINDOW5_LAG_S``; returns the row batches."""
        out: List[List[dict]] = []
        while self._next_window <= t - WINDOW5_LAG_S:
            w = self._next_window
            self._next_window += WINDOW5_S
            rows = close_window5(self.state, w)
            self._emit_rows(rows)
            out.append(rows)
        return out

    def _emit_rows(self, rows: List[dict]) -> None:
        if self.store is not None:
            for row in rows:
                try:
                    self.store.append_json("rollups", row)
                except Exception:  # noqa: BLE001
                    log.exception("cannot append rollups row")
        self.state.publish("rollup5", rows)

    def _verdict(self, t: int, now: float, force: bool = False) -> Optional[dict]:
        due = force or self.detector.verdict_due or self._next_verdict is None or t >= self._next_verdict
        if not due:
            return None
        self.detector.verdict_due = False
        self._next_verdict = t + VERDICT_INTERVAL_S
        v = verdictmod.compute_verdict(self.ctx, now=now)
        sig = "%s|%s" % (v.get("text"), v.get("top"))
        if sig != self._last_verdict_sig:
            self._last_verdict_sig = sig
            self.state.publish("verdict", v)
        return v

    def _health(self, t: int, now: float) -> None:
        if self._next_health is not None and t < self._next_health:
            return
        self._next_health = t + HEALTH_INTERVAL_S
        healthmod.refresh(self.state, now, session=(t % VERDICT_INTERVAL_S == 0 or self.state.health.get("session") is None))

    # ------------------------------------------------------------ status
    def degraded_collectors(self) -> List[str]:
        """``name (reason)`` for collectors that are degraded or disabled for a non-configuration reason."""
        out: List[str] = []
        for name, entry in sorted(self.state.collectors().items()):
            status = entry.get("status")
            reason = str(entry.get("reason") or "")
            if status == "degraded":
                out.append("%s (%s)" % (name, reason or "degraded"))
            elif status == "disabled":
                low = reason.lower()
                if any(c in low for c in CHOICE_REASONS):
                    continue
                out.append("%s (%s)" % (name, reason or "disabled"))
        return out

    def _status(self, now: float) -> None:
        st = self.state
        elapsed = now - st.t0
        open_ep = self.detector.open_episode()
        if open_ep is None:
            for e in st.open_episodes():
                if e.id:
                    open_ep = e
                    break
        recent = None
        with st.lock:
            for e in reversed(st.episodes):
                if e.t1 is not None and e.id and now - e.t1 <= RECENT_S and (e.dur_s or 0) >= 1.5:
                    recent = e
                    break
        degraded = self.degraded_collectors()
        if st.loadtest.get("running"):
            status, pill = STATUS_LOADTEST, "Load test running"
        elif now < self._gap_until:
            status, pill = STATUS_GAP, "Monitor paused/resumed"
        elif open_ep is not None:
            status = STATUS_TROUBLE
            pill = "Trouble now: %s" % st.gw_text(TROUBLE_PHRASES.get(open_ep.cls, TROUBLE_PHRASES["unknown"]))
        elif recent is not None:
            ago = max(0, int((now - (recent.t1 or now)) // 60))
            status = STATUS_RECENT
            where = st.gw_text(RECENT_PHRASES.get(recent.cls, RECENT_PHRASES["unknown"]))
            pill = "Trouble %s ago: %s" % ("%d min" % ago if ago >= 1 else "moments", where)
        elif elapsed < self.warmup_s:
            status, pill = STATUS_WARMUP, "Learning your normal… %d s" % int(math.ceil(self.warmup_s - elapsed))
        elif degraded:
            status, pill = STATUS_DEGRADED, "All clear — monitoring %s" % verdictmod.fmt_duration(elapsed)
        else:
            status, pill = STATUS_OK, "All clear — monitoring %s" % verdictmod.fmt_duration(elapsed)
        if degraded:
            pill += "\nDegraded: " + ", ".join(degraded)
        head = verdictmod.headline(self.ctx, now=now)
        st.set_status(status, pill, head)

    # ------------------------------------------------------------- final
    def close_final(self) -> None:
        """Close pending seconds/windows, open events/episodes and write a last verdict."""
        if self._final_done:
            return
        self._final_done = True
        st = self.state
        now = self.clock()
        t = int(now)
        for name, fn in (
            ("second", lambda: close_second(st, t + 1)),
            ("windows", lambda: self._final_windows(t)),
            ("detector", lambda: self.detector.finalize(now)),
            ("verdict", lambda: self._verdict(t, now, force=True)),
            ("health", lambda: healthmod.refresh(st, now, session=True)),
        ):
            try:
                fn()
            except Exception:  # noqa: BLE001
                self.errors += 1
                log.exception("close_final stage %s failed", name)

    def _final_windows(self, t: int) -> None:
        while self._next_window <= t:
            w = self._next_window
            self._next_window += WINDOW5_S
            self._emit_rows(close_window5(self.state, w))

    # ------------------------------------------------------------ replay
    def replay(self, samples: Iterable[Any], final: bool = True) -> int:
        """Offline reconstruction (``--report DIR``): feed stored samples through the whole pipeline.

        ``samples`` are :class:`laglens.state.Sample` objects (or
        ``store.read_samples`` tuples ``(ts_ms, target_id, kind, flags, seq, value)``)
        in time order. The ticker's clock follows the sample timestamps, so
        every second is ticked exactly as it would have been live (rollups,
        events, episodes, verdict). The context's ``store`` may be ``None``
        (nothing is written) or a store opened for the rebuild. Returns the
        number of ticks.
        """
        st = self.state
        clock = [st.t0]
        self.clock = lambda: clock[0]
        n = 0
        for s in samples:
            if not isinstance(s, Sample):
                s = Sample(ts_ms=int(s[0]), target_id=int(s[1]), kind=int(s[2]), flags=int(s[3]), seq=int(s[4]), value=int(s[5]))
            ts = s.ts_ms / 1000.0
            while int(clock[0]) + 1 <= int(ts):  # tick every wall second up to the sample's second
                clock[0] = float(int(clock[0]) + 1)
                self.tick(int(clock[0]), clock[0])
                n += 1
            st.add_sample(s)
            if self.store is not None:
                try:
                    self.store.append_sample(s)
                except Exception:  # noqa: BLE001
                    log.debug("replay: append_sample failed", exc_info=True)
        if final:
            clock[0] = clock[0] + 1.0
            self.close_final()
        return n


__all__ = ["Ticker", "VERDICT_INTERVAL_S", "HEALTH_INTERVAL_S", "RECENT_S", "GAP_LATE_S", "GAP_SHOW_S",
           "TROUBLE_PHRASES", "RECENT_PHRASES", "CHOICE_REASONS"]
