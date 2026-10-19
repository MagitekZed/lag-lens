"""Detector tests (SPEC §7.1–7.4): symptoms, notes → events, hop corroboration, episode lifecycle.

The harness lives in ``helpers_detection``; this module re-exports it for the
older ``from test_detector_base import Session, T0`` imports.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers_detection import *  # noqa: E402,F401,F403  (re-export for the other test modules)
from helpers_detection import (  # noqa: E402
    BEYOND_GW,
    ICMP_KEYS,
    INTERNET,
    T0,
    FakeClock,
    Session,
    fault,
    feed,
    make_cfg,
    make_ticker,
    run_detector,
    run_episode,
)
from laglens.engine import detector as detmod  # noqa: E402
from laglens.engine.detector import Detector  # noqa: E402
from laglens.state import KIND_CDN_TTFB, with_extra  # noqa: E402


class HarnessTests(unittest.TestCase):
    def test_session_builds_ladder_and_streams(self):
        s = Session()
        try:
            self.assertEqual(s.ids["gw4"], 0)
            self.assertEqual(s.state.slot_origin_ms, int(T0 * 1000))
            n = s.stream(T0, T0 + 2, keys=["gw4", "inet4_cf"], lost=lambda k, t: k == "inet4_cf" and t >= T0 + 1)
            self.assertEqual(n, 16)
            raw = s.state.raw_window(s.ids["inet4_cf"], T0, T0 + 2)
            self.assertEqual(sum(1 for x in raw if x.lost), 4)
            self.assertEqual(s.state.clock(), T0)
            s.clock.advance(1.5)
            self.assertEqual(s.state.now(), T0 + 1.5)
        finally:
            s.close()

    def test_feed_ticks_once_per_second_and_flags_loadtest(self):
        s = Session()
        self.addCleanup(s.close)
        seen = []
        n = feed(s, seen.append, T0, T0 + 5, keys=["gw4"], loadtest=(T0 + 2, T0 + 4))
        self.assertEqual((n, seen), (5, [int(T0) + i for i in range(1, 6)]))
        flagged = [x for x in s.state.raw_window(s.ids["gw4"], T0, T0 + 5) if x.flags & F_LOADTEST]
        self.assertEqual(len(flagged), 8)
        self.assertEqual(s.state.loadtest["running"], False)
        self.assertEqual(s.state.loadtest["last"]["t0"], T0 + 2)


class DetectorBase(unittest.TestCase):
    warmup = 30

    def setUp(self):
        self.s = Session(cfg=make_cfg(warmup_s=self.warmup))
        self.addCleanup(self.s.close)
        self.det = Detector(self.s.ctx)

    def run_fault(self, **kw):
        kw.setdefault("baseline_s", 40)
        return run_episode(self.s, self.det.step, **kw)


class SymptomTests(DetectorBase):
    def test_loss_burst_times_peak_and_severity(self):
        s = self.s
        self.run_fault(lost_keys=["inet4_cf"], fault_s=3)
        evs = s.events("loss_burst", "inet4_cf")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertAlmostEqual(ev.t0, s.fault_t0, delta=0.3)
        self.assertAlmostEqual(ev.t1, s.fault_t1, delta=0.5)
        self.assertEqual(ev.severity, 3)  # 1–5 s
        self.assertEqual(ev.peak["lost"], 12)
        self.assertGreaterEqual(ev.peak["loss_pct"], 90)
        self.assertEqual(ev.source, "auto")
        self.assertEqual(s.events("loss_burst", "inet4_g"), [])
        rows = s.rows("events")
        self.assertEqual(rows[0]["id"], ev.id)
        self.assertIsNone(rows[0]["t1"])  # opened
        self.assertEqual(rows[-1]["t1"], ev.t1)  # closed row rewritten

    def test_loss_severity_by_length(self):
        self.assertEqual(detmod.loss_severity(0.5), 2)
        self.assertEqual(detmod.loss_severity(3), 3)
        self.assertEqual(detmod.loss_severity(20), 4)
        self.assertEqual(detmod.loss_severity(31), 5)
        self.assertEqual(detmod.spike_severity(49), 2)
        self.assertEqual(detmod.spike_severity(149), 3)
        self.assertEqual(detmod.spike_severity(399), 4)
        self.assertEqual(detmod.spike_severity(400), 5)

    def test_gateway_and_xbox_need_three_lost_in_eight(self):
        s = self.s
        f0 = T0 + 40
        drops = {0.0, 0.5}  # 2 of 8 at 4 Hz

        def lost(key, ts):
            return key in ("gw4", "xbox", "inet4_cf") and round(ts - f0 - (s.state.targets[s.ids[key]].id * 23 % 200) / 1000.0, 2) in drops

        feed(s, self.det.step, T0, T0 + 60, lost=lost)
        self.assertEqual(len(s.events("loss_burst", "inet4_cf")), 1)
        self.assertEqual(s.events("loss_burst", "gw4"), [])
        self.assertEqual(s.events("loss_burst", "xbox"), [])
        drops.add(1.0)
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        feed(s2, Detector(s2.ctx).step, T0, T0 + 60,
             lost=lambda k, ts: k == "gw4" and round(ts - f0, 2) in drops)
        self.assertEqual(len(s2.events("loss_burst", "gw4")), 1)

    def test_no_loss_events_in_the_first_fifteen_seconds(self):
        s = self.s
        feed(s, self.det.step, T0, T0 + 30, lost=lambda k, ts: k == "inet4_cf" and T0 + 5 <= ts < T0 + 8)
        self.assertEqual(s.events("loss_burst"), [])
        feed(s, self.det.step, T0 + 30, T0 + 50, lost=lambda k, ts: k == "inet4_cf" and T0 + 32 <= ts < T0 + 35)
        self.assertEqual(len(s.events("loss_burst")), 1)

    def test_latency_spike_needs_warmup_baseline_and_three_consecutive(self):
        s = self.s
        # a 3 s +100 ms step during warm-up: nothing
        feed(s, self.det.step, T0, T0 + 25, rtt=lambda k, ts, b: b + 100 if k == "inet4_cf" and T0 + 10 <= ts < T0 + 13 else b)
        self.assertEqual(s.events("latency_spike"), [])
        # after warm-up: a spike with the right numbers
        feed(s, self.det.step, T0 + 25, T0 + 60, rtt=lambda k, ts, b: b + 100 if k == "inet4_cf" and T0 + 40 <= ts < T0 + 43 else b)
        evs = s.events("latency_spike", "inet4_cf")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertAlmostEqual(ev.t0, T0 + 40, delta=0.3)
        self.assertAlmostEqual(ev.t1, T0 + 43, delta=0.5)
        self.assertEqual(ev.severity, 3)  # +100 ms excess
        self.assertAlmostEqual(ev.peak["excess_ms"], 100, delta=2)
        self.assertAlmostEqual(ev.peak["p50_ms"], 14.0, delta=0.5)
        self.assertGreaterEqual(ev.peak["threshold_ms"], 44.0)  # p50 + 30 ms floor
        # two slow probes only: no event
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        feed(s2, Detector(s2.ctx).step, T0, T0 + 60,
             rtt=lambda k, ts, b: b + 100 if k == "inet4_cf" and T0 + 40 <= ts < T0 + 40.5 else b)
        self.assertEqual(s2.events("latency_spike"), [])

    def test_spike_threshold_uses_role_floor(self):
        b = detmod.Baseline()
        b.p50, b.mad, b.n = 1.0, 0.1, 100
        self.assertEqual(detmod.spike_threshold(b, "gateway"), 11.0)  # p50 + max(10, 5·MAD)
        b.mad = 3.0
        self.assertEqual(detmod.spike_threshold(b, "gateway"), 16.0)  # 5·MAD = 15
        b.p50, b.mad = 12.0, 0.2
        self.assertEqual(detmod.spike_threshold(b, "isp_hop"), 37.0)
        b.p50 = 40.0
        self.assertEqual(detmod.spike_threshold(b, "anycast"), 80.0)  # 2·p50 wins

    def test_late_burst_and_jitter(self):
        s = self.s
        late_at = {T0 + 40.0, T0 + 40.5}
        feed(s, self.det.step, T0, T0 + 60, late=lambda k, ts: k == "inet4_g" and round(ts - (s.ids["inet4_g"] * 23 % 200) / 1000.0, 2) in late_at)
        evs = s.events("late_burst", "inet4_g")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].severity, 2)
        self.assertEqual(evs[0].peak["late"], 2)
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        cnt = {"i": 0}

        def wobble(k, ts, b):
            if k != "inet4_cf" or not (T0 + 40 <= ts < T0 + 56):
                return b
            cnt["i"] += 1
            return b + (40.0 if cnt["i"] % 2 else 0.0)

        feed(s2, Detector(s2.ctx).step, T0, T0 + 85, rtt=wobble)  # closes after 10 s below 2× baseline
        evs = s2.events("jitter", "inet4_cf")
        self.assertEqual(len(evs), 1)
        self.assertGreater(evs[0].peak["jitter_ms"], 15.0)
        self.assertIsNotNone(evs[0].t1)
        self.assertEqual(s2.events("jitter", "inet4_g"), [])

    def test_probe_error_permission_diagnosis_on_darwin(self):
        s = self.s

        def per(t):
            if T0 + 20 <= t < T0 + 23:
                s.emit("gw4", t + 0.9, error=65)

        feed(s, self.det.step, T0, T0 + 40, keys=["inet4_cf"], per_second=per)
        evs = s.events("probe_error", "gw4")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].severity, 1)
        self.assertTrue(evs[0].peak["permission"])
        self.assertIn("Local Network", evs[0].note)
        self.assertIn("Terminal", evs[0].note)
        # a generic errno on an internet target is severity 2 with the errno text
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        feed(s2, Detector(s2.ctx).step, T0, T0 + 40, keys=["gw4"],
             per_second=lambda t: s2.emit("inet4_cf", t + 0.9, error=51) if T0 + 20 <= t < T0 + 23 else None)
        evs = s2.events("probe_error", "inet4_cf")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].severity, 2)
        self.assertFalse(evs[0].peak["permission"])
        self.assertIn("errno 51", evs[0].note)

    def test_send_errors_of_a_sleeping_xbox_are_not_symptoms(self):
        s = self.s
        s.state.xbox = dict(s.state.xbox, state="asleep")  # rest mode: no ARP answer, so macOS refuses the sends

        def per(t):
            if T0 + 20 <= t < T0 + 26:
                s.emit("xbox", t + 0.9, error=65)

        feed(s, self.det.step, T0, T0 + 40, keys=["inet4_cf"], per_second=per)
        self.assertEqual(s.events("probe_error", "xbox"), [])
        s.state.xbox = dict(s.state.xbox, state="awake")  # an awake console that refuses sends is a fault again
        feed(s, self.det.step, T0 + 40, T0 + 70, keys=["inet4_cf"],
             per_second=lambda t: s.emit("xbox", t + 0.9, error=65) if T0 + 50 <= t < T0 + 53 else None)
        self.assertEqual(len(s.events("probe_error", "xbox")), 1)

    def test_engine_probe_error_note_shares_the_rate_limit(self):
        s = self.s
        gw = s.ids["gw4"]
        s.clock.set(T0 + 20)
        s.state.raise_note("probe_error", target=gw, severity=2, note="Local Network permission", reason="local_network_permission")
        self.det.step(int(T0 + 21))
        s.clock.set(T0 + 30)
        s.state.raise_note("probe_error", target=gw, severity=2, note="again")
        self.det.step(int(T0 + 31))
        self.assertEqual(len(s.events("probe_error", "gw4")), 1)

    def test_probe_notes_share_the_sample_rule_limiter(self):
        s = self.s
        dns = s.ids["dns_gw"]

        def per(t):
            rel = int(t - T0)
            if rel % 3 == 0:
                s.emit("dns_gw", t + 0.1, lost=42 <= rel < 48)
            if rel == 47:  # the DNS probe raises its own note at the 5th timeout
                s.state.raise_note("dns_fail", target=dns, severity=2, note="unreachable", t=t)

        feed(s, self.det.step, T0, T0 + 70, keys=["gw4"], per_second=per)
        self.assertEqual(len(s.events("dns_fail", "dns_gw")), 1)
        self.assertEqual(s.events("dns_fail")[0].source, "auto")

    def test_dns_tcp_and_cdn_symptoms(self):
        s = self.s
        s.add_target("cdn_cf", "cdn", "104.16.0.1", kind="cdn", rate_hz=1 / 60.0, p50_ms=300.0)

        def per(t):
            rel = int(t - T0)
            if rel % 3 == 0:
                if 42 <= rel < 48:  # rel 42 (timeout) and 45 (SERVFAIL)
                    s.emit("dns_gw", t + 0.1, lost=(rel == 42), flags=with_extra(0, 2) if rel != 42 else 0)
                elif 60 <= rel < 66:
                    s.emit("dns_gw", t + 0.1, rtt_ms=700.0)
                else:
                    s.emit("dns_gw", t + 0.1)
            if rel % 2 == 0:
                if 40 <= rel < 44:
                    s.emit("tcp_cf4", t + 0.2, lost=True)
                elif 60 <= rel < 66:
                    s.emit("tcp_cf4", t + 0.2, rtt_ms=120.0)
                else:
                    s.emit("tcp_cf4", t + 0.2)
            if rel % 10 == 0:
                s.emit("cdn_cf", t + 0.3, rtt_ms=1500.0 if 50 <= rel < 70 else 300.0, kind=KIND_CDN_TTFB)

        feed(s, self.det.step, T0, T0 + 90, keys=["gw4"], per_second=per)
        self.assertEqual(len(s.events("dns_fail", "dns_gw")), 1)
        self.assertEqual(s.events("dns_fail")[0].peak["servfail"], 1)
        self.assertEqual(s.events("dns_fail")[0].severity, 3)
        self.assertEqual(len(s.events("dns_slow", "dns_gw")), 1)
        self.assertEqual(s.events("dns_slow")[0].severity, 2)
        self.assertEqual(len(s.events("tcp_timeout", "tcp_cf4")), 1)
        self.assertEqual(len(s.events("tcp_slow", "tcp_cf4")), 1)
        self.assertAlmostEqual(s.events("tcp_slow")[0].peak["connect_ms"], 120.0, delta=0.5)
        self.assertEqual(len(s.events("cdn_slow", "cdn_cf")), 1)
        self.assertEqual(s.events("cdn_slow")[0].peak["count"], 2)


class NoteTests(DetectorBase):
    def test_notes_become_events_with_severity_and_dedupe(self):
        s = self.s
        s.clock.set(T0 + 100)
        s.state.raise_note("wifi_drop", t=T0 + 100, severity=2, note="RSSI -60 -> -80", rssi=-80)
        s.state.raise_note("wifi_drop", t=T0 + 104, severity=2, note="again")
        s.state.raise_note("link_flap", t=T0 + 101, severity=3, note="carrier down", source="host")
        s.state.raise_note("docsis_reboot", t=T0 + 102, severity=4, note="uptime dropped", uptime_s=5)
        s.state.raise_note("monitor_gap", t=T0 + 90, severity=1, note="paused", gap_s=6.0)
        self.det.step(int(T0 + 101))
        evs = s.events("wifi_drop")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].peak["count"], 2)
        self.assertEqual(evs[0].peak["rssi"], -80)
        lf = s.events("link_flap")[0]
        self.assertEqual((lf.severity, lf.source, lf.stall), (3, "host", False))
        self.assertEqual(s.events("docsis_reboot")[0].severity, 4)
        gap = s.events("monitor_gap")[0]
        self.assertEqual((gap.t0, gap.t1, gap.stall, gap.severity), (T0 + 90, T0 + 96, True, 1))
        self.assertEqual(s.state.drain_notes(), [])
        rows = s.rows("events")
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["type"], "wifi_drop")

    def test_notes_attach_to_episodes_docsis_as_correlation(self):
        s = self.s
        s.ctx.components["tracer"] = s.tracer

        def per(t):
            if int(t) == int(s.fault_t0) + 1:
                s.state.raise_note("iface_errors", t=t, severity=2, note="rx_err +3")
            if int(t) == int(s.fault_t0) + 30:
                s.state.raise_note("docsis_t3", t=t, severity=3, note="XB7 log: T3 time-out")
            if int(t) == int(s.fault_t0) + 70:
                s.state.raise_note("docsis_t4", t=t, severity=3, note="too late")

        eps = self.run_fault(lost_keys=BEYOND_GW, fault_s=3, quiet_s=80, per_second=per)
        self.assertEqual(len(eps), 1)
        ep = eps[0]
        iface = s.events("iface_errors")[0]
        self.assertIn(iface.id, ep.events)
        self.assertEqual(iface.episode, ep.id)
        self.assertIn("iface_errors", ep.host_tags)
        self.assertFalse(ep.comcast_relevant)
        self.assertEqual([d["type"] for d in ep.docsis["events"]], ["docsis_t3"])
        self.assertNotIn(s.events("docsis_t3")[0].id, ep.events)
        self.assertIn("XB7 log: T3 time-out", ep.docsis["log_lines"])
        self.assertTrue(any("T3 time-out" in line for line in ep.evidence), ep.evidence)


class HopTests(DetectorBase):
    def test_hop_symptom_is_informational_unless_a_deeper_target_agrees(self):
        s = self.s
        self.run_fault(lost_keys=["isp_hop4"], fault_s=5)
        evs = s.events("loss_burst", "isp_hop4")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].severity, 1)
        self.assertFalse(evs[0].peak["corroborated"])
        self.assertEqual(evs[0].peak["base_severity"], 3)
        self.assertEqual(s.episodes(), [])
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=["isp_hop4", "inet4_cf"], fault_s=5)
        ev = s2.events("loss_burst", "isp_hop4")[0]
        self.assertTrue(ev.peak["corroborated"])
        self.assertEqual(ev.peak["corroborated_by"], [s2.ids["inet4_cf"]])
        self.assertEqual(ev.severity, 3)
        self.assertEqual(len(eps), 1)
        self.assertIn(s2.ids["isp_hop4"], eps[0].targets)

    def test_rate_limit_suspected_hop_needs_two_deeper_targets(self):
        s = self.s
        s.state.set_target_state("isp_hop4", extra={"rate_limit_suspected": True})
        self.run_fault(lost_keys=["isp_hop4", "inet4_cf"], fault_s=5)
        self.assertFalse(s.events("loss_burst", "isp_hop4")[0].peak["corroborated"])
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        s2.state.set_target_state("isp_hop4", extra={"rate_limit_suspected": True})
        run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=["isp_hop4", "inet4_cf", "inet6_g"], fault_s=5)
        self.assertTrue(s2.events("loss_burst", "isp_hop4")[0].peak["corroborated"])


class EpisodeTests(DetectorBase):
    def test_lifecycle_register_update_close_rows_and_side_effects(self):
        s = self.s
        eps = self.run_fault(lost_keys=BEYOND_GW, fault_s=4)
        self.assertEqual(len(eps), 1)
        ep = eps[0]
        self.assertEqual(ep.id, "ep-000001")
        self.assertAlmostEqual(ep.t0, s.fault_t0, delta=0.3)
        self.assertAlmostEqual(ep.t1, s.fault_t1, delta=0.6)
        self.assertAlmostEqual(ep.dur_s, 4.0, delta=0.8)
        self.assertEqual(sorted(ep.targets), sorted(s.ids[k] for k in BEYOND_GW))
        self.assertEqual(len(ep.events), 6)
        self.assertEqual(ep.cls, "docsis_access")
        self.assertEqual(ep.activity, "idle")
        self.assertEqual(ep.onset_order[0], "isp_hop4")
        names = s.published_names()
        self.assertEqual(names.count("episode_open"), 1)
        self.assertGreaterEqual(names.count("episode_update"), 1)
        self.assertEqual(names.count("episode_close"), 1)
        self.assertLess(names.index("episode_open"), names.index("episode_close"))
        self.assertEqual(s.tracer.sweeps, ["episode"])
        self.assertEqual(s.docsis.refreshes, 1)
        rows = s.rows("episodes")
        self.assertEqual(rows[0]["id"], "ep-000001")
        self.assertIsNone(rows[0]["t1"])
        self.assertEqual(rows[-1]["t1"], ep.t1)
        self.assertEqual(rows[-1]["class"], "docsis_access")
        self.assertIn("sweep", rows[-1])
        for e in s.events("loss_burst"):
            self.assertEqual(e.episode, ep.id)
        ev_rows = [r for r in s.rows("events") if r["type"] == "loss_burst" and r["episode"] == ep.id]
        self.assertGreaterEqual(len(ev_rows), 6)
        self.assertEqual(self.det.open_episode(), None)
        self.assertEqual(self.det.stats()["blips"], 0)

    def test_short_burst_is_a_blip(self):
        s = self.s
        eps = self.run_fault(lost_keys=["inet4_cf", "inet4_g"], fault_s=1.0)
        self.assertEqual(eps, [])
        self.assertEqual(s.state.episodes, [])
        self.assertEqual(s.state.blips, 1)
        self.assertTrue(all(e.peak.get("blip") for e in s.events("loss_burst")))
        self.assertEqual(s.tracer.sweeps, [])
        self.assertNotIn("episode_open", s.published_names())

    def test_bursts_closer_than_five_seconds_join(self):
        s = self.s
        f0 = T0 + 40
        lost = lambda k, ts: k in INTERNET and (f0 <= ts < f0 + 2 or f0 + 5 <= ts < f0 + 7)  # noqa: E731
        feed(s, self.det.step, T0, f0 + 30, lost=lost)
        eps = s.closed_episodes()
        self.assertEqual(len(eps), 1)
        self.assertAlmostEqual(eps[0].t0, f0, delta=0.3)
        self.assertAlmostEqual(eps[0].t1, f0 + 7, delta=0.6)
        # a second burst more than 10 s of quiet later is a new episode
        feed(s, self.det.step, f0 + 30, f0 + 60, lost=lambda k, ts: k in INTERNET and f0 + 35 <= ts < f0 + 38)
        self.assertEqual(len(s.closed_episodes()), 2)
        self.assertEqual(s.closed_episodes()[1].id, "ep-000002")

    def test_open_episode_splits_after_ten_minutes(self):
        s = self.s
        keys = ["gw4", "inet4_cf", "inet4_g", "inet6_cf", "inet6_g"]
        f0 = T0 + 40
        feed(s, self.det.step, T0, f0 + 640, keys=keys, lost=lambda k, ts: k in INTERNET and ts >= f0)
        eps = s.episodes()
        self.assertEqual(len(eps), 2)
        first, second = eps
        self.assertIsNotNone(first.t1)
        self.assertAlmostEqual(first.t1 - first.t0, 600.0, delta=0.01)
        self.assertIsNone(second.t1)
        self.assertAlmostEqual(second.t0, first.t1, delta=0.01)
        self.assertIs(self.det.open_episode(), second)

    def test_more_than_thirty_episodes_in_ten_minutes_collapse(self):
        s = self.s
        keys = ["gw4", "inet4_cf", "inet4_g"]
        cycle = 14.0
        f0 = T0 + 40
        lost = lambda k, ts: k in ("inet4_cf", "inet4_g") and ts >= f0 and ((ts - f0) % cycle) < 2.0  # noqa: E731
        feed(s, self.det.step, T0, f0 + cycle * 31 + 5, keys=keys, lost=lost)
        eps = s.episodes()
        self.assertGreaterEqual(len(eps), 31)
        self.assertTrue(all(e.subclass != "unstable_period" for e in eps[:30]))
        last = eps[-1]
        self.assertEqual(last.subclass, "unstable_period")
        self.assertTrue(any("unstable period" in line for line in last.evidence))
        self.assertIsNone(last.t1)
        # the collapsed episode only closes after 60 s of quiet
        feed(s, self.det.step, s.clock.t, s.clock.t + 40, keys=keys)
        self.assertIsNone(s.state.episode(last.id).t1)
        feed(s, self.det.step, s.clock.t, s.clock.t + 30, keys=keys)
        self.assertIsNotNone(s.state.episode(last.id).t1)

    def test_host_stall_cover_exonerates(self):
        s = self.s

        def per(t):
            stalled = s.fault_t0 - 1 <= t <= s.fault_t1 + 1
            s.state.set_latest("host", {"late_ms_max": 300 if stalled else 2, "loop_gap_ms": 400 if stalled else 3,
                                        "stall": stalled, "t": t + 0.5})

        eps = self.run_fault(lost_keys=INTERNET, fault_s=4, per_second=per)
        self.assertEqual(len(eps), 1)
        ep = eps[0]
        self.assertEqual(ep.cls, "probe_host")
        self.assertEqual(ep.host_tags, ["host_stall"])
        self.assertFalse(ep.comcast_relevant)
        stall = s.events("host_stall")
        self.assertEqual(len(stall), 1)
        self.assertTrue(stall[0].stall)
        self.assertIsNotNone(stall[0].t1)

    def test_loss_during_a_load_test_is_a_loadtest_episode_without_sweep(self):
        s = self.s
        f0 = T0 + 40
        eps = self.run_fault(lost_keys=INTERNET, fault_s=4, loadtest=(f0 - 5, f0 + 30))
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0].cls, "loadtest")
        self.assertTrue(all(e.peak.get("loadtest") for e in s.events("loss_burst")))
        self.assertEqual(s.tracer.sweeps, [])
        self.assertEqual(s.docsis.refreshes, 0)

    def test_load_test_latency_makes_no_spike_or_jitter(self):
        s = self.s
        f0 = T0 + 40
        self.run_fault(slow_keys=BEYOND_GW, slow_ms=150, fault_s=8, loadtest=(f0 - 2, f0 + 10))
        self.assertEqual(s.events("latency_spike"), [])
        self.assertEqual(s.events("jitter"), [])
        self.assertEqual(s.episodes(), [])

    def test_marks_link_when_the_episode_registers(self):
        s = self.s
        from laglens.state import Mark
        m = Mark(id="mk-1", t_pressed=T0 + 30, offset_s=0, t_est=T0 + 30)
        s.state.add_mark(m)
        eps = self.run_fault(lost_keys=INTERNET, fault_s=4)  # t0 = T0+40, 10 s after the press
        self.assertEqual(m.episode, eps[0].id)
        self.assertEqual(eps[0].marks, ["mk-1"])
        self.assertEqual(s.rows("marks")[-1]["episode"], eps[0].id)

    def test_xb7_reset_composite(self):
        s = self.s
        f0 = T0 + 40

        def per(t):
            if int(t) == int(f0) + 2:
                s.state.raise_note("link_flap", t=t, severity=3, note="carrier down")

        feed(s, self.det.step, T0, f0 + 50, lost=lambda k, ts: k in BEYOND_GW and f0 <= ts < f0 + 18, per_second=per)
        evs = s.events("xb7_reset")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].severity, 4)
        self.assertEqual(evs[0].peak["pattern"], "internet_dark")
        self.assertIn("link_flap", evs[0].peak["corroborated_by"])
        self.assertEqual(evs[0].target, s.ids["gw4"])
        ep = s.closed_episodes()[0]
        self.assertIn(evs[0].id, ep.events)

    def test_finalize_closes_open_events_and_episode(self):
        s = self.s
        f0 = T0 + 40
        feed(s, self.det.step, T0, f0 + 5, lost=lambda k, ts: k in INTERNET and ts >= f0)
        self.assertIsNotNone(self.det.open_episode())
        self.assertTrue(any(e.t1 is None for e in s.events("loss_burst")))
        self.det.finalize(s.clock.t)
        self.assertIsNone(self.det.open_episode())
        self.assertTrue(all(e.t1 is not None for e in s.events("loss_burst")))
        ep = s.episodes()[0]
        self.assertIsNotNone(ep.t1)
        self.assertEqual(s.rows("episodes")[-1]["t1"], ep.t1)
        self.assertTrue(self.det.verdict_due)


if __name__ == "__main__":
    unittest.main()
