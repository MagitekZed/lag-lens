"""Tests for MarkService: offset → t_est, episode linking, instant assessment, snapshots."""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from laglens.engine import marks as marksmod  # noqa: E402
from laglens.engine.detector import Detector  # noqa: E402
from laglens.state import Episode, KIND_ICMP  # noqa: E402
from test_detector_base import Session, T0  # noqa: E402


class CreateTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)
        self.svc = marksmod.MarkService(self.s.ctx)
        self.svc.snapshot_delay_s = 0.0

    def test_offset_gives_t_est_and_rows(self):
        s = self.s
        s.stream(T0, T0 + 60)
        s.clock.set(T0 + 60)
        m = self.svc.create(offset_s=30, activity="bf6", note="teleport", source="phone")
        self.assertEqual(m.id, "mk-1")
        self.assertEqual(m.t_pressed, T0 + 60)
        self.assertEqual(m.offset_s, 30.0)
        self.assertEqual(m.t_est, T0 + 30)
        self.assertEqual((m.activity, m.note, m.source), ("bf6", "teleport", "phone"))
        self.assertIsNone(m.episode)
        self.assertEqual(m.assessment, marksmod.NULL_ASSESSMENT)
        self.assertIs(s.state.mark("mk-1"), m)
        self.assertIn("mark", [n for n, _ in s.published])
        rows = s.rows("marks")
        self.assertEqual(rows[0]["id"], "mk-1")
        self.assertEqual(rows[0]["t_est"], T0 + 30)
        notes = s.state.drain_notes()
        self.assertEqual(notes[0]["type"], "mark")
        self.assertEqual(notes[0]["t"], T0 + 30)
        self.assertEqual(notes[0]["peak"]["mark"], "mk-1")

    def test_client_t_pressed_and_default_activity(self):
        s = self.s
        s.state.set_activity("rocket_league")
        s.clock.set(T0 + 100)
        m = self.svc.create(offset_s=5, t_pressed=T0 + 80, replay=True)
        self.assertEqual(m.t_pressed, T0 + 80)
        self.assertEqual(m.t_est, T0 + 75)
        self.assertEqual(m.activity, "rocket_league")
        m2 = self.svc.create(offset_s="bad")
        self.assertEqual(m2.offset_s, 0.0)
        self.assertEqual(m2.t_est, T0 + 100)

    def test_mark_note_becomes_timeline_event(self):
        s = self.s
        s.clock.set(T0 + 100)
        self.svc.create(offset_s=10)
        det = Detector(s.ctx)
        det.step(int(T0 + 100))
        ev = s.events("mark")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0].severity, ev[0].t0, ev[0].peak["mark"]), (1, T0 + 90, "mk-1"))


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)
        self.svc = marksmod.MarkService(self.s.ctx)
        self.svc.snapshot_delay_s = 0.0

    def _episode(self, eid, t0, t1, cls="docsis_access"):
        ep = Episode(id=eid, t0=t0, t1=t1, dur_s=None if t1 is None else t1 - t0, cls=cls, confidence=0.8)
        self.s.state.add_episode(ep)
        return ep

    def test_links_nearest_episode_within_sixty_seconds(self):
        s = self.s
        far = self._episode("ep-000001", T0 + 100, T0 + 110)
        near = self._episode("ep-000002", T0 + 300, T0 + 309)
        s.clock.set(T0 + 400)
        m = self.svc.create(offset_s=40)  # t_est = 360, 51 s after ep-2, 250 s after ep-1
        self.assertEqual(m.episode, "ep-000002")
        self.assertEqual(near.marks, ["mk-1"])
        self.assertEqual(far.marks, [])
        rows = s.rows("episodes")
        self.assertEqual(rows[-1]["id"], "ep-000002")
        self.assertEqual(rows[-1]["marks"], ["mk-1"])
        self.assertIn("episode_update", [n for n, _ in s.published])

    def test_outside_window_is_unlinked(self):
        s = self.s
        self._episode("ep-000001", T0 + 100, T0 + 110)
        s.clock.set(T0 + 400)
        m = self.svc.create(offset_s=0)  # t_est 400, 290 s after the episode
        self.assertIsNone(m.episode)
        s.clock.set(T0 + 170)
        m2 = self.svc.create(offset_s=0)  # exactly 60 s after t1 -> links
        self.assertEqual(m2.episode, "ep-000001")

    def test_open_episode_and_mark_inside_span(self):
        s = self.s
        self._episode("ep-000001", T0 + 100, None)
        s.clock.set(T0 + 130)
        m = self.svc.create(offset_s=10)
        self.assertEqual(m.episode, "ep-000001")


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)

    def test_null_case_sentence(self):
        s = self.s
        s.stream(T0, T0 + 60)
        text, groups = marksmod.assess_window(s.state, T0 + 50)
        self.assertEqual(text, marksmod.NULL_ASSESSMENT)
        self.assertEqual(set(groups), {"gateway", "xbox", "isp_hop", "mid_hop", "internet"})

    def test_single_miss_is_not_abnormal(self):
        s = self.s
        s.stream(T0, T0 + 60, lost=lambda k, t: k == "inet4_cf" and T0 + 45 <= t < T0 + 45.25)
        text, _ = marksmod.assess_window(s.state, T0 + 50)
        self.assertEqual(text, marksmod.NULL_ASSESSMENT)

    def test_comcast_hop_and_internet_lost_xb7_answered(self):
        s = self.s
        s.stream(T0, T0 + 60, lost=lambda k, t: k in ("isp_hop4", "mid_hop4", "inet4_cf", "inet4_g", "inet6_cf", "inet6_g")
                 and T0 + 41 <= t < T0 + 50)
        text, groups = marksmod.assess_window(s.state, T0 + 50)
        expect_start = time.strftime("%H:%M:%S", time.localtime(T0 + 41))
        self.assertTrue(text.startswith("Comcast hop, mid-path hop and internet lost packets for 9 s starting %s" % expect_start), text)
        self.assertIn("; XB7 and Xbox answered normally.", text)
        self.assertTrue(groups["gateway"].answered)
        self.assertFalse(groups["gateway"].lost_packets)

    def test_xbox_only_and_latency_styles(self):
        s = self.s
        s.stream(T0, T0 + 60, lost=lambda k, t: k == "xbox" and T0 + 44 <= t < T0 + 50)
        text, _ = marksmod.assess_window(s.state, T0 + 50)
        self.assertTrue(text.startswith("Xbox stopped answering for 6 s starting"), text)
        self.assertIn("XB7, Comcast hop, mid-path hop and internet answered normally", text)
        s2 = Session()
        self.addCleanup(s2.close)
        s2.stream(T0, T0 + 60, rtt=lambda k, t, base: base + 160 if (k.startswith("inet") and T0 + 45 <= t < T0 + 50) else base)
        text2, _ = marksmod.assess_window(s2.state, T0 + 50)
        self.assertTrue(text2.startswith("Internet latency rose to 17"), text2)
        self.assertIn("(normally 1", text2)
        self.assertIn("answered normally", text2)

    def test_everything_lost_including_gateway(self):
        s = self.s
        s.stream(T0, T0 + 60, lost=lambda k, t: T0 + 45 <= t < T0 + 50)
        text, _ = marksmod.assess_window(s.state, T0 + 50)
        self.assertTrue(text.startswith("Everything including the XB7 lost packets for 5 s"), text)
        self.assertNotIn("answered normally", text)

    def test_asleep_xbox_is_ignored(self):
        s = self.s
        s.state.xbox = {"ip": "10.0.0.23", "state": "asleep", "source": None, "link_mbps": None}
        s.stream(T0, T0 + 60, lost=lambda k, t: k == "xbox")
        text, groups = marksmod.assess_window(s.state, T0 + 50)
        self.assertEqual(text, marksmod.NULL_ASSESSMENT)
        self.assertNotIn("xbox", groups)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)
        self.svc = marksmod.MarkService(self.s.ctx)
        self.svc.snapshot_delay_s = 0.0

    def test_snapshot_window_contents(self):
        s = self.s
        from laglens.engine.rollup import close_second
        s.stream(T0, T0 + 400, keys=["gw4", "inet4_cf"])
        close_second(s.state, int(T0 + 400))
        for t in range(int(T0), int(T0 + 400), 5):
            s.state.add_row5("iface", {"t": t, "iface": {"tx_mbps": 1.0, "rx_mbps": 2.0}})
            s.state.add_row5("wan", {"t": t, "wan": {"tx_mbps": 0.5, "trusted": True}})
        s.state.set_latest("docsis", {"ds_snr_min": 36.0})
        s.clock.set(T0 + 300)
        self.assertIsNone(self.svc.snapshot("mk-1"))
        m = self.svc.create(offset_s=0)
        self.svc.wait(5.0)
        self.assertEqual(m.snapshot, "marks/mk-1.json")
        doc = self.svc.snapshot("mk-1")
        self.assertIsNotNone(doc)
        self.assertEqual(doc["id"], "mk-1")
        self.assertEqual(doc["columns"], ["ts_ms", "id", "kind", "flags", "value"])
        self.assertEqual((doc["from_ms"], doc["to_ms"]), (int((T0 + 180) * 1000), int((T0 + 330) * 1000)))
        ts = [r[0] for r in doc["rows"]]
        self.assertTrue(ts)
        self.assertGreaterEqual(min(ts), doc["from_ms"])
        self.assertLess(max(ts), doc["to_ms"])
        self.assertEqual(ts, sorted(ts))
        self.assertEqual(len(doc["rows"]), 2 * 150 * 4)  # 2 targets × 150 s × 4 Hz
        self.assertEqual(doc["rows"][0][2], KIND_ICMP)
        self.assertEqual(len(doc["rollups"]), 2 * 150)
        self.assertTrue(all(T0 + 180 <= r["t"] < T0 + 330 for r in doc["rollups"]))
        self.assertEqual(len(doc["iface"]), 30)
        self.assertEqual(len(doc["wan"]), 30)
        self.assertEqual(doc["wifi"], [])
        self.assertEqual(doc["docsis"][0]["docsis"], {"ds_snr_min": 36.0})
        self.assertTrue(doc["docsis"][0]["latest"])
        self.assertEqual(doc["mark"]["id"], "mk-1")
        rows = s.rows("marks")
        self.assertEqual(rows[-1]["snapshot"], "marks/mk-1.json")
        with open(s.store.path("marks/mk-1.json"), "r", encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["id"], "mk-1")

    def test_snapshot_without_store(self):
        s = Session(with_store=False)
        self.addCleanup(s.close)
        svc = marksmod.MarkService(s.ctx)
        svc.snapshot_delay_s = 0.0
        m = svc.create()
        svc.wait(2.0)
        self.assertIsNone(m.snapshot)
        self.assertIsNone(svc.snapshot(m.id))


if __name__ == "__main__":
    unittest.main()
