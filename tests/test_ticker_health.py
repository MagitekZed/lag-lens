"""Tests for the health score (SPEC §7.8): formula bounds, exclusions, episode minutes."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from laglens.engine import health  # noqa: E402
from laglens.state import F_LOADTEST, F_STALL, F_XBOX_ASLEEP, Episode  # noqa: E402
from test_detector_base import Session, T0  # noqa: E402


class FormulaTests(unittest.TestCase):
    def test_perfect_and_bounds(self):
        self.assertEqual(health.score(0.0, 10.0, 12.0, 0.5, 0.0, 0.0), 99.8)
        self.assertEqual(health.score(0.0, 10.0, 10.0, 0.0, 0.0, None), 100.0)
        # every term capped: 40 + 25 + 15 + 20 + 20 = 120 -> clamped to 0
        self.assertEqual(health.score(50.0, 10.0, 500.0, 100.0, 1000.0, 50.0), 0.0)

    def test_each_term(self):
        self.assertEqual(health.score(1.0, None, None, None, 0.0, None), 80.0)  # 20·1%
        self.assertEqual(health.score(0.0, 10.0, 60.0, None, 0.0, None), 90.0)  # (60-10-10)/4
        self.assertEqual(health.score(0.0, None, None, 10.0, 0.0, None), 95.0)  # jitter/2
        self.assertEqual(health.score(0.0, None, None, None, 12.0, None), 98.0)  # minutes/6
        self.assertEqual(health.score(0.0, None, None, None, 0.0, 0.25), 90.0)  # 40·0.25
        self.assertEqual(health.score(5.0, None, None, None, 0.0, None), 60.0)  # loss term capped at 40


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)

    def test_reference_set_and_clean_window(self):
        s = self.s
        keys = [t.key for t in health.reference_targets(s.state)]
        self.assertEqual(keys, ["inet4_cf", "inet4_g", "inet6_cf", "inet6_g", "isp_hop4"])
        s.state.set_target_state("isp_hop4", mode="ttl_expiry")
        self.assertNotIn("isp_hop4", [t.key for t in health.reference_targets(s.state)])
        s.stream(T0, T0 + 30, jitter_ms=0.2)
        h = health.window_health(s.state, T0, T0 + 30, now=T0 + 30)
        self.assertIsNotNone(h)
        self.assertGreaterEqual(h, 98.0)
        self.assertIsNone(health.window_health(s.state, T0 + 100, T0 + 130, now=T0 + 130))

    def test_loss_counts_but_stall_and_loadtest_samples_are_excluded(self):
        s = self.s
        inet = ["inet4_cf", "inet4_g", "inet6_cf", "inet6_g", "isp_hop4"]
        s.stream(T0, T0 + 10, keys=inet, lost=lambda k, t: k == "inet4_cf" and t < T0 + 2)
        base = health.window_health(s.state, T0, T0 + 10, now=T0 + 10)
        self.assertLess(base, 70.0)  # 8 of 176 lost = 4.5 % -> loss term at the 40 cap
        s2 = Session()
        self.addCleanup(s2.close)
        s2.stream(T0, T0 + 10, keys=inet, lost=lambda k, t: k == "inet4_cf" and t < T0 + 2,
                  flags=lambda k, t: F_STALL if t < T0 + 2 else 0)
        self.assertGreaterEqual(health.window_health(s2.state, T0, T0 + 10, now=T0 + 10), 98.0)
        s3 = Session()
        self.addCleanup(s3.close)
        s3.stream(T0, T0 + 10, keys=inet, lost=lambda k, t: k == "inet4_cf" and t < T0 + 2,
                  flags=lambda k, t: F_LOADTEST if t < T0 + 2 else 0)
        self.assertGreaterEqual(health.window_health(s3.state, T0, T0 + 10, now=T0 + 10), 98.0)

    def test_xbox_loss_only_while_awake(self):
        s = self.s
        inet = ["inet4_cf", "inet4_g", "inet6_cf", "inet6_g"]
        s.stream(T0, T0 + 10, keys=inet)
        s.stream(T0, T0 + 10, keys=["xbox"], lost=lambda k, t: True)
        self.assertLessEqual(health.window_health(s.state, T0, T0 + 10, now=T0 + 10), 80.0)
        s2 = Session()
        self.addCleanup(s2.close)
        s2.stream(T0, T0 + 10, keys=inet)
        s2.stream(T0, T0 + 10, keys=["xbox"], lost=lambda k, t: True, flags=lambda k, t: F_XBOX_ASLEEP)
        self.assertGreaterEqual(health.window_health(s2.state, T0, T0 + 10, now=T0 + 10), 98.0)

    def test_episode_minutes_skip_blips_and_non_path_classes(self):
        s = self.s
        st = s.state
        st.episodes.append(Episode(id="ep-1", t0=T0 + 10, t1=T0 + 70, dur_s=60, cls="docsis_access"))
        st.episodes.append(Episode(id="ep-2", t0=T0 + 100, t1=T0 + 101, dur_s=1.0, cls="docsis_access"))  # blip
        st.episodes.append(Episode(id="ep-3", t0=T0 + 200, t1=T0 + 260, dur_s=60, cls="loadtest"))
        st.episodes.append(Episode(id="ep-4", t0=T0 + 300, t1=None, cls="internet"))  # open, counted to now
        self.assertAlmostEqual(health.episode_minutes(st, T0, T0 + 330, now=T0 + 330), 1.5)
        self.assertAlmostEqual(health.episode_minutes(st, T0 + 40, T0 + 330, now=T0 + 330), 1.0)

    def test_refresh_sets_state_health(self):
        s = self.s
        s.stream(T0, T0 + 30)
        s.clock.set(T0 + 30)
        out = health.refresh(s.state, session=True)
        self.assertEqual(set(out), {"now", "session"})
        self.assertIsNotNone(out["now"])
        self.assertIsNotNone(out["session"])
        self.assertEqual(s.state.health, out)


if __name__ == "__main__":
    unittest.main()
