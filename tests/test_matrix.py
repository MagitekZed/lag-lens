"""Tests for the simultaneity matrix and loss locus (SPEC §7.5) on constructed slot sets and raw samples."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from laglens.engine import classify as cm  # noqa: E402
from laglens.state import F_LATE, KIND_TTL  # noqa: E402
from test_detector_base import Session, T0  # noqa: E402


def sets(**kw):
    return {k: set(v) for k, v in kw.items()}


class MatrixFromSetsTests(unittest.TestCase):
    def test_conditional_loss_and_locus_at_isp_hop(self):
        lost = sets(gw4=[], isp_hop4=range(0, 10), mid_hop4=range(0, 10), inet4_cf=range(0, 11), inet4_g=range(1, 10))
        probed = {k: set(range(12)) for k in lost}
        cond, locus = cm.matrix_from_sets(lost, probed)
        self.assertEqual(locus, "isp_hop4")
        self.assertEqual(cond["isp_hop4|inet4_cf"], round(10 / 11, 2))
        self.assertEqual(cond["gw4|inet4_cf"], 0.0)
        self.assertEqual(cond["isp_hop4|mid_hop4"], 1.0)
        self.assertNotIn("inet4_cf|isp_hop4", cond)  # pairs are shallow|deep only

    def test_locus_needs_seventy_percent(self):
        lost = sets(gw4=[], isp_hop4=range(0, 6), inet4_cf=range(0, 10), inet4_g=range(0, 10))
        probed = {k: set(range(10)) for k in lost}
        cond, locus = cm.matrix_from_sets(lost, probed)
        self.assertEqual(cond["isp_hop4|inet4_cf"], 0.6)
        self.assertEqual(locus, "internet")
        lost["isp_hop4"] = set(range(0, 7))
        _, locus = cm.matrix_from_sets(lost, probed)
        self.assertEqual(locus, "isp_hop4")

    def test_two_hz_hop_is_conditioned_on_probed_slots(self):
        # a 2 Hz hop is probed only in even slots: lost in every probed slot of the burst
        lost = sets(gw4=[], isp_hop4=[0, 2, 4, 6], inet4_cf=range(0, 8), inet6_cf=range(0, 8))
        probed = {"gw4": set(range(8)), "isp_hop4": {0, 2, 4, 6}, "inet4_cf": set(range(8)), "inet6_cf": set(range(8))}
        cond, locus = cm.matrix_from_sets(lost, probed)
        self.assertEqual(cond["isp_hop4|inet4_cf"], 1.0)
        self.assertEqual(locus, "isp_hop4")

    def test_gateway_locus_and_none(self):
        lost = sets(gw4=range(0, 8), isp_hop4=range(0, 8), inet4_cf=range(0, 8))
        probed = {k: set(range(8)) for k in lost}
        _, locus = cm.matrix_from_sets(lost, probed)
        self.assertEqual(locus, "gw4")
        lost = sets(gw4=[], isp_hop4=[], inet4_cf=[])
        cond, locus = cm.matrix_from_sets(lost, probed)
        self.assertIsNone(locus)
        self.assertEqual(cond, {})

    def test_only_hop_lost_has_no_deeper_reference(self):
        lost = sets(gw4=[], isp_hop4=range(0, 5), inet4_cf=[], inet4_g=[])
        probed = {k: set(range(8)) for k in lost}
        _, locus = cm.matrix_from_sets(lost, probed)
        self.assertIsNone(locus)


class ComputeMatrixTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)

    def test_from_raw_samples_with_late_turning_lost_into_late(self):
        s = self.s
        t0 = T0 + 20
        s.stream(t0, t0 + 3, keys=["gw4", "isp_hop4", "inet4_cf", "inet4_g", "inet6_cf", "inet6_g"],
                 lost=lambda k, t: k != "gw4" and t0 + 1 <= t < t0 + 2)
        # a late reply for one inet4_cf lost slot turns that slot into "late", not lost
        lost_samples = [x for x in s.state.raw_window(s.ids["inet4_cf"], t0 + 1, t0 + 2) if x.lost]
        first = lost_samples[0]
        s.emit("inet4_cf", first.ts_ms / 1000.0, rtt_ms=2500.0, late=True)
        m = cm.compute_matrix(s.state, t0, t0 + 3)
        self.assertEqual(m["shallowest"], "isp_hop4")
        self.assertEqual(m["lost_slots"]["inet4_cf"], 3)  # 4 lost slots minus the late one
        self.assertEqual(m["lost_slots"]["inet4_g"], 4)
        self.assertEqual(m["cond"]["isp_hop4|inet4_g"], 1.0)
        self.assertIn("loss locus: Comcast hop 10.60.12.1", m["sentence"])
        self.assertIn("gateway 0%", m["sentence"])
        self.assertEqual(m["excluded"], [])

    def test_off_grid_and_disabled_targets_are_excluded_and_said(self):
        s = self.s
        s.state.set_target_state("isp_hop4", mode="ttl_expiry")
        s.state.set_target_state("xbox", enabled=False, reason="not found")
        t0 = T0 + 20
        s.stream(t0, t0 + 2, keys=["gw4", "inet4_cf", "inet4_g"], lost=lambda k, t: k != "gw4" and t >= t0 + 1)
        m = cm.compute_matrix(s.state, t0, t0 + 2)
        self.assertEqual(m["shallowest"], "internet")
        self.assertTrue(any(e.startswith("isp_hop4 (off-grid") for e in m["excluded"]), m["excluded"])
        self.assertTrue(any(e.startswith("xbox (disabled") for e in m["excluded"]), m["excluded"])
        self.assertIn("excluded from the matrix", m["sentence"])
        self.assertNotIn("isp_hop4|inet4_cf", m["cond"])

    def test_accumulate_into_state_matrix(self):
        s = self.s
        t0 = T0 + 20
        s.stream(t0, t0 + 2, keys=["gw4", "isp_hop4", "inet4_cf", "inet4_g"], lost=lambda k, t: k != "gw4" and t >= t0 + 1)
        m = cm.compute_matrix(s.state, t0, t0 + 2)
        cm.accumulate_matrix(s.state, m, t0, t0 + 2)
        cm.accumulate_matrix(s.state, m, t0, t0 + 2)
        self.assertEqual(s.state.matrix["locus_counts"], {"isp_hop4": 2})
        self.assertEqual(s.state.matrix["pairs"]["isp_hop4|inet4_cf"], 1.0)
        self.assertEqual(s.state.matrix["pairs"]["gw4|inet4_cf"], 0.0)
        self.assertEqual(s.state.matrix_acc["b_lost"]["isp_hop4|inet4_cf"], 4)  # 2 probed-lost slots × 2 calls

    def test_window_without_raw_samples_falls_back_to_bitmasks(self):
        s = self.s
        tid = s.ids["inet4_cf"]
        slot = s.state.slot_for(int((T0 + 20) * 1000))
        with s.state.lock:
            s.state._slot_lost[slot] = 1 << tid
            s.state._slot_lost[slot + 1] = 1 << tid
        m = cm.compute_matrix(s.state, T0 + 20, T0 + 21)
        self.assertEqual(m["lost_slots"], {"inet4_cf": 2})
        self.assertEqual(m["shallowest"], "internet")


if __name__ == "__main__":
    unittest.main()
