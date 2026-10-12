"""Tests for the additive State extensions used by the detection engine: clock, blips, matrix_acc."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.state import State  # noqa: E402

T0 = 1_760_000_000.0


class ClockTests(unittest.TestCase):
    def test_default_clock_is_wall_time(self):
        st = State(T0, "s")
        import time
        self.assertLess(abs(st.now() - time.time()), 5.0)

    def test_injected_clock_drives_now_elapsed_and_notes(self):
        st = State(T0, "s")
        st.clock = lambda: T0 + 42.5
        self.assertEqual(st.now(), T0 + 42.5)
        self.assertEqual(st.elapsed(), 42.5)
        n = st.raise_note("link_flap", severity=3, note="carrier down")
        self.assertEqual(n["t"], T0 + 42.5)
        st.set_collector("engine", "ok")
        self.assertEqual(st.collector("engine")["since"], T0 + 42.5)
        tag = st.set_activity("bf6")
        self.assertEqual(tag["since"], T0 + 42.5)

    def test_explicit_note_time_wins(self):
        st = State(T0, "s")
        st.clock = lambda: T0 + 10
        n = st.raise_note("wifi_drop", t=T0 + 3, severity=2)
        self.assertEqual(n["t"], T0 + 3)
        self.assertEqual(st.drain_notes(), [n])
        self.assertEqual(st.drain_notes(), [])


class CountersTests(unittest.TestCase):
    def test_blips_and_matrix_acc_defaults(self):
        st = State(T0, "s")
        self.assertEqual(st.blips, 0)
        self.assertEqual(st.matrix_acc, {"both": {}, "b_lost": {}})
        self.assertEqual(st.matrix, {"pairs": {}, "locus_counts": {}})

    def test_snapshot_shape_unchanged(self):
        st = State(T0, "s")
        st.blips = 3
        snap = st.snapshot()
        self.assertNotIn("blips", snap)
        self.assertNotIn("matrix_acc", snap)
        self.assertEqual(snap["verdict"]["marks"], {"total": 0, "linked": 0})


if __name__ == "__main__":
    unittest.main()
