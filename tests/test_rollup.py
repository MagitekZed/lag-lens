"""Tests for laglens.engine.rollup: percentiles, jitter, 1 s/5 s rollups, slots, stats."""
import os
import random
import statistics
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.engine import rollup  # noqa: E402
from laglens.state import F_LATE, F_LOST, F_ERROR, KIND_ICMP, KIND_ICMP_BIG, Sample, State, Target  # noqa: E402

T0 = 1_760_000_000.0


def mk_state(keys=("gw4", "inet4_cf")) -> State:
    st = State(T0, "s")
    for k in keys:
        st.add_target(Target(id=-1, key=k, role="anycast", addr="1.1.1.1", family=4, kind="icmp", label=k))
    return st


def add(st: State, tid: int, offset_ms: int, value: int = 10_000, flags: int = 0, kind: int = KIND_ICMP) -> Sample:
    s = Sample(ts_ms=st.t0_ms + offset_ms, target_id=tid, kind=kind, flags=flags, seq=offset_ms, value=value)
    st.add_sample(s)
    return s


class PercentileTests(unittest.TestCase):
    def test_matches_statistics_quantiles_inclusive(self):
        rng = random.Random(42)
        for n in (2, 5, 17, 100, 333):
            data = sorted(rng.uniform(1, 100) for _ in range(n))
            q = statistics.quantiles(data, n=100, method="inclusive")
            for p in (50, 95, 99):
                self.assertAlmostEqual(rollup.percentile(data, p), q[p - 1], places=9, msg="n=%d p=%d" % (n, p))

    def test_edges(self):
        self.assertIsNone(rollup.percentile([], 50))
        self.assertEqual(rollup.percentile([7.0], 95), 7.0)
        self.assertEqual(rollup.percentile([1.0, 2.0], 0), 1.0)
        self.assertEqual(rollup.percentile([1.0, 2.0], 100), 2.0)
        self.assertEqual(rollup.percentile([1, 2, 3, 4], 50), 2.5)

    def test_jitter(self):
        self.assertIsNone(rollup.jitter([]))
        self.assertIsNone(rollup.jitter([5.0]))
        self.assertAlmostEqual(rollup.jitter([10, 12, 11, 15]), 7 / 3.0)
        self.assertEqual(rollup.jitter([3, 3, 3]), 0.0)


class CloseSecondTests(unittest.TestCase):
    def test_close_second_builds_rollups_and_leaves_open_seconds(self):
        st = mk_state()
        for i, v in enumerate((10_000, 12_000, 11_000, 15_000)):
            add(st, 0, 1_000 + i * 250, value=v)
        add(st, 0, 1_500, flags=F_LOST, value=-1)
        add(st, 1, 1_100, value=20_000)
        add(st, 0, 2_100, value=9_000)  # next second stays open
        out = rollup.close_second(st, int(T0) + 2)
        self.assertEqual([(r.t, r.id) for r in out], [(int(T0) + 1, 0), (int(T0) + 1, 1)])
        r = out[0]
        self.assertEqual((r.n, r.lost, r.late, r.err), (5, 1, 0, 0))
        self.assertEqual((r.min, r.max), (10.0, 15.0))
        self.assertEqual(r.p50, 11.5)
        self.assertAlmostEqual(r.jit, 7 / 3.0, places=2)
        self.assertEqual(st.rollups(1, T0, T0 + 5)[0], [r])
        self.assertEqual(st.pending_seconds(), [int(T0) + 2])
        self.assertEqual(rollup.close_second(st, int(T0) + 2), [])

    def test_late_lost_verdict_merges_into_the_closed_second(self):
        """Repro A: a lost verdict lands after its second was closed → one row, not two."""
        st = mk_state()
        S = int(T0) + 1
        for i in range(3):
            add(st, 0, 1_000 + i * 250, value=10_000)
        rollup.close_second(st, S + 1)  # closes S with 3 replies
        add(st, 0, 1_750, flags=F_LOST, value=-1)  # 4th probe of S, known lost 2 s later
        rollup.close_second(st, S + 3)
        rows = st.rollups(1, S, S + 1)[0]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].t, rows[0].n, rows[0].lost), (S, 4, 1))
        self.assertEqual(rows[0].p50, 10.0)
        add(st, 0, 1_750 + 2, flags=F_LATE, value=2_600_000)  # late reply for it, keyed by its send second
        rollup.close_second(st, S + 10)
        rows = st.rollups(1, S, S + 1)[0]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].n, rows[0].lost, rows[0].late), (4, 1, 1))

    def test_second_close_lag(self):
        self.assertEqual(rollup.second_close_lag_s({"timeout_ms": 2000}), 3)
        self.assertEqual(rollup.second_close_lag_s({}), 3)
        self.assertEqual(rollup.second_close_lag_s(timeout_ms=2500), 4)
        self.assertEqual(rollup.second_close_lag_s(timeout_ms=100), 2)
        self.assertEqual(rollup.WINDOW5_LAG_S, 10)

    def test_all_lost_second_has_none_percentiles(self):
        st = mk_state()
        for i in range(4):
            add(st, 0, 1_000 + i * 250, flags=F_LOST, value=-1)
        (r,) = rollup.close_second(st, int(T0) + 2)
        self.assertEqual(r.lost, 4)
        self.assertIsNone(r.p50)
        self.assertIsNone(r.jit)
        self.assertEqual(r.loss_pct, 100.0)

    def test_late_vs_lost(self):
        st = mk_state()
        add(st, 0, 1_000, flags=F_LOST, value=-1)  # slot 4 lost
        add(st, 0, 3_400, flags=F_LATE, value=2_600_000)  # late reply for it, recorded at arrival
        add(st, 0, 1_250, value=10_000)
        rs = rollup.close_second(st, int(T0) + 4)
        by_t = {r.t: r for r in rs}
        first = by_t[int(T0) + 1]
        self.assertEqual((first.n, first.lost, first.late), (2, 1, 0))
        self.assertEqual(first.p50, 10.0)  # the late RTT is not mixed into percentiles
        third = by_t[int(T0) + 3]
        self.assertEqual((third.n, third.lost, third.late), (0, 0, 1))
        self.assertEqual(st.slots(4, 1), [1])
        self.assertEqual(st.slots(13, 1, late=True), [1])  # 3400 ms → slot 13
        self.assertEqual(st.slots(13, 1), [0])


class Window5Tests(unittest.TestCase):
    def test_close_window5_rows(self):
        st = mk_state()
        t = int(T0) + 5  # window [t0+5, t0+10)
        for i in range(20):
            add(st, 0, 5_000 + i * 250, value=10_000 + i * 100, flags=F_LOST if i in (3, 4) else 0)
        add(st, 1, 6_000, value=30_000)
        add(st, 0, 11_000, value=1)  # outside the window
        st.set_latest("iface", {"rx_mbps": 0.4})
        rows = rollup.close_window5(st, t)
        probe = [r for r in rows if "id" in r]
        self.assertEqual([r["id"] for r in probe], [0, 1])
        self.assertEqual(probe[0]["n"], 20)
        self.assertEqual(probe[0]["lost"], 2)
        self.assertEqual(probe[0]["min"], 10.0)
        self.assertEqual(probe[0]["max"], 11.9)
        self.assertEqual(probe[0]["t"], t)
        slots = [r for r in rows if "slots" in r][0]
        self.assertEqual(len(slots["slots"]), 20)
        self.assertEqual(len(slots["late_slots"]), 20)
        self.assertEqual(slots["slots"][3], 1)
        self.assertEqual(slots["slots"][4], 1)
        self.assertEqual(sum(slots["slots"]), 2)
        iface = [r for r in rows if "iface" in r][0]
        self.assertEqual(iface, {"t": t, "iface": {"rx_mbps": 0.4}})
        self.assertEqual(st.rollups(5, t, t + 5)[0][0].n, 20)
        self.assertEqual(st.rows5("slots", t, t + 5)[0], slots)
        self.assertEqual(st.rows5("iface", t, t + 5)[0], iface)

    def test_lagged_window_counts_every_lost_probe(self):
        """Repro B: 20 lost probes whose verdicts arrive up to 2 s late are all in the window closed at t+10."""
        st = mk_state()
        T = int(T0) + 5
        for i in range(20):  # verdicts become known at send + 2 s, but are keyed by send time
            add(st, 0, 5_000 + i * 250, flags=F_LOST, value=-1)
        t_now = T + 5 + rollup.WINDOW5_LAG_S
        rows = rollup.close_window5(st, t_now - rollup.WINDOW5_LAG_S - rollup.WINDOW5_S)
        probe = [r for r in rows if "id" in r][0]
        self.assertEqual((probe["t"], probe["n"], probe["lost"]), (T, 20, 20))
        slots = [r for r in rows if "slots" in r][0]
        self.assertEqual(sum(1 for b in slots["slots"] if b & 1), 20)

    def test_slots_row_is_phase_aligned_for_unaligned_t0(self):
        st = State(T0 + 3.7, "s")  # session started 3.7 s into a 5 s grid cell
        st.add_target(Target(id=-1, key="gw4", role="gateway", addr="10.0.0.1", family=4, kind="icmp", label="gw"))
        T = int(T0) + 5
        s = Sample(ts_ms=T * 1000 + 0, target_id=0, kind=KIND_ICMP, flags=F_LOST, seq=1, value=-1)
        st.add_sample(s)
        s2 = Sample(ts_ms=T * 1000 + 4_999, target_id=0, kind=KIND_ICMP, flags=F_LOST, seq=2, value=-1)
        st.add_sample(s2)
        rows = rollup.close_window5(st, T)
        slots = [r for r in rows if "slots" in r][0]["slots"]
        self.assertEqual(slots[0], 1)  # first ms of the window → first slot of the row
        self.assertEqual(slots[19], 1)  # last ms of the window → last slot, not the next window's
        self.assertEqual(sum(slots), 2)

    def test_rollup_from_samples_counts_big_and_errors(self):
        st = mk_state()
        samples = [
            add(st, 0, 0, value=5_000),
            add(st, 0, 250, flags=F_ERROR, value=65),
            add(st, 0, 500, kind=KIND_ICMP_BIG, flags=F_LOST, value=-1),
            add(st, 0, 750, kind=KIND_ICMP_BIG, value=6_000),
        ]
        r = rollup.rollup_from_samples(int(T0), 0, samples)
        self.assertEqual((r.n, r.lost, r.err, r.big_n, r.big_lost), (4, 1, 1, 2, 1))
        self.assertEqual(r.to_row()["p50"], 5.5)


class StatsTests(unittest.TestCase):
    def test_window_stats(self):
        st = mk_state()
        samples = []
        for i in range(8):
            flags = F_LOST if i in (2, 3, 4) else 0
            samples.append(add(st, 0, i * 250, value=-1 if flags else 10_000 + i, flags=flags))
        samples.append(add(st, 0, 2_100, flags=F_LATE, value=3_000_000))
        ws = rollup.window_stats(samples, rate_hz=4.0)
        self.assertEqual((ws["sent"], ws["lost"], ws["late"]), (8, 3, 1))
        self.assertEqual(ws["loss_pct"], 37.5)
        self.assertEqual(ws["late_pct"], 12.5)
        self.assertEqual(ws["longest_outage_s"], 0.75)
        self.assertEqual(ws["min"], 10.0)
        self.assertIsNotNone(ws["p99"])
        self.assertEqual(rollup.longest_outage([], 4.0), 0.0)

    def test_stats_windows_and_shape(self):
        st = mk_state()
        now = T0 + 100
        for i in range(40):
            add(st, 0, 90_000 + i * 250, value=10_000, flags=F_LOST if i == 0 else 0)
        rollup.close_second(st, int(now))
        for window in ("5m", "1h", "session"):
            out = rollup.stats(st, window, now=now)
            self.assertEqual(set(out), {"window", "activity", "targets", "health", "matrix"})
            tgt = out["targets"]["0"]
            self.assertEqual(tgt["sent"], 40, window)
            self.assertEqual(tgt["lost"], 1, window)
            self.assertEqual(tgt["p50"], 10.0, window)
            self.assertIn("episodes", tgt)
        self.assertTrue(rollup.stats(st, "1h", now=now)["targets"]["0"].get("approx"))
        st.set_activity("bf6")
        out = rollup.stats(st, "5m", activity="bf6", now=st.now() + 1)
        self.assertEqual(out["targets"]["0"]["sent"], 0)  # samples predate the tag

    def test_w5m_for(self):
        st = mk_state()
        now = T0 + 10
        add(st, 0, 9_000, value=12_000)
        w = rollup.w5m_for(st, now=now)
        self.assertEqual(w[0]["p50"], 12.0)
        self.assertEqual(st.w5m[0]["loss_pct"], 0.0)
        self.assertEqual(set(w[0]), {"p50", "p95", "loss_pct", "late_pct", "jitter"})


if __name__ == "__main__":
    unittest.main()
