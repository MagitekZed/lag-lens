"""Tests for laglens.server.series: grid alignment, res validation, file merge, segments math."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.server import series  # noqa: E402
from laglens.server.series import build_series, segments  # noqa: E402
from laglens.state import Rollup, State, Target  # noqa: E402
from laglens.store import Store  # noqa: E402

T0 = 1_760_000_000.0  # a multiple of 5 and 10


class FakeUsage:
    def __init__(self, free_mb=50_000):
        self.free = int(free_mb * 1024 * 1024)
        self.total = self.free * 2
        self.used = self.free


def mk_state(keys=("gw4", "isp_hop4", "mid_hop4", "inet4_cf")):
    st = State(T0, "s")
    for k in keys:
        st.add_target(Target(id=-1, key=k, role="x", addr="1.1.1.1", family=4, kind="icmp", label=k))
    return st


def rl(t, tid, p50, n=20, lost=0, late=0, jit=0.5):
    return Rollup(t=int(t), id=tid, n=n, lost=lost, late=late, err=0, min=p50, p50=p50, p95=p50 + 2, max=p50 + 5,
                  jit=jit, stall=0)


class GridTests(unittest.TestCase):
    def test_arrays_align_with_t_and_pad_nulls(self):
        st = mk_state(("gw4",))
        for i in range(0, 30, 5):
            if i == 10:
                continue  # a hole
            st.add_rollup(5, rl(T0 + i, 0, 1.0 + i))
        body = build_series(st, None, T0, T0 + 30, 5)
        self.assertEqual(body["res"], 5)
        self.assertEqual(body["t"], [int(T0) + i for i in range(0, 30, 5)])
        tg = body["targets"]["0"]
        for key in series.TARGET_KEYS:
            self.assertEqual(len(tg[key]), 6, key)
        self.assertEqual(tg["p50"], [1.0, 6.0, None, 16.0, 21.0, 26.0])
        self.assertEqual(tg["n"], [20, 20, None, 20, 20, 20])
        for key in ("iface", "wan", "wifi", "docsis", "ntp", "segments"):
            for arr in body[key].values():
                self.assertEqual(len(arr), 6, key)
        for key in ("slots_lost", "xbox_state", "stall"):
            self.assertEqual(len(body[key]), 6, key)
            self.assertTrue(all(v is None for v in body[key]), key)

    def test_grid_start_is_aligned_to_res(self):
        st = mk_state(("gw4",))
        body = build_series(st, None, T0 + 3, T0 + 13, 5)
        self.assertEqual(body["t"][0] % 5, 0)
        self.assertEqual(body["t"], [int(T0), int(T0) + 5, int(T0) + 10])
        self.assertEqual(body["from"], T0 + 3)

    def test_res1_uses_1s_ring(self):
        st = mk_state(("gw4",))
        st.add_rollup(1, rl(T0 + 1, 0, 9.0))
        st.add_rollup(1, rl(T0 + 3, 0, 11.0, lost=1))
        body = build_series(st, None, T0, T0 + 5, 1)
        self.assertEqual(body["t"], [int(T0) + i for i in range(5)])
        self.assertEqual(body["targets"]["0"]["p50"], [None, 9.0, None, 11.0, None])
        self.assertEqual(body["targets"]["0"]["lost"], [None, 0, None, 1, None])

    def test_target_filter(self):
        st = mk_state(("gw4", "inet4_cf"))
        st.add_rollup(5, rl(T0, 0, 1.0))
        st.add_rollup(5, rl(T0, 1, 20.0))
        body = build_series(st, None, T0, T0 + 5, 5, target_ids=[1])
        self.assertEqual(list(body["targets"]), ["1"])

    def test_ctx_or_state_accepted(self):
        st = mk_state(("gw4",))

        class Ctx:
            state = st

        body = build_series(Ctx(), None, T0, T0 + 5, 5)
        self.assertIn("0", body["targets"])


class ValidationTests(unittest.TestCase):
    def test_res_must_be_1_or_5(self):
        st = mk_state(("gw4",))
        with self.assertRaises(ValueError):
            build_series(st, None, T0, T0 + 5, 2)

    def test_res1_limited_to_two_hours(self):
        st = mk_state(("gw4",))
        build_series(st, None, T0, T0 + 7200, 1)  # exactly 2 h is fine
        with self.assertRaises(ValueError):
            build_series(st, None, T0, T0 + 7201, 1)

    def test_inverted_range_rejected(self):
        st = mk_state(("gw4",))
        with self.assertRaises(ValueError):
            build_series(st, None, T0 + 10, T0, 5)

    def test_empty_range_gives_one_point(self):
        st = mk_state(("gw4",))
        body = build_series(st, None, T0, T0, 5)
        self.assertEqual(body["t"], [int(T0)])


class FileMergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-series-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = Store(self.tmp / "20261011-190000", {"disk": {}}, disk_usage=lambda p: FakeUsage())
        self.addCleanup(self.store.stop)

    def _write_rows(self, rows):
        with open(self.store.path("rollups.jsonl"), "a", encoding="utf-8") as fh:
            import json

            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def test_older_rows_come_from_file_and_ram_wins(self):
        st = mk_state(("gw4",))
        st.add_rollup(5, rl(T0 + 10, 0, 5.0))  # RAM holds only t0+10
        self._write_rows([
            {"t": int(T0), "id": 0, "n": 20, "lost": 2, "late": 0, "err": 0, "min": 1, "p50": 1.5, "p95": 3, "max": 4, "jit": 0.1, "stall": 0},
            {"t": int(T0) + 10, "id": 0, "n": 20, "lost": 0, "late": 0, "err": 0, "min": 1, "p50": 99.0, "p95": 3, "max": 4, "jit": 0.1, "stall": 0},
            {"t": int(T0), "iface": {"rx_mbps": 1.5, "tx_mbps": 0.5, "rx_err": 1, "tx_err": 2, "rx_drop": 0, "tx_drop": 3, "carrier_changes": 0, "mcast_pps": 7}},
            {"t": int(T0), "slots": [1] * 20, "late_slots": [0] * 20},
            {"t": int(T0), "xbox": {"state": "asleep", "src": "icmp"}},
            {"t": int(T0), "host": {"late_ms_max": 80, "loop_gap_ms": 5}},
        ])
        body = build_series(st, self.store, T0, T0 + 15, 5)
        tg = body["targets"]["0"]
        self.assertEqual(tg["p50"], [1.5, None, 5.0])  # RAM (5.0) wins over the file (99.0)
        self.assertEqual(tg["lost"], [2, None, 0])
        self.assertEqual(body["iface"]["err"], [3.0, None, None])
        self.assertEqual(body["iface"]["drop"], [3.0, None, None])
        self.assertEqual(body["iface"]["mcast_pps"], [7.0, None, None])
        self.assertEqual(body["slots_lost"][0], [1] * 20)
        self.assertEqual(body["xbox_state"], ["asleep", None, None])
        self.assertEqual(body["stall"], [1, None, None])

    def test_file_not_read_when_ram_covers_range(self):
        st = mk_state(("gw4",))
        st.add_rollup(5, rl(T0, 0, 5.0))
        self._write_rows([{"t": int(T0), "id": 0, "n": 20, "lost": 0, "late": 0, "err": 0, "min": 1, "p50": 99.0, "p95": 3, "max": 4, "jit": 0.1, "stall": 0}])
        body = build_series(st, self.store, T0, T0 + 5, 5)
        self.assertEqual(body["targets"]["0"]["p50"], [5.0])

    def test_store_none_is_tolerated(self):
        st = mk_state(("gw4",))
        body = build_series(st, None, T0 - 3600, T0, 5)
        self.assertEqual(len(body["t"]), 720)


class CollectorRowTests(unittest.TestCase):
    def test_rows5_from_ram_and_ntp_shift(self):
        st = mk_state(("gw4",))
        st.add_row5("ntp", {"t": int(T0), "ntp": {"cf": {"rtt": 14.0, "offset": -1.0}, "g": {"rtt": 15.0, "offset": -3.0}}})
        st.add_row5("ntp", {"t": int(T0) + 5, "ntp": {"cf": {"rtt": 14.0, "offset": 1.0}, "g": {"rtt": 15.0, "offset": 1.0}}})
        st.add_row5("wifi", {"t": int(T0), "wifi": {"rssi": -58, "noise": -92}})
        st.add_row5("docsis", {"t": int(T0) + 5, "docsis": {"ds_snr_min": 36.1, "us_pwr_max": 44.0, "uncorr_delta": 3}})
        st.add_row5("wan", {"t": int(T0), "wan": {"rx_mbps": 12.3, "tx_mbps": 1.1}})
        st.add_row5("slots", {"t": int(T0), "slots": list(range(20)), "late_slots": [0] * 20})
        body = build_series(st, None, T0, T0 + 10, 5)
        self.assertEqual(body["ntp"]["offset_shift"], [0.0, 3.0])
        self.assertEqual(body["ntp"]["rtt"], [14.0, 14.0])
        self.assertEqual(body["wifi"]["rssi"], [-58.0, None])
        self.assertEqual(body["docsis"]["uncorr_delta"], [None, 3.0])
        self.assertEqual(body["wan"]["rx_mbps"], [12.3, None])
        self.assertEqual(body["slots_lost"], [list(range(20)), None])

    def test_slots_split_per_second_at_res1(self):
        st = mk_state(("gw4",))
        st.add_row5("slots", {"t": int(T0), "slots": list(range(20)), "late_slots": [0] * 20})
        body = build_series(st, None, T0, T0 + 5, 1)
        self.assertEqual(body["slots_lost"], [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15], [16, 17, 18, 19]])


class SegmentTests(unittest.TestCase):
    def test_segment_math_and_clamp(self):
        st = mk_state()
        gw, isp, mid, inet = (st.target(k).id for k in ("gw4", "isp_hop4", "mid_hop4", "inet4_cf"))
        # one 10 s bucket = two 5 s rows; medians: gw 1.0, isp 12.0, mid 10.0 (below isp -> clamp), inet 25.0
        for t, g, i, m, n in ((T0, 1.0, 11.0, 9.0, 24.0), (T0 + 5, 1.0, 13.0, 11.0, 26.0)):
            st.add_rollup(5, rl(t, gw, g))
            st.add_rollup(5, rl(t, isp, i))
            st.add_rollup(5, rl(t, mid, m))
            st.add_rollup(5, rl(t, inet, n))
        body = build_series(st, None, T0, T0 + 10, 5)
        seg = body["segments"]
        self.assertEqual(seg["lan"], [1.0, 1.0])
        self.assertEqual(seg["docsis"], [11.0, 11.0])
        self.assertEqual(seg["comcast"], [0.0, 0.0])  # 10 - 12 clamped to 0
        self.assertEqual(seg["internet"], [15.0, 15.0])

    def test_missing_mid_hop_falls_back_to_isp(self):
        st = mk_state(("gw4", "isp_hop4", "inet4_cf"))
        gw, isp, inet = (st.target(k).id for k in ("gw4", "isp_hop4", "inet4_cf"))
        st.add_rollup(5, rl(T0, gw, 1.0))
        st.add_rollup(5, rl(T0, isp, 11.0))
        st.add_rollup(5, rl(T0, inet, 20.0))
        seg = build_series(st, None, T0, T0 + 5, 5)["segments"]
        self.assertEqual(seg["comcast"], [None])
        self.assertEqual(seg["internet"], [9.0])

    def test_segments_helper_direct(self):
        t = [int(T0), int(T0) + 5, int(T0) + 10]
        targets = {"0": {"p50": [1.0, 3.0, 2.0]}, "1": {"p50": [10.0, 20.0, 30.0]}}
        seg = segments(targets, {"gw4": 0, "inet4_cf": 1}, t)
        self.assertEqual(seg["lan"], [2.0, 2.0, 2.0])  # median of bucket (1,3) = 2; third point alone = 2
        self.assertEqual(seg["internet"], [13.0, 13.0, 28.0])
        self.assertEqual(seg["docsis"], [None, None, None])


if __name__ == "__main__":
    unittest.main()
