"""Tests for laglens.report.sessions: /api/sessions rows, session_summary, the static index page, the rollup scan."""
import gzip
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_report_fixture as F  # noqa: E402
from laglens.report import sessions as S  # noqa: E402

ROW_KEYS = ("id", "label", "started", "stopped", "dur_s", "score", "loss_pct", "p95", "episodes", "top_class", "spark")
SECOND_ID = "20261011-200000"  # replaced in setUpClass: the dir name must not post-date the data it holds


class SessionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global SECOND_ID
        cls.tmp = Path(tempfile.mkdtemp(prefix="laglens-sessions-"))
        cls.fx = F.make_session(cls.tmp, duration_s=500, close=True)  # 500 s: includes the +450 s latency spike
        cls.root = cls.fx.sessions_root
        # a second session without session.json (crashed before the first write) and some junk.
        # Its directory name (= its start time) is one minute after the fixture's t0, so it sorts
        # newer than the first session yet its copied rollups still lie inside [started, t_last].
        SECOND_ID = time.strftime("%Y%m%d-%H%M%S", time.localtime(cls.fx.t0 + 60))
        second = cls.root / SECOND_ID
        shutil.copytree(cls.fx.dir, second)
        (second / "session.json").unlink()
        (second / "report.html").unlink()
        (cls.root / "notes").mkdir()
        (cls.root / "notes" / "readme.txt").write_text("not a session")
        (cls.root / ".last").write_text("sessions/%s\n" % F.SESSION_ID)
        (cls.root / "laglens.pid").write_text("1\n")
        cls.rows = S.list_sessions(cls.root)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_rows_newest_first_with_every_field(self):
        self.assertEqual([r["id"] for r in self.rows], [SECOND_ID, F.SESSION_ID])
        for r in self.rows:
            for k in ROW_KEYS:
                self.assertIn(k, r, k)
        first = self.rows[1]
        self.assertEqual(first["label"], F.LABEL)
        self.assertAlmostEqual(first["started"], self.fx.t0, places=3)
        self.assertEqual(first["stopped"], self.fx.t_end)
        self.assertEqual(first["dur_s"], 500.0)
        self.assertEqual(first["score"], 83)
        self.assertEqual(first["episodes"], 2)
        self.assertEqual(first["top_class"], "docsis_access")
        self.assertGreater(first["loss_pct"], 0.5)
        self.assertGreater(first["p95"], 14.0)
        self.assertEqual(len(first["spark"]), S.SPARK_POINTS)
        self.assertTrue(all(isinstance(v, float) for v in first["spark"]))
        self.assertGreater(max(first["spark"]), 100.0)  # the latency spike shows up in the sparkline
        self.assertTrue(first["has_report"])
        self.assertFalse(first["has_zip"])

    def test_row_without_session_json_falls_back_to_scan(self):
        r = self.rows[0]
        self.assertIsNone(r["label"])
        self.assertEqual(time.strftime("%Y%m%d-%H%M%S", time.localtime(r["started"])), SECOND_ID)
        self.assertIsNone(r["stopped"])
        self.assertIsNone(r["score"])
        self.assertIsNone(r["top_class"])
        self.assertEqual(r["episodes"], 2)  # counted from episodes.jsonl ids
        self.assertIsNotNone(r["loss_pct"])
        self.assertIsNotNone(r["p95"])
        self.assertEqual(len(r["spark"]), S.SPARK_POINTS)
        self.assertIsNotNone(r["dur_s"])

    def test_cache_written_and_reused(self):
        cache = json.loads((self.root / S.CACHE_FILE).read_text())
        self.assertIn(F.SESSION_ID, cache)
        self.assertIn(SECOND_ID, cache)
        orig = S.rollup_scan

        def boom(*a, **k):
            raise AssertionError("rollups.jsonl must not be rescanned when the cache is fresh")

        S.rollup_scan = boom
        try:
            rows = S.list_sessions(self.root)
        finally:
            S.rollup_scan = orig
        self.assertEqual(rows[1]["loss_pct"], self.rows[1]["loss_pct"])
        self.assertEqual(rows[1]["spark"], self.rows[1]["spark"])

    def test_session_summary(self):
        doc = S.session_summary(self.fx.dir)
        self.assertEqual(doc["id"], F.SESSION_ID)
        self.assertEqual(doc["summary"]["episodes"], 2)
        synth = S.session_summary(self.root / SECOND_ID)
        self.assertTrue(synth["missing"])
        self.assertEqual(synth["id"], SECOND_ID)
        self.assertEqual(synth["summary"], {})
        self.assertEqual(time.strftime("%Y%m%d-%H%M%S", time.localtime(synth["started"])), SECOND_ID)

    def test_rebuild_index_page(self):
        self.assertEqual(S.rebuild_index(self.root), 0)
        html = (self.root / S.INDEX_FILE).read_text(encoding="utf-8")
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("--bg:#0f1115", html)
        self.assertIn('href="%s/report.html"' % F.SESSION_ID, html)
        self.assertIn('href="%s/report.html"' % SECOND_ID, html)
        self.assertIn('href="/sessions/%s/export.zip"' % F.SESSION_ID, html)
        self.assertIn(F.LABEL, html)
        self.assertIn("docsis_access", html)
        self.assertIn('<svg class="spark"', html)
        self.assertIn("2 sessions", html)
        self.assertNotIn("{{", html)
        self.assertNotIn(F.PASSWORD, html)
        # once a zip was exported next to the session, the index links it directly
        (self.root / ("laglens-%s.zip" % F.SESSION_ID)).write_bytes(b"PK")
        S.rebuild_index(self.root)
        html = (self.root / S.INDEX_FILE).read_text(encoding="utf-8")
        self.assertIn('href="laglens-%s.zip"' % F.SESSION_ID, html)

    def test_empty_and_unwritable_roots(self):
        empty = self.tmp / "empty"
        self.assertEqual(S.rebuild_index(empty), 0)
        self.assertIn("No sessions yet", (empty / S.INDEX_FILE).read_text())
        self.assertEqual(S.list_sessions(empty), [])
        self.assertEqual(S.rebuild_index(self.fx.dir / "targets.json" / "x"), 1)

    def test_rollup_scan_and_reference_ids(self):
        ids = S.reference_target_ids(self.fx.dir)
        self.assertEqual(set(ids), {self.fx.ids[k] for k in ("inet4_cf", "inet4_g", "inet6_cf", "isp_hop4")})
        scan = S.rollup_scan(self.fx.dir, self.fx.t0, self.fx.t_end)
        gw = scan["targets"][str(self.fx.ids["gw4"])]
        self.assertEqual(gw["lost"], 0)
        self.assertGreater(gw["sent"], 1400)
        self.assertTrue(gw["approx"])
        self.assertAlmostEqual(gw["p50"], 1.45, delta=0.1)  # 1.0 ms base + 0..0.9 ms wobble; grid alignment varies
        hop = scan["targets"][str(self.fx.ids["isp_hop4"])]
        self.assertEqual(hop["lost"], self.fx.state.totals[self.fx.ids["isp_hop4"]].lost)
        self.assertGreater(hop["longest_outage_s"], 0)
        self.assertGreater(scan["windows"], 500)
        self.assertEqual(len(scan["spark"]), S.SPARK_POINTS)
        self.assertEqual(S.rollup_scan(self.tmp / "nothing"), {"targets": {}, "loss_pct": None, "p95": None, "spark": [],
                                                              "t_first": None, "t_last": None, "windows": 0})

    def test_iter_jsonl_torn_and_gz(self):
        p = self.tmp / "x.jsonl"
        p.write_bytes(b'{"a":1}\nnot json\n{"a":2}\n{"a":3')
        self.assertEqual(list(S.iter_jsonl(p)), [{"a": 1}, {"a": 2}])
        p.unlink()
        with gzip.open(str(p) + ".gz", "wb") as fh:
            fh.write(b'{"b":1}\n[1,2]\n{"b":2}\n')
        self.assertEqual(list(S.iter_jsonl(p)), [{"b": 1}, {"b": 2}])
        self.assertEqual(list(S.iter_jsonl(self.tmp / "missing.jsonl")), [])

    def test_is_session_dir(self):
        self.assertTrue(S.is_session_dir(self.fx.dir))
        self.assertFalse(S.is_session_dir(self.root / "notes"))
        self.assertFalse(S.is_session_dir(self.root / "laglens.pid"))
        odd = self.root / "custom-name"
        odd.mkdir()
        self.assertFalse(S.is_session_dir(odd))
        (odd / "session.json").write_text("{}")
        self.assertTrue(S.is_session_dir(odd))
        shutil.rmtree(odd)


if __name__ == "__main__":
    unittest.main()
