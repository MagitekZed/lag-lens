"""Tests for laglens.report.build: live ReportBuilder, blob contract (INTERFACES §10.3), offline rebuild."""
import gzip
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_report_fixture as F  # noqa: E402
from laglens.app import AppContext  # noqa: E402
from laglens.report import build as B  # noqa: E402
from laglens.state import F_LOST, KIND_ICMP, Rollup, Sample, State, Target  # noqa: E402
from laglens.store import SAMPLE_SIZE, SAMPLE_STRUCT, Store, pack_sample  # noqa: E402
import argparse  # noqa: E402

PLACEHOLDER_NAMES = ("TITLE", "STYLE", "UPLOT_CSS", "UPLOT_JS", "COMMON_JS", "APP_JS", "DATA_JSON")


def _tmp(prefix="laglens-report-"):
    return Path(tempfile.mkdtemp(prefix=prefix))


class LiveBlobTests(unittest.TestCase):
    """One fixture session, one live build; read-only assertions on the result."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = _tmp()
        cls.fx = F.make_session(cls.tmp, duration_s=600)
        cls.builder = B.ReportBuilder(cls.fx.ctx)
        cls.path = cls.builder.build()
        cls.html = cls.path.read_text(encoding="utf-8")
        cls.blob = F.data_blob(cls.html)

    @classmethod
    def tearDownClass(cls):
        cls.fx.store.stop()
        shutil.rmtree(cls.tmp, True)

    def test_file_written_and_blob_has_every_key(self):
        self.assertTrue(self.path.exists())
        self.assertEqual(self.path.name, "report.html")
        for key in F.BLOB_KEYS:
            self.assertIn(key, self.blob, key)
        self.assertIs(self.blob["static"], True)
        self.assertTrue(self.blob["version"])
        self.assertGreater(self.blob["generated_at"], self.fx.t0)

    def test_template_filled_and_assets_inlined(self):
        for name in PLACEHOLDER_NAMES:
            self.assertNotIn("{{%s}}" % name, self.html)
        for sentinel in ("TEMPLATE-SENTINEL", "STYLE-SENTINEL", "UPLOT-CSS-SENTINEL", "UPLOT-JS-SENTINEL",
                         "COMMON_SENTINEL", "APP_SENTINEL"):
            self.assertIn(sentinel, self.html)
        self.assertIn("<title>Lag Lens report %s - %s</title>" % (F.SESSION_ID, F.LABEL), self.html)
        # common.js contained a literal "</script>" string: it must not close the inline tag
        self.assertIn("var s='<\\/script>'", self.html)

    def test_data_block_escapes_closing_tags_but_keeps_content(self):
        start = self.html.index('<script id="laglens-data"')
        end = self.html.index("</script>", start)
        self.assertNotIn("</", self.html[start + 50:end])
        ep = next(e for e in self.blob["episodes"] if e["id"] == "ep-000001")
        self.assertIn("note: " + F.XSS, ep["evidence"])
        self.assertIn(F.XSS, next(m for m in self.blob["marks"] if m["id"] == "mk-1")["note"])

    def test_no_password_token_or_mac(self):
        for secret in (F.PASSWORD, self.fx.token, F.MAC, F.MAC2, F.MAC2.lower(), F.MAC.upper()):
            self.assertNotIn(secret, self.html, secret)
        self.assertEqual(self.blob["config"]["docsis"]["password"], "***")
        ep = next(e for e in self.blob["episodes"] if e["id"] == "ep-000001")
        self.assertTrue(any("CM-MAC=xx:xx:xx:xx:xx:xx" in s for s in ep["evidence"]))
        self.assertIn("xx:xx:xx:xx:xx:xx", ep["docsis"]["log_lines"][0])
        poll = self.blob["docsis"]["polls"][-1]
        self.assertEqual(poll["mac"], "xx:xx:xx:xx:xx:xx")
        self.assertIn("xx:xx:xx:xx:xx:xx", poll["log_new"][0]["text"])
        # booleans with "token" in their name are not clobbered by the scrubber
        self.assertIs(self.blob["state"]["token_required"], True)

    def test_series_shape_and_values(self):
        s = self.blob["series"]
        self.assertEqual(s["res"], 5)
        n = len(s["t"])
        self.assertGreater(n, 100)
        self.assertEqual(s["t"][1] - s["t"][0], 5)
        for key in ("targets", "iface", "wan", "wifi", "docsis", "ntp", "segments", "slots_lost", "xbox_state", "stall"):
            self.assertIn(key, s)
        gw = s["targets"][str(self.fx.ids["gw4"])]
        for arr in ("p50", "p95", "max", "lost", "late", "n", "jit"):
            self.assertEqual(len(gw[arr]), n, arr)
        self.assertEqual(sum(v for v in gw["lost"] if v), 0)
        self.assertGreater(sum(v for v in gw["n"] if v), 2000)
        hop = s["targets"][str(self.fx.ids["isp_hop4"])]
        self.assertGreater(sum(v for v in hop["lost"] if v), 5)
        # the burst sits in the windows around t0+300..310
        burst_cols = [i for i, t in enumerate(s["t"]) if self.fx.t0 + 295 <= t < self.fx.t0 + 312]
        self.assertTrue(any(hop["lost"][i] for i in burst_cols))
        self.assertTrue(any(v for v in s["slots_lost"] if v and any(v)))
        self.assertIn("awake", s["xbox_state"])
        self.assertIn(1, s["stall"])
        self.assertTrue(any(v is not None and 9 <= v <= 12 for v in s["segments"]["docsis"]))
        self.assertTrue(any(v is not None for v in s["iface"]["rx_mbps"]))
        self.assertTrue(any(v is not None for v in s["wifi"]["rssi"]))
        self.assertTrue(any(v is not None for v in s["docsis"]["uncorr_delta"]))
        self.assertTrue(any(v is not None for v in s["ntp"]["offset_shift"]))

    def test_raw_slices_around_episodes_and_marks(self):
        rs = self.blob["raw_slices"]
        self.assertEqual(set(rs), {"ep-000001", "ep-000002", "mk-1", "mk-2"})
        ep = rs["ep-000001"]
        self.assertEqual(ep["from_ms"], int((self.fx.t0 + 300.25 - 90) * 1000))
        self.assertEqual(ep["to_ms"], int((self.fx.t0 + 309.5 + 90) * 1000))
        self.assertGreater(len(ep["rows"]), 1000)
        for row in ep["rows"]:
            self.assertEqual(len(row), 5)
            self.assertTrue(ep["from_ms"] <= row[0] < ep["to_ms"])
        self.assertTrue(any(r[1] == self.fx.ids["isp_hop4"] and r[3] & F_LOST for r in ep["rows"]))
        mk = rs["mk-1"]
        self.assertEqual(mk["to_ms"] - mk["from_ms"], 180 * 1000)

    def test_stats_activity_and_heatmap(self):
        st = self.blob["stats"]
        self.assertEqual(st["window"], "session")
        for key, tid in self.fx.ids.items():
            self.assertIn(str(tid), st["targets"], key)
        hop = st["targets"][str(self.fx.ids["isp_hop4"])]
        self.assertGreater(hop["lost"], 0)
        self.assertEqual(hop["episodes"], 1)
        self.assertEqual(self.blob["stats_1h"]["window"], "1h")
        self.assertEqual(set(self.blob["activity_stats"]), {"idle", "bf6"})
        cf = str(self.fx.ids["inet4_cf"])
        self.assertEqual(self.blob["activity_stats"]["idle"][cf]["lost"], 0)
        self.assertGreater(self.blob["activity_stats"]["bf6"][cf]["lost"], 0)
        hm = self.blob["hour_heatmap"]
        self.assertEqual([r["hour"] for r in hm], list(range(24)))
        self.assertEqual(sum(r["episodes"] for r in hm), 2)
        self.assertGreater(sum(r["windows"] for r in hm), 100)
        self.assertTrue(any(r["loss_pct"] and r["loss_pct"] > 0 for r in hm))

    def test_file_derived_blocks_when_components_absent(self):
        d = self.blob["docsis"]
        self.assertEqual(d["status"], "ok")
        self.assertEqual(len(d["polls"]), 3)
        self.assertEqual(d["log"][0]["class"], "t3")
        self.assertEqual(self.blob["igd"]["status"], "Connected")
        self.assertEqual(self.blob["igd"]["mappings"][0]["ext"], 3074)
        self.assertEqual(len(self.blob["path"]["v4"]), 3)
        self.assertEqual(self.blob["loadtests"][0]["grade"], "D")
        self.assertEqual(len(self.blob["doctor"]), 2)
        self.assertEqual(self.blob["collectors"]["wifi"]["reason"], "wired interface")
        self.assertEqual(self.blob["collectors"]["report"]["status"], "ok")
        self.assertEqual(len(self.blob["tags"]), 2)
        self.assertEqual(len(self.blob["events"]), 4)

    def test_verdict_comcast_and_session(self):
        self.assertEqual(self.blob["verdict"]["confidence"], "medium")
        # INTERFACES §10.2: the Tell-Comcast text comes from engine.verdict.comcast_text(ctx), not
        # from the (fixture-faked) verdict["comcast"]; the same text is written to comcast_evidence.txt.
        from laglens.engine import verdict as verdictmod

        expected = verdictmod.comcast_text(self.fx.ctx, now=self.blob["generated_at"], write=False)
        self.assertEqual(self.blob["comcast_text"], expected)
        self.assertIn(F.SESSION_ID, self.blob["comcast_text"])
        self.assertIn("Comcast", self.blob["comcast_text"])
        self.assertEqual((self.fx.dir / "comcast_evidence.txt").read_text(encoding="utf-8").strip(), expected.strip())
        for secret in (F.PASSWORD, self.fx.token, F.MAC, F.MAC2):
            self.assertNotIn(secret, self.blob["comcast_text"])
        self.assertEqual(self.blob["session"]["id"], F.SESSION_ID)
        self.assertEqual(self.blob["session"]["label"], F.LABEL)
        self.assertEqual(self.blob["session"]["config"]["docsis"]["password"], "***")
        self.assertEqual(self.blob["state"]["session"]["id"], F.SESSION_ID)
        self.assertEqual(len(self.blob["targets"]), len(F.TARGET_SPECS))

    def test_methodology_and_collector_entry(self):
        m = self.blob["methodology"]
        self.assertGreaterEqual(len(m), 10)
        text = " ".join(m)
        self.assertIn("ICMP to the gateway is answered by its CPU", text)
        self.assertIn("Hop loss alone is not evidence", text)
        self.assertIn("parallel witness", text)
        c = self.fx.state.collector("report")
        self.assertEqual(c["status"], "ok")
        self.assertEqual(c["size"], len(self.html))
        self.assertEqual(self.builder.builds, 1)


class BuilderBehaviourTests(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp()
        self.fx = F.make_session(self.tmp, duration_s=120)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self.fx.store.stop)

    def test_skipped_while_store_not_writing(self):
        self.fx.store.writing = False
        self.fx.store.disk["reason"] = "free space below 500 MB (12 MB free): writing stopped"
        b = B.ReportBuilder(self.fx.ctx)
        self.assertIsNone(b.build())
        self.assertFalse((self.fx.dir / "report.html").exists())
        c = self.fx.state.collector("report")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("free space below", c["reason"])
        self.fx.store.writing = True
        self.assertIsNotNone(b.build(final=True))
        self.assertEqual(self.fx.state.collector("report")["status"], "ok")

    def test_thread_builds_on_episode_close_and_periodically(self):
        b = B.ReportBuilder(self.fx.ctx, interval_s=60.0, debounce_s=0.2, poll_s=0.05)
        b.start()
        try:
            self.fx.state.publish("episode_close", {"id": "ep-000001"})
            deadline = time.monotonic() + 5.0
            while b.builds < 1 and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(b.builds, 1)
            self.assertTrue((self.fx.dir / "report.html").exists())
        finally:
            self.fx.state.stop_event.set()
            b.stop(2.0)
        self.assertFalse(b.thread.is_alive())
        b2 = B.ReportBuilder(self.fx.ctx, interval_s=0.3, debounce_s=10.0, poll_s=0.05)
        self.fx.state.stop_event.clear()
        b2.start()
        try:
            deadline = time.monotonic() + 5.0
            while b2.builds < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertGreaterEqual(b2.builds, 2)
        finally:
            self.fx.state.stop_event.set()
            b2.stop(2.0)

    def test_build_failure_is_reported_not_raised(self):
        b = B.ReportBuilder(self.fx.ctx)
        orig = B.render_html

        def boom(*a, **k):
            raise RuntimeError("template exploded")

        B.render_html = boom
        try:
            self.assertIsNone(b.build())
        finally:
            B.render_html = orig
        c = self.fx.state.collector("report")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("template exploded", c["reason"])

    def test_size_limit_drops_oldest_raw_slices(self):
        # Needs a session long enough that the episodes/marks (at +300 s / +450 s / +500 s) have raw
        # samples: with the 120 s fixture every slice is empty and nothing can be dropped.
        tmp = _tmp()
        self.addCleanup(shutil.rmtree, tmp, True)
        fx = F.make_session(tmp, duration_s=600)
        self.addCleanup(fx.store.stop)
        full = F.data_blob(B.ReportBuilder(fx.ctx).build().read_text(encoding="utf-8"))
        self.assertEqual(len(full["raw_slices"]), 4)
        self.assertNotIn("raw_slices_truncated", full)
        orig = B.SIZE_LIMIT_BYTES
        B.SIZE_LIMIT_BYTES = 60 * 1024
        try:
            blob = F.data_blob(B.ReportBuilder(fx.ctx).build().read_text(encoding="utf-8"))
        finally:
            B.SIZE_LIMIT_BYTES = orig
        self.assertTrue(blob.get("raw_slices_truncated"))
        self.assertLess(len(blob["raw_slices"]), 4)
        # the newest slices survive, the oldest go first
        kept = sorted(blob["raw_slices"], key=lambda k: blob["raw_slices"][k]["from_ms"])
        dropped = sorted(set(full["raw_slices"]) - set(kept), key=lambda k: full["raw_slices"][k]["from_ms"])
        if kept and dropped:
            self.assertLessEqual(full["raw_slices"][dropped[-1]]["from_ms"], blob["raw_slices"][kept[0]]["from_ms"])

    def test_components_are_preferred_over_files(self):
        class Docsis:
            def recent(self, n=20):
                return {"status": "ok", "polls": [{"t": 1, "ok": True, "src": "component"}], "log": []}

        class Igd:
            def status(self):
                return {"status": "ok", "trusted": True, "uptime_s": 7, "ext_ip": "73.1.2.3", "mappings": []}

        class Tracer:
            def current(self):
                return {"v4": [{"ttl": 1, "ip": "10.0.0.1", "role": "gateway"}], "v6": [], "roles": {}, "discovered_at": 1,
                        "changes": 2, "history": [], "method": "component"}

        class Broken:
            def recent(self, n=20):
                raise RuntimeError("no")

        self.fx.ctx.components.update({"docsis": Docsis(), "igd": Igd(), "tracer": Tracer()})
        blob = F.data_blob(B.ReportBuilder(self.fx.ctx).build().read_text(encoding="utf-8"))
        self.assertEqual(blob["docsis"]["polls"][0]["src"], "component")
        self.assertEqual(blob["igd"]["uptime_s"], 7)
        self.assertEqual(blob["path"]["method"], "component")
        self.fx.ctx.components["docsis"] = Broken()
        blob = F.data_blob(B.ReportBuilder(self.fx.ctx).build().read_text(encoding="utf-8"))
        self.assertEqual(len(blob["docsis"]["polls"]), 3)  # file fallback

    def test_server_series_and_verdict_modules_are_used_when_present(self):
        saved = {k: sys.modules.get(k) for k in ("laglens.server", "laglens.server.series", "laglens.engine.verdict")}
        server = types.ModuleType("laglens.server")
        series = types.ModuleType("laglens.server.series")
        calls = []

        def build_series(ctx_or_state, store, t_from, t_to, res, target_ids=None):
            calls.append((res, target_ids))
            return {"res": res, "from": t_from, "to": t_to, "t": [1, 2, 3], "targets": {}, "marker": "server"}

        series.build_series = build_series
        verdict = types.ModuleType("laglens.engine.verdict")
        verdict.comcast_text = lambda ctx: "LIVE COMCAST TEXT for %s" % ctx.state.session_id
        sys.modules["laglens.server"] = server
        sys.modules["laglens.server.series"] = series
        sys.modules["laglens.engine.verdict"] = verdict
        try:
            blob = F.data_blob(B.ReportBuilder(self.fx.ctx).build().read_text(encoding="utf-8"))
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        self.assertEqual(blob["series"]["marker"], "server")
        self.assertEqual(calls, [(5, None)])
        self.assertEqual(blob["comcast_text"], "LIVE COMCAST TEXT for " + F.SESSION_ID)
        self.assertEqual((self.fx.dir / "comcast_evidence.txt").read_text(encoding="utf-8").strip(),
                         "LIVE COMCAST TEXT for " + F.SESSION_ID)

    def test_fallback_template_when_web_assets_missing(self):
        self.fx.ctx.root = self.tmp / "nowhere"
        b = B.ReportBuilder(self.fx.ctx)
        html = b.build().read_text(encoding="utf-8")
        blob = F.data_blob(html)
        self.assertEqual(blob["session"]["id"], F.SESSION_ID)
        self.assertIn("built-in fallback", html)
        for name in PLACEHOLDER_NAMES:
            self.assertNotIn("{{%s}}" % name, html)


class ThinningTests(unittest.TestCase):
    """A 12 h synthetic session: series folded to every 3rd window, page under 8 MB."""

    def setUp(self):
        self.tmp = _tmp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        F.make_web_tree(self.tmp)

    def _ctx(self, hours):
        now = time.time()
        t0 = now - hours * 3600
        cfg = F.make_cfg()
        state = State(t0=t0, session_id="20261011-070000", cfg=cfg)
        store = Store(self.tmp / "sessions" / "20261011-070000", cfg, resume=False, state=state,
                      disk_usage=lambda p: F._Usage())
        self.addCleanup(store.stop)
        keys = ["gw4", "inet4_cf", "inet4_g", "inet6_cf", "inet6_g", "isp_hop4", "mid_hop4", "dns_cf4", "tcp_cf4", "ntp_cf"]
        for k in keys:
            state.add_target(Target(id=-1, key=k, role="anycast", addr="1.1.1.1", family=4, kind="icmp", label=k))
        first = (int(t0) // 5) * 5 + 5
        t = first
        windows = 0
        while t + 5 <= now - 15:
            for tid in range(len(keys)):
                lost = 1 if (windows % 97 == 0 and tid > 0) else 0
                state.add_rollup(5, Rollup(t=t, id=tid, n=20, lost=lost, late=0, err=0, min=10.0, p50=12.0 + tid,
                                           p95=15.0 + tid, max=30.0, jit=1.2, stall=0))
            state.add_row5("slots", {"t": t, "slots": [0] * 20, "late_slots": [0] * 20})
            state.add_row5("iface", {"t": t, "iface": {"rx_mbps": 0.5, "tx_mbps": 0.1, "rx_err": 0, "tx_err": 0}})
            t += 5
            windows += 1
        ctx = AppContext(cfg, argparse.Namespace(), state, store, F.StubPlatform(), root=self.tmp,
                         sessions_root=self.tmp / "sessions")
        return ctx, windows

    def test_twelve_hours_is_folded_to_15s_and_under_8mb(self):
        ctx, windows = self._ctx(12)
        self.assertGreater(windows, 8500)
        html = B.ReportBuilder(ctx).build().read_text(encoding="utf-8")
        self.assertLess(len(html.encode("utf-8")), B.SIZE_LIMIT_BYTES)
        blob = F.data_blob(html)
        s = blob["series"]
        self.assertEqual(s["res"], 15)
        self.assertEqual(s["thinned"], 3)
        self.assertTrue(all(b - a == 15 for a, b in zip(s["t"], s["t"][1:])))
        self.assertTrue(2800 <= len(s["t"]) <= 2900, len(s["t"]))
        cf = s["targets"]["1"]
        self.assertEqual(len(cf["n"]), len(s["t"]))
        # counts are folded (3 windows x 20 probes), p95 keeps the max, nothing is dropped
        self.assertEqual(sum(v for v in cf["n"] if v), windows * 20)
        self.assertEqual(sum(v for v in cf["lost"] if v), sum(1 for w in range(windows) if w % 97 == 0))
        self.assertEqual(max(v for v in cf["p95"] if v is not None), 16.0)
        self.assertEqual(len(s["slots_lost"][0]), 60)
        self.assertEqual(len(blob["hour_heatmap"]), 24)
        self.assertGreater(sum(r["windows"] for r in blob["hour_heatmap"]), 8000)

    def test_short_session_keeps_5s_resolution(self):
        ctx, windows = self._ctx(2)
        blob = F.data_blob(B.ReportBuilder(ctx).build().read_text(encoding="utf-8"))
        self.assertEqual(blob["series"]["res"], 5)
        self.assertNotIn("thinned", blob["series"])
        self.assertTrue(all(b - a == 5 for a, b in zip(blob["series"]["t"], blob["series"]["t"][1:])))


class RebuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _check_common(self, blob, fx):
        self.assertTrue(blob["rebuilt"])
        for key in F.BLOB_KEYS:
            self.assertIn(key, blob, key)
        self.assertEqual(blob["session"]["id"], F.SESSION_ID)
        self.assertEqual(blob["replayed_samples"], fx.sample_count)
        self.assertEqual([e["id"] for e in blob["episodes"]], ["ep-000001", "ep-000002"])  # open+close rows deduped
        self.assertEqual(blob["episodes"][0]["class"], "docsis_access")
        self.assertIsNotNone(blob["episodes"][0]["sweep"])
        self.assertEqual(len(blob["marks"]), 2)
        self.assertEqual(len(blob["events"]), 4)
        self.assertEqual(len(blob["tags"]), 2)
        self.assertEqual(set(blob["raw_slices"]), {"ep-000001", "ep-000002", "mk-1", "mk-2"})
        self.assertGreater(len(blob["raw_slices"]["ep-000001"]["rows"]), 1000)
        for key, tid in fx.ids.items():
            tot = fx.state.totals[tid]
            got = blob["stats"]["targets"][str(tid)]
            self.assertEqual((got["sent"], got["lost"]), (tot.sent, tot.lost), key)
        s = blob["series"]
        self.assertEqual(s["res"], 5)
        hop = s["targets"][str(fx.ids["isp_hop4"])]
        self.assertGreater(sum(v for v in hop["lost"] if v), 5)
        self.assertTrue(any(v is not None for v in s["iface"]["rx_mbps"]))  # collector rows from the file
        self.assertTrue(any(v for v in s["slots_lost"] if v and any(v)))
        self.assertEqual(len(blob["path"]["v4"]), 3)
        self.assertEqual(len(blob["docsis"]["polls"]), 3)
        self.assertEqual(blob["igd"]["status"], "Connected")
        self.assertIn(blob["verdict"]["confidence"], ("low", "medium", "high"))
        self.assertTrue(blob["verdict"]["text"])
        self.assertEqual(blob["verdict"]["top"][0]["class"], "docsis_access")
        self.assertIsNotNone(blob["state"]["health"]["session"])
        # comcast_evidence.txt is preferred when present (written by the live builder), otherwise the
        # engine renders it offline and the rebuild writes the file; either way blob == file.
        self.assertIn(F.SESSION_ID, blob["comcast_text"])
        self.assertIn("Comcast", blob["comcast_text"])
        self.assertEqual((fx.dir / "comcast_evidence.txt").read_text(encoding="utf-8").strip(),
                         blob["comcast_text"].strip())
        self.assertEqual(set(blob["activity_stats"]), {"idle", "bf6"})
        self.assertEqual(sum(r["episodes"] for r in blob["hour_heatmap"]), 2)
        self.assertEqual(blob["state"]["state"], "STOPPED")
        self.assertEqual(blob["config"]["docsis"]["password"], "***")

    def test_rebuild_closed_gz_session(self):
        fx = F.make_session(self.tmp, duration_s=600, close=True)
        self.assertTrue((fx.dir / "samples.bin.gz").exists())
        self.assertFalse((fx.dir / "samples.bin").exists())
        (fx.dir / "report.html").unlink(missing_ok=True) if hasattr(Path, "unlink") else None
        out = B.rebuild(fx.dir, fx.cfg, root=fx.root)
        self.assertIsInstance(out, Path)
        self.assertEqual(out, fx.dir / "report.html")
        html = out.read_text(encoding="utf-8")
        blob = F.data_blob(html)
        self._check_common(blob, fx)
        self.assertTrue(blob["clean_shutdown"])
        self.assertEqual(blob["session"]["stopped"], fx.t_end)
        # a clean session.json carries the verdict/health the live run stored: they are kept as-is
        self.assertEqual(blob["verdict"]["confidence"], "medium")
        self.assertEqual(blob["verdict"]["text"], fx.state.verdict["text"])
        self.assertEqual(blob["state"]["health"], {"now": 88, "session": 83})
        for secret in (F.PASSWORD, fx.token, F.MAC, F.MAC2, F.MAC2.lower()):
            self.assertNotIn(secret, html)
        self.assertIn("TEMPLATE-SENTINEL", html)
        self.assertFalse((fx.dir / "samples.bin").exists(), "rebuild must not inflate the archive")

    def test_rebuild_torn_crashed_session(self):
        fx = F.make_session(self.tmp, duration_s=600)
        fx.store.flush()
        fx.store.stop()  # closes files; then undo the gzip to simulate a crash mid-run
        gz = fx.dir / "samples.bin.gz"
        with gzip.open(gz, "rb") as fh:
            raw = fh.read()
        gz.unlink()
        (fx.dir / "samples.bin").write_bytes(raw[:-7])  # torn trailing record
        # The torn record never reached the file, so the rebuilt totals lack it: take it out of the
        # live totals the check compares against (the fixture state still counted it).
        torn = SAMPLE_STRUCT.unpack(raw[-SAMPLE_SIZE:])
        tot = fx.state.totals[torn[1]]
        tot.sent -= 1
        if torn[3] & F_LOST:
            tot.lost -= 1
        hgz = fx.dir / "host.jsonl.gz"
        if hgz.exists():
            hgz.unlink()
        for name in ("episodes.jsonl", "events.jsonl", "rollups.jsonl", "marks.jsonl", "xb7.jsonl"):
            with open(fx.dir / name, "ab") as fh:
                fh.write(b'{"id":"torn","t":12345,"n":3,"lo')
        (fx.dir / "session.json").write_text('{"id": "20261011-190000", "started": %r, "sto' % fx.t0, encoding="utf-8")
        with open(fx.dir / "targets.json", "r+", encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["targets"].append({"id": "bad", "key": None})
        doc["targets"].append("junk")
        (fx.dir / "targets.json").write_text(json.dumps(doc), encoding="utf-8")
        out = B.rebuild(fx.dir, fx.cfg, root=fx.root)
        blob = F.data_blob(out.read_text(encoding="utf-8"))
        fx.sample_count -= 1  # the torn record
        self._check_common(blob, fx)
        self.assertFalse(blob["clean_shutdown"])
        self.assertIsNone(blob["session"].get("stopped"))
        self.assertAlmostEqual(blob["session"]["started"], fx.t0, places=2)
        self.assertIn("no clean shutdown", blob["state"]["pill"])
        # the torn session.json lost the stored verdict/health: both are recomputed offline from
        # the replayed state (episodes.jsonl, marks.jsonl, samples.bin)
        self.assertNotEqual(blob["verdict"]["text"], fx.state.verdict["text"])
        self.assertIn("docsis_access", [t["class"] for t in blob["verdict"]["top"]])
        self.assertEqual(blob["verdict"]["marks"], {"total": 2, "linked": 1})
        self.assertTrue(0 <= blob["state"]["health"]["session"] <= 100)
        self.assertTrue((fx.dir / "comcast_evidence.txt").exists())

    def test_rebuild_reads_comcast_file_and_handles_truncated_gz(self):
        fx = F.make_session(self.tmp, duration_s=300, close=True)
        (fx.dir / "comcast_evidence.txt").write_text("FROM FILE\n", encoding="utf-8")
        gz = fx.dir / "samples.bin.gz"
        data = gz.read_bytes()
        gz.write_bytes(data[: len(data) // 2])
        blob = F.data_blob(B.rebuild(fx.dir, fx.cfg, root=fx.root).read_text(encoding="utf-8"))
        self.assertEqual(blob["comcast_text"], "FROM FILE")
        self.assertGreater(blob["replayed_samples"], 100)
        self.assertLess(blob["replayed_samples"], fx.sample_count)

    def test_rebuild_minimal_and_missing_dirs(self):
        sdir = self.tmp / "sessions" / "20261012-010203"
        sdir.mkdir(parents=True)
        (sdir / "targets.json").write_text(json.dumps({"targets": [
            {"id": 0, "key": "gw4", "role": "gateway", "addr": "10.0.0.1", "family": 4, "kind": "icmp", "label": "gw"}]}))
        out = B.rebuild(sdir, F.make_cfg(), root=self.tmp)
        blob = F.data_blob(out.read_text(encoding="utf-8"))
        self.assertEqual(blob["replayed_samples"], 0)
        self.assertEqual(blob["session"]["id"], "20261012-010203")
        self.assertEqual(time.strftime("%Y%m%d-%H%M%S", time.localtime(blob["session"]["started"])), "20261012-010203")
        self.assertEqual(blob["episodes"], [])
        self.assertIsNone(blob["docsis"])
        self.assertIsNone(blob["igd"])
        with self.assertRaises(FileNotFoundError):
            B.rebuild(self.tmp / "sessions" / "nope", F.make_cfg())


class UnitTests(unittest.TestCase):
    def test_scrub(self):
        out = B.scrub({"token_required": True, "bssid": F.MAC, "mac": "", "password": None,
                       "docsis": {"password": "pw-secret-1", "username": "admin"},
                       "text": "CM-MAC=%s and %s v6 2606:4700:4700::1111 fe80::1 pw-secret-1" % (F.MAC, F.MAC2),
                       "nan": float("nan"), "inf": float("inf"), "list": [F.MAC, 1, None, 2.5], "tuple": (1, 2)},
                      secrets=["pw-secret-1"])
        self.assertIs(out["token_required"], True)
        self.assertEqual(out["bssid"], "xx:xx:xx:xx:xx:xx")
        self.assertEqual(out["mac"], "")
        self.assertIsNone(out["password"])
        self.assertEqual(out["docsis"], {"password": "***", "username": "admin"})
        self.assertEqual(out["text"], "CM-MAC=xx:xx:xx:xx:xx:xx and xx:xx:xx:xx:xx:xx v6 2606:4700:4700::1111 fe80::1 ***")
        self.assertIsNone(out["nan"])
        self.assertIsNone(out["inf"])
        self.assertEqual(out["list"], ["xx:xx:xx:xx:xx:xx", 1, None, 2.5])
        self.assertEqual(out["tuple"], [1, 2])
        self.assertEqual(B.escape_json_for_html('{"a":"</script>"}'), '{"a":"<\\/script>"}')
        pre = B.scrub({"v6_prefix": "2601:abcd:4321:abe0::/64", "wan": {"prefix6": "2601:abcd:4321:abe0::/64", "ext_ip6": "2601:abcd:4321:abe0::1"},
                       "short": {"v6_prefix": "fe80::/64"}, "done": {"v6_prefix": "2601:abcd:4321::/64 (truncated)"}})
        self.assertEqual(pre["v6_prefix"], "2601:abcd:4321::/64 (truncated)")
        self.assertEqual(pre["wan"]["prefix6"], "2601:abcd:4321::/64 (truncated)")
        self.assertEqual(pre["wan"]["ext_ip6"], "2601:abcd:4321:abe0::1")  # the WAN address itself is allowed
        self.assertEqual(pre["short"]["v6_prefix"], "fe80::/64")
        self.assertEqual(pre["done"]["v6_prefix"], "2601:abcd:4321::/64 (truncated)")
        # an EUI-64 interface id is a MAC address in disguise (the XB7's global address is hop 1 of the v6 path)
        eui = B.scrub({"roles": {"gw6": "2601:abcd:4321:abe0:211:22ff:fe33:4455"}, "ll": "fe80::211:22ff:fe33:4455%en0",
                       "txt": "hop 2601:abcd:4321:abe0:211:22ff:fe33:4455 answered", "plain": "2001:558:aaaa:bbbb::2",
                       "host": "2601:abcd:4321:abe0:1111:2222:3333:4444"})
        self.assertEqual(eui["roles"]["gw6"], "2601:abcd:4321:abe0:xxxx:xxff:fexx:xxxx")
        self.assertEqual(eui["ll"], "fe80::xxxx:xxff:fexx:xxxx%en0")
        self.assertEqual(eui["txt"], "hop 2601:abcd:4321:abe0:xxxx:xxff:fexx:xxxx answered")
        self.assertEqual(eui["plain"], "2001:558:aaaa:bbbb::2")  # not EUI-64: untouched
        self.assertEqual(eui["host"], "2601:abcd:4321:abe0:1111:2222:3333:4444")  # a privacy address: untouched

    def test_salvage_torn_session_json(self):
        sdir = _tmp("laglens-salvage-")
        self.addCleanup(shutil.rmtree, sdir, True)
        p = sdir / "session.json"
        p.write_text('{"id": "20261011-190000", "version": "1.0.0", "os": "darwin", "started": 1791748407.074552, '
                     '"stopped": null, "resumed_count": 2, "label": "xbox on port 2", "summary": {"sa', encoding="utf-8")
        got = B.salvage_session_json(p)
        self.assertEqual(got["id"], "20261011-190000")
        self.assertEqual(got["started"], 1791748407.074552)
        self.assertEqual(got["label"], "xbox on port 2")
        self.assertEqual(got["resumed_count"], 2)
        self.assertNotIn("stopped", got)
        self.assertTrue(got["torn"])
        self.assertEqual(B.salvage_session_json(sdir / "missing.json"), {})
        p.write_text("garbage", encoding="utf-8")
        self.assertEqual(B.salvage_session_json(p), {})

    def test_iter_sample_rows_plain_torn_and_gz_torn(self):
        sdir = _tmp("laglens-rows-")
        self.addCleanup(shutil.rmtree, sdir, True)
        recs = b"".join(pack_sample(Sample(ts_ms=1_000 + i, target_id=1, kind=KIND_ICMP, flags=0, seq=i, value=i))
                        for i in range(50))
        (sdir / "samples.bin").write_bytes(recs + b"\x01\x02\x03")
        rows = list(B.iter_sample_rows(sdir))
        self.assertEqual(len(rows), 50)
        self.assertEqual(rows[-1][4], 49)
        (sdir / "samples.bin").unlink()
        gzdata = gzip.compress(recs)
        (sdir / "samples.bin.gz").write_bytes(gzdata)
        self.assertEqual(len(list(B.iter_sample_rows(sdir))), 50)
        (sdir / "samples.bin.gz").write_bytes(gzdata[:-12])
        rows = list(B.iter_sample_rows(sdir))
        self.assertTrue(0 < len(rows) <= 50)
        (sdir / "samples.bin.gz").unlink()
        self.assertEqual(list(B.iter_sample_rows(sdir)), [])

    def test_collect_slices_handles_out_of_order_rows(self):
        w1 = B.SliceWindow("a", 10.0, 10.0, 20.0)
        w2 = B.SliceWindow("b", 100.0, 100.0, 110.0)
        rows = [(5_000, 1, 0, 0, 1, 5), (12_000, 1, 0, 0, 2, 5), (19_999, 1, 0, 0, 3, 5), (20_000, 1, 0, 0, 4, 5),
                (25_000, 1, 0, 0, 5, 5), (15_000, 1, 0, 2, 2, 7), (105_000, 2, 0, 1, 6, -1), (200_000, 1, 0, 0, 7, 5)]
        B.collect_slices(rows, [w2, w1])
        self.assertEqual([r[0] for r in w1.rows], [12_000, 19_999, 15_000])
        self.assertEqual(w1.rows[-1], [15_000, 1, 0, 2, 7])
        self.assertEqual(w2.rows, [[105_000, 2, 0, 1, -1]])
        many = [{"id": "ep-%d" % i, "t0": 1000.0 + i * 10, "t1": 1005.0 + i * 10} for i in range(80)]
        wins = B.slice_windows(many, [{"id": "mk-1", "t_est": 100.0}], now=5000.0)
        self.assertEqual(len(wins), B.RAW_MAX_SLICES)
        self.assertEqual(wins[0].id, "ep-79")
        self.assertNotIn("mk-1", [w.id for w in wins])
        long_ep = B.slice_windows([{"id": "ep-l", "t0": 1000.0, "t1": 9000.0}], [], now=9999.0)[0]
        self.assertEqual(long_ep.to_ms - long_ep.from_ms, B.RAW_SLICE_MAX_S * 1000)
        open_ep = B.slice_windows([{"id": "ep-o", "t0": 1000.0, "t1": None}], [], now=1030.0)[0]
        self.assertEqual(open_ep.to_ms, 1120_000)

    def test_series_local_from_file_rows_and_thinning(self):
        st = State(t0=1000.0, session_id="x")
        st.add_target(Target(id=0, key="gw4", role="gateway", addr="10.0.0.1", family=4, kind="icmp", label="gw"))
        st.add_target(Target(id=1, key="isp_hop4", role="isp_hop", addr="10.60.0.1", family=4, kind="icmp", label="hop"))
        st.add_target(Target(id=2, key="inet4_cf", role="anycast", addr="1.1.1.1", family=4, kind="icmp", label="cf"))
        rows = []
        for i in range(6):
            t = 1000 + i * 5
            rows.append({"t": t, "id": 0, "n": 20, "lost": 0, "late": 0, "err": 0, "min": 1, "p50": 1.0, "p95": 2.0, "max": 3,
                         "jit": 0.1, "stall": 0})
            rows.append({"t": t, "id": 1, "n": 10, "lost": i, "late": 1, "err": 0, "min": 10, "p50": 11.0, "p95": 12.0,
                         "max": 20, "jit": 0.5, "stall": 0})
            rows.append({"t": t, "id": 2, "n": 20, "lost": 0, "late": 0, "err": 0, "min": 14, "p50": 15.0, "p95": 18.0,
                         "max": 30, "jit": 0.7, "stall": 0})
            rows.append({"t": t, "iface": {"rx_mbps": 1.0, "tx_mbps": 0.5, "rx_err": 1, "tx_err": 2, "rx_drop": 0,
                                           "tx_drop": 1, "carrier_changes": 0, "mcast_pps": 3}})
            rows.append({"t": t, "host": {"late_ms_max": 90 if i == 2 else 1, "loop_gap_ms": 5}})
            rows.append({"t": t, "ntp": {"cf": {"rtt": 10, "offset": -1.0 + i * 0.5}}})
            rows.append({"t": t, "slots": [1 << 1 if i == 3 else 0] * 20, "late_slots": [0] * 20})
        rows.append({"t": "bad"})
        rows.append({"t": 99999, "id": 0, "n": 1})  # outside the grid
        s = B.build_series_local(st, None, 1000.0, 1030.0, file_rows=rows)
        self.assertEqual(s["t"], [1000, 1005, 1010, 1015, 1020, 1025])
        self.assertEqual(s["targets"]["1"]["lost"], [0, 1, 2, 3, 4, 5])
        self.assertEqual(s["iface"]["err"], [3] * 6)
        self.assertEqual(s["iface"]["drop"], [1] * 6)
        self.assertEqual(s["stall"], [0, 0, 1, 0, 0, 0])
        self.assertEqual(s["ntp"]["offset_shift"], [None, 0.5, 0.5, 0.5, 0.5, 0.5])
        self.assertEqual(s["segments"]["lan"], [1.0] * 6)
        self.assertEqual(s["segments"]["docsis"], [10.0] * 6)
        self.assertEqual(s["segments"]["internet"], [4.0] * 6)
        self.assertEqual(s["slots_lost"][3][0], 2)
        # RAM ring rows overwrite file rows for the same (t, id)
        st.add_rollup(5, Rollup(t=1010, id=1, n=10, lost=9, late=0, err=0, min=1, p50=1, p95=1, max=1, jit=None, stall=0))
        s = B.build_series_local(st, None, 1000.0, 1030.0, file_rows=rows)
        self.assertEqual(s["targets"]["1"]["lost"][2], 9)
        thin = B.thin_series(s, 3)
        self.assertEqual(thin["t"], [1000, 1015])
        self.assertEqual(thin["res"], 15)
        self.assertEqual(thin["targets"]["1"]["lost"], [10, 12])
        self.assertEqual(thin["targets"]["1"]["n"], [30, 30])
        self.assertEqual(thin["targets"]["1"]["p95"], [12.0, 12.0])
        self.assertEqual(thin["stall"], [1, 0])
        self.assertEqual(len(thin["slots_lost"][1]), 60)
        self.assertEqual(thin["iface"]["err"], [3, 3])
        self.assertIs(B.thin_series(s, 1), s)

    def test_file_derived_blocks(self):
        self.assertIsNone(B.docsis_from_rows([]))
        d = B.docsis_from_rows([{"t": 1, "ok": False}, {"t": 2, "ok": True, "log_new": [{"class": "t3"}]}], last=1)
        self.assertEqual(d["status"], "ok")
        self.assertEqual(len(d["polls"]), 1)
        self.assertEqual(d["log"], [{"class": "t3"}])
        self.assertEqual(B.docsis_from_rows([{"t": 1, "ok": False}])["status"], "error")
        self.assertIsNone(B.igd_from_rows([]))
        self.assertEqual(B.igd_from_rows([{"t": 1}, {"t": 2, "uptime_s": 5}])["uptime_s"], 5)
        p = B.path_from_rows([{"t": 1, "dst": "1.1.1.1", "hops": [{"ttl": 1}], "changed": True, "method": "m"},
                              {"t": 2, "dst": "2606::1", "hops": [{"ttl": 1}, {"ttl": 2}], "changed": True}],
                             base={"changes": 1, "discovered_at": None})
        self.assertEqual(len(p["v4"]), 1)
        self.assertEqual(len(p["v6"]), 2)
        self.assertEqual(p["changes"], 2)
        self.assertEqual(p["discovered_at"], 2)
        self.assertEqual(p["method"], "m")
        self.assertEqual(len(p["history"]), 2)

    def test_render_with_fallback_template_and_hour_heatmap(self):
        assets = B.load_assets(Path(tempfile.gettempdir()) / "laglens-does-not-exist")
        self.assertIn("report_template.html", assets["missing"])
        html = B.render_html({"session": {"id": "s"}, "x": "</script>"}, assets)
        self.assertIn('<script id="laglens-data" type="application/json">{"session":{"id":"s"},"x":"<\\/script>"}</script>', html)
        self.assertIn("<title>Lag Lens report s</title>", html)
        st = State(t0=1000.0, session_id="h")
        st.add_target(Target(id=0, key="inet4_cf", role="anycast", addr="1.1.1.1", family=4, kind="icmp", label="cf"))
        st.add_rollup(5, Rollup(t=1000, id=0, n=20, lost=5, late=0, err=0, min=1, p50=2, p95=9.0, max=3, jit=0, stall=0))
        hm = B.hour_heatmap(st, 990.0, 1100.0, [{"t0": 1001.0}, {"t0": "x"}])
        h = time.localtime(1000).tm_hour
        self.assertEqual(hm[h]["loss_pct"], 25.0)
        self.assertEqual(hm[h]["p95"], 9.0)
        self.assertEqual(hm[h]["episodes"], 1)
        self.assertEqual(sum(r["windows"] for r in hm), 1)


if __name__ == "__main__":
    unittest.main()
