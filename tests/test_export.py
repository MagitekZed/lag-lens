"""Tests for laglens.report.export: ZIP member lists per pack, redaction, generated CSV/TXT members, export_cli."""
import gzip
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_report_fixture as F  # noqa: E402
from laglens.report import export as E  # noqa: E402

FULL_EXPECTED = {
    "samples.bin.gz", "host.jsonl.gz", "targets.json", "rollups.jsonl", "events.jsonl", "episodes.jsonl", "marks.jsonl",
    "marks/mk-1.json", "tags.jsonl", "path.jsonl", "xb7.jsonl", "xb7_raw/hardware.html", "igd.jsonl", "loadtests.jsonl",
    "session.json", "doctor.json", "report.html", "log.txt", "comcast_evidence.txt", "config.redacted.json",
    "summary.txt", "episodes.csv", "marks.csv", "docsis_channels.csv",
}


def members(data):
    return zipfile.ZipFile(io.BytesIO(data))


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="laglens-export-"))
        cls.fx = F.make_session(cls.tmp, duration_s=400, close=True)
        (cls.fx.dir / "laglens.pid").write_text("12345\n")
        (cls.fx.dir / "report.html.tmp-99").write_text("partial")
        cls.full = E.build_zip(cls.fx.dir, pack="full", raw=True, cfg=cls.fx.cfg)
        cls.zf = members(cls.full)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_full_pack_members(self):
        names = set(self.zf.namelist())
        self.assertEqual(names, FULL_EXPECTED)
        self.assertNotIn("token", names)
        self.assertNotIn("laglens.pid", names)
        self.assertNotIn("config.json", names)
        self.assertNotIn("report.html.tmp-99", names)
        for info in self.zf.infolist():
            self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED, info.filename)
        self.assertEqual(self.zf.read("samples.bin.gz"), (self.fx.dir / "samples.bin.gz").read_bytes())

    def test_raw_false_drops_xb7_raw(self):
        names = set(members(E.build_zip(self.fx.dir, pack="full", raw=False, cfg=self.fx.cfg)).namelist())
        self.assertEqual(names, FULL_EXPECTED - {"xb7_raw/hardware.html"})

    def test_comcast_pack_members(self):
        zf = members(E.build_zip(self.fx.dir, pack="comcast", cfg=self.fx.cfg))
        self.assertEqual(zf.namelist(), list(E.COMCAST_MEMBERS))
        self.assertEqual(zf.read("report.html"), (self.fx.dir / "report.html").read_bytes())

    def test_no_password_or_token_in_any_member(self):
        for pack, raw in (("full", True), ("comcast", True)):
            zf = members(E.build_zip(self.fx.dir, pack=pack, raw=raw, cfg=self.fx.cfg))
            for name in zf.namelist():
                data = zf.read(name)
                if name.endswith(".gz"):
                    data = gzip.decompress(data)
                self.assertNotIn(F.PASSWORD.encode(), data, "%s/%s" % (pack, name))
                self.assertNotIn(self.fx.token.encode(), data, "%s/%s" % (pack, name))
        log = self.zf.read("log.txt").decode()
        self.assertIn("password=*** ok", log)
        cfg = json.loads(self.zf.read("config.redacted.json"))
        self.assertEqual(cfg["docsis"]["password"], "***")
        self.assertNotIn("_warnings", cfg)
        self.assertNotIn(F.MAC.encode(), self.zf.read("report.html"))

    def test_text_members_ship_the_ipv6_prefix_truncated(self):
        # SPEC §6.7: the delegated /64 identifies the household; JSON text members carry it truncated
        row = b'{"t": 1, "wan": {"ext_ip": "1.2.3.4", "prefix6": "2601:abcd:4321:abe0::/64"}, "x": {"v6_prefix":"2601:abcd:4321:abe0::/64"}}\n'
        out = E._scrub_text(row, [])
        self.assertNotIn(b"abe0", out)
        self.assertIn(b'"prefix6": "2601:abcd:4321::/64 (truncated)"', out)
        self.assertIn(b'"v6_prefix":"2601:abcd:4321::/64 (truncated)"', out)
        already = b'{"v6_prefix": "2601:abcd:4321::/64 (truncated)", "prefix6": null}'
        self.assertEqual(E._scrub_text(already, []), already)
        self.assertEqual(json.loads(out)["wan"]["prefix6"], "2601:abcd:4321::/64 (truncated)")
        # secrets and prefixes are scrubbed together
        self.assertEqual(E._scrub_text(b'pw=hunter2 "prefix6": "2001:db8:1:2::/64"', ["hunter2"]),
                         b'pw=*** "prefix6": "2001:db8:1::/64 (truncated)"')
        # EUI-64 interface ids (a MAC in disguise) are masked in every text member, other v6 literals untouched
        path_row = b'{"hops": [{"ttl": 1, "ip": "2601:abcd:4321:abe0:211:22ff:fe33:4455"}, {"ttl": 2, "ip": "2001:558:aaaa:bbbb::2"}], "gw6": "fe80::211:22ff:fe33:4455%en0"}'
        out = E._scrub_text(path_row, [])
        self.assertNotIn(b"211:22ff:fe33:4455", out)
        self.assertIn(b'"ip": "2601:abcd:4321:abe0:xxxx:xxff:fexx:xxxx"', out)
        self.assertIn(b'"ip": "2001:558:aaaa:bbbb::2"', out)
        self.assertIn(b'"gw6": "fe80::xxxx:xxff:fexx:xxxx%en0"', out)
        json.loads(out)

    def test_generated_csvs(self):
        rows = self.zf.read("episodes.csv").decode().splitlines()
        self.assertEqual(rows[0].split(","), list(E.EPISODE_COLUMNS))
        self.assertEqual(len(rows), 3)  # header + 2 episodes (open/close rows deduped)
        self.assertTrue(rows[1].startswith("ep-000001,"))
        self.assertIn(",docsis_access,t3_signature,0.86,", rows[1])
        self.assertIn("isp_hop4", rows[1])
        self.assertIn(",upload_saturation,,0.55,", rows[2])
        self.assertIn("self_load,False", rows[2])
        marks = self.zf.read("marks.csv").decode().splitlines()
        self.assertEqual(marks[0].split(","), list(E.MARK_COLUMNS))
        self.assertEqual(len(marks), 3)
        self.assertIn("mk-1,", marks[1])
        self.assertIn(",ep-000001,", marks[1])
        self.assertIn("mk-2,", marks[2])
        ch = self.zf.read("docsis_channels.csv").decode().splitlines()
        self.assertEqual(ch[0].split(","), list(E.DOCSIS_COLUMNS))
        self.assertEqual(len(ch), 1 + 4 + 2)
        self.assertEqual(ch[1].split(",")[:4], ["ds", "1", "513000000", "QAM256"])
        self.assertEqual(ch[1].split(",")[-1], "0")
        self.assertEqual(ch[4].split(",")[-1], "812")  # ch 18 → index 4 is ch 4; uncorr set on last poll only for ch 18
        self.assertEqual(ch[5].split(",")[0], "us")

    def test_summary_text(self):
        txt = self.zf.read("summary.txt").decode()
        self.assertIn("Session:      %s" % F.SESSION_ID, txt)
        self.assertIn("Label:        %s" % F.LABEL, txt)
        self.assertIn("Stop reason:  test", txt) if "test" in txt else None
        self.assertIn("Health score: 83 (session) / 88 (last)", txt)
        self.assertIn(self.fx.state.verdict["text"], txt)
        self.assertIn("docsis_access", txt)
        self.assertIn("Call Comcast with the attached evidence", txt)
        self.assertIn("XB7 gateway", txt)
        self.assertIn("Comcast hop 10.60.12.1", txt)
        self.assertIn("ep-000001", txt)
        self.assertIn("host-side; not Comcast-relevant", txt)
        self.assertIn("Tell Comcast", txt)
        # Without a live ctx the exporter ships the session's comcast_evidence.txt (written by the
        # engine via the final report build), not the fixture's faked verdict["comcast"].
        file_text = (self.fx.dir / "comcast_evidence.txt").read_text(encoding="utf-8").strip()
        self.assertIn(F.SESSION_ID, file_text)
        self.assertIn(file_text, txt)
        self.assertEqual(self.zf.read("comcast_evidence.txt").decode().strip(), file_text)

    def test_bad_pack_and_missing_dir(self):
        with self.assertRaises(ValueError):
            E.build_zip(self.fx.dir, pack="everything", cfg=self.fx.cfg)
        with self.assertRaises(FileNotFoundError):
            E.build_zip(self.tmp / "nope", pack="full", cfg=self.fx.cfg)


class ExportMutatingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-export-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fx = F.make_session(self.tmp, duration_s=200, close=True)

    def test_session_config_json_is_redacted_and_report_rebuilt_when_missing(self):
        cfg = dict(self.fx.cfg)
        (self.fx.dir / "config.json").write_text(json.dumps({"docsis": {"password": "other-pass-77"}, "port": 1}))
        (self.fx.dir / "report.html").unlink()
        zf = members(E.build_zip(self.fx.dir, pack="full", cfg=cfg))
        names = zf.namelist()
        self.assertIn("config.redacted.json", names)
        self.assertNotIn("config.json", names)
        self.assertEqual(json.loads(zf.read("config.redacted.json")), {"docsis": {"password": "***"}, "port": 1})
        self.assertIn("report.html", names)
        self.assertTrue((self.fx.dir / "report.html").exists())
        for name in names:
            data = zf.read(name)
            if name.endswith(".gz"):
                data = gzip.decompress(data)
            self.assertNotIn(b"other-pass-77", data, name)

    def test_without_password_or_comcast_text(self):
        (self.fx.dir / "comcast_evidence.txt").unlink()
        doc = json.loads((self.fx.dir / "session.json").read_text())
        doc["summary"]["verdict"] = {}
        (self.fx.dir / "session.json").write_text(json.dumps(doc))
        zf = members(E.build_zip(self.fx.dir, pack="comcast", cfg=F.make_cfg(password=None)))
        self.assertEqual(zf.read("comcast_evidence.txt").decode(), "(no Comcast-relevant episodes)\n")
        self.assertIn("No verdict was computed", zf.read("summary.txt").decode())

    def test_live_ctx_comcast_text(self):
        saved = sys.modules.get("laglens.engine.verdict")
        mod = types.ModuleType("laglens.engine.verdict")
        mod.comcast_text = lambda ctx: "LIVE TEXT %s" % ctx.state.session_id
        sys.modules["laglens.engine.verdict"] = mod
        try:
            zf = members(E.build_zip(self.fx.dir, pack="comcast", cfg=self.fx.cfg, ctx=self.fx.ctx))
        finally:
            if saved is None:
                sys.modules.pop("laglens.engine.verdict", None)
            else:
                sys.modules["laglens.engine.verdict"] = saved
        self.assertEqual(zf.read("comcast_evidence.txt").decode().strip(), "LIVE TEXT " + F.SESSION_ID)

    def test_export_cli(self):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            rc = E.export_cli(self.fx.dir, "full", self.fx.cfg)
            rc2 = E.export_cli(self.fx.dir, "comcast", self.fx.cfg)
            rc_bad = E.export_cli(self.fx.dir, "bogus", self.fx.cfg)
            rc_missing = E.export_cli(self.tmp / "sessions" / "none", "full", self.fx.cfg)
        finally:
            sys.stdout = old
        self.assertEqual((rc, rc2, rc_bad, rc_missing), (0, 0, 1, 1))
        zip_path = self.fx.sessions_root / ("laglens-%s.zip" % F.SESSION_ID)
        self.assertTrue(zip_path.exists())
        self.assertTrue((self.fx.sessions_root / ("laglens-%s-comcast.zip" % F.SESSION_ID)).exists())
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], str(zip_path))
        self.assertIn("unknown pack", lines[2])
        self.assertIn("not found", lines[3])
        names = set(zipfile.ZipFile(zip_path).namelist())
        self.assertIn("summary.txt", names)
        # a second full export does not swallow the previous zip (it lives outside the session dir)
        self.assertEqual(E.export_cli(self.fx.dir, "full", self.fx.cfg), 0)
        self.assertNotIn("laglens-%s.zip" % F.SESSION_ID, zipfile.ZipFile(zip_path).namelist())


if __name__ == "__main__":
    unittest.main()
