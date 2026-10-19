"""Tests for laglens.collectors.docsis: table recognition on the fixtures, login flow with a fake opener,
codeword deltas, log classes, dedupe, uptime reset, refresh rate limit, redaction, dump_cli."""
import io
import json
import logging
import os
import shutil
import sys
import tempfile
import weakref
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.collectors import docsis as d  # noqa: E402
from laglens.state import State  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "xb7"
PASSWORD = "s3cretXB7pw!"


def fx(name):
    return (FIX / name).read_text(encoding="utf-8")


class FakeResp(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body.encode("utf-8") if isinstance(body, str) else body)
        self.status = status

    def getcode(self):
        return self.status


REFUSAL_PAGE = ('<html><head><script type="text/javascript" src="./cmn/js/lib/jquery-3.7.1.js"></script></head><body>'
                '<input type="hidden" id="loc" value="en"><script type="text/javascript">'
                'alert($.i18n("You have ")+"3"+$.i18n(" failed login attempts and your account will be locked for ")+"5"'
                '+$.i18n(" minutes"));history.back();</script></body></html>')


class FakeOpener:
    """Simulates the XB7: logged-out pages until a correct POST to /check.jst sets a session cookie."""

    def __init__(self, pages=None, password=PASSWORD, login_path="/check.jst", fail=None, refusal=None):
        self.pages = dict(pages or {})
        self.refusal = refusal  # what a wrong password gets back (default: the login form again)
        self.password = password
        self.login_path = login_path
        self.session = False
        self.calls = []
        self.fail = fail  # exception to raise for every request
        self.expire_after = None  # number of GETs after which the session expires

    def open(self, req, timeout=None):
        url = req.full_url
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        self.calls.append((req.get_method(), path, timeout))
        if self.fail is not None:
            raise self.fail
        if req.get_method() == "POST":
            if path != self.login_path:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b"nope"))
            body = (req.data or b"").decode("utf-8")
            fields = dict(p.split("=", 1) for p in body.split("&"))
            if fields.get("password") == self.password.replace("!", "%21") and fields.get("locale") == "false":
                self.session = True
                self.expire_after = None  # a fresh login issues a fresh session (one-shot expiry)
                return FakeResp(self.pages.get("/at_a_glance.jst", "<html><body>At a glance</body></html>"))
            return FakeResp(self.refusal if self.refusal is not None else fx("login_page.html"))
        if path == "/":
            return FakeResp(fx("login_page.html"))
        if not self.session:
            return FakeResp(fx("home_loggedout_redirect.html"))
        if self.expire_after is not None:
            self.expire_after -= 1
            if self.expire_after < 0:
                self.session = False
                return FakeResp(fx("home_loggedout_redirect.html"))
        if path not in self.pages:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b"<html>404</html>"))
        return FakeResp(self.pages[path])


class FakeStore:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="laglens-docsis-"))
        weakref.finalize(self, shutil.rmtree, str(self.dir), True)  # no leaked temp dirs
        self.rows = []
        self.files = {}

    def append_json(self, name, obj):
        json.dumps(obj)
        self.rows.append((name, obj))

    def write_atomic(self, name, data):
        self.files[name] = data
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p


PAGES = ["/network_setup.jst", "/troubleshooting_logs.jst", "/hardware.jst", "/network_setup.jsp", "/troubleshooting_logs.jsp"]


def cfg(password=PASSWORD, pages=None, interval=60, save_raw=True):
    return {"docsis": {"url": "http://10.0.0.1", "username": "admin", "password": password, "interval_s": interval,
                       "pages": pages or PAGES, "login_paths": ["/check.jst", "/check.jsp"], "save_raw": save_raw},
            "link": {"up_mbps": 25}}


class Ctx:
    def __init__(self, c):
        self.cfg = c
        self.state = State(cfg=c)
        self.store = FakeStore()
        self.platform = None
        self.components = {}

    def component(self, n):
        return self.components.get(n)


class Clock:
    def __init__(self):
        self.t = 1_760_000_000.0
        self.m = 1000.0


def site_pages():
    return {"/network_setup.jst": fx("network_setup.jst.html"), "/troubleshooting_logs.jst": fx("troubleshooting_logs.jst.html"),
            "/hardware.jst": fx("hardware.jst.html"), "/at_a_glance.jst": "<html><body><h1>At a Glance</h1></body></html>"}


def make(c=None, opener=None):
    c = c or cfg()
    ctx = Ctx(c)
    clk = Clock()
    op = opener or FakeOpener(site_pages())
    client = d.Xb7Client(c["docsis"], opener=op)
    dc = d.DocsisCollector(ctx, client=client, clock=lambda: clk.t, mono=lambda: clk.m)
    return ctx, clk, op, dc


# ---------------------------------------------------------------------------
class ParsingTests(unittest.TestCase):
    def test_transposed_xb7_layout(self):
        r = d.parse_page(fx("network_setup.jst.html"))
        kinds = [t["kind"] for t in r["tables"]]
        self.assertEqual(kinds.count("downstream"), 2)  # SNR/power table + codeword table
        self.assertEqual(kinds.count("upstream"), 1)
        self.assertEqual(len(r["ds"]), 33)
        ch18 = [c for c in r["ds"] if c["ch"] == 18][0]
        self.assertEqual(ch18["snr_db"], 36.6)
        self.assertEqual(ch18["pwr_dbmv"], -2.4)
        self.assertEqual(ch18["freq_hz"], 609000000)
        self.assertEqual(ch18["mod"], "256 QAM")
        self.assertTrue(ch18["lock"])
        self.assertEqual(ch18["uncorr"], 3)
        self.assertEqual(ch18["corr"], 138)
        self.assertEqual(ch18["unerr"], 987672000)
        ofdm = r["ds"][-1]
        self.assertEqual((ofdm["ch"], ofdm["mod"], ofdm["freq_hz"]), (33, "OFDM PLC", 850000000))
        self.assertEqual(len(r["us"]), 5)
        self.assertEqual(r["us"][3]["pwr_dbmv"], 45.3)
        self.assertEqual(r["us"][4]["type"], "OFDMA")
        self.assertEqual(r["us"][0]["symrate"], 5120.0)
        self.assertEqual(r["uptime_s"], 3 * 86400 + 4 * 3600 + 22 * 60 + 15)
        self.assertFalse(r["logged_out"])
        self.assertEqual(r["log"], [])

    def test_column_layout_variant(self):
        r = d.parse_page(fx("network_setup_columns.jst.html"))
        self.assertEqual(len(r["ds"]), 8)
        self.assertEqual(r["ds"][0]["freq_hz"], 507000000)  # "507" MHz column
        self.assertEqual(r["ds"][0]["snr_db"], 40.9)
        self.assertEqual(r["ds"][0]["uncorr"], 0)
        self.assertEqual(len(r["us"]), 4)
        self.assertEqual(r["us"][0]["type"], "ATDMA")
        self.assertEqual(r["fw"], "CGM4331COM_5.3p7s1_PROD_sey")
        self.assertEqual(r["uptime_s"], 4 * 60 + 12)

    def test_log_page(self):
        r = d.parse_page(fx("troubleshooting_logs.jst.html"))
        self.assertEqual([t["kind"] for t in r["tables"] if t["kind"]], ["log"])
        classes = [ln["class"] for ln in r["log"]]
        self.assertEqual(classes, ["t3", "t3", "t4", "drw", "lost_mdd", "sync", "ranging", "reg_rsp", "partial", "other", "t3"])
        self.assertEqual(r["log"][0]["ts"], "Sat Oct 11 21:14:03 2025")
        self.assertIn("T3 time-out", r["log"][0]["text"])
        self.assertEqual(r["log"][0]["prio"], "Critical (3)")
        merged = d.merge_pages({"/troubleshooting_logs.jst": r})
        self.assertEqual(len(merged["log"]), 10)  # duplicate (ts, text) collapsed

    def test_unknown_layout_not_recognised(self):
        r = d.parse_page(fx("hardware.jst.html"))
        self.assertEqual([t["kind"] for t in r["tables"] if t["kind"]], [])
        self.assertEqual((r["ds"], r["us"], r["log"]), ([], [], []))
        self.assertEqual(r["fw"], "CGM4331COM_5.3p7s1_PROD_sey")
        self.assertEqual(r["uptime_s"], 86400 + 2 * 3600 + 3 * 60 + 4)

    def test_login_detection_on_real_login_page(self):
        self.assertTrue(d.logged_out(fx("login_page.html")))
        self.assertTrue(d.logged_out(fx("home_loggedout_redirect.html")))
        self.assertFalse(d.logged_out(fx("network_setup.jst.html")))
        self.assertIn('check.jst', fx("login_page.html"))

    def test_script_tables_ignored_and_classify(self):
        self.assertEqual(d.classify_table([["Channel ID", "SNR"], ["1", "40"]]), "downstream")
        self.assertEqual(d.classify_table([["Channel", "Power Level"], ["1", "44"]]), "upstream")
        self.assertEqual(d.classify_table([["Channel", "Power Level", "SNR"], ["1", "44", "38"]]), "downstream")
        self.assertEqual(d.classify_table([["2025-10-11 21:14:03", "T3 time-out"]]), "log")
        self.assertEqual(d.classify_table([["Port", "Status"], ["1", "Active"]]), None)
        self.assertEqual(d.classify_table([]), None)
        tables, text = d.extract_tables("<script>var x='<table><tr><td>SNR</td></tr></table>'</script><table><tr><td>a</td></tr></table>")
        self.assertEqual(tables, [[["a"]]])
        self.assertNotIn("SNR", text)

    def test_helpers(self):
        self.assertEqual(d.classify_log_line("Started Unicast Maintenance Ranging - No Response received - T3 time-out"), "t3")
        self.assertEqual(d.classify_log_line("Unicast Ranging Received Abort Response"), "ranging")
        self.assertEqual(d.classify_log_line("Dynamic Range Window violation"), "drw")
        self.assertEqual(d.classify_log_line("TLV-11 unrecognized"), "other")
        self.assertEqual(d.parse_uptime("System Uptime: 12d 3h 4m 5s"), 12 * 86400 + 3 * 3600 + 4 * 60 + 5)
        self.assertEqual(d.parse_uptime("System Uptime 0 days 00:00:30"), 30)
        self.assertIsNone(d.parse_uptime("no uptime here"))
        ts = d.parse_log_ts("Sat Oct 11 21:14:03 2025")
        self.assertIsNotNone(ts)
        self.assertEqual(d.parse_log_ts("2025-10-11 21:14:03"), d.parse_log_ts("2025-10-11, 21:14:03"))
        self.assertIsNone(d.parse_log_ts("1970-01-01 00:00:05"))
        self.assertIsNone(d.parse_log_ts("not a time"))
        self.assertEqual(d.orient([["Index", "1", "2"], ["SNR", "40", "41"], ["Power Level", "1", "2"]]),
                         [["Index", "SNR", "Power Level"], ["1", "40", "1"], ["2", "41", "2"]])


class DeriveTests(unittest.TestCase):
    def base(self):
        return d.merge_pages({"/n": d.parse_page(fx("network_setup.jst.html"))})

    def test_first_poll_flags_only_rf(self):
        cur = self.base()
        r = d.derive(cur, None, None)
        self.assertEqual(r["flags"], [])
        self.assertEqual(r["ds_snr_min"], 33.4)
        self.assertEqual(r["ds_pwr_min"], -6.4)
        self.assertEqual(r["ds_pwr_max"], 2.4)
        self.assertEqual(r["us_pwr_max"], 45.3)
        self.assertEqual(r["ds_locked"], 33)

    def test_uncorr_burst_and_deltas(self):
        prev = self.base()
        cur = self.base()
        for c in cur["ds"]:
            if c["ch"] == 7:
                c["uncorr"] += 150
                c["corr"] += 20
        r = d.derive(cur, prev, 60.0)
        self.assertIn("uncorr_burst", r["flags"])
        self.assertEqual(r["uncorr_delta"], 150)
        self.assertEqual(r["corr_delta"], 20)
        self.assertEqual(r["deltas"]["uncorr"]["7"], 150)
        self.assertEqual(r["deltas"]["uncorr"]["8"], 0)
        slow = d.derive(cur, prev, 120.0)  # 150 per 2 min = 75/min: no burst
        self.assertNotIn("uncorr_burst", slow["flags"])

    def test_rf_flags_partial_and_reboot(self):
        prev = self.base()
        cur = self.base()
        cur["ds"][0]["snr_db"] = 31.0
        cur["ds"][1]["pwr_dbmv"] = 9.5
        cur["us"][0]["pwr_dbmv"] = 51.0
        cur["us"][1]["pwr_dbmv"] = 30.0
        cur["ds"][2]["lock"] = False
        cur["uptime_s"] = 10
        r = d.derive(cur, prev, 60.0)
        for f in ("ds_snr_low", "ds_power_out", "us_power_high", "us_power_low", "partial_service", "reboot"):
            self.assertIn(f, r["flags"])
        for c in cur["ds"]:
            c["uncorr"] = 0  # counters reset after the reboot
        r = d.derive(cur, prev, 60.0)
        self.assertNotIn("uncorr_burst", r["flags"])
        self.assertIsNone(r["deltas"]["uncorr"]["18"])


class ModelTests(unittest.TestCase):
    def test_model_from_the_hardware_page_names_the_gateway(self):
        hw = ('<div class="form-row"><span class="readonlyLabel">Model:</span> <span class="value">CGM4981COM</span></div>'
              '<div class="form-row"><span class="readonlyLabel">Vendor:</span> <span class="value">Technicolor</span></div>')
        self.assertEqual(d.parse_page(hw)["model"], "CGM4981COM")
        self.assertEqual([d.model_name(m) for m in ("CGM4981COM", "TG4482A", "cgm4331com", "SX9999Z", None)],
                         ["XB8", "XB7", "XB7", "SX9999Z", None])
        pages = dict(site_pages(), **{"/hardware.jst": hw})
        ctx, clk, op, dc = make(opener=FakeOpener(pages))
        self.assertTrue(dc.poll()["ok"])
        lat = ctx.state.latest("docsis")
        self.assertEqual((lat["model"], lat["hw_model"]), ("XB8", "CGM4981COM"))
        self.assertEqual(dc.recent()["summary"]["model"], "XB8")
        self.assertEqual(ctx.state.modem_name(), "XB8")
        self.assertEqual(ctx.state.gw_text("XB7 reboot/reset count: 1."), "XB8 reboot/reset count: 1.")
        # before any status page has been read the old default stands
        self.assertEqual(Ctx(cfg()).state.modem_name(), "XB7")


class LoginTests(unittest.TestCase):
    def test_login_posts_then_verifies(self):
        op = FakeOpener(site_pages())
        c = d.Xb7Client(cfg()["docsis"], opener=op)
        self.assertTrue(c.login())
        self.assertEqual(c.login_path_used, "/check.jst")
        self.assertEqual([m for m, _, _ in op.calls], ["GET", "POST"])
        self.assertEqual(op.calls[1][1], "/check.jst")
        self.assertEqual(op.calls[0][2], 10.0)

    def test_jsp_fallback_when_jst_404(self):
        op = FakeOpener(site_pages(), login_path="/check.jsp")
        c = d.Xb7Client(cfg()["docsis"], opener=op)
        self.assertTrue(c.login())
        self.assertEqual(c.login_path_used, "/check.jsp")

    def test_wrong_password_rejected(self):
        op = FakeOpener(site_pages(), password="other")
        c = d.Xb7Client(cfg()["docsis"], opener=op)
        self.assertFalse(c.login())
        self.assertFalse(c.logged_in)

    def test_refusal_alert_is_a_rejection_and_stops_at_the_first_path(self):
        # what an RDK-B gateway answers to a wrong password once it counts failures (seen on a real gateway)
        op = FakeOpener(site_pages(), password="other", refusal=REFUSAL_PAGE)
        c = d.Xb7Client(cfg()["docsis"], opener=op)
        self.assertFalse(c.login())
        self.assertFalse(c.logged_in)
        self.assertEqual(c.refused, "You have 3 failed login attempts and your account will be locked for 5 minutes")
        self.assertEqual([m for m, _, _ in op.calls], ["GET", "POST"])  # no second path: no extra failed attempt
        self.assertIsNone(d.login_alert(fx("login_page.html")))

    def test_transport_error_scrubbed(self):
        op = FakeOpener(site_pages(), fail=OSError("connection refused while sending %s" % PASSWORD))
        c = d.Xb7Client(cfg()["docsis"], opener=op)
        with self.assertRaises(d.Xb7Error) as cm:
            c.login()
        self.assertNotIn(PASSWORD, str(cm.exception))
        self.assertIn("***", str(cm.exception))
        self.assertNotIn(PASSWORD, repr(c))


class CollectorTests(unittest.TestCase):
    def test_disabled_without_password(self):
        ctx = Ctx(cfg(password=None))
        dc = d.DocsisCollector(ctx)
        dc.start()
        self.assertEqual(ctx.state.collector("docsis")["reason"], "docsis.password not set")
        self.assertFalse(dc.refresh())
        self.assertEqual(dc.recent()["status"], "disabled")
        self.assertIsNone(dc.poll())

    def test_full_poll_row_latest_raw(self):
        ctx, clk, op, dc = make()
        row = dc.poll()
        self.assertTrue(row["ok"])
        self.assertTrue(row["initial"])
        self.assertEqual(len(row["ds"]), 33)
        self.assertEqual(len(row["us"]), 5)
        self.assertEqual(row["uptime_s"], 274935)
        self.assertEqual(row["fw"], "CGM4331COM_5.3p7s1_PROD_sey")
        self.assertEqual(len(row["log_new"]), 10)
        self.assertEqual(row["flags"], [])
        self.assertIsNone(row["log_clock_offset_s"])
        self.assertEqual(ctx.state.drain_notes(), [])  # backlog never becomes events
        self.assertEqual(ctx.store.rows[-1][0], "xb7")
        lat = ctx.state.latest("docsis")
        self.assertEqual(lat["ds_snr_min"], 33.4)
        self.assertEqual(lat["uptime_s"], 274935)
        self.assertEqual(lat["ds_channels"], 33)
        self.assertEqual(sorted(ctx.store.files), ["xb7_raw/hardware.jst.html", "xb7_raw/network_setup.jst.html", "xb7_raw/troubleshooting_logs.jst.html"])
        self.assertEqual(ctx.state.collector("docsis")["status"], "ok")
        pages = {p["path"]: p["status"] for p in dc.pages}
        self.assertEqual(pages["/network_setup.jsp"], "skipped (.jst ok)")
        self.assertEqual(pages["/troubleshooting_logs.jsp"], "skipped (.jst ok)")
        # second poll: nothing new, raw not re-saved
        clk.t += 60
        n = len(ctx.store.files)
        row2 = dc.poll()
        self.assertEqual(row2["log_new"], [])
        self.assertFalse(row2["initial"])
        self.assertEqual(len(ctx.store.files), n)
        self.assertEqual(dc.recent(5)["summary"]["polls"], 2)
        self.assertEqual(len(dc.recent(1)["polls"]), 1)
        self.assertEqual(len(dc.recent()["log"]), 10)

    def test_new_log_lines_raise_notes_and_offset(self):
        ctx, clk, op, dc = make()
        dc.poll()
        ctx.state.drain_notes()
        clk.t += 60
        import time as _t

        stamp = _t.strftime("%a %b %d %H:%M:%S %Y", _t.localtime(clk.t - 3))
        extra = '<tr><td>%s</td><td>Critical (3)</td><td>Started Unicast Maintenance Ranging - No Response received - T3 time-out;CM-MAC=7c:ed:8d:aa:bb:cc;</td></tr>' % stamp
        extra += '<tr><td>%s</td><td>Notice (6)</td><td>TLV-11 - unrecognized OID</td></tr>' % stamp
        op.pages["/troubleshooting_logs.jst"] = fx("troubleshooting_logs.jst.html").replace("</tbody>", extra + "</tbody>")
        row = dc.poll()
        self.assertEqual([ln["class"] for ln in row["log_new"]], ["t3", "other"])
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["docsis_t3"])
        self.assertEqual(notes[0]["severity"], 3)
        self.assertIn("T3 time-out", notes[0]["note"])
        self.assertNotIn(PASSWORD, json.dumps(notes))
        self.assertAlmostEqual(row["log_clock_offset_s"], 3.0, delta=1.5)
        clk.t += 60
        row = dc.poll()
        self.assertEqual(row["log_new"], [])
        self.assertEqual(ctx.state.drain_notes(), [])

    def test_flag_notes(self):
        ctx, clk, op, dc = make()
        dc.poll()
        ctx.state.drain_notes()
        html = fx("network_setup.jst.html")
        html = html.replace("<td>3</td>", "<td>303</td>")  # ch 18 uncorrectables: 3 -> 303
        html = html.replace("<td>40.9 dB</td>", "<td>30.9 dB</td>")
        html = html.replace("System Uptime: 3 days 04h:22m:15s", "System Uptime: 0 days 00h:00m:40s")
        op.pages["/network_setup.jst"] = html
        clk.t += 60
        row = dc.poll()
        self.assertIn("uncorr_burst", row["flags"])
        self.assertIn("ds_snr_low", row["flags"])
        self.assertIn("reboot", row["flags"])
        types = sorted(n["type"] for n in ctx.state.drain_notes())
        self.assertEqual(types, ["docsis_power_snr", "docsis_reboot", "docsis_uncorr"])
        clk.t += 60
        dc.poll()
        self.assertEqual([n["type"] for n in ctx.state.drain_notes()], [])  # snr still low: no repeat; counters unchanged

    def test_login_rejected_three_times_pauses(self):
        ctx, clk, op, dc = make(opener=FakeOpener(site_pages(), password="nope"))
        for i in range(3):
            self.assertIsNone(dc.poll())
        c = ctx.state.collector("docsis")
        self.assertEqual(c["status"], "degraded")
        self.assertEqual(c["reason"], d.LOGIN_REJECTED_CHIP)
        self.assertFalse(dc._due(clk.m + 1))
        self.assertFalse(dc.refresh())
        self.assertTrue(dc._due(clk.m + d.LOGIN_PAUSE_S + 1))
        self.assertEqual(dc._login_failures, 0)

    def test_password_refusal_pauses_for_an_hour(self):
        ctx, clk, op, dc = make(opener=FakeOpener(site_pages(), password="nope", refusal=REFUSAL_PAGE))
        self.assertIsNone(dc.poll())
        c = ctx.state.collector("docsis")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("rejected the password (You have 3 failed login attempts", c["reason"])
        self.assertIn("config.json", c["reason"])
        posts = sum(1 for m, _, _ in op.calls if m == "POST")
        self.assertEqual(posts, 1)
        self.assertFalse(dc._due(clk.m + 1))
        self.assertFalse(dc._due(clk.m + d.LOGIN_PAUSE_S + 1))  # longer than the generic 10 min pause
        self.assertFalse(dc.refresh())  # a manual refresh does not try again either
        self.assertTrue(dc._due(clk.m + d.LOGIN_REFUSED_PAUSE_S + 1))

    def test_session_expiry_relogin_and_404_drop(self):
        pages = site_pages()
        op = FakeOpener(pages)
        ctx, clk, _, dc = make(opener=op)
        dc.poll()
        op.expire_after = 1
        clk.t += 60
        row = dc.poll()
        self.assertTrue(row["ok"])
        self.assertEqual(len(row["ds"]), 33)
        posts = [c for c in op.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 2)
        # hardware.jst disappears -> 404 x3 -> dropped
        del op.pages["/hardware.jst"]
        for _ in range(3):
            clk.t += 60
            dc.poll()
        hw = [p for p in dc.pages if p["path"] == "/hardware.jst"][0]
        self.assertTrue(hw["dropped"])
        self.assertEqual(hw["fail404"], 3)
        self.assertEqual(dc.recent()["summary"]["pages"]["/hardware.jst"], "dropped")

    def test_unreachable_degrades(self):
        op = FakeOpener(site_pages())
        ctx, clk, _, dc = make(opener=op)
        op.fail = OSError(65, "No route to host")
        self.assertIsNone(dc.poll())
        self.assertIn("XB7 unreachable", ctx.state.collector("docsis")["reason"])

    def test_refresh_rate_limit(self):
        ctx, clk, op, dc = make()
        self.assertTrue(dc.refresh())
        self.assertEqual(len(dc._extra), 2)
        self.assertFalse(dc.refresh())
        self.assertTrue(dc._due(clk.m))
        dc.poll()
        self.assertFalse(dc._due(clk.m + 1))  # second extra is at +15 s
        self.assertTrue(dc._due(clk.m + 16))
        clk.m += 61
        self.assertTrue(dc.refresh())

    def test_password_never_in_rows_state_or_logs(self):
        ctx, clk, op, dc = make()
        with self.assertLogs("laglens.docsis", level="DEBUG") as cm:
            dc.poll()
            dc.client.logged_in = False
            op.password = "changed"
            clk.t += 60
            dc.poll()
        blob = "\n".join(cm.output) + json.dumps(ctx.store.rows) + json.dumps(ctx.state.latest("docsis")) + json.dumps(dc.recent())
        blob += json.dumps(ctx.state.collectors()) + json.dumps(ctx.state.drain_notes())
        self.assertNotIn(PASSWORD, blob)

    def test_raw_capture_limits(self):
        ctx, clk, op, dc = make()
        dc._raw_files = d.RAW_MAX_FILES
        dc.poll()
        self.assertEqual(ctx.store.files, {})
        ctx2, _, op2, dc2 = make()
        op2.pages["/network_setup.jst"] = fx("network_setup.jst.html") + "<!-- " + "x" * 300_000 + " -->"
        dc2.poll()
        self.assertLessEqual(len(ctx2.store.files["xb7_raw/network_setup.jst.html"]), d.RAW_MAX_BYTES)

    def test_thread_start_stop(self):
        ctx, clk, op, dc = make()
        dc.start()
        import time as _t

        _t.sleep(0.3)
        ctx.state.stop_event.set()
        dc.stop(3.0)
        self.assertFalse(dc.thread.is_alive())
        self.assertGreaterEqual(dc.poll_count, 1)


class DumpCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-dump-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_dump_saves_pages_and_reports(self):
        op = FakeOpener(site_pages())
        c = cfg()
        client = d.Xb7Client(c["docsis"], opener=op)
        lines = []
        rc = d.dump_cli(c, out_dir=self.tmp / "dump", client=client, out=lines.append)
        self.assertEqual(rc, 0)
        files = sorted(p.name for p in (self.tmp / "dump").iterdir())
        self.assertEqual(files, ["hardware.jst.html", "login_page.html", "login_response_0.html", "network_setup.jst.html",
                                 "troubleshooting_logs.jst.html"])  # login_response_*: the POST reply, for diagnosing rejections
        text = "\n".join(lines)
        self.assertIn("downstream(33)", text)
        self.assertIn("upstream(5)", text)
        self.assertIn("log(11)", text)
        self.assertIn("no table recognised", text)
        # the .jsp twins are skipped once their .jst page worked (they do not exist on .jst firmware)
        self.assertNotIn("/network_setup.jsp", text)
        self.assertNotIn(PASSWORD, text)

    def test_dump_reports_a_missing_page(self):
        op = FakeOpener(site_pages())
        c = cfg(pages=["/network_setup.jst", "/no_such_page.jst"])
        client = d.Xb7Client(c["docsis"], opener=op)
        lines = []
        d.dump_cli(c, out_dir=self.tmp / "dump2", client=client, out=lines.append)
        self.assertIn("HTTP 404", "\n".join(lines))

    def test_dump_without_password(self):
        lines = []
        self.assertEqual(d.dump_cli(cfg(password=None), out_dir=self.tmp, out=lines.append), 1)
        self.assertIn("not set", lines[0])

    def test_dump_login_rejected(self):
        op = FakeOpener(site_pages(), password="x")
        c = cfg()
        lines = []
        rc = d.dump_cli(c, out_dir=self.tmp / "d2", client=d.Xb7Client(c["docsis"], opener=op), out=lines.append)
        self.assertEqual(rc, 1)
        self.assertTrue(any("rejected" in ln for ln in lines))


if __name__ == "__main__":
    unittest.main()


class Tg4482aLayoutTests(unittest.TestCase):
    """Regression for the real Arris TG4482A (XB7) pages: logged-in pages mention home_loggedout.jst
    (Logout link, inactivity timer) and "Please Login First" (i18n), and use rotated tables."""

    LOGGED_IN = "network_setup_tg4482a_loggedin.jst.html"
    LOGGED_OUT = "network_setup_tg4482a_loggedout.jst.html"

    def test_logged_in_page_is_not_mistaken_for_logged_out(self):
        self.assertFalse(d.logged_out(fx(self.LOGGED_IN)))
        self.assertTrue(d.logged_out(fx(self.LOGGED_OUT)))
        self.assertTrue(d.logged_out(fx("login_page.html")))
        self.assertTrue(d.logged_out(fx("home_loggedout_redirect.html")))
        # the inactivity-timer script alone (no Logout link) is not a redirect page either
        timer_only = '<script>function t(c){ if (c<=0) { location.href="home_loggedout.jst"; } }</script><table></table>'
        self.assertFalse(d.logged_out(timer_only))

    def test_login_succeeds_when_logged_in_pages_carry_a_logout_link(self):
        page = fx(self.LOGGED_IN)
        op = FakeOpener({"/at_a_glance.jst": page, "/network_setup.jst": page})
        c = d.Xb7Client(cfg()["docsis"], opener=op)
        self.assertTrue(c.login())
        self.assertEqual(c.login_path_used, "/check.jst")

    def test_rotated_tables_title_row_placeholder_and_ofdm(self):
        pg = d.parse_page(fx(self.LOGGED_IN))
        m = d.merge_pages({"/network_setup.jst": pg})
        self.assertEqual([c["ch"] for c in m["ds"]], [9, 10, 193])  # the unused "0" column is dropped
        self.assertEqual([c["ch"] for c in m["us"]], [1, 4])
        by = {c["ch"]: c for c in m["ds"]}
        self.assertAlmostEqual(by[9]["snr_db"], 37.36, places=2)
        self.assertEqual((by[9]["unerr"], by[9]["corr"], by[9]["uncorr"]), (2155900450, 0, 3))
        self.assertEqual(by[10]["corr"], 21)
        self.assertEqual(by[193]["mod"], "OFDM")
        self.assertAlmostEqual(by[193]["snr_db"], 39.64, places=2)  # "39.64 dB"
        self.assertAlmostEqual(by[193]["pwr_dbmv"], 7.40, places=2)  # "7.400002 dBmV"
        self.assertTrue(all(c["lock"] for c in m["ds"]))
        us = {c["ch"]: c for c in m["us"]}
        self.assertAlmostEqual(us[4]["pwr_dbmv"], 41.01, places=2)
        self.assertEqual(us[4]["type"], "US_TYPE_ATDMA")
        self.assertEqual(m["uptime_s"], 4 * 86400 + 22 * 3600 + 13 * 60 + 3)


# ---------------------------------------------------------------------------
# The TG4482A troubleshooting page renders empty log tables and loads the lines from a JSON endpoint.
import time as _time  # noqa: E402
import urllib.parse as _up  # noqa: E402

TG_TOKEN = "tok123abc"


def tg_log_page(local_ts=None):
    lt = ""
    if local_ts is not None:
        lt = ('<div class="form-row "><span class="readonlyLabel">Local time:</span> <span class="value">%s</span></div>'
              % _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(local_ts)))
    return ('<html><head><title>XFINITY</title><script>var sessionCsrf= "%s"; function ajaxDo(mode,timef){ var token = "%s"; '
            '$.ajax({type:"GET", url:"actionHandler/ajax_troubleshooting_logs.jst", data:{mode:mode,timef:timef,csrfp_token: token}}); }'
            '</script></head><body><ul id="userToolbar"><li><a href="home_loggedout.jst" id="logout">Logout</a></li></ul>%s'
            '<table id="event_logs_today"><thead><tr><td>All logs for Today</td></tr></thead><tbody></tbody></table>'
            '<table id="system_logs_week"><thead><tr><td>All logs from Last Week</td></tr></thead><tbody></tbody></table>'
            '</body></html>') % (TG_TOKEN, TG_TOKEN, lt)


def log_entry(text, ts="2026-10-11 19:01:02", level="Critical"):
    return {"Des": text, "time": ts, "Level": level}


class LogOpener(FakeOpener):
    """FakeOpener plus the JSON log endpoint (needs the session and the page's CSRF token)."""

    def __init__(self, pages, logs=None, token=TG_TOKEN):
        super().__init__(pages)
        self.logs = dict(logs or {})
        self.token = token
        self.log_calls = []

    def open(self, req, timeout=None):
        url = req.full_url
        if d.LOG_ENDPOINT + "?" in url:
            q = dict(_up.parse_qsl(url.split("?", 1)[1]))
            self.log_calls.append((q.get("mode"), q.get("timef"), timeout, req.get_header("X-requested-with")))
            if not self.session:
                return FakeResp(fx("login_page.html"))
            if q.get("csrfp_token") != self.token:
                raise urllib.error.HTTPError(url, 403, "Forbidden", {}, io.BytesIO(b"csrf"))
            return FakeResp(json.dumps(self.logs.get((q.get("mode"), q.get("timef")), [])))
        return super().open(req, timeout)


def tg_cfg():
    return cfg(pages=["/network_setup.jst", "/troubleshooting_logs.jst"])


def tg_pages(local_ts=None):
    return {"/network_setup.jst": fx(Tg4482aLayoutTests.LOGGED_IN), "/troubleshooting_logs.jst": tg_log_page(local_ts),
            "/at_a_glance.jst": fx(Tg4482aLayoutTests.LOGGED_IN)}


class JsonLogTests(unittest.TestCase):
    def test_token_and_json_parsing(self):
        self.assertEqual(d.extract_csrf_token(tg_log_page()), TG_TOKEN)
        self.assertIsNone(d.extract_csrf_token("<html>no token</html>"))
        body = json.dumps([log_entry("16 consecutive T3 timeouts while trying to range on upstream channel 4"),
                           log_entry("No Ranging Response received - T3 time-out", level="Warning"), {"Des": ""}, "junk"])
        lines = d.parse_log_json(body, "event")
        self.assertEqual([ln["class"] for ln in lines], ["t3", "t3"])
        self.assertEqual(lines[0]["prio"], "Critical")
        self.assertEqual(lines[0]["mode"], "event")
        as_dict = d.parse_log_json(json.dumps({"0": log_entry("Started Unicast Maintenance Ranging - No Response received - T3 time-out")}), "system")
        self.assertEqual(len(as_dict), 1)
        self.assertEqual(d.parse_log_json(json.dumps([{"Des": "blocked", "Count": "3", "time": "x", "Type": "TCP"}]), "firewall")[0]["prio"], "TCP")
        with self.assertRaises(ValueError):
            d.parse_log_json("<html>login</html>", "event")

    def test_firmware_download_version_and_local_time(self):
        self.assertEqual(d.parse_fw("Product Type: XB7 Download Version: 7.3.4.0.114 Downstream"), "7.3.4.0.114")
        ts = _time.mktime((2026, 10, 11, 19, 35, 8, 0, 0, -1))
        self.assertEqual(d.parse_local_time("Local time: 2026-10-11 19:35:08 System Uptime: 4 days"), ts)
        self.assertIsNone(d.parse_local_time("no clock here"))

    def test_history_first_then_today_and_only_new_lines_become_events(self):
        week = [log_entry("No Ranging Response received - T3 time-out", "2026-10-05 10:00:00")]
        today_1 = [log_entry("No Ranging Response received - T3 time-out", "2026-10-05 10:00:00")]
        today_2 = today_1 + [log_entry("16 consecutive T3 timeouts while trying to range on upstream channel 4", "2026-10-11 20:00:00")]
        op = LogOpener(tg_pages(), logs={("event", "Last week"): week, ("system", "Last week"): [],
                                          ("event", "Today"): today_1, ("system", "Today"): []})
        ctx, clk, _op, dc = make(tg_cfg(), opener=op)
        row = dc.poll()
        self.assertTrue(row["ok"])
        self.assertEqual(sorted((m, t) for m, t, _to, _x in op.log_calls), [("event", "Last week"), ("system", "Last week")])
        self.assertTrue(all(to == d.LOG_TIMEOUT_S and x == "XMLHttpRequest" for _m, _t, to, x in op.log_calls))
        self.assertEqual(len(row["log_new"]), 1)
        self.assertTrue(row["log_new"][0]["history"])
        self.assertEqual(ctx.state.drain_notes(), [])
        self.assertTrue(dc.log_status.startswith("ok"))
        # second poll: only today's lines are asked for; the old line is already seen
        op.log_calls.clear()
        clk.t += 60
        clk.m += 60
        row = dc.poll()
        self.assertEqual(sorted(t for _m, t, _to, _x in op.log_calls), ["Today", "Today"])
        self.assertEqual(row["log_new"], [])
        # third poll: a new T3 line becomes a docsis_t3 note
        op.logs[("event", "Today")] = today_2
        clk.t += 60
        clk.m += 60
        row = dc.poll()
        self.assertEqual(len(row["log_new"]), 1)
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["docsis_t3"])

    def test_history_arriving_late_never_becomes_events(self):
        week = [log_entry("No Ranging Response received - T3 time-out", "2026-10-05 10:00:00")]
        op = LogOpener(tg_pages(), logs={("event", "Last week"): week}, token="different")
        ctx, clk, _op, dc = make(tg_cfg(), opener=op)
        dc.poll()  # the endpoint refuses (bad token): no history yet, poll still ok
        self.assertTrue(dc.log_status.startswith("failed"))
        self.assertEqual(ctx.state.collector("docsis")["status"], "ok")
        op.token = TG_TOKEN
        clk.t += 60
        clk.m += 60
        row = dc.poll()  # history now arrives on a non-initial poll
        self.assertFalse(row["initial"])
        self.assertEqual(len(row["log_new"]), 1)
        self.assertEqual(ctx.state.drain_notes(), [])

    def test_midnight_rollover_asks_for_yesterday_too(self):
        op = LogOpener(tg_pages())
        ctx, clk, _op, dc = make(tg_cfg(), opener=op)
        dc.poll()
        op.log_calls.clear()
        clk.t += 86400
        clk.m += 86400
        dc.poll()
        self.assertEqual(sorted(t for _m, t, _to, _x in op.log_calls), ["Today", "Today", "Yesterday", "Yesterday"])

    def test_clock_offset_from_the_gateways_local_time(self):
        op = LogOpener(tg_pages(local_ts=1_760_000_000.0 - 3600))
        ctx, clk, _op, dc = make(tg_cfg(), opener=op)
        row = dc.poll()
        self.assertAlmostEqual(row["log_clock_offset_s"], 3600.0, delta=1.0)

    def test_dump_fetches_a_month_of_logs(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-dumplogs-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        month = [log_entry("16 consecutive T3 timeouts while trying to range on upstream channel 4", "2026-10-10 21:14:03"),
                 log_entry("DHCP RENEW sent - No response for IPv4", "2026-10-09 08:00:00", "Notice")]
        op = LogOpener(tg_pages(), logs={("event", "Last month"): month, ("system", "Last month"): []})
        c = tg_cfg()
        client = d.Xb7Client(c["docsis"], opener=op)
        lines = []
        self.assertEqual(d.dump_cli(c, out_dir=tmp / "dump", client=client, out=lines.append), 0)
        text = "\n".join(lines)
        self.assertIn("logs event  (Last month): 2 lines", text)
        self.assertIn("[t3] 16 consecutive T3 timeouts", text)
        saved = json.loads((tmp / "dump" / "event_log_last_month.json").read_text())
        self.assertEqual(len(saved), 2)
        self.assertIn("2 log line(s)", text)
        self.assertTrue(all(to == 120.0 for _m, _t, to, _x in op.log_calls))


class Tg4482aLogFormatTests(unittest.TestCase):
    def test_real_json_shape_with_slash_dates_and_trailing_newlines(self):
        body = json.dumps([{"time": "2026/9/30 02:41:54", "Des": "FW.IPv6 FORWARD drop \n", "Count": "491 \n",
                            "Target": "0.0.0.0 \n", "Source": "0.0.0.0 \n", "Type": "Firewall Blocked \n"}])
        ln = d.parse_log_json(body, "firewall")[0]
        self.assertEqual((ln["text"], ln["prio"], ln["ts"]), ("FW.IPv6 FORWARD drop", "Firewall Blocked", "2026/9/30 02:41:54"))
        self.assertEqual(d.parse_log_ts(ln["ts"]), _time.mktime((2026, 9, 30, 2, 41, 54, 0, 0, -1)))

    def test_dump_says_when_the_event_log_is_empty(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-dumpempty-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        op = LogOpener(tg_pages())
        c = tg_cfg()
        lines = []
        d.dump_cli(c, out_dir=tmp / "dump", client=d.Xb7Client(c["docsis"], opener=op), out=lines.append)
        text = "\n".join(lines)
        self.assertIn("logs event  (Last month): empty", text)
        self.assertIn("T3/T4 history is not available", text)
