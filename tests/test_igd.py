"""Tests for laglens.collectors.igd: SSDP parsing, device XML, SOAP, u32 wrap, trust validation, mappings, saturation."""
import io
import json
import os
import socket
import sys
import shutil
import tempfile
import weakref
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.collectors import igd as g  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.state import State  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "igd"


def fx(name, binary=False):
    p = FIX / name
    return p.read_bytes() if binary else p.read_text(encoding="utf-8")


class FakeResp(io.BytesIO):
    status = 200

    def getcode(self):
        return 200


class FakeGateway:
    """Answers the device XML and the SOAP actions like MiniUPnPd on an XB7."""

    def __init__(self):
        self.sent = 4294967000
        self.recv = 123456789
        self.uptime = 123456
        self.ext_ip = "73.1.2.3"
        self.mappings = [fx("soap_GetGenericPortMappingEntry_0.xml")]
        self.calls = []
        self.fail_counters = False

    def __call__(self, req, timeout=None):
        url = req.full_url
        self.calls.append((url, req.headers.get("Soapaction"), timeout))
        if url.endswith("/rootDesc.xml"):
            return FakeResp(fx("device.xml").encode("utf-8"))
        action = (req.headers.get("Soapaction") or "").strip('"').split("#")[-1]
        if self.fail_counters and action.startswith("GetTotalBytes"):
            raise OSError("timed out")
        if action == "GetTotalBytesSent":
            body = fx("soap_GetTotalBytesSent.xml").replace("4294967000", str(self.sent))
        elif action == "GetTotalBytesReceived":
            body = fx("soap_GetTotalBytesReceived.xml").replace("123456789", str(self.recv))
        elif action == "GetStatusInfo":
            body = fx("soap_GetStatusInfo.xml").replace("123456", str(self.uptime))
        elif action == "GetExternalIPAddress":
            body = fx("soap_GetExternalIPAddress.xml").replace("73.1.2.3", self.ext_ip)
        elif action == "GetGenericPortMappingEntry":
            idx = int(req.data.decode("utf-8").split("<NewPortMappingIndex>")[1].split("<")[0])
            if idx >= len(self.mappings):
                raise urllib.error.HTTPError(url, 500, "Internal Server Error", {}, io.BytesIO(fx("soap_fault_713.xml").encode("utf-8")))
            body = self.mappings[idx]
        else:
            raise urllib.error.HTTPError(url, 500, "err", {}, io.BytesIO(b""))
        return FakeResp(body.encode("utf-8"))


class FakeStore:
    def __init__(self):
        self.rows = []
        self.dir = Path(tempfile.mkdtemp(prefix="laglens-igd-"))
        weakref.finalize(self, shutil.rmtree, str(self.dir), True)  # no leaked temp dirs

    def append_json(self, name, obj):
        json.dumps(obj)
        self.rows.append((name, obj))


class FakePlatform(Platform):
    name = "darwin"

    def __init__(self):
        super().__init__(runner=lambda a, t: (1, "", ""), reader=lambda p: None, exists=lambda p: False, env={}, which=lambda n: None)

    def default_route(self):
        return {"gateway": "10.0.0.1", "iface": "en0", "gateway6": None, "iface6": None, "lan_ip": "10.0.0.35", "prefixlen": 24}


class Ctx:
    def __init__(self, cfg=None):
        self.cfg = cfg or {"igd": {"enabled": True, "counter_interval_s": 2, "status_interval_s": 30, "mappings_interval_s": 300},
                           "link": {"up_mbps": 25}}
        self.state = State(cfg=self.cfg)
        self.store = FakeStore()
        self.platform = FakePlatform()
        self.route = self.platform.default_route()
        self.components = {}

    def component(self, n):
        return self.components.get(n)


class Clock:
    def __init__(self):
        self.t = 1_760_000_000.0
        self.m = 100.0

    def tick(self, s):
        self.t += s
        self.m += s


def make(locations=None, err=None, uploader=None):
    ctx = Ctx()
    clk = Clock()
    gw = FakeGateway()
    locs = ["http://10.0.0.1:49152/rootDesc.xml"] if locations is None else locations

    def no_upload(n, rate):  # tests never send real traffic
        raise AssertionError("unexpected self-check upload")

    col = g.IgdCollector(ctx, urlopen=gw, discover=lambda ip: (list(locs), err), clock=lambda: clk.t, mono=lambda: clk.m,
                         uploader=uploader or no_upload, sleep=lambda s: clk.tick(s))
    return ctx, clk, gw, col


def verified(col, clk):
    """Mark the counters as verified the way a passing check would (for tests about rates and saturation)."""
    col._apply_verification(clk.t, 1_000_000.0, 1_000_000.0, "test")


class ParseTests(unittest.TestCase):
    def test_ssdp_reply(self):
        h = g.parse_ssdp_reply(fx("ssdp_reply.txt", binary=True))
        self.assertEqual(h["location"], "http://10.0.0.1:49152/rootDesc.xml")
        self.assertEqual(h["st"], "urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        self.assertEqual(g.parse_ssdp_reply(b"NOTIFY * HTTP/1.1\r\nNT: x\r\n\r\n"), {})
        self.assertEqual(g.parse_ssdp_reply(b"\xff\xfe"), {})
        pl = g.msearch_payload(g.SSDP_TARGETS[1])
        self.assertTrue(pl.startswith(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"))
        self.assertIn(b'MAN: "ssdp:discover"', pl)
        self.assertIn(b"InternetGatewayDevice:2", pl)

    def test_device_xml_control_urls(self):
        dev = g.parse_device_xml(fx("device.xml"), "http://10.0.0.1:49152/rootDesc.xml")
        self.assertEqual(dev["services"][g.WANCIC], "http://10.0.0.1:49152/ctl/CmnIfCfg")
        self.assertEqual(dev["services"][g.WANIP1], "http://10.0.0.1:49152/ctl/IPConn")
        self.assertEqual(dev["friendly_name"], "Xfinity XB7 Gateway")
        self.assertEqual(dev["model"], "CGM4331COM")
        with_base = fx("device.xml").replace("<device>", "<URLBase>http://10.0.0.1:5000/</URLBase><device>", 1)
        self.assertEqual(g.parse_device_xml(with_base, "http://x/")["services"][g.WANCIC], "http://10.0.0.1:5000/ctl/CmnIfCfg")
        self.assertEqual(g.parse_device_xml("<not xml", "http://x/")["services"], {})

    def test_soap_parse_and_fault(self):
        r = g.parse_soap_response(fx("soap_GetStatusInfo.xml"), "GetStatusInfo")
        self.assertEqual(r["NewUptime"], "123456")
        self.assertEqual(r["NewConnectionStatus"], "Connected")
        with self.assertRaises(g.SoapFault) as cm:
            g.parse_soap_response(fx("soap_fault_713.xml"), "GetGenericPortMappingEntry")
        self.assertEqual(cm.exception.code, 713)
        self.assertEqual(cm.exception.desc, "SpecifiedArrayIndexInvalid")
        env = g.soap_envelope(g.WANIP1, "GetGenericPortMappingEntry", {"NewPortMappingIndex": 3})
        self.assertIn(b'<u:GetGenericPortMappingEntry xmlns:u="%s">' % g.WANIP1.encode(), env)
        self.assertIn(b"<NewPortMappingIndex>3</NewPortMappingIndex>", env)

    def test_soap_call_headers(self):
        gw = FakeGateway()
        r = g.soap_call("http://10.0.0.1:49152/ctl/CmnIfCfg", g.WANCIC, "GetTotalBytesSent", urlopen=gw)
        self.assertEqual(r["NewTotalBytesSent"], "4294967000")
        self.assertEqual(gw.calls[0][1], '"%s#GetTotalBytesSent"' % g.WANCIC)
        self.assertEqual(gw.calls[0][2], g.SOAP_TIMEOUT_S)

    def test_u32_wrap(self):
        self.assertEqual(g.u32_delta(100, 4294967000), 396)
        self.assertEqual(g.u32_delta(5000, 1000), 4000)
        self.assertEqual(g.u32_delta(10, 5_000_000_000 % g.U32), 0)
        self.assertEqual(g.u32_delta(10, 4000), 0)  # reset
        self.assertIsNone(g.u32_delta(None, 1))


class DiscoveryTests(unittest.TestCase):
    def test_discover_ok(self):
        ctx, clk, gw, col = make()
        self.assertTrue(col.discover())
        self.assertTrue(col.ready)
        self.assertEqual(col.services[g.WANCIC], "http://10.0.0.1:49152/ctl/CmnIfCfg")
        self.assertEqual(ctx.state.collector("igd")["status"], "ok")
        self.assertEqual(ctx.state.collector("igd")["model"], "CGM4331COM")

    def test_no_igd(self):
        ctx, clk, gw, col = make(locations=[])
        self.assertFalse(col.discover())
        self.assertEqual(ctx.state.collector("igd")["reason"], g.NO_IGD_REASON)
        self.assertEqual(col.status()["status"], "disabled")
        col.step()  # nothing happens while disabled
        self.assertEqual(gw.calls, [])

    def test_errno_65_on_macos(self):
        ctx, clk, gw, col = make(locations=[], err=65)
        col.discover()
        self.assertIn("local network permission", ctx.state.collector("igd")["reason"].lower())

    def test_no_wancic(self):
        ctx, clk, gw, col = make()
        xml = fx("device.xml").replace("WANCommonInterfaceConfig:1", "WANCommonInterfaceConfigX:1")

        def uo(req, timeout=None):
            return FakeResp(xml.encode("utf-8"))

        col._urlopen = uo
        self.assertFalse(col.discover())
        self.assertEqual(ctx.state.collector("igd")["reason"], g.NO_WANCIC_REASON)

    def test_ssdp_discover_with_fake_socket(self):
        class FakeSock:
            def __init__(self):
                self.sent = []
                self.replies = [(fx("ssdp_reply.txt", binary=True), ("10.0.0.1", 1900)),
                                (fx("ssdp_reply.txt", binary=True).replace(b"10.0.0.1:49152", b"10.0.0.99:1900"), ("10.0.0.99", 1900))]

            def settimeout(self, t):
                pass

            def sendto(self, data, dest):
                self.sent.append(dest)

            def recvfrom(self, n):
                if self.replies:
                    return self.replies.pop(0)
                raise socket.timeout()

            def close(self):
                pass

        fs = FakeSock()
        t = {"now": 0.0}

        def clock():
            t["now"] += 0.4
            return t["now"]

        locs, err = g.ssdp_discover("10.0.0.1", socket_factory=lambda: fs, collect_s=3.0, clock=clock)
        self.assertEqual(locs, ["http://10.0.0.1:49152/rootDesc.xml"])
        self.assertIsNone(err)
        self.assertEqual(len(fs.sent), 4)  # 2 STs x (multicast + unicast)
        self.assertIn(("239.255.255.250", 1900), fs.sent)
        self.assertIn(("10.0.0.1", 1900), fs.sent)

        def bad():
            raise OSError(65, "No route to host")

        self.assertEqual(g.ssdp_discover("10.0.0.1", socket_factory=bad), ([], 65))


class PollTests(unittest.TestCase):
    def test_counters_rates_and_wrap(self):
        ctx, clk, gw, col = make()
        col.discover()
        col.poll_counters()
        self.assertIsNone(col.rx_mbps)
        clk.tick(2.0)
        gw.sent = (gw.sent + 250_000) % g.U32  # wraps past 2^32; 1 Mb/s up
        gw.recv += 2_500_000  # 10 Mb/s down
        r = col.poll_counters()
        self.assertAlmostEqual(col.tx_mbps, 1.0, places=2)
        self.assertAlmostEqual(col.rx_mbps, 10.0, places=2)
        lat = ctx.state.latest("igd")
        self.assertEqual(lat["tx_mbps"], 1.0)
        self.assertIsNone(lat["trusted"])  # the counters move, but that does not make them right
        self.assertTrue(col.live)
        self.assertEqual(ctx.state.collector("igd")["reason"], g.NOT_VERIFIED_CHIP)
        verified(col, clk)
        wan = ctx.state.latest("wan")
        self.assertEqual((wan["rx_mbps"], wan["trusted"]), (10.0, True))
        self.assertEqual(ctx.state.collector("igd")["trusted"], True)

    def test_untrusted_after_5_minutes_static(self):
        ctx, clk, gw, col = make()
        col.discover()
        ctx.state.set_latest("iface", {"rx_mbps": 1.0, "tx_mbps": 0.5})
        for _ in range(160):
            col.poll_counters()
            clk.tick(2.0)
        self.assertFalse(col.trusted)
        c = ctx.state.collector("igd")
        self.assertEqual(c["status"], "ok")
        self.assertEqual(c["reason"], g.NOT_TRUSTED_CHIP)
        self.assertFalse(c["trusted"])
        # still no saturation note even with huge "tx"
        gw.sent += 100_000_000
        clk.tick(2.0)
        col.poll_counters()
        self.assertEqual(ctx.state.drain_notes(), [])

    def test_untrusted_waits_for_host_traffic(self):
        ctx, clk, gw, col = make()
        col.discover()
        for _ in range(160):
            col.poll_counters()
            clk.tick(2.0)
        self.assertIsNone(col.trusted)  # the host sent nothing: cannot judge yet

    def test_wan_saturated_note(self):
        ctx, clk, gw, col = make()
        col.discover()
        col.poll_counters()
        verified(col, clk)
        for i in range(4):
            clk.tick(2.0)
            gw.sent += 6_000_000  # 24 Mb/s > 80% of 25
            col.poll_counters()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["wan_saturated"])
        self.assertEqual(notes[0]["severity"], 2)
        clk.tick(2.0)
        col.poll_counters()  # tx 0 → re-armed, no repeat
        self.assertEqual(ctx.state.drain_notes(), [])

    def test_status_and_mappings(self):
        ctx, clk, gw, col = make()
        col.discover()
        row = col.poll_status()
        self.assertEqual((row["uptime_s"], row["status"], row["ext_ip"]), (123456, "Connected", "73.1.2.3"))
        self.assertEqual(ctx.store.rows[-1][0], "igd")
        maps = col.poll_mappings()
        self.assertEqual(len(maps), 1)
        self.assertEqual(maps[0]["proto"], "UDP")
        self.assertEqual(maps[0]["ext"], 3074)
        self.assertEqual(maps[0]["int"], "10.0.0.23:3074")
        self.assertEqual(maps[0]["desc"], "Xbox (10.0.0.23)")
        self.assertEqual(ctx.state.drain_notes(), [])
        gw.mappings = []
        col.poll_mappings()
        self.assertEqual([n["type"] for n in ctx.state.drain_notes()], ["nat_mapping_change"])
        st = col.status()
        self.assertEqual(st["status"], "ok")
        self.assertEqual(st["ext_ip"], "73.1.2.3")
        self.assertEqual(st["uptime_s"], 123456)
        self.assertEqual(st["mappings"], [])
        self.assertEqual(st["location"], "http://10.0.0.1:49152/rootDesc.xml")
        self.assertIn("WANIPConnection:1", "".join(st["services"]))

    def test_step_cadence(self):
        ctx, clk, gw, col = make()
        col.step()
        actions = [c[1] for c in gw.calls if c[1]]
        self.assertEqual(len([a for a in actions if "GetTotalBytes" in a]), 2)
        self.assertEqual(len([a for a in actions if "GetStatusInfo" in a]), 1)
        self.assertEqual(len([a for a in actions if "GetGenericPortMappingEntry" in a]), 2)  # entry 0 + fault
        n = len(gw.calls)
        clk.tick(1.0)
        col.step()
        self.assertEqual(len(gw.calls), n)
        clk.tick(1.0)
        col.step()
        self.assertEqual(len(gw.calls), n + 2)

    def test_counter_failures_degrade_then_disable(self):
        ctx, clk, gw, col = make()
        col.discover()
        gw.fail_counters = True
        for _ in range(5):
            col.poll_counters()
        self.assertEqual(ctx.state.collector("igd")["status"], "degraded")
        for _ in range(25):
            col.poll_counters()
        self.assertEqual(ctx.state.collector("igd")["status"], "disabled")
        self.assertFalse(col.ready)

    def test_thread(self):
        ctx, clk, gw, col = make()
        col.start()
        import time as _t

        _t.sleep(0.3)
        ctx.state.stop_event.set()
        col.stop(3.0)
        self.assertFalse(col.thread.is_alive())
        self.assertTrue(col.ready)


if __name__ == "__main__":
    unittest.main()


class PeggedCounterTests(unittest.TestCase):
    """A counter clamped at INT32 max (Arris TG4482A behaviour) must not read as a 0 Mb/s rate."""

    def test_pegged_receive_counter_gives_no_rx_rate_but_keeps_tx_trusted(self):
        ctx, clk, gw, col = make()
        col.discover()
        gw.recv = 2 ** 31 - 1
        col.poll_counters()
        clk.tick(2.0)
        gw.sent += 250_000  # 1 Mb/s up
        col.poll_counters()
        self.assertTrue(col.rx_pegged)
        self.assertFalse(col.tx_pegged)
        self.assertIsNone(col.rx_mbps)
        self.assertAlmostEqual(col.tx_mbps, 1.0, places=2)
        self.assertTrue(col.live)  # the upload counter still moves (trust needs a verification)
        lat = ctx.state.latest("igd")
        self.assertTrue(lat["rx_pegged"])
        self.assertIsNone(lat["rx_mbps"])
        self.assertIsNone(ctx.state.latest("wan")["rx_mbps"])
        # a counter that merely passes through the value once is not pegged
        gw.recv = 2 ** 31 - 1 + 5_000_000
        clk.tick(2.0)
        col.poll_counters()
        self.assertFalse(col.rx_pegged)
        self.assertAlmostEqual(col.rx_mbps, 20.0, places=1)



class UploadCounterVerificationTests(unittest.TestCase):
    """Moving counters are not trusted until they account for a known upload from this computer."""

    def host_upload(self, ctx, clk, gw, col, mbps, seconds, counted_share):
        """This computer uploads at ``mbps`` for ``seconds``; the gateway counts ``counted_share`` of it."""
        for _ in range(int(seconds / 2)):
            ctx.state.set_latest("iface", {"tx_mbps": mbps, "rx_mbps": 0.1})
            clk.tick(2.0)
            gw.sent += int(mbps * 1e6 / 8 * 2 * counted_share)
            col.poll_counters()

    def quiet(self, ctx, clk, gw, col, seconds):
        for _ in range(int(seconds / 2)):
            ctx.state.set_latest("iface", {"tx_mbps": 0.05, "rx_mbps": 0.1})
            clk.tick(2.0)
            gw.sent += 1500
            col.poll_counters()

    def test_passive_check_catches_a_counter_that_misses_most_traffic(self):
        ctx, clk, gw, col = make()
        col.discover()
        col.poll_counters()
        self.host_upload(ctx, clk, gw, col, mbps=8.0, seconds=4, counted_share=0.04)  # 2 MB, 4 % counted (the TG4482A)
        self.assertIsNone(col.trusted)  # still uploading: not judged yet
        self.quiet(ctx, clk, gw, col, 8)
        self.assertIs(col.trusted, False)
        c = ctx.state.collector("igd")
        self.assertIn("counted only", c["reason"])
        self.assertEqual(col.verification["method"], "passive")
        self.assertLess(col.verification["ratio"], 0.1)
        self.assertFalse(ctx.state.latest("wan")["trusted"])

    def test_passive_check_trusts_a_counter_that_adds_up(self):
        ctx, clk, gw, col = make()
        col.discover()
        col.poll_counters()
        self.host_upload(ctx, clk, gw, col, mbps=8.0, seconds=4, counted_share=1.05)
        self.quiet(ctx, clk, gw, col, 8)
        self.assertIs(col.trusted, True)
        self.assertIsNone(ctx.state.collector("igd")["reason"])

    def test_small_uploads_are_not_judged(self):
        ctx, clk, gw, col = make()
        col.discover()
        col.poll_counters()
        self.host_upload(ctx, clk, gw, col, mbps=1.0, seconds=4, counted_share=0.0)  # 0.5 MB < 1 MB
        self.quiet(ctx, clk, gw, col, 8)
        self.assertIsNone(col.trusted)

    def test_self_check_runs_once_a_minute_after_discovery(self):
        uploads = []

        def uploader(n, rate):
            uploads.append((n, rate))
            gw.sent += int(n * 0.04)  # the gateway counts 4 %
            return n

        ctx, clk, gw, col = make(uploader=uploader)
        col.step()
        self.assertTrue(col.ready)
        self.assertEqual(uploads, [])
        clk.tick(30)
        col.step()
        self.assertEqual(uploads, [])
        clk.tick(31)
        col.step()
        self.assertEqual(uploads, [(g.SELFCHECK_BYTES, g.SELFCHECK_RATE_BPS)])
        self.assertIs(col.trusted, False)
        self.assertEqual(col.verification["method"], "self-check")
        clk.tick(3600)
        col.step()
        self.assertEqual(len(uploads), 1)  # judged: never again

    def test_self_check_waits_while_an_episode_is_open_and_respects_the_switch(self):
        from laglens.state import Episode
        uploads = []

        def uploader(n, rate):
            uploads.append(n)
            gw.sent += n
            return n

        ctx, clk, gw, col = make(uploader=uploader)
        col.step()
        ctx.state.add_episode(Episode(id="ep-1", t0=clk.t))
        clk.tick(61)
        col.step()
        self.assertEqual(uploads, [])
        ctx.state.episodes[0].t1 = clk.t
        clk.tick(61)
        col.step()
        self.assertEqual(uploads, [g.SELFCHECK_BYTES])
        self.assertIs(col.trusted, True)
        ctx2, clk2, gw2, col2 = make()
        col2.verify_upload = False
        col2.step()
        clk2.tick(120)
        col2.step()  # make()'s default uploader would raise if called
        self.assertIsNone(col2.trusted)

    def test_failed_upload_is_retried_later(self):
        calls = []

        def uploader(n, rate):
            calls.append(n)
            raise OSError("offline")

        ctx, clk, gw, col = make(uploader=uploader)
        col.step()
        clk.tick(61)
        col.step()
        self.assertEqual(len(calls), 1)
        self.assertIsNone(col.trusted)
        clk.tick(60)
        col.step()
        self.assertEqual(len(calls), 1)
        clk.tick(g.SELFCHECK_RETRY_S)
        col.step()
        self.assertEqual(len(calls), 2)
