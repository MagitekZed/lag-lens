"""Tests for laglens.collectors.wan: trace parsing, WAN IP / prefix change notes, v6 route and neighbour health."""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.collectors.wan import TRACE_V4, TRACE_V6, WanCollector, parse_trace, prefix64  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.state import State  # noqa: E402


TRACE4 = "fl=123f45\nh=1.1.1.1\nip=73.1.2.3\nts=1760000000.123\nvisit_scheme=https\nuag=LagLens\ncolo=ORD\nsliver=none\nhttp=http/1.1\nloc=US\ntls=TLSv1.3\nsni=off\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n"
TRACE6 = TRACE4.replace("ip=73.1.2.3", "ip=2601:abcd:1234:5678:1:2:3:4").replace("h=1.1.1.1", "h=[2606:4700:4700::1111]")


class FakeResp(io.BytesIO):
    status = 200

    def getcode(self):
        return 200


class FakeUrlopen:
    def __init__(self):
        self.bodies = {TRACE_V4: TRACE4, TRACE_V6: TRACE6}
        self.calls = []

    def __call__(self, req, timeout=None):
        self.calls.append((req.full_url, timeout))
        body = self.bodies.get(req.full_url)
        if body is None:
            raise OSError(65, "No route to host")
        if isinstance(body, Exception):
            raise body
        return FakeResp(body.encode("utf-8"))


class FakePlatform(Platform):
    name = "darwin"

    def __init__(self):
        super().__init__(runner=lambda a, t: (1, "", ""), reader=lambda p: None, exists=lambda p: False, env={}, which=lambda n: None)
        self.route = {"gateway": "10.0.0.1", "iface": "en0", "gateway6": "fe80::7eed:8dff:feaa:bbcc%en0", "iface6": "en0", "lan_ip": "10.0.0.35", "prefixlen": 24}
        self.neigh = [{"ip": "fe80::7eed:8dff:feaa:bbcc%en0", "mac": "7c:ed:8d:aa:bb:cc", "iface": "en0", "state": "REACHABLE"}]

    def default_route(self):
        return dict(self.route)

    def neighbors(self):
        return list(self.neigh)


class Ctx:
    def __init__(self):
        self.cfg = {}
        self.state = State(cfg=self.cfg)
        self.platform = FakePlatform()
        self.route = self.platform.default_route()
        self.components = {}

    def component(self, n):
        return self.components.get(n)


class Clock:
    t = 1_760_000_000.0
    m = 100.0


def make():
    ctx = Ctx()
    clk = Clock()
    uo = FakeUrlopen()
    wc = WanCollector(ctx, urlopen=uo, clock=lambda: clk.t, mono=lambda: clk.m)
    return ctx, clk, uo, wc


class ParseTests(unittest.TestCase):
    def test_parse_trace_and_prefix(self):
        self.assertEqual(parse_trace(TRACE4)["ip"], "73.1.2.3")
        self.assertEqual(parse_trace(TRACE4)["colo"], "ORD")
        self.assertEqual(prefix64("2601:abcd:1234:5678:1:2:3:4"), "2601:abcd:1234:5678::/64")
        self.assertIsNone(prefix64("73.1.2.3"))
        self.assertIsNone(prefix64("garbage"))
        self.assertIsNone(prefix64(None))


class TraceTests(unittest.TestCase):
    def test_first_poll_publishes_without_notes(self):
        ctx, clk, uo, wc = make()
        r = wc.poll_trace()
        self.assertEqual(r["ext_ip"], "73.1.2.3")
        self.assertEqual(r["prefix6"], "2601:abcd:1234:5678::/64")
        self.assertEqual(ctx.state.drain_notes(), [])
        w = ctx.state.latest("wan")
        self.assertEqual(w["ext_ip"], "73.1.2.3")
        self.assertEqual(w["ext_ip6"], "2601:abcd:1234:5678:1:2:3:4")
        self.assertEqual(w["t"], clk.t)
        self.assertIn("rx_mbps", w)
        self.assertEqual(ctx.state.host["v6_prefix"], "2601:abcd:1234:5678::/64")
        self.assertEqual([c[1] for c in uo.calls], [5.0, 5.0])
        self.assertEqual(ctx.state.collector("wan")["status"], "ok")

    def test_change_notes(self):
        ctx, clk, uo, wc = make()
        wc.poll_trace()
        uo.bodies[TRACE_V4] = TRACE4.replace("73.1.2.3", "73.9.9.9")
        uo.bodies[TRACE_V6] = TRACE6.replace("2601:abcd:1234:5678", "2601:abcd:1234:9999")
        wc.poll_trace()
        notes = ctx.state.drain_notes()
        self.assertEqual(sorted(n["type"] for n in notes), ["v6_prefix_change", "wan_ip_change"])
        ip = [n for n in notes if n["type"] == "wan_ip_change"][0]
        self.assertEqual((ip["peak"]["old"], ip["peak"]["new"]), ("73.1.2.3", "73.9.9.9"))
        wc.poll_trace()
        self.assertEqual(ctx.state.drain_notes(), [])

    def test_v6_unreachable_keeps_v4(self):
        ctx, clk, uo, wc = make()
        del uo.bodies[TRACE_V6]
        r = wc.poll_trace()
        self.assertEqual(r["ext_ip"], "73.1.2.3")
        self.assertIsNone(r["ext_ip6"])
        self.assertIn("No route", r["err6"])
        self.assertEqual(ctx.state.collector("wan")["status"], "ok")
        uo.bodies = {}
        wc.poll_trace()
        c = ctx.state.collector("wan")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("unreachable", c["reason"])
        self.assertEqual(ctx.state.latest("wan")["ext_ip"], "73.1.2.3")  # last known kept

    def test_merges_igd_fields(self):
        ctx, clk, uo, wc = make()
        ctx.state.set_latest("wan", {"rx_mbps": 1.5, "tx_mbps": 0.2, "trusted": True, "uptime_s": 99})
        wc.poll_trace()
        w = ctx.state.latest("wan")
        self.assertEqual((w["rx_mbps"], w["trusted"], w["uptime_s"], w["ext_ip"]), (1.5, True, 99, "73.1.2.3"))

    def test_step_cadence(self):
        ctx, clk, uo, wc = make()
        wc.step()
        self.assertEqual(len(uo.calls), 2)
        clk.m += 30
        wc.step()
        self.assertEqual(len(uo.calls), 2)
        clk.m += 270
        wc.step()
        self.assertEqual(len(uo.calls), 4)


class V6HealthTests(unittest.TestCase):
    def test_route_expired(self):
        ctx, clk, uo, wc = make()
        wc.check_v6()
        self.assertEqual(wc.v6["route"], True)
        self.assertEqual(wc.v6["neigh_state"], "REACHABLE")
        ctx.platform.route["gateway6"] = None
        wc.check_v6()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["v6_route_expired"])
        wc.check_v6()
        self.assertEqual(ctx.state.drain_notes(), [])

    def test_gateway_stale_over_60s(self):
        ctx, clk, uo, wc = make()
        ctx.platform.neigh[0]["state"] = "STALE"
        wc.check_v6()
        clk.t += 30
        wc.check_v6()
        self.assertEqual(ctx.state.drain_notes(), [])
        clk.t += 31
        wc.check_v6()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["v6_gw_stale"])
        self.assertEqual(notes[0]["peak"]["state"], "STALE")
        clk.t += 30
        wc.check_v6()
        self.assertEqual(ctx.state.drain_notes(), [])
        ctx.platform.neigh[0]["state"] = "REACHABLE"
        wc.check_v6()
        ctx.platform.neigh[0]["state"] = "FAILED"
        clk.t += 100
        wc.check_v6()
        clk.t += 61
        wc.check_v6()
        self.assertEqual([n["type"] for n in ctx.state.drain_notes()], ["v6_gw_stale"])

    def test_no_v6_at_all(self):
        ctx, clk, uo, wc = make()
        ctx.platform.route["gateway6"] = None
        wc.check_v6()
        wc.check_v6()
        self.assertEqual(ctx.state.drain_notes(), [])
        self.assertFalse(wc.v6["route"])


if __name__ == "__main__":
    unittest.main()
