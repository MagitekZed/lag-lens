"""Tests for laglens.platform.darwin with fixture outputs injected through fakes."""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.platform import get_platform  # noqa: E402
from laglens.platform.darwin import DarwinPlatform, netmask_to_prefixlen, parse_kv_block, parse_media, parse_netstat_ibn  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "darwin"


def fx(name: str) -> str:
    return (FIX / name).read_text()


class FakeRunner:
    def __init__(self, table=None):
        self.table = dict(table or {})
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        key = tuple(argv)
        if key not in self.table:
            raise FileNotFoundError(argv[0])
        v = self.table[key]
        if isinstance(v, str):
            return 0, v, ""
        return v


ROUTE_DEFAULT = ("route", "-n", "get", "default")
ROUTE6_DEFAULT = ("route", "-n", "get", "-inet6", "default")
IFCONFIG_EN0 = ("ifconfig", "en0")
PORTS = ("networksetup", "-listallhardwareports")


def make(table=None, env=None, which=None) -> DarwinPlatform:
    return DarwinPlatform(runner=FakeRunner(table), reader=lambda p: None, exists=lambda p: False, env=env or {}, which=which or (lambda n: None))


class RouteTests(unittest.TestCase):
    def test_default_route(self):
        p = make({ROUTE_DEFAULT: fx("route_get_default.txt"), ROUTE6_DEFAULT: fx("route_get_inet6_default.txt"), IFCONFIG_EN0: fx("ifconfig_en0.txt")})
        r = p.default_route()
        self.assertEqual(r["gateway"], "10.0.0.1")
        self.assertEqual(r["iface"], "en0")
        self.assertEqual(r["gateway6"], "fe80::7eed:8dff:feaa:bbcc%en0")
        self.assertEqual(r["iface6"], "en0")
        self.assertEqual(r["lan_ip"], "10.0.0.35")
        self.assertEqual(r["prefixlen"], 24)

    def test_netstat_fallback(self):
        p = make({("netstat", "-rn"): fx("netstat_rn.txt"), ROUTE6_DEFAULT: (1, "", "route: not in table")})
        r = p.default_route()
        self.assertEqual((r["gateway"], r["iface"]), ("10.0.0.1", "en0"))
        self.assertIsNone(r["gateway6"])

    def test_no_route(self):
        r = make().default_route()
        self.assertIsNone(r["gateway"])
        self.assertIsNone(r["iface"])

    def test_route_to_and_vpn(self):
        p = make({("route", "-n", "get", "1.1.1.1"): fx("route_get_1111.txt"), IFCONFIG_EN0: fx("ifconfig_en0.txt")})
        self.assertEqual(p.route_to("1.1.1.1"), {"iface": "en0", "src": "10.0.0.35"})
        self.assertFalse(p.vpn_routes()["via_tunnel"])
        v = make({("route", "-n", "get", "1.1.1.1"): fx("route_get_1111_vpn.txt")})
        self.assertEqual(v.vpn_routes("1.1.1.1"), {"via_tunnel": True, "iface": "utun4"})
        c = make({("route", "-n", "get", "1.1.1.1"): "  interface: en7\n", ("ifconfig", "en7"): "\tinet 100.70.1.2 netmask 0xffffffff\n"})
        self.assertTrue(c.vpn_routes("1.1.1.1")["via_tunnel"])

    def test_kv_and_netmask(self):
        self.assertEqual(parse_kv_block("   route to: default\n  interface: en0\n")["interface"], "en0")
        self.assertEqual(netmask_to_prefixlen("ffffff00"), 24)
        self.assertEqual(netmask_to_prefixlen("fffffffe"), 31)
        self.assertIsNone(netmask_to_prefixlen("zz"))


class StatsLinkTests(unittest.TestCase):
    def test_netstat_ibn_header_based(self):
        s = parse_netstat_ibn(fx("netstat_ibn_en0.txt"), "en0")
        self.assertEqual(s["rx_packets"], 1234567)
        self.assertEqual(s["rx_errors"], 3)
        self.assertEqual(s["rx_bytes"], 987654321)
        self.assertEqual(s["tx_packets"], 234567)
        self.assertEqual(s["tx_errors"], 5)
        self.assertEqual(s["tx_bytes"], 123456789)
        self.assertEqual(s["collisions"], 7)
        self.assertIsNone(s["multicast"])
        self.assertIsNone(s["crc"])
        self.assertIsNone(s["rx_dropped"])

    def test_netstat_ibn_without_address_column(self):
        s = parse_netstat_ibn(fx("netstat_ibn_lo0.txt"), "lo0")
        self.assertEqual((s["rx_packets"], s["rx_errors"], s["rx_bytes"], s["tx_bytes"], s["collisions"]), (1000, 0, 100000, 100000, 0))

    def test_netstat_ibn_with_drop_columns_and_junk(self):
        text = "Name  Mtu   Network  Address  Ipkts Ierrs  Ibytes  Idrop Opkts Oerrs  Obytes Odrop Coll\nen0  1500  <Link#4>  aa:bb  10 1 100 2 20 3 200 4 5\n"
        s = parse_netstat_ibn(text, "en0")
        self.assertEqual((s["rx_dropped"], s["tx_dropped"], s["rx_bytes"], s["collisions"]), (2, 4, 100, 5))
        self.assertTrue(all(v is None for v in parse_netstat_ibn("garbage\n", "en0").values()))
        self.assertTrue(all(v is None for v in make().iface_stats("en0").values()))
        p = make({("netstat", "-ibn", "-I", "en0"): fx("netstat_ibn_en0.txt")})
        self.assertEqual(p.iface_stats("en0")["rx_bytes"], 987654321)

    def test_parse_media(self):
        self.assertEqual(parse_media("autoselect (1000baseT <full-duplex>)"), {"speed": 1000, "duplex": "full"})
        self.assertEqual(parse_media("autoselect (10GbaseT <full-duplex,flow-control>)"), {"speed": 10000, "duplex": "full"})
        self.assertEqual(parse_media("autoselect (2500Base-T <full-duplex>)"), {"speed": 2500, "duplex": "full"})
        self.assertEqual(parse_media("autoselect (100baseTX <half-duplex>)"), {"speed": 100, "duplex": "half"})
        self.assertEqual(parse_media("autoselect"), {"speed": None, "duplex": None})

    def test_link_info(self):
        p = make({PORTS: fx("networksetup_ports.txt"), ("ifconfig", "en5"): fx("ifconfig_en5.txt"), IFCONFIG_EN0: fx("ifconfig_en0.txt"), ("ifconfig", "en6"): fx("ifconfig_en6_half.txt")})
        wired = p.link_info("en5")
        self.assertEqual((wired["speed"], wired["duplex"], wired["carrier"], wired["operstate"], wired["wireless"]), (1000, "full", True, "up", False))
        wifi = p.link_info("en0")
        self.assertTrue(wifi["wireless"])
        self.assertIsNone(wifi["speed"])
        self.assertTrue(wifi["carrier"])
        half = p.link_info("en6")
        self.assertEqual((half["speed"], half["duplex"], half["carrier"]), (100, "half", False))
        self.assertEqual(len([c for c in p._runner.calls if c[0] == list(PORTS)]), 1)  # port map cached
        self.assertEqual(make().link_info("en0")["carrier"], None)


class NeighborWifiDnsTests(unittest.TestCase):
    def test_neighbors_arp_and_ndp(self):
        p = make({("arp", "-an"): fx("arp_an.txt"), ("ndp", "-an"): fx("ndp_an.txt")})
        n = p.neighbors()
        v4 = [x for x in n if ":" not in x["ip"]]
        v6 = [x for x in n if ":" in x["ip"]]
        self.assertEqual(len(v4), 4)
        self.assertEqual(v4[0], {"ip": "10.0.0.1", "mac": "7c:ed:8d:aa:bb:cc", "iface": "en0", "state": "REACHABLE"})
        self.assertEqual(v4[2]["mac"], None)
        self.assertEqual(v4[2]["state"], "INCOMPLETE")
        self.assertEqual(len(v6), 4)
        self.assertEqual(v6[0]["ip"], "fe80::7eed:8dff:feaa:bbcc%en0")
        self.assertEqual(v6[0]["state"], "STALE")
        self.assertEqual(v6[1]["state"], "REACHABLE")
        self.assertEqual(v6[3]["mac"], None)
        self.assertEqual(make().neighbors(), [])

    def test_wifi_system_profiler(self):
        p = make({("system_profiler", "SPAirPortDataType", "-json"): fx("system_profiler_airport.json"), ("ipconfig", "getsummary", "en0"): fx("ipconfig_getsummary.txt")})
        w = p.wifi_info("en0")
        self.assertEqual(w["rssi"], -58)
        self.assertEqual(w["noise"], -92)
        self.assertEqual(w["chan"], 36)
        self.assertEqual(w["ssid"], "HomeNet5")
        self.assertEqual(w["rate_mbps"], 866.0)
        self.assertEqual(w["bssid"], "aa:bb:cc:11:22:33")
        self.assertEqual(w["phy"], "802.11ax")
        self.assertEqual([c[1] for c in p._runner.calls if c[0][0] == "system_profiler"], [10.0])

    def test_wifi_fallbacks(self):
        s = make({("ipconfig", "getsummary", "en0"): fx("ipconfig_getsummary.txt")})
        w = s.wifi_info("en0")
        self.assertEqual(w["ssid"], "HomeNet5")
        self.assertIsNone(w["rssi"])
        self.assertIsNone(make().wifi_info("en0"))
        bad = make({("system_profiler", "SPAirPortDataType", "-json"): "{not json"})
        self.assertIsNone(bad.wifi_info("en0"))
        other = make({("system_profiler", "SPAirPortDataType", "-json"): fx("system_profiler_airport.json")})
        self.assertIsNone(other.wifi_info("en1"))

    def test_resolvers(self):
        p = make({("scutil", "--dns"): fx("scutil_dns.txt")})
        self.assertEqual(p.resolvers(), ["10.0.0.1", "2001:558:feed::1"])
        g = make({ROUTE_DEFAULT: fx("route_get_default.txt"), ROUTE6_DEFAULT: (1, "", ""), IFCONFIG_EN0: fx("ifconfig_en0.txt")})
        self.assertEqual(g.resolvers(), ["10.0.0.1"])
        self.assertEqual(make().resolvers(), [])


class MiscTests(unittest.TestCase):
    def test_keepawake_battery_terminal(self):
        p = make(which=lambda n: "/usr/bin/caffeinate" if n == "caffeinate" else None, env={"TERM_PROGRAM": "Apple_Terminal"})
        self.assertEqual(p.keepawake_cmd(4242), ["/usr/bin/caffeinate", "-i", "-s", "-w", "4242"])
        self.assertEqual(p.terminal_app_name(), "Terminal")
        self.assertEqual(make(env={"TERM_PROGRAM": "ghostty"}).terminal_app_name(), "Ghostty")
        self.assertEqual(make(env={"TERM_PROGRAM": "vscode"}).terminal_app_name(), "Visual Studio Code")
        self.assertTrue(make({("pmset", "-g", "batt"): fx("pmset_batt.txt")}).on_battery())
        self.assertFalse(make({("pmset", "-g", "batt"): "Now drawing from 'AC Power'\n"}).on_battery())
        self.assertIsNone(make().on_battery())
        self.assertFalse(make().is_game_mode())
        self.assertEqual(make().firewall_info(), {})

    def test_dhcp_lease(self):
        txt = "op = BOOTREPLY\nyiaddr = 10.0.0.35\nserver_identifier (ip): 10.0.0.1\nlease_time (uint32): 0x15180\nrouter (ip_mult): {10.0.0.1}\n"
        p = make({("ipconfig", "getpacket", "en0"): txt})
        lease = p.dhcp_lease("en0")
        self.assertEqual(lease["lease_time"], 86400)
        self.assertEqual(lease["server_identifier"], "10.0.0.1")
        self.assertEqual(lease["router"], ["10.0.0.1"])
        self.assertEqual(make().dhcp_lease("en0"), {})

    def test_get_platform(self):
        self.assertIsInstance(get_platform("darwin", runner=FakeRunner()), DarwinPlatform)
        self.assertEqual(get_platform("darwin", runner=FakeRunner()).name, "darwin")
        la = get_platform("darwin", runner=FakeRunner()).load_avg()
        self.assertTrue(la is None or len(la) == 3)


if __name__ == "__main__":
    unittest.main()
