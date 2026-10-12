"""Tests for laglens.platform.linux with fixture outputs injected through fakes."""
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.platform import get_platform  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.platform.linux import LinuxPlatform, freq_to_channel  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "linux"


def fx(name: str) -> str:
    return (FIX / name).read_text()


class FakeRunner:
    """argv tuple → (rc, out, err) | str | Exception; unknown commands are 'not installed'."""

    def __init__(self, table=None):
        self.table = dict(table or {})
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        key = tuple(argv)
        if key not in self.table:
            raise FileNotFoundError(argv[0])
        v = self.table[key]
        if isinstance(v, BaseException):
            raise v
        if isinstance(v, str):
            return 0, v, ""
        return v


def make(table=None, files=None, exists=(), env=None, which=None) -> LinuxPlatform:
    files = dict(files or {})
    return LinuxPlatform(
        runner=FakeRunner(table),
        reader=lambda p: files.get(p),
        exists=lambda p: p in set(exists) or p in files,
        env=env or {},
        which=which or (lambda n: None),
    )


IP_ROUTE = ("ip", "-j", "route", "show", "default")
IP6_ROUTE = ("ip", "-j", "-6", "route", "show", "default")
IP_ADDR = ("ip", "-j", "addr", "show", "dev", "enp3s0")


class RouteTests(unittest.TestCase):
    def test_default_route_prefers_lowest_metric(self):
        p = make({IP_ROUTE: fx("ip_route_default.json"), IP6_ROUTE: fx("ip_6_route_default.json"), IP_ADDR: fx("ip_addr_enp3s0.json")})
        r = p.default_route()
        self.assertEqual(r["gateway"], "10.0.0.1")
        self.assertEqual(r["iface"], "enp3s0")
        self.assertEqual(r["gateway6"], "fe80::1%enp3s0")
        self.assertEqual(r["iface6"], "enp3s0")
        self.assertEqual(r["lan_ip"], "10.0.0.50")
        self.assertEqual(r["prefixlen"], 24)
        self.assertEqual(r["expires6"], 1497)

    def test_text_fallback_when_json_fails(self):
        p = make({IP_ROUTE: (1, "", "bad option"), ("ip", "route", "show", "default"): "default via 10.0.0.1 dev enp3s0 proto dhcp metric 100 \n"})
        r = p.default_route()
        self.assertEqual((r["gateway"], r["iface"]), ("10.0.0.1", "enp3s0"))
        self.assertIsNone(r["gateway6"])

    def test_proc_net_route_fallback_when_ip_missing(self):
        p = make({}, files={"/proc/net/route": fx("proc_net_route.txt")})
        r = p.default_route()
        self.assertEqual((r["gateway"], r["iface"]), ("10.0.0.1", "enp3s0"))
        self.assertIn("ip", p.missing)

    def test_no_route(self):
        p = make({IP_ROUTE: "[]", IP6_ROUTE: "[]"})
        r = p.default_route()
        self.assertIsNone(r["gateway"])
        self.assertIsNone(r["lan_ip"])

    def test_route_to_and_vpn(self):
        p = make({("ip", "-j", "route", "get", "1.1.1.1"): fx("ip_route_get.json")})
        self.assertEqual(p.route_to("1.1.1.1"), {"iface": "enp3s0", "src": "10.0.0.50"})
        self.assertEqual(p.vpn_routes("1.1.1.1"), {"via_tunnel": False, "iface": "enp3s0"})
        v = make({("ip", "-j", "route", "get", "1.1.1.1"): fx("ip_route_get_vpn.json")})
        self.assertEqual(v.vpn_routes("1.1.1.1"), {"via_tunnel": True, "iface": "tailscale0"})
        t = make({("ip", "-j", "route", "get", "1.1.1.1"): "[]", ("ip", "route", "get", "1.1.1.1"): "1.1.1.1 via 10.0.0.1 dev enp3s0 src 10.0.0.50 uid 1000 \n"})
        self.assertEqual(t.route_to("1.1.1.1"), {"iface": "enp3s0", "src": "10.0.0.50"})


class StatsLinkTests(unittest.TestCase):
    def test_sysfs_stats(self):
        base = "/sys/class/net/enp3s0/statistics/"
        files = {base + "rx_bytes": "100\n", base + "tx_bytes": "200", base + "rx_packets": "10", base + "tx_packets": "20",
                 base + "rx_errors": "1", base + "tx_errors": "2", base + "rx_dropped": "3", base + "tx_dropped": "4",
                 base + "rx_crc_errors": "5", base + "collisions": "6", base + "multicast": "7"}
        p = make({}, files=files)
        s = p.iface_stats("enp3s0")
        self.assertEqual(s, {"rx_bytes": 100, "tx_bytes": 200, "rx_packets": 10, "tx_packets": 20, "rx_errors": 1, "tx_errors": 2,
                             "rx_dropped": 3, "tx_dropped": 4, "crc": 5, "collisions": 6, "multicast": 7})

    def test_proc_net_dev_fallback(self):
        p = make({}, files={"/proc/net/dev": fx("proc_net_dev.txt")})
        s = p.iface_stats("enp3s0")
        self.assertEqual(s["rx_bytes"], 987654321)
        self.assertEqual(s["rx_packets"], 1234567)
        self.assertEqual(s["rx_errors"], 2)
        self.assertEqual(s["rx_dropped"], 3)
        self.assertEqual(s["multicast"], 4567)
        self.assertEqual(s["tx_bytes"], 123456789)
        self.assertEqual(s["tx_errors"], 5)
        self.assertEqual(s["tx_dropped"], 6)
        self.assertEqual(s["collisions"], 7)
        self.assertIsNone(s["crc"])
        self.assertTrue(all(v is None for v in make().iface_stats("nope").values()))

    def test_link_info(self):
        base = "/sys/class/net/enp3s0/"
        p = make({}, files={base + "speed": "1000", base + "duplex": "full", base + "carrier": "1", base + "carrier_changes": "3", base + "operstate": "up"})
        self.assertEqual(p.link_info("enp3s0"), {"speed": 1000, "duplex": "full", "carrier": True, "carrier_changes": 3, "operstate": "up", "wireless": False})
        w = make({}, files={"/sys/class/net/wlp2s0/speed": "-1", "/sys/class/net/wlp2s0/carrier": "0", "/sys/class/net/wlp2s0/duplex": "unknown"},
                 exists={"/sys/class/net/wlp2s0/wireless"})
        li = w.link_info("wlp2s0")
        self.assertIsNone(li["speed"])
        self.assertIsNone(li["duplex"])
        self.assertFalse(li["carrier"])
        self.assertTrue(li["wireless"])
        self.assertEqual(make().link_info("x")["carrier"], None)


class NeighborWifiDnsTests(unittest.TestCase):
    def test_neighbors(self):
        p = make({("ip", "-j", "neigh", "show"): fx("ip_neigh.json"), ("ip", "-j", "-6", "neigh", "show"): fx("ip_6_neigh.json")})
        n = p.neighbors()
        self.assertEqual(len(n), 4)
        self.assertEqual(n[0], {"ip": "10.0.0.1", "mac": "7c:ed:8d:aa:bb:cc", "iface": "enp3s0", "state": "REACHABLE"})
        self.assertEqual(n[2]["mac"], None)
        self.assertEqual(n[2]["state"], "FAILED")
        self.assertEqual(n[3]["ip"], "fe80::1")

    def test_neighbors_proc_arp_fallback(self):
        arp = "IP address       HW type     Flags       HW address            Mask     Device\n10.0.0.1         0x1         0x2         7C:ED:8D:AA:BB:CC     *        enp3s0\n10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        enp3s0\n"
        p = make({}, files={"/proc/net/arp": arp})
        self.assertEqual(p.neighbors(), [{"ip": "10.0.0.1", "mac": "7c:ed:8d:aa:bb:cc", "iface": "enp3s0", "state": "REACHABLE"}])

    def test_wifi_iw(self):
        p = make({("iw", "dev", "wlp2s0", "link"): fx("iw_link.txt")})
        w = p.wifi_info("wlp2s0")
        self.assertEqual(w["rssi"], -58)
        self.assertEqual(w["chan"], 36)
        self.assertEqual(w["ssid"], "HomeNet5")
        self.assertEqual(w["bssid"], "7c:ed:8d:aa:bb:cc")
        self.assertEqual(w["rate_mbps"], 780.0)
        self.assertIsNone(w["noise"])

    def test_wifi_proc_fallback_then_nmcli(self):
        p = make({("iw", "dev", "wlp2s0", "link"): "Not connected.\n"}, files={"/proc/net/wireless": fx("proc_net_wireless.txt")})
        w = p.wifi_info("wlp2s0")
        self.assertEqual(w["rssi"], -58)
        self.assertIsNone(w["noise"])
        self.assertEqual(w["quality"], 52.0)
        n = make({("nmcli", "-t", "-f", "IN-USE,SIGNAL,CHAN,BSSID", "dev", "wifi"): " :40:11:AA\\:BB\\:CC\\:DD\\:EE\\:01\n*:70:36:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n"})
        w = n.wifi_info("wlp2s0")
        self.assertEqual(w["chan"], 36)
        self.assertEqual(w["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertIsNone(make().wifi_info("wlp2s0"))

    def test_resolvers(self):
        p = make({("resolvectl", "status"): fx("resolvectl_status.txt")})
        self.assertEqual(p.resolvers(), ["10.0.0.1", "2001:558:feed::1", "2001:558:feed::2"])
        n = make({IP_ROUTE: fx("ip_route_default.json"), IP6_ROUTE: "[]", IP_ADDR: fx("ip_addr_enp3s0.json"),
                  ("nmcli", "-t", "-f", "IP4.DNS,IP6.DNS", "dev", "show", "enp3s0"): fx("nmcli_dns.txt")})
        self.assertEqual(n.resolvers(), ["10.0.0.1", "2001:558:feed::1"])
        g = make({IP_ROUTE: fx("ip_route_default.json"), IP6_ROUTE: "[]", IP_ADDR: fx("ip_addr_enp3s0.json")})
        self.assertEqual(g.resolvers(), ["10.0.0.1"])
        self.assertEqual(make().resolvers(), [])

    def test_freq_to_channel(self):
        self.assertEqual(freq_to_channel(2412), 1)
        self.assertEqual(freq_to_channel(2484), 14)
        self.assertEqual(freq_to_channel(5180), 36)
        self.assertEqual(freq_to_channel(5955), 1)
        self.assertIsNone(freq_to_channel(None))
        self.assertIsNone(freq_to_channel(1000))


class MiscTests(unittest.TestCase):
    def test_keepawake_order(self):
        p = make(which=lambda n: "/usr/bin/" + n if n == "kde-inhibit" else None)
        self.assertEqual(p.keepawake_cmd(1)[0], "kde-inhibit")
        p = make(which=lambda n: "/usr/bin/" + n if n == "systemd-inhibit" else None)
        self.assertEqual(p.keepawake_cmd(1)[:2], ["systemd-inhibit", "--what=sleep"])
        self.assertIsNone(make().keepawake_cmd(1))

    def test_battery_and_game_mode(self):
        self.assertTrue(make({}, files={"/sys/class/power_supply/AC/online": "0\n"}).on_battery())
        self.assertFalse(make({}, files={"/sys/class/power_supply/ACAD/online": "1"}).on_battery())
        self.assertIsNone(make().on_battery())
        self.assertTrue(make(env={"XDG_CURRENT_DESKTOP": "gamescope"}).is_game_mode())
        self.assertTrue(make({("pgrep", "-x", "gamescope"): "1234\n"}).is_game_mode())
        self.assertFalse(make({("pgrep", "-x", "gamescope"): (1, "", "")}).is_game_mode())

    def test_firewall_info(self):
        p = make({("firewall-cmd", "--state"): fx("firewall_cmd.txt"), ("firewall-cmd", "--get-default-zone"): "FedoraWorkstation\n",
                  ("firewall-cmd", "--list-ports"): "1025-65535/udp 1025-65535/tcp\n", ("firewall-cmd", "--list-services"): "dhcpv6-client ssh\n"})
        self.assertEqual(p.firewall_info(), {"state": "running", "zone": "FedoraWorkstation", "ports": ["1025-65535/udp", "1025-65535/tcp"], "services": ["dhcpv6-client", "ssh"]})
        self.assertEqual(make().firewall_info(), {})
        self.assertEqual(make({("firewall-cmd", "--state"): (252, "", "not running\n")}).firewall_info()["state"], "not running")

    def test_dhcp_lease(self):
        p = make({("nmcli", "-t", "-f", "DHCP4.OPTION", "dev", "show", "enp3s0"): "DHCP4.OPTION[1]:dhcp_lease_time = 86400\nDHCP4.OPTION[2]:dhcp_server_identifier = 10.0.0.1\n"})
        self.assertEqual(p.dhcp_lease("enp3s0"), {"dhcp_lease_time": "86400", "dhcp_server_identifier": "10.0.0.1"})

    def test_missing_binary_cached_once_and_timeouts(self):
        p = make()
        self.assertIsNone(p.run(["ip", "-j", "route"]))
        self.assertIsNone(p.run(["ip", "link"]))
        self.assertEqual(len(p._runner.calls), 1)
        self.assertEqual(p.capabilities["ip"], False)
        slow = make({("sleepy",): subprocess.TimeoutExpired("sleepy", 5)})
        self.assertIsNone(slow.run(["sleepy"]))
        self.assertEqual(slow.last_error["sleepy"], "timeout")
        self.assertNotIn("sleepy", slow.missing)
        self.assertIsNone(make({("x",): (2, "out", "")}).run(["x"]))
        self.assertEqual(make({("x",): (2, "out", "")}).run_rc(["x"]), (2, "out", ""))

    def test_get_platform_and_generic(self):
        self.assertIsInstance(get_platform("linux", runner=FakeRunner()), LinuxPlatform)
        g = get_platform("freebsd", runner=FakeRunner())
        self.assertIs(type(g), Platform)
        self.assertEqual(g.name, "generic")
        self.assertEqual(g.neighbors(), [])
        self.assertIsNone(g.wifi_info("x"))
        self.assertEqual(g.terminal_app_name(), "your terminal app")
        self.assertEqual(Platform(env={"TERM_PROGRAM": "iTerm.app"}).terminal_app_name(), "iTerm")
        self.assertEqual(Platform(env={"TERM_PROGRAM": "Other"}).terminal_app_name(), "Other")
        self.assertTrue(get_platform("linux", runner=FakeRunner()).hostname())


if __name__ == "__main__":
    unittest.main()
