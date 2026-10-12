"""Tests for laglens.doctor: every check with a fake platform and no network, the macOS Local Network
diagnosis, the firewall admin command only when blocked, fast(ctx) -> doctor.json + state.doctor,
selftest()'s return code, ICMP helpers and the table renderer."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import doctor as d  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.state import State  # noqa: E402

GW = "10.0.0.1"
Usage = namedtuple("Usage", "total used free")


def echo_result(addr, received=3, sent=3, errno=None, method="socket", error=None, rtt=1.5):
    return {"addr": addr, "sent": sent, "received": received, "errno": errno, "rtts": [rtt] * received,
            "method": method, "error": error}


class FakeEcho:
    """``echo(addr, count, timeout, platform)`` answering from a table; every call is recorded."""

    def __init__(self, table=None):
        self.table = dict(table or {})
        self.calls = []

    def __call__(self, addr, count=d.ECHO_COUNT, timeout=d.ECHO_TIMEOUT_S, platform=None, **kw):
        self.calls.append((addr, count))
        if addr in self.table:
            r = dict(self.table[addr])
            r["sent"] = count
            r["received"] = min(count, r["received"])
            r["rtts"] = r["rtts"][:r["received"]]
            return r
        return echo_result(addr, received=count, sent=count)


class FakePlatform(Platform):
    name = "darwin"

    def __init__(self, name="darwin", wireless=False, gateway=GW, speed=1000, duplex="full", vpn=False,
                 keepawake=True, battery=False, game_mode=False, firewall=None, resolvers=None, neighbors=None,
                 binaries=("ping", "traceroute", "arp", "netstat", "route")):
        super().__init__(runner=lambda a, t: (1, "", ""), reader=lambda p: None, exists=lambda p: False,
                         env={"TERM_PROGRAM": "iTerm.app"}, which=lambda n: ("/usr/bin/" + n) if n in binaries else None)
        self.name = name
        self._wireless = wireless
        self._gateway = gateway
        self._speed = speed
        self._duplex = duplex
        self._vpn = vpn
        self._keepawake = keepawake
        self._battery = battery
        self._game = game_mode
        self._firewall = firewall if firewall is not None else {}
        self._resolvers = list(resolvers) if resolvers is not None else [GW]
        self._neighbors = list(neighbors or [])

    def default_route(self):
        if not self._gateway:
            return {"gateway": None, "iface": None, "gateway6": None, "iface6": None, "lan_ip": None, "prefixlen": None}
        return {"gateway": self._gateway, "iface": "en0", "gateway6": "fe80::1%en0", "iface6": "en0", "lan_ip": "10.0.0.35", "prefixlen": 24}

    def link_info(self, iface):
        return {"speed": self._speed, "duplex": self._duplex, "carrier": True, "carrier_changes": 0, "operstate": "up",
                "wireless": self._wireless}

    def vpn_routes(self, addr="1.1.1.1"):
        return {"via_tunnel": self._vpn, "iface": "utun3" if self._vpn else "en0"}

    def resolvers(self):
        return list(self._resolvers)

    def neighbors(self):
        return list(self._neighbors)

    def keepawake_cmd(self, pid):
        if not self._keepawake:
            return None
        return ["/usr/bin/caffeinate", "-i", "-s", "-w", str(pid)] if self.name == "darwin" else ["kde-inhibit", "--power", "sleep", "infinity"]

    def on_battery(self):
        return self._battery

    def is_game_mode(self):
        return self._game

    def firewall_info(self):
        return dict(self._firewall)

    def hostname(self):
        return "probe-mac"

    def os_info(self):
        return {"system": "Darwin" if self.name == "darwin" else "Linux", "release": "25.6.0", "machine": "arm64"}


def fakes(echo=None, **over):
    base = {
        "echo": echo or FakeEcho(),
        "dns": lambda server, name, timeout=2.0: {"ok": True, "rcode": 0, "addr": "20.1.2.3", "ms": 12.5, "error": None},
        "sntp": lambda: 0.012,
        "v6addr": lambda: "2601:1:2:3::10",
        "bind": lambda port, host="0.0.0.0": None,
        "resolve": lambda name, timeout=1.0: True,
        "ttl2": lambda platform, dst=d.INET4: ("ping -m", "10.60.1.1"),
        "docsis_probe": lambda cfg: {"ok": True, "login_path": "/check.jst", "tables": 3, "kinds": ["network_setup.jst:downstream"], "log_page": True},
        "igd_probe": lambda gw: {"found": True, "location": "http://10.0.0.1:49152/rootDesc.xml", "services": ["WANCommonInterfaceConfig", "WANIPConnection"],
                                 "wancic": True, "counters_move": True, "ext_ip": "73.1.2.3"},
        "disk_usage": lambda path: Usage(1000 * 2**20, 100 * 2**20, 900 * 2**20),
        "env": {},
        "pid": 4242,
    }
    base.update(over)
    return base


def cfg(**over):
    c = {"port": 8787, "bind": "0.0.0.0", "targets": {"xbox_ip": None}, "docsis": {"password": "pw", "pages": ["/network_setup.jst"]},
         "disk": {"min_free_mb": 500}}
    c.update(over)
    return c


def by_name(checks):
    out = {}
    for c in checks:
        out[c["check"]] = c
    return out


FULL_CHECKS = ["python", "icmp_v4_socket", "icmp_v6_socket", "local_network", "default_route", "interface_type", "link", "vpn",
               "gateway", "internet_v4", "internet_v6", "ttl_probe", "resolvers", "dns", "xbox", "xb7_login", "igd",
               "sleep_inhibitor", "battery", "firewall", "port", "local_name", "disk", "sessions_writable", "clock", "binaries"]
FAST_CHECKS = ["python", "icmp_v4_socket", "icmp_v6_socket", "local_network", "default_route", "interface_type", "link", "vpn",
               "sleep_inhibitor", "battery", "port", "local_name", "disk", "sessions_writable", "binaries"]


class FullTableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-doctor-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_every_check_present_and_all_ok(self):
        doc = d.Doctor(cfg(), FakePlatform(), root=self.tmp, **fakes())
        checks = doc.run(fast=False)
        self.assertEqual([c["check"] for c in checks], FULL_CHECKS)
        for c in checks:
            self.assertIn(c["status"], (d.OK, d.WARN, d.FAIL, d.SKIP))
            self.assertEqual(set(c), {"check", "status", "detail", "fallback"})
        bad = {c["check"]: c["status"] for c in checks if c["status"] != d.OK}
        self.assertEqual(bad, {"xbox": d.WARN})  # no Xbox IP configured is the only warning
        n = by_name(checks)
        self.assertIn("Python %d.%d" % sys.version_info[:2], n["python"]["detail"])
        self.assertIn("session: desktop", n["python"]["detail"])
        self.assertIn("wired", n["default_route"]["detail"])
        self.assertIn("hop at TTL 2: 10.60.1.1", n["ttl_probe"]["detail"])
        self.assertIn("20.1.2.3 in 12.5 ms", n["dns"]["detail"])
        self.assertIn("/check.jst", n["xb7_login"]["detail"])
        self.assertIn("incrementing", n["igd"]["detail"])
        self.assertEqual(n["sleep_inhibitor"]["detail"], "caffeinate")
        self.assertEqual(n["battery"]["detail"], "on AC power")
        self.assertIn("http://10.0.0.35:8787", n["port"]["detail"])
        self.assertEqual(n["local_name"]["detail"], "http://probe-mac.local:8787")
        self.assertIn("900 MB free", n["disk"]["detail"])
        self.assertEqual(n["sessions_writable"]["detail"], str(self.tmp / "sessions"))
        self.assertIn("offset +0.012 s", n["clock"]["detail"])
        self.assertIn("present: ping", n["binaries"]["detail"])
        self.assertTrue((self.tmp / "sessions").is_dir())
        self.assertEqual(list((self.tmp / "sessions").iterdir()), [])  # the write probe is removed

    def test_run_cli_prints_table_and_counts(self):
        lines = []
        rc = d.run_cli(cfg(), FakePlatform(wireless=True), out=lines.append, root=self.tmp, **fakes())
        self.assertEqual(rc, 0)
        text = "\n".join(lines)
        table = lines[0].splitlines()  # the table is printed as one block, then the counts line
        self.assertTrue(table[0].startswith("CHECK"))
        self.assertIn("| STATUS |", table[0])
        self.assertTrue(table[1].startswith("---"))
        self.assertEqual(len(table), len(FULL_CHECKS) + 2)
        self.assertIn("interface_type", text)
        self.assertIn("WARN", text)
        self.assertIn(d.WIFI_WARN, text)
        self.assertRegex(lines[-1], r"^\d+ ok, \d+ warn, \d+ fail, \d+ skipped$")
        self.assertIn("24 ok, 2 warn, 0 fail, 0 skipped", lines[-1])

    def test_no_net_skips_network_checks(self):
        echo = FakeEcho()
        doc = d.Doctor(cfg(), FakePlatform(), no_net=True, root=self.tmp, **fakes(echo=echo))
        n = by_name(doc.run(fast=False))
        for name in ("local_network", "gateway", "internet_v4", "internet_v6", "ttl_probe", "dns", "xb7_login", "igd", "clock", "local_name"):
            self.assertEqual(n[name]["status"], d.SKIP, name)
        self.assertEqual(n["resolvers"]["status"], d.OK)
        self.assertEqual(n["xbox"]["status"], d.WARN)
        # only the loopback socket echoes were sent
        self.assertEqual(sorted({a for a, _ in echo.calls}), ["127.0.0.1", "::1"])

    def test_warn_and_fail_paths(self):
        plat = FakePlatform(wireless=True, speed=100, duplex="half", vpn=True, keepawake=False, battery=True, game_mode=True,
                            resolvers=[], binaries=())
        f = fakes(
            echo=FakeEcho({d.INET6: echo_result(d.INET6, received=0, error="timeout"), GW: echo_result(GW, received=0, error="timeout")}),
            dns=lambda server, name, timeout=2.0: {"ok": False, "rcode": 2, "addr": None, "ms": None, "error": None},
            sntp=lambda: 12.0, v6addr=lambda: None, ttl2=lambda platform, dst=d.INET4: (None, None),
            docsis_probe=lambda cfg: {"ok": False, "error": "XB7 rejected the login (user admin)"},
            igd_probe=lambda gw: {"found": False, "error": d.LOCAL_NETWORK_MSG[:10]},
            disk_usage=lambda path: Usage(1000 * 2**20, 900 * 2**20, 100 * 2**20),
            resolve=lambda name, timeout=1.0: False,
            bind=lambda port, host="0.0.0.0": "Address already in use",
        )
        doc = d.Doctor(cfg(), plat, root=self.tmp, **f)
        n = by_name(doc.run(fast=False))
        self.assertEqual(n["session"]["status"], d.WARN)
        self.assertIn("Game Mode", n["python"]["detail"])
        self.assertEqual(n["interface_type"]["status"], d.WARN)
        self.assertEqual(n["link"]["status"], d.OK)  # Wi-Fi links are not judged on speed/duplex
        self.assertEqual(n["vpn"]["status"], d.WARN)
        self.assertIn("utun3", n["vpn"]["detail"])
        self.assertEqual(n["local_network"]["status"], d.WARN)  # gateway silent but no errno 65
        self.assertEqual(n["gateway"]["status"], d.FAIL)
        self.assertEqual(n["gateway"]["fallback"], "Local Network permission?")
        self.assertEqual(n["internet_v4"]["status"], d.OK)
        self.assertEqual(n["internet_v6"]["status"], d.WARN)
        self.assertEqual(n["ttl_probe"]["status"], d.WARN)
        self.assertEqual(n["resolvers"]["status"], d.WARN)
        self.assertEqual(n["dns"]["status"], d.FAIL)
        self.assertIn("rcode 2", n["dns"]["detail"])
        self.assertEqual(n["xb7_login"]["status"], d.FAIL)
        self.assertIn("rejected", n["xb7_login"]["detail"])
        self.assertEqual(n["igd"]["status"], d.WARN)
        self.assertEqual(n["sleep_inhibitor"]["status"], d.WARN)
        self.assertEqual(n["battery"]["status"], d.WARN)
        self.assertEqual(n["port"]["status"], d.FAIL)
        self.assertEqual(n["local_name"]["status"], d.WARN)
        self.assertEqual(n["disk"]["status"], d.FAIL)
        self.assertEqual(n["clock"]["status"], d.WARN)
        self.assertIn("+12.0 s", n["clock"]["detail"])
        self.assertEqual(n["binaries"]["status"], d.WARN)

    def test_wired_link_speed_warning_and_port_fallback(self):
        plat = FakePlatform(speed=100, duplex="half")
        busy = {8787: "Address already in use", 8788: "Address already in use"}
        f = fakes(bind=lambda port, host="0.0.0.0": busy.get(port))
        n = by_name(d.Doctor(cfg(), plat, root=self.tmp, **f).run(fast=True))
        self.assertEqual(n["link"]["status"], d.WARN)
        self.assertIn("100 Mb/s / half", n["link"]["detail"])
        self.assertEqual(n["port"]["status"], d.WARN)
        self.assertIn("will use 8789", n["port"]["detail"])
        self.assertEqual(n["port"]["fallback"], "http://10.0.0.35:8789")

    def test_no_default_route(self):
        n = by_name(d.Doctor(cfg(), FakePlatform(gateway=None), root=self.tmp, **fakes()).run(fast=False))
        self.assertEqual(n["default_route"]["status"], d.FAIL)
        self.assertEqual(n["local_network"]["status"], d.WARN)
        self.assertEqual(n["link"]["status"], d.SKIP)
        self.assertEqual(n["gateway"]["status"], d.FAIL)
        self.assertEqual(n["igd"]["status"], d.SKIP)

    def test_xbox_and_xb7_variants(self):
        n = by_name(d.Doctor(cfg(targets={"xbox_ip": "10.0.0.50"}, docsis={"password": None}), FakePlatform(), root=self.tmp, **fakes()).run(fast=False))
        self.assertEqual(n["xbox"]["status"], d.OK)
        self.assertEqual(n["xb7_login"]["status"], d.SKIP)
        self.assertIn("docsis.password not set", n["xb7_login"]["detail"])
        plat = FakePlatform(neighbors=[{"ip": "10.0.0.77", "mac": "7C:ED:8D:11:22:33", "iface": "en0", "state": "reachable"},
                                       {"ip": "10.0.0.78", "mac": "AA:BB:CC:11:22:33", "iface": "en0", "state": "reachable"}])
        n = by_name(d.Doctor(cfg(), plat, root=self.tmp, **fakes()).run(fast=False))
        self.assertEqual(n["xbox"]["status"], d.WARN)
        self.assertIn("10.0.0.77", n["xbox"]["detail"])
        self.assertNotIn("10.0.0.78", n["xbox"]["detail"])
        f = fakes(docsis_probe=lambda cfg: {"ok": True, "login_path": "/check.jsp", "tables": 0, "kinds": [], "log_page": False})
        n = by_name(d.Doctor(cfg(), FakePlatform(), root=self.tmp, **f).run(fast=False))
        self.assertEqual(n["xb7_login"]["status"], d.WARN)
        self.assertIn("--docsis-dump", n["xb7_login"]["fallback"])

    def test_check_crash_is_contained(self):
        def boom(server, name, timeout=2.0):
            raise RuntimeError("kaboom")

        checks = d.Doctor(cfg(), FakePlatform(), root=self.tmp, **fakes(dns=boom)).run(fast=False)
        n = by_name(checks)
        self.assertEqual(n["dns"]["status"], d.FAIL)
        self.assertIn("check crashed: RuntimeError: kaboom", n["dns"]["detail"])
        self.assertEqual(len(checks), len(FULL_CHECKS) - 1)  # the crashed group lost its 'resolvers' sibling only

    def test_socket_fallbacks(self):
        echo = FakeEcho({"127.0.0.1": echo_result("127.0.0.1", received=0, method="socket", error="timeout"),
                         "::1": echo_result("::1", received=0, method=None, errno=1, error="socket: [Errno 1] Operation not permitted")})
        plat = FakePlatform(name="linux")
        plat._reader = lambda p: "1 0\n" if p.endswith("ping_group_range") else None
        n = by_name(d.Doctor(cfg(), plat, root=self.tmp, **fakes(echo=echo)).run(fast=True))
        self.assertEqual(n["icmp_v4_socket"]["status"], d.WARN)
        self.assertEqual(n["icmp_v4_socket"]["fallback"], "ping-binary backend")
        self.assertEqual(n["icmp_v6_socket"]["status"], d.WARN)
        self.assertIn("ping_group_range = 1 0", n["icmp_v6_socket"]["detail"])
        self.assertEqual(n["ping_group_range"]["detail"], "1 0")


class LocalNetworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-doctor-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def denied_echo(self):
        return FakeEcho({GW: echo_result(GW, received=0, errno=d.EHOSTUNREACH, error="sendto: [Errno 65] No route to host")})

    def test_denied_diagnosis_names_the_terminal_app(self):
        echo = self.denied_echo()
        doc = d.Doctor(cfg(), FakePlatform(), root=self.tmp, **fakes(echo=echo))
        n = by_name(doc.run(fast=False))
        self.assertTrue(doc.local_network_denied)
        self.assertEqual(n["local_network"]["status"], d.FAIL)
        self.assertIn("errno 65", n["local_network"]["detail"])
        self.assertIn("Privacy & Security > Local Network", n["local_network"]["fallback"])
        self.assertIn("**iTerm**", n["local_network"]["fallback"])
        self.assertEqual(n["gateway"]["status"], d.FAIL)
        self.assertEqual(n["internet_v4"]["status"], d.OK)
        # the provocation echoes the gateway and 1.1.1.1 first, before any other network check
        net_calls = [a for a, _ in echo.calls if a not in ("127.0.0.1", "::1")]
        self.assertEqual(set(net_calls[:2]), {GW, d.INET4})
        # and those results are reused, not re-sent, by the reachability check
        self.assertEqual(net_calls.count(GW), 1)
        self.assertEqual(net_calls.count(d.INET4), 1)

    def test_allowed_and_not_macos(self):
        n = by_name(d.Doctor(cfg(), FakePlatform(), root=self.tmp, **fakes()).run(fast=True))
        self.assertEqual(n["local_network"]["status"], d.OK)
        self.assertIn("3/3 gateway echoes", n["local_network"]["detail"])
        n = by_name(d.Doctor(cfg(), FakePlatform(name="linux"), root=self.tmp, **fakes(echo=self.denied_echo())).run(fast=True))
        self.assertEqual(n["local_network"]["status"], d.OK)
        self.assertEqual(n["local_network"]["detail"], "n/a (not macOS)")

    def test_fast_sets_collector_when_denied(self):
        ctx = Ctx(self.tmp)
        checks = d.fast(ctx, **fakes(echo=self.denied_echo()))
        self.assertEqual(by_name(checks)["local_network"]["status"], d.FAIL)
        c = ctx.state.collector("local_network")
        self.assertEqual(c["status"], "disabled")
        self.assertIn("**iTerm**", c["reason"])


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-doctor-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def firewall(self, info, port=8787):
        plat = FakePlatform(name="linux", firewall=info)
        return by_name(d.Doctor(cfg(port=port), plat, root=self.tmp, **fakes()).run(fast=False))["firewall"]

    def test_admin_command_only_when_blocked(self):
        c = self.firewall({"state": "running", "zone": "public", "ports": []})
        self.assertEqual(c["status"], d.WARN)
        self.assertEqual(c["fallback"], "sudo firewall-cmd --add-port=8787/tcp && sudo firewall-cmd --permanent --add-port=8787/tcp")
        c = self.firewall({"state": "running", "zone": "public", "ports": ["22/tcp"]}, port=9000)
        self.assertIn("--add-port=9000/tcp", c["fallback"])
        for info in ({"state": "running", "zone": "FedoraWorkstation", "ports": []},
                     {"state": "running", "zone": "public", "ports": ["8787/tcp"]},
                     {}):
            c = self.firewall(info)
            self.assertEqual(c["status"], d.OK, info)
            self.assertIsNone(c["fallback"], info)

    def test_not_linux(self):
        c = by_name(d.Doctor(cfg(), FakePlatform(firewall={"state": "running", "zone": "public", "ports": []}), root=self.tmp, **fakes()).run(fast=False))["firewall"]
        self.assertEqual((c["status"], c["detail"], c["fallback"]), (d.OK, "n/a (not Linux)", None))


class FakeStore:
    def __init__(self, root):
        self.dir = root / "sessions" / "20261011-000000"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.written = []

    def write_json_atomic(self, name, obj, indent=1):
        p = self.dir / name
        p.write_text(json.dumps(obj, indent=indent), encoding="utf-8")
        self.written.append(name)
        return p


class Ctx:
    def __init__(self, root, platform=None):
        self.cfg = cfg()
        self.state = State(cfg=self.cfg)
        self.store = FakeStore(root)
        self.platform = platform or FakePlatform()
        self.root = root
        self.route = {"gateway": GW, "iface": "en0", "gateway6": None, "iface6": None, "lan_ip": "10.0.0.35", "prefixlen": 24}
        self.components = {}

    def component(self, n):
        return self.components.get(n)


class FastTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-doctor-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_fast_writes_doctor_json_and_state(self):
        ctx = Ctx(self.tmp)
        echo = FakeEcho()
        checks = d.fast(ctx, **fakes(echo=echo))
        self.assertEqual([c["check"] for c in checks], FAST_CHECKS)
        self.assertIs(ctx.state.doctor, checks)
        self.assertEqual(ctx.store.written, ["doctor.json"])
        on_disk = json.loads((ctx.store.dir / "doctor.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk, checks)
        for c in checks:
            self.assertIn("t", c)
            self.assertIsInstance(c["t"], float)
        # ctx.route is used instead of asking the platform again
        self.assertIn("10.0.0.35", by_name(checks)["port"]["detail"])
        # no network check beyond the Local Network provocation
        self.assertEqual({a for a, _ in echo.calls}, {"127.0.0.1", GW, d.INET4, "::1"})
        self.assertIsNone(ctx.state.collector("local_network"))
        self.assertIn("doctor", ctx.state.snapshot())
        self.assertEqual(len(ctx.state.snapshot()["doctor"]), len(FAST_CHECKS))

    def test_fast_survives_a_broken_store(self):
        ctx = Ctx(self.tmp)
        ctx.store = object()
        with self.assertLogs("laglens.doctor", level="DEBUG"):
            checks = d.fast(ctx, **fakes())
        self.assertEqual(len(checks), len(FAST_CHECKS))
        self.assertEqual(ctx.state.doctor, checks)


class SelftestTests(unittest.TestCase):
    def test_return_codes(self):
        lines = []
        ok = FakeEcho()
        self.assertEqual(d.selftest(run_tests=False, out=lines.append, echo=ok), 0)
        self.assertEqual([a for a, _ in ok.calls], ["127.0.0.1", "::1"])
        self.assertTrue(all("ok" in ln for ln in lines))
        lines = []
        bad = FakeEcho({"::1": echo_result("::1", received=0, error="timeout")})
        self.assertEqual(d.selftest(run_tests=False, out=lines.append, echo=bad), 1)
        self.assertTrue(any("FAIL" in ln for ln in lines))
        lines = []
        nosock = FakeEcho({"127.0.0.1": echo_result("127.0.0.1", received=0, method=None, error="socket: denied"),
                           "::1": echo_result("::1", received=0, method=None, error="socket: denied")})
        self.assertEqual(d.selftest(run_tests=False, out=lines.append, echo=nosock), 0)
        self.assertTrue(all("skipped" in ln for ln in lines))

    def test_loopback_checks_direct(self):
        self.assertEqual(d.loopback_checks(echo=FakeEcho(), out=lambda s: None), 0)


class HelperTests(unittest.TestCase):
    def test_build_echo_and_strip_header(self):
        pkt = d.build_echo(0x1234, 7, b"payload")
        self.assertEqual(pkt[0], 8)
        self.assertEqual(pkt[4:8], b"\x12\x34\x00\x07")
        self.assertEqual(d._checksum(pkt), 0)  # a valid checksum sums to zero
        v6 = d.build_echo(1, 2, b"x", v6=True)
        self.assertEqual((v6[0], v6[2:4]), (128, b"\x00\x00"))
        ip_hdr = bytes([0x45]) + b"\0" * 19
        self.assertEqual(d.strip_ip_header(ip_hdr + b"icmp-body"), b"icmp-body")
        self.assertEqual(d.strip_ip_header(b"\x00\x00\x00\x00" + b"linux-body"), b"\x00\x00\x00\x00linux-body")

    def test_format_table_alignment(self):
        rows = [d.check("python", d.OK, "fine"), d.check("local_network", d.FAIL, "denied", "allow it")]
        text = d.format_table(rows).splitlines()
        self.assertEqual(len(text), 4)
        self.assertEqual(text[0].index("|"), text[2].index("|"))
        self.assertEqual(text[2].index("|"), text[3].index("|"))
        self.assertRegex(text[3], r"\| FAIL\s+\|")
        self.assertTrue(text[3].endswith("| allow it"))

    def test_local_network_message_names_app(self):
        self.assertIn("**Terminal**", d.LOCAL_NETWORK_MSG.format(app="Terminal"))

    def test_echo_parallel_reports_every_address(self):
        def flaky(addr, count=3, timeout=0.5, platform=None):
            if addr == "b":
                raise RuntimeError("no")
            return echo_result(addr, received=count, sent=count)

        out = d.echo_parallel(["a", "b"], count=2, timeout=0.1, echo=flaky)
        self.assertEqual(out["a"]["received"], 2)
        self.assertEqual((out["b"]["received"], out["b"]["error"]), (0, "no"))


if __name__ == "__main__":
    unittest.main()
