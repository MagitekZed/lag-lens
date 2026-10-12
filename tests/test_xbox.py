"""Tests for laglens.probes.xbox_presence and laglens.collectors.xbox.

Covers the SmartGlass discovery packet and reply parsing, OUI matching and
discovery from fixture neighbours, target registration, and the
UNKNOWN → AWAKE → ASLEEP → AWAKE state machine with the ICMP-only fallback.
"""
import argparse
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.collectors import xbox as xb  # noqa: E402
from laglens.collectors.xbox import XboxCollector, find_candidates, load_ouis, normalize_mac, oui_of  # noqa: E402
from laglens.probes import xbox_presence  # noqa: E402
from laglens.state import F_LOST, KIND_ICMP, Sample, State, Target  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------- presence probe
class FakeUdp:
    def __init__(self, family, type_, inbox=None, exc=None):
        self.family = family
        self.type = type_
        self.inbox = list(inbox or [])
        self.exc = exc
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, t):
        self.timeout = t

    def sendto(self, data, addr):
        if self.exc is not None:
            raise self.exc
        self.sent.append((data, addr))

    def recvfrom(self, n):
        if not self.inbox:
            raise socket.timeout("timed out")
        return self.inbox.pop(0), ("10.0.0.23", 5050)

    def close(self):
        self.closed = True


class PresenceTests(unittest.TestCase):
    def test_discovery_request_bytes(self):
        pkt = xbox_presence.DISCOVERY_REQUEST
        self.assertEqual(len(pkt), 16)
        self.assertEqual(pkt, bytes.fromhex("dd00000a0000" "00000000" "0008" "0000" "0002"))
        self.assertEqual(pkt[:2], b"\xdd\x00")          # DiscoveryRequest
        self.assertEqual(pkt[2:4], b"\x00\x0a")          # payload length 10
        self.assertEqual(pkt[4:6], b"\x00\x00")          # version 0
        self.assertEqual(pkt[6:10], b"\x00\x00\x00\x00")  # flags
        self.assertEqual(pkt[10:12], b"\x00\x08")        # client type 8
        self.assertEqual(pkt[12:14], b"\x00\x00")        # min version
        self.assertEqual(pkt[14:16], b"\x00\x02")        # max version

    def test_reply_detection(self):
        self.assertTrue(xbox_presence.is_discovery_response(b"\xdd\x01\x00\x10" + b"\x00" * 16))
        self.assertFalse(xbox_presence.is_discovery_response(b"\xdd\x00\x00\x10"))
        self.assertFalse(xbox_presence.is_discovery_response(b"\xdd"))
        self.assertFalse(xbox_presence.is_discovery_response(b""))

    def test_probe_true_on_reply(self):
        made = []

        def factory(fam, typ):
            s = FakeUdp(fam, typ, inbox=[b"garbage", b"\xdd\x01\x00\x20" + b"\x00" * 32])
            made.append(s)
            return s

        self.assertTrue(xbox_presence.probe("10.0.0.23", timeout=1.5, sock_factory=factory))
        s = made[0]
        self.assertEqual(s.sent, [(xbox_presence.DISCOVERY_REQUEST, ("10.0.0.23", 5050))])
        self.assertEqual(s.timeout, 1.5)
        self.assertTrue(s.closed)
        self.assertEqual(s.family, socket.AF_INET)

    def test_probe_false_on_timeout_garbage_or_error(self):
        self.assertFalse(xbox_presence.probe("10.0.0.23", sock_factory=lambda f, t: FakeUdp(f, t)))
        self.assertFalse(xbox_presence.probe("10.0.0.23", sock_factory=lambda f, t: FakeUdp(f, t, inbox=[b"\xdd\x00"])))
        self.assertFalse(xbox_presence.probe("10.0.0.23",
                                             sock_factory=lambda f, t: FakeUdp(f, t, exc=OSError(65, "no route"))))

        def boom(f, t):
            raise RuntimeError("factory exploded")

        self.assertFalse(xbox_presence.probe("10.0.0.23", sock_factory=boom))
        self.assertFalse(xbox_presence.probe("", sock_factory=boom))


# ---------------------------------------------------------------- OUI / discovery helpers
class OuiTests(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(normalize_mac("7c:ed:8d:1:2:3"), "7C:ED:8D:01:02:03")
        self.assertEqual(normalize_mac("28-16-A8-11-22-33"), "28:16:A8:11:22:33")
        self.assertEqual(normalize_mac("2816.a811.2233"), "28:16:A8:11:22:33")
        self.assertIsNone(normalize_mac("(incomplete)"))
        self.assertIsNone(normalize_mac(None))
        self.assertIsNone(normalize_mac("7c:ed:8d"))
        self.assertEqual(oui_of("7c:ed:8d:1:2:3"), "7C:ED:8D")

    def test_load_ouis_from_shipped_file(self):
        ouis = load_ouis()
        self.assertIn("7C:ED:8D", ouis)
        self.assertIn("28:16:A8", ouis)
        self.assertNotIn("00:15:5D", ouis)  # Hyper-V excluded by the data file
        self.assertTrue(all(len(o) == 8 for o in ouis))
        self.assertEqual(load_ouis(os.path.join(ROOT, "does-not-exist.txt")), set())

    def test_find_candidates_from_fixture_neighbours(self):
        from laglens.platform.darwin import DarwinPlatform

        with open(os.path.join(ROOT, "tests", "fixtures", "darwin", "arp_an.txt")) as fh:
            arp = fh.read()

        def runner(argv, timeout):
            if argv[0] == "arp":
                return 0, arp, ""
            raise FileNotFoundError(argv[0])

        rows = DarwinPlatform(runner=runner).neighbors()
        ouis = load_ouis()
        # the gateway 10.0.0.1 carries a Microsoft OUI in the fixture: it must be excluded
        cands = find_candidates(rows, ouis, exclude_ips=["10.0.0.1"])
        self.assertEqual(cands, [{"ip": "10.0.0.23", "mac": "28:16:a8:11:22:33", "oui_match": "28:16:A8"}])
        self.assertEqual(len(find_candidates(rows, ouis)), 2)

    def test_find_candidates_filters(self):
        ouis = {"7C:ED:8D"}
        rows = [
            {"ip": "10.0.0.5", "mac": "7c:ed:8d:1:2:3"},
            {"ip": "10.0.0.5", "mac": "7c:ed:8d:1:2:3"},            # duplicate ip
            {"ip": "10.0.0.6", "mac": None},                        # incomplete
            {"ip": "224.0.0.251", "mac": "7c:ed:8d:0:0:fb"},        # multicast
            {"ip": "fe80::1%en0", "mac": "7c:ed:8d:4:5:6"},         # v6 ignored (xbox target is v4)
            {"ip": "10.0.0.7", "mac": "aa:bb:cc:dd:ee:ff"},         # other vendor
            {"ip": "10.0.0.8", "mac": "7c:ed:8d:9:9:9"},
            "garbage",
        ]
        cands = find_candidates(rows, ouis, exclude_macs=["7C:ED:8D:09:09:09"])
        self.assertEqual([c["ip"] for c in cands], ["10.0.0.5"])


# ---------------------------------------------------------------- collector fakes
class FakeClock:
    def __init__(self, mono=1000.0, wall=1_700_000_000.0):
        self.mono = mono
        self.wall = wall

    def advance(self, s):
        self.mono += s
        self.wall += s


class FakeStore:
    def __init__(self):
        self.written = []

    def write_json_atomic(self, name, obj, indent=1):
        self.written.append((name, obj))
        return name


class FakePlatform:
    def __init__(self, rows=None, gateway="10.0.0.1"):
        self.rows = rows or []
        self.gateway = gateway
        self.calls = 0

    def neighbors(self):
        self.calls += 1
        return list(self.rows)

    def default_route(self):
        return {"gateway": self.gateway, "iface": "en0"}


class FakeCtx:
    def __init__(self, wall, xbox_arg=None, xbox_ip=None, discovery=True, rows=None):
        self.cfg = {"rate_hz": 4, "targets": {"xbox_ip": xbox_ip, "xbox_discovery": discovery}}
        self.args = argparse.Namespace(xbox=xbox_arg)
        self.state = State(t0=wall, session_id="test")
        self.store = FakeStore()
        self.platform = FakePlatform(rows)
        self.route = {"gateway": "10.0.0.1", "iface": "en0", "lan_ip": "10.0.0.35", "prefixlen": 24}
        self.components = {}

    def component(self, name):
        return self.components.get(name)


GW_ROW = {"ip": "10.0.0.1", "mac": "7c:ed:8d:aa:bb:cc", "iface": "en0", "state": "REACHABLE"}
XBOX_ROW = {"ip": "10.0.0.23", "mac": "28:16:a8:11:22:33", "iface": "en0", "state": "REACHABLE"}
XBOX_ROW2 = {"ip": "10.0.0.24", "mac": "7c:ed:8d:11:22:34", "iface": "en0", "state": "REACHABLE"}
OTHER_ROW = {"ip": "10.0.0.50", "mac": "aa:bb:cc:dd:ee:ff", "iface": "en0", "state": "REACHABLE"}


def make(ctx, clock, presence=None, sweep_answers=None, saved=None):
    """A collector with fake presence probe and fake LAN sweep (tests must never send real packets)."""
    calls = {"n": 0, "answer": False, "sweeps": []}

    def probe(ip, timeout=2.0):
        calls["n"] += 1
        calls["ip"] = ip
        return calls["answer"]

    def sweep(ips, broadcast=("255.255.255.255",)):
        calls["sweeps"].append((list(ips), list(broadcast)))
        return list(sweep_answers or [])

    def save(values):
        if saved is not None:
            saved.append(dict(values))
        return True

    c = XboxCollector(ctx, clock=lambda: clock.mono, wall=lambda: clock.wall, presence_probe=presence or probe,
                      sweep=sweep, save_config=save)
    c._probe_calls = calls
    return c


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_args_ip_wins_and_registers_target(self):
        ctx = FakeCtx(self.clock.wall, xbox_arg="10.0.0.77", xbox_ip="10.0.0.23", rows=[GW_ROW, XBOX_ROW])
        c = make(ctx, self.clock)
        self.assertEqual(c.initialize(), "10.0.0.77")
        t = ctx.state.target("xbox")
        self.assertIsNotNone(t)
        self.assertEqual((t.addr, t.role, t.kind, t.family, t.rate_hz, t.label), ("10.0.0.77", "xbox", "icmp", 4, 4.0, "Xbox 10.0.0.77"))
        self.assertTrue(t.enabled)
        self.assertGreaterEqual(t.id, 0)
        self.assertEqual(ctx.store.written[0][0], "targets.json")
        self.assertEqual(ctx.store.written[0][1]["targets"][0]["key"], "xbox")
        self.assertEqual(ctx.state.collector("xbox")["status"], "ok")
        self.assertEqual(ctx.state.xbox["ip"], "10.0.0.77")
        self.assertEqual(ctx.state.xbox["state"], "unknown")
        self.assertEqual(ctx.state.xbox["candidates"], [])
        self.assertEqual(ctx.state.latest("xbox")["state"], "unknown")
        self.assertEqual(c.ip_source, "args")

    def test_config_ip(self):
        ctx = FakeCtx(self.clock.wall, xbox_ip="10.0.0.23")
        c = make(ctx, self.clock)
        self.assertEqual(c.initialize(), "10.0.0.23")
        self.assertEqual(c.ip_source, "config")
        self.assertEqual(ctx.platform.calls, 1)  # one neighbour lookup for the MAC only

    def test_invalid_config_ip_falls_back_to_discovery(self):
        ctx = FakeCtx(self.clock.wall, xbox_ip="not-an-ip", rows=[GW_ROW, XBOX_ROW, OTHER_ROW])
        c = make(ctx, self.clock)
        self.assertEqual(c.initialize(), "10.0.0.23")
        self.assertEqual(c.ip_source, "discovery")
        self.assertEqual(c.mac, "28:16:a8:11:22:33")
        self.assertEqual(ctx.state.xbox["mac"], "28:16:a8:11:22:33")

    def test_discovery_single_candidate_excludes_gateway(self):
        ctx = FakeCtx(self.clock.wall, rows=[GW_ROW, XBOX_ROW, OTHER_ROW])
        c = make(ctx, self.clock)
        self.assertEqual(c.initialize(), "10.0.0.23")
        self.assertEqual(ctx.state.target("xbox").addr, "10.0.0.23")
        self.assertEqual(ctx.state.collector("xbox")["status"], "ok")
        self.assertEqual(ctx.state.xbox["candidates"][0]["ip"], "10.0.0.23")

    def test_discovery_multiple_candidates_degraded(self):
        ctx = FakeCtx(self.clock.wall, rows=[GW_ROW, XBOX_ROW, XBOX_ROW2])
        c = make(ctx, self.clock)
        self.assertIsNone(c.initialize())
        self.assertIsNone(ctx.state.target("xbox"))
        col = ctx.state.collector("xbox")
        self.assertEqual(col["status"], "degraded")
        self.assertEqual(col["reason"], xb.REASON_MULTIPLE)
        self.assertEqual([x["ip"] for x in ctx.state.xbox["candidates"]], ["10.0.0.23", "10.0.0.24"])
        self.assertEqual(ctx.state.xbox["candidates"][0]["mac"], "28:16:a8:11:22:33")
        self.assertIsNone(ctx.state.xbox["ip"])
        # choosing on /setup
        self.assertTrue(c.set_ip("10.0.0.24"))
        self.assertEqual(ctx.state.target("xbox").addr, "10.0.0.24")
        self.assertEqual(ctx.state.collector("xbox")["status"], "ok")
        self.assertEqual(c.ip_source, "setup")
        self.assertEqual(ctx.cfg["targets"]["xbox_ip"], "10.0.0.24")
        self.assertFalse(c.set_ip("nope"))

    def test_discovery_none_disabled_and_retried_every_600s(self):
        ctx = FakeCtx(self.clock.wall, rows=[GW_ROW, OTHER_ROW])
        c = make(ctx, self.clock)
        self.assertIsNone(c.initialize())
        col = ctx.state.collector("xbox")
        self.assertEqual((col["status"], col["reason"]), ("disabled", xb.REASON_NOT_FOUND))
        self.assertEqual(ctx.platform.calls, 1)
        self.clock.advance(599.0)
        c.step()
        self.assertEqual(ctx.platform.calls, 1)
        ctx.platform.rows = [GW_ROW, XBOX_ROW]
        self.clock.advance(2.0)
        c.step()
        self.assertEqual(ctx.platform.calls, 2)
        self.assertEqual(c.ip, "10.0.0.23")
        self.assertEqual(ctx.state.target("xbox").addr, "10.0.0.23")

    def test_discovery_disabled_in_config(self):
        ctx = FakeCtx(self.clock.wall, discovery=False, rows=[GW_ROW, XBOX_ROW])
        c = make(ctx, self.clock)
        self.assertIsNone(c.initialize())
        self.assertEqual(ctx.platform.calls, 0)
        self.assertEqual(ctx.state.collector("xbox")["status"], "disabled")
        self.clock.advance(601.0)
        c.step()
        self.assertEqual(ctx.platform.calls, 0)

    def test_resume_reuses_existing_target(self):
        ctx = FakeCtx(self.clock.wall, rows=[GW_ROW, XBOX_ROW])
        ctx.state.add_target(Target(id=7, key="xbox", role="xbox", addr="10.0.0.23", family=4, kind="icmp", label="Xbox 10.0.0.23"))
        c = make(ctx, self.clock)
        self.assertEqual(c.initialize(), "10.0.0.23")
        self.assertEqual(c.ip_source, "resume")
        self.assertEqual(ctx.state.target("xbox").id, 7)
        self.assertEqual(ctx.store.written, [])  # nothing to rewrite

    def test_config_ip_switches_resumed_target(self):
        ctx = FakeCtx(self.clock.wall, xbox_ip="10.0.0.30")
        ctx.state.add_target(Target(id=7, key="xbox", role="xbox", addr="10.0.0.23", family=4, kind="icmp", label="Xbox 10.0.0.23", enabled=False, reason="x"))
        c = make(ctx, self.clock)
        c.initialize()
        t = ctx.state.target("xbox")
        self.assertEqual((t.id, t.addr, t.enabled, t.reason, t.label), (7, "10.0.0.30", True, None, "Xbox 10.0.0.30"))
        self.assertEqual(ctx.store.written[0][0], "targets.json")


class StateMachineTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.ctx = FakeCtx(self.clock.wall, xbox_ip="10.0.0.23", rows=[GW_ROW, XBOX_ROW])
        self.state = self.ctx.state
        self.gw = self.state.add_target(Target(id=-1, key="gw4", role="gateway", addr="10.0.0.1", family=4, kind="icmp", label="gw"))
        self.c = make(self.ctx, self.clock)
        self.c.initialize()
        self.xb = self.state.target("xbox")
        self.seq = 0

    def feed(self, seconds, xbox_reply=True, gw_reply=True, rate=4):
        """Advance ``seconds`` while the engine would have probed both targets at ``rate`` Hz."""
        steps = int(seconds * rate)
        for _ in range(steps):
            self.clock.advance(1.0 / rate)
            self.seq += 1
            ts = int(self.clock.wall * 1000)
            self.state.add_sample(Sample(ts, self.xb.id, KIND_ICMP, 0 if xbox_reply else F_LOST, self.seq, 2500 if xbox_reply else -1))
            self.state.add_sample(Sample(ts, self.gw.id, KIND_ICMP, 0 if gw_reply else F_LOST, self.seq, 1500 if gw_reply else -1))
            if self.seq % rate == 0:
                self.c.step()

    def test_unknown_to_awake_via_icmp_run(self):
        self.assertEqual(self.c.xbox_state, "unknown")
        self.feed(2.0)  # 8 replies
        self.assertEqual(self.c.xbox_state, "unknown")
        self.feed(1.0)  # 12 replies
        self.assertEqual(self.c.xbox_state, "awake")
        self.assertEqual(self.c.src, "icmp")
        self.assertEqual(self.state.xbox["state"], "awake")
        self.assertEqual(self.state.xbox["source"], "icmp")
        self.assertEqual(self.state.latest("xbox")["state"], "awake")
        self.assertEqual(self.state.latest("xbox")["src"], "icmp")

    def test_awake_via_udp_reply(self):
        self.c._probe_calls["answer"] = True
        self.c.step()
        self.assertEqual(self.c._probe_calls["ip"], "10.0.0.23")
        self.assertEqual(self.c.xbox_state, "awake")
        self.assertEqual(self.c.src, "udp5050")
        self.assertEqual(self.state.xbox["presence"], "udp5050")
        self.assertIsNone(self.state.collector("xbox")["reason"])

    def test_presence_probe_every_ten_seconds(self):
        for _ in range(11):
            self.c.step()
            self.clock.advance(1.0)
        self.assertEqual(self.c._probe_calls["n"], 2)  # t=0 and t=10

    def test_full_cycle_awake_asleep_awake(self):
        self.feed(5.0)
        self.assertEqual(self.c.xbox_state, "awake")
        # silence from the xbox while the gateway stays healthy
        self.feed(29.0, xbox_reply=False)
        self.assertEqual(self.c.xbox_state, "awake")
        self.feed(3.0, xbox_reply=False)
        self.assertEqual(self.c.xbox_state, "asleep")
        self.assertEqual(self.state.xbox["state"], "asleep")
        self.assertEqual(self.state.latest("xbox")["state"], "asleep")
        # wakes up again: a UDP reply is enough
        self.c._probe_calls["answer"] = True
        self.feed(11.0, xbox_reply=False)
        self.assertEqual(self.c.xbox_state, "awake")
        self.assertEqual(self.c.src, "udp5050")
        # and back to sleep after 30 s silence (no more UDP replies either)
        self.c._probe_calls["answer"] = False
        self.feed(40.0, xbox_reply=False)
        self.assertEqual(self.c.xbox_state, "asleep")
        # ICMP replies again → awake via icmp
        self.feed(4.0, xbox_reply=True)
        self.assertEqual(self.c.xbox_state, "awake")
        self.assertEqual(self.c.src, "icmp")

    def test_no_asleep_when_gateway_unhealthy(self):
        self.feed(5.0)
        self.assertEqual(self.c.xbox_state, "awake")
        self.feed(40.0, xbox_reply=False, gw_reply=False)
        self.assertEqual(self.c.xbox_state, "awake")
        # gateway recovers → now the silence counts
        self.feed(31.0, xbox_reply=False, gw_reply=True)
        self.assertEqual(self.c.xbox_state, "asleep")

    def test_no_asleep_without_any_xbox_samples(self):
        # the engine is not probing the xbox target at all: no evidence either way
        for _ in range(40):
            self.clock.advance(1.0)
            for i in range(4):
                self.state.add_sample(Sample(int(self.clock.wall * 1000) + i, self.gw.id, KIND_ICMP, 0, i, 1500))
            self.c.step()
        self.assertEqual(self.c.xbox_state, "unknown")

    def test_icmp_only_fallback_after_60s(self):
        self.feed(59.0)
        self.assertIsNone(self.c.presence_source)
        self.feed(2.0)
        self.assertEqual(self.c.presence_source, "icmp")
        col = self.state.collector("xbox")
        self.assertEqual((col["status"], col["reason"]), ("ok", xb.REASON_ICMP_ONLY))
        self.assertEqual(self.state.xbox["presence"], "icmp")
        self.assertEqual(self.state.latest("xbox")["src"], "icmp")
        # a late UDP reply restores UDP presence
        self.c._probe_calls["answer"] = True
        self.feed(11.0)
        self.assertEqual(self.c.presence_source, "udp5050")
        self.assertIsNone(self.state.collector("xbox")["reason"])

    def test_no_fallback_without_icmp_replies(self):
        self.feed(70.0, xbox_reply=False)
        self.assertIsNone(self.c.presence_source)
        self.assertIsNone(self.state.collector("xbox")["reason"])

    def test_set_ip_switches_target_and_resets(self):
        self.feed(5.0)
        self.assertEqual(self.c.xbox_state, "awake")
        self.assertTrue(self.c.set_ip("10.0.0.24"))
        self.assertEqual(self.c.xbox_state, "unknown")
        self.assertIsNone(self.c.src)
        t = self.state.target("xbox")
        self.assertEqual((t.id, t.addr, t.label), (self.xb.id, "10.0.0.24", "Xbox 10.0.0.24"))
        self.assertEqual(self.state.xbox["ip"], "10.0.0.24")
        self.assertEqual(self.state.xbox["state"], "unknown")
        self.assertEqual(self.ctx.store.written[-1][0], "targets.json")
        self.assertEqual(self.c._probe_calls["ip"], "10.0.0.23")
        self.c.step()
        self.assertEqual(self.c._probe_calls["ip"], "10.0.0.24")

    def test_mac_refresh_from_neighbour_table(self):
        self.assertEqual(self.c.mac, "28:16:a8:11:22:33")
        self.ctx.platform.rows = [GW_ROW, {"ip": "10.0.0.23", "mac": "28:16:a8:99:99:99"}]
        self.clock.advance(601.0)
        self.c.step()
        self.assertEqual(self.c.mac, "28:16:a8:99:99:99")
        self.assertEqual(self.state.xbox["mac"], "28:16:a8:99:99:99")

    def test_status_shape(self):
        row = self.c.status()
        self.assertEqual(set(row) >= {"ip", "state", "source", "link_mbps", "candidates"}, True)
        self.assertIsNone(row["link_mbps"])

    def test_start_and_stop_thread(self):
        c = XboxCollector(self.ctx, presence_probe=lambda ip, timeout=2.0: False, sweep=lambda ips, broadcast=(): [])
        c.start()
        self.assertTrue(c.thread.is_alive())
        self.state.stop_event.set()
        c.stop(timeout=3.0)
        self.assertFalse(c.thread.is_alive())
        self.assertEqual(self.state.collector("xbox")["status"], "ok")


if __name__ == "__main__":
    unittest.main()


class LossyConsoleAwakeTests(unittest.TestCase):
    setUp = StateMachineTests.setUp
    """A powered-on console behind a bad cable never answers 10 in a row but must still count as awake."""

    def feed_pattern(self, seconds, pattern, rate=4):
        steps = int(seconds * rate)
        for i in range(steps):
            self.clock.advance(1.0 / rate)
            self.seq += 1
            ts = int(self.clock.wall * 1000)
            ok = pattern[i % len(pattern)]
            self.state.add_sample(Sample(ts, self.xb.id, KIND_ICMP, 0 if ok else F_LOST, self.seq, 2500 if ok else -1))
            self.state.add_sample(Sample(ts, self.gw.id, KIND_ICMP, 0, self.seq, 1500))
            if self.seq % rate == 0:
                self.c.step()

    def test_lossy_but_powered_console_becomes_awake(self):
        self.feed_pattern(12.0, [True, True, False])  # 67 % answered, never 10 in a row
        self.assertEqual(self.c.xbox_state, "awake")

    def test_standby_console_answering_a_few_percent_stays_unknown(self):
        self.feed_pattern(12.0, [True] + [False] * 19)  # 5 % answered (what a console in standby did live)
        self.assertEqual(self.c.xbox_state, "unknown")


# ---------------------------------------------------------------------------
# Finding the console by the discovery reply (any vendor prefix) and following it when its address changes.
import socket as _socket  # noqa: E402

from laglens.probes import xbox_presence as _xp  # noqa: E402

NEW_ROW = {"ip": "10.0.0.59", "mac": "02:11:22:33:44:59", "iface": "en0", "state": "REACHABLE"}  # prefix not in the list


class FakeSweepSocket:
    def __init__(self, replies, clock):
        self.replies = list(replies)  # (data, ip)
        self.sent = []
        self.opts = []
        self.clock = clock
        self.closed = False

    def setsockopt(self, *a):
        self.opts.append(a)

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def settimeout(self, t):
        self.timeout = t

    def recvfrom(self, n):
        if not self.replies:
            self.clock[0] += 10  # nothing more: the deadline passes
            raise _socket.timeout()
        data, ip = self.replies.pop(0)
        return data, (ip, 5050)

    def close(self):
        self.closed = True


class SweepTests(unittest.TestCase):
    def test_sweep_sends_to_neighbours_and_broadcast_and_collects_consoles(self):
        clk = [100.0]
        sock = FakeSweepSocket([(b"\xdd\x01rest", "10.0.0.59"), (b"junk", "10.0.0.50"), (b"\xdd\x01again", "10.0.0.59")], clk)
        found = _xp.sweep(["10.0.0.59", "10.0.0.50", "10.0.0.59", "fe80::1"], broadcast=["255.255.255.255", "10.0.0.255"],
                          timeout=1.5, sock_factory=lambda fam, typ: sock, clock=lambda: clk[0])
        self.assertEqual(found, ["10.0.0.59"])
        self.assertEqual([a for _d, a in sock.sent], [("10.0.0.59", 5050), ("10.0.0.50", 5050), ("255.255.255.255", 5050), ("10.0.0.255", 5050)])
        self.assertTrue(all(d == _xp.DISCOVERY_REQUEST for d, _a in sock.sent))
        self.assertIn((_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1), sock.opts)
        self.assertTrue(sock.closed)

    def test_sweep_never_raises(self):
        def boom(*a):
            raise OSError("no network")
        self.assertEqual(_xp.sweep(["10.0.0.59"], sock_factory=boom), [])


class FindByReplyTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_discovery_prefers_the_console_that_answers_even_without_a_known_prefix(self):
        ctx = FakeCtx(self.clock.wall, rows=[GW_ROW, OTHER_ROW, NEW_ROW])
        ctx.route = {"gateway": "10.0.0.1", "iface": "en0", "lan_ip": "10.0.0.35", "prefixlen": 24}
        c = make(ctx, self.clock, sweep_answers=["10.0.0.59"])
        self.assertEqual(c.initialize(), "10.0.0.59")
        self.assertEqual(c.ip_source, "discovery")
        self.assertEqual(ctx.state.target("xbox").addr, "10.0.0.59")
        ips, bcast = c._probe_calls["sweeps"][0]
        self.assertNotIn("10.0.0.1", ips)  # never the gateway
        self.assertIn("10.0.0.59", ips)
        self.assertEqual(bcast, ["255.255.255.255", "10.0.0.255"])
        self.assertTrue(c.candidates[0]["answers_5050"])

    def test_two_answering_consoles_need_a_choice(self):
        ctx = FakeCtx(self.clock.wall, rows=[GW_ROW, XBOX_ROW, NEW_ROW])
        c = make(ctx, self.clock, sweep_answers=["10.0.0.23", "10.0.0.59"])
        self.assertIsNone(c.initialize())
        self.assertEqual(sorted(x["ip"] for x in c.candidates), ["10.0.0.23", "10.0.0.59"])
        self.assertEqual(ctx.state.collector("xbox")["status"], "degraded")

    def test_no_answer_falls_back_to_the_prefix_list(self):
        ctx = FakeCtx(self.clock.wall, rows=[GW_ROW, XBOX_ROW, OTHER_ROW])
        c = make(ctx, self.clock, sweep_answers=[])
        self.assertEqual(c.initialize(), "10.0.0.23")


class FollowTheConsoleTests(unittest.TestCase):
    """The configured address went quiet (DHCP moved the console): follow it and remember the new address."""

    def setUp(self):
        self.clock = FakeClock()
        self.seq = 0

    def start(self, source_kw, answers, rows=None):
        self.ctx = FakeCtx(self.clock.wall, rows=rows or [GW_ROW, NEW_ROW], **source_kw)
        self.state = self.ctx.state
        self.gw = self.state.add_target(Target(id=-1, key="gw4", role="gateway", addr="10.0.0.1", family=4, kind="icmp", label="gw"))
        self.saved = []
        self.c = make(self.ctx, self.clock, sweep_answers=answers, saved=self.saved)
        self.c.initialize()
        self.xb = self.state.target("xbox")

    def silence(self, seconds, rate=4):
        for _ in range(int(seconds * rate)):
            self.clock.advance(1.0 / rate)
            self.seq += 1
            ts = int(self.clock.wall * 1000)
            self.state.add_sample(Sample(ts, self.xb.id, KIND_ICMP, F_LOST, self.seq, -1))
            self.state.add_sample(Sample(ts, self.gw.id, KIND_ICMP, 0, self.seq, 1500))
            if self.seq % rate == 0:
                self.c.step()

    def test_configured_address_goes_silent_and_the_console_answers_elsewhere(self):
        self.start({"xbox_ip": "10.0.0.239"}, ["10.0.0.59"])
        self.assertEqual(self.c.ip, "10.0.0.239")
        self.silence(40)  # asleep after 30 s of silence, then one sweep
        self.assertEqual(self.c.ip, "10.0.0.59")
        self.assertEqual(self.c.ip_source, "rediscovered")
        self.assertEqual(self.state.target("xbox").addr, "10.0.0.59")
        self.assertEqual(self.saved, [{"targets.xbox_ip": "10.0.0.59"}])
        self.assertEqual(self.ctx.cfg["targets"]["xbox_ip"], "10.0.0.59")

    def test_sweeps_are_rate_limited_while_nothing_answers(self):
        self.start({"xbox_ip": "10.0.0.239"}, [])
        self.silence(40)
        n = len(self.c._probe_calls["sweeps"])
        self.silence(60)
        self.assertEqual(len(self.c._probe_calls["sweeps"]), n)  # not again within REFIND_EVERY_S
        self.assertEqual(self.c.ip, "10.0.0.239")

    def test_an_address_given_with_xbox_flag_is_not_overridden(self):
        self.start({"xbox_arg": "10.0.0.239"}, ["10.0.0.59"])
        self.silence(40)
        self.assertEqual(self.c.ip, "10.0.0.239")
        self.assertEqual(self.saved, [])

    def test_a_sleeping_console_at_its_own_address_is_left_alone(self):
        self.start({"xbox_ip": "10.0.0.59"}, ["10.0.0.59"])
        self.silence(40)
        self.assertEqual(self.c.ip, "10.0.0.59")
        self.assertEqual(self.saved, [])


class AddressSwitchTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.ctx = FakeCtx(self.clock.wall, xbox_ip="10.0.0.239", rows=[GW_ROW, NEW_ROW])
        self.c = make(self.ctx, self.clock)
        self.c.initialize()

    def test_switch_publishes_the_boundary_and_same_address_is_a_no_op(self):
        self.clock.advance(5)
        self.c.set_ip("10.0.0.59")
        since = self.ctx.state.xbox["since"]
        self.assertEqual(since, self.clock.wall)
        self.c.xbox_state = "awake"
        self.clock.advance(5)
        self.c.set_ip("10.0.0.59")  # saved again on /setup
        self.assertEqual(self.c.xbox_state, "awake")  # not reset
        self.assertEqual(self.ctx.state.xbox["since"], since)
        self.assertEqual(self.c.ip_source, "setup")



class OfflineSweepTests(unittest.TestCase):
    def test_no_route_means_no_sweep_and_no_broadcast(self):
        clock = FakeClock()
        ctx = FakeCtx(clock.wall, rows=[])
        ctx.route = {}
        c = make(ctx, clock, sweep_answers=["10.0.0.59"])
        ctx.platform.default_route = lambda: {}
        self.assertIsNone(c.initialize())
        self.assertEqual(c._probe_calls["sweeps"], [])
