"""Tests for laglens.collectors.host: rates, counter reset, link flap, iface errors, clock jump, VPN, self_load."""
import json
import os
import sys
import shutil
import tempfile
import weakref
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.collectors.host import HostCollector  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.state import State  # noqa: E402


class FakeClock:
    def __init__(self, t=1_760_000_000.0):
        self.t = t
        self.m = 1000.0

    def time(self):
        return self.t

    def mono(self):
        return self.m

    def tick(self, s=1.0, wall=None):
        self.m += s
        self.t += s if wall is None else wall


class FakeStore:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="laglens-host-"))
        weakref.finalize(self, shutil.rmtree, str(self.dir), True)  # no leaked temp dirs
        self.rows = []

    def append_json(self, name, obj):
        json.dumps(obj)  # must be serialisable
        self.rows.append((name, obj))

    def append_sample(self, s):
        pass

    def write_atomic(self, name, data):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def write_json_atomic(self, name, obj, indent=1):
        return self.write_atomic(name, json.dumps(obj))


class FakePlatform(Platform):
    name = "linux"

    def __init__(self):
        super().__init__(runner=lambda argv, timeout: (_ for _ in ()).throw(FileNotFoundError(argv[0])), reader=lambda p: None,
                         exists=lambda p: False, env={}, which=lambda n: None)
        self.stats = {"rx_bytes": 1000, "tx_bytes": 2000, "rx_packets": 10, "tx_packets": 20, "rx_errors": 0, "tx_errors": 0,
                      "rx_dropped": 0, "tx_dropped": 0, "crc": 0, "collisions": 0, "multicast": 100}
        self.link = {"speed": 1000, "duplex": "full", "carrier": True, "carrier_changes": 2, "operstate": "up", "wireless": False}
        self.vpn = {"via_tunnel": False, "iface": "enp3s0"}
        self.lease = {"expiry": "1760003600", "dhcp_server_identifier": "10.0.0.1"}
        self.route = {"gateway": "10.0.0.1", "iface": "enp3s0", "gateway6": "fe80::1%enp3s0", "iface6": "enp3s0", "lan_ip": "10.0.0.50", "prefixlen": 24}

    def default_route(self):
        return dict(self.route)

    def iface_stats(self, iface):
        return dict(self.stats)

    def link_info(self, iface):
        return dict(self.link)

    def vpn_routes(self, addr="1.1.1.1"):
        return dict(self.vpn)

    def dhcp_lease(self, iface):
        return dict(self.lease)

    def load_avg(self):
        return (0.5, 0.4, 0.3)

    def hostname(self):
        return "bazzite"


class Ctx:
    def __init__(self, cfg=None):
        self.cfg = cfg or {"link": {"up_mbps": 25, "down_mbps": 1000}}
        self.state = State(cfg=self.cfg)
        self.store = FakeStore()
        self.platform = FakePlatform()
        self.route = self.platform.default_route()
        self.components = {}
        self.root = self.store.dir
        self.sessions_root = self.store.dir

    def component(self, name):
        return self.components.get(name)


def make(cfg=None):
    ctx = Ctx(cfg)
    clk = FakeClock()
    hc = HostCollector(ctx, clock=clk.time, mono=clk.mono)
    hc.refresh_static()
    return ctx, clk, hc


class StaticFactsTests(unittest.TestCase):
    def test_static_facts_fill_state_host(self):
        ctx, _, hc = make()
        h = ctx.state.host
        self.assertEqual(h["iface"], "enp3s0")
        self.assertEqual(h["gateway"], "10.0.0.1")
        self.assertEqual(h["gw6"], "fe80::1%enp3s0")
        self.assertTrue(h["v6"])
        self.assertFalse(h["wifi"])
        self.assertEqual(h["speed"], 1000)
        self.assertEqual(h["link_up_mbps"], 25)
        self.assertEqual(h["hostname"], "bazzite")
        self.assertEqual(ctx.state.collector("host")["status"], "ok")

    def test_no_route_degraded(self):
        ctx = Ctx()
        ctx.route = {}
        ctx.platform.route = {"gateway": None, "iface": None, "gateway6": None, "iface6": None, "lan_ip": None, "prefixlen": None}
        hc = HostCollector(ctx, clock=FakeClock().time, mono=FakeClock().mono)
        hc.refresh_static()
        self.assertEqual(ctx.state.collector("host")["status"], "degraded")
        self.assertIn("no default route", ctx.state.collector("host")["reason"])
        row = hc.step()
        self.assertIsNone(row["iface"]["rx_mbps"])


class RateTests(unittest.TestCase):
    def test_rates_from_deltas(self):
        ctx, clk, hc = make()
        hc.step()
        clk.tick(1.0)
        ctx.platform.stats["rx_bytes"] += 125_000  # 1 Mb/s
        ctx.platform.stats["tx_bytes"] += 250_000  # 2 Mb/s
        ctx.platform.stats["multicast"] += 12
        row = hc.step()
        self.assertAlmostEqual(row["iface"]["rx_mbps"], 1.0, places=3)
        self.assertAlmostEqual(row["iface"]["tx_mbps"], 2.0, places=3)
        self.assertEqual(row["iface"]["mcast_pps"], 12.0)
        self.assertEqual(row["iface"]["rx_err"], 0)
        self.assertEqual(row["iface"]["speed"], 1000)
        self.assertEqual(row["iface"]["duplex"], "full")
        self.assertEqual(row["iface"]["carrier_changes"], 2)
        self.assertEqual(ctx.state.latest("iface")["tx_mbps"], 2.0)
        self.assertEqual(ctx.state.latest("host")["load1"], 0.5)
        self.assertEqual(ctx.store.rows[-1][0], "host")
        self.assertEqual(ctx.store.rows[-1][1]["iface"]["rx_mbps"], 1.0)
        self.assertIn("t", ctx.store.rows[-1][1])

    def test_counter_reset_gives_zero_once(self):
        ctx, clk, hc = make()
        hc.step()
        clk.tick(1.0)
        ctx.platform.stats["rx_bytes"] = 10  # went backwards
        row = hc.step()
        self.assertEqual(row["iface"]["rx_mbps"], 0.0)
        self.assertTrue(hc._counter_reset_logged)
        self.assertEqual([n for n in ctx.state.drain_notes()], [])

    def test_missing_counters_degrade(self):
        ctx, clk, hc = make()
        ctx.platform.stats = {k: None for k in ctx.platform.stats}
        hc.step()
        c = ctx.state.collector("host")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("sysfs unreadable", c["reason"])
        ctx.platform.stats["rx_bytes"] = 5
        clk.tick(1.0)
        hc.step()
        self.assertEqual(ctx.state.collector("host")["status"], "ok")


class NoteTests(unittest.TestCase):
    def notes(self, ctx):
        return [n["type"] for n in ctx.state.drain_notes()]

    def test_iface_errors_rate_limited(self):
        ctx, clk, hc = make()
        hc.step()
        for i in range(5):
            clk.tick(1.0)
            ctx.platform.stats["rx_errors"] += 1
            hc.step()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["iface_errors"])
        self.assertEqual(notes[0]["severity"], 2)
        self.assertEqual(notes[0]["peak"]["rx_err"], 1)
        clk.tick(60.0)
        ctx.platform.stats["crc"] += 3
        hc.step()
        self.assertEqual(self.notes(ctx), ["iface_errors"])

    def test_link_flap_on_carrier_change(self):
        ctx, clk, hc = make()
        hc.step()
        ctx.platform.link["carrier_changes"] = 3
        clk.tick(10.0)
        hc.step()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["link_flap"])
        self.assertEqual(notes[0]["severity"], 3)
        self.assertIn("carrier_changes 2 -> 3", notes[0]["note"])
        # macOS style: status flips without a counter
        ctx.platform.link = {"speed": None, "duplex": None, "carrier": False, "carrier_changes": None, "operstate": "down", "wireless": False, "media": "autoselect"}
        clk.tick(10.0)
        hc.step()
        self.assertEqual(self.notes(ctx), ["link_flap"])
        clk.tick(5.0)
        hc.step()  # not yet due again
        self.assertEqual(self.notes(ctx), [])

    def test_clock_jump(self):
        ctx, clk, hc = make()
        hc.step()
        clk.tick(1.0)
        hc.step()
        clk.tick(1.0, wall=301.0)  # the wall clock jumped 5 min while monotonic advanced 1 s
        row = hc.step()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["clock_jump"])
        self.assertAlmostEqual(notes[0]["peak"]["shift_s"], 300.0, places=1)
        self.assertEqual(row["host"]["drift_ms"], 0.0)  # new baseline after the jump
        clk.tick(1.0, wall=1.5)
        row = hc.step()
        self.assertAlmostEqual(row["host"]["drift_ms"], 500.0, places=0)
        self.assertEqual(self.notes(ctx), [])

    def test_vpn_route_note_and_host_flag(self):
        ctx, clk, hc = make()
        hc.step()
        ctx.platform.vpn = {"via_tunnel": True, "iface": "tailscale0"}
        clk.tick(1.0)
        hc.step()
        self.assertEqual(self.notes(ctx), [])  # not yet re-checked (300 s)
        clk.tick(300.0)
        row = hc.step()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["vpn_route"])
        self.assertIn("tailscale0", notes[0]["note"])
        self.assertTrue(row["host"]["vpn_route"])
        self.assertTrue(ctx.state.host["vpn_route"])
        clk.tick(300.0)
        hc.step()
        self.assertEqual(self.notes(ctx), [])  # still via tunnel: no repeat

    def test_dhcp_renew_on_change_only(self):
        ctx, clk, hc = make()
        hc.step()
        clk.tick(300.0)
        hc.step()
        self.assertEqual(self.notes(ctx), [])
        ctx.platform.lease["expiry"] = "1760090000"
        clk.tick(300.0)
        hc.step()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["dhcp_renew"])
        self.assertEqual(notes[0]["peak"]["lease"]["expiry"], "1760090000")

    def test_self_load_after_three_seconds(self):
        ctx, clk, hc = make()
        hc.step()
        for i in range(5):
            clk.tick(1.0)
            ctx.platform.stats["tx_bytes"] += 2_500_000  # 20 Mb/s > 60% of 25
            hc.step()
            if i < 3:
                self.assertEqual(self.notes(ctx), [], "no self_load before 3 s (i=%d)" % i)
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["self_load"])
        self.assertEqual(notes[0]["peak"]["up_mbps"], 25.0)
        clk.tick(1.0)
        hc.step()  # tx drops to 0 → re-armed
        self.assertEqual(self.notes(ctx), [])

    def test_engine_lateness_and_stall_flag(self):
        ctx, clk, hc = make()

        class Eng:
            def stats(self):
                return {"pps": 40, "late_ms_max": 75.0, "loop_gap_ms": 12.0}

        ctx.components["engine"] = Eng()
        row = hc.step()
        self.assertEqual(row["host"]["late_ms_max"], 75.0)
        self.assertEqual(row["host"]["loop_gap_ms"], 12.0)
        self.assertTrue(row["host"]["stall"])
        self.assertTrue(ctx.state.tick_payload()["stall"])
        ctx.components["engine"] = object()  # no stats()
        clk.tick(1.0)
        row = hc.step()
        self.assertIsNone(row["host"]["late_ms_max"])
        self.assertFalse(row["host"]["stall"])


class ThreadTests(unittest.TestCase):
    def test_start_stop_thread(self):
        ctx = Ctx()
        hc = HostCollector(ctx)
        hc.start()
        self.assertIsNotNone(hc.thread)
        import time

        time.sleep(0.3)
        ctx.state.stop_event.set()
        hc.stop(timeout=3.0)
        self.assertFalse(hc.thread.is_alive())
        self.assertTrue(any(n == "host" for n, _ in ctx.store.rows))
        self.assertEqual(ctx.state.collector("host")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
