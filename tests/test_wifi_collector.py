"""Tests for laglens.collectors.wifi: wired disable, drop/roam notes, macOS back-off."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.collectors.wifi import MAC_INTERVAL_S, MAC_SLOW_INTERVAL_S, WifiCollector  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.state import State  # noqa: E402


class FakePlatform(Platform):
    name = "linux"

    def __init__(self, wireless=True, name="linux"):
        super().__init__(runner=lambda a, t: (1, "", ""), reader=lambda p: None, exists=lambda p: False, env={}, which=lambda n: None)
        self.name = name
        self.wireless = wireless
        self.info = {"rssi": -58, "noise": -92, "chan": 36, "bssid": "aa:bb:cc:11:22:33", "ssid": "HomeNet5", "rate_mbps": 866.0}
        self.calls = 0
        self.slow = 0.0

    def default_route(self):
        return {"gateway": "10.0.0.1", "iface": "wlan0", "gateway6": None, "iface6": None, "lan_ip": "10.0.0.50", "prefixlen": 24}

    def link_info(self, iface):
        return {"speed": None, "duplex": None, "carrier": True, "carrier_changes": 0, "operstate": "up", "wireless": self.wireless}

    def wifi_info(self, iface):
        self.calls += 1
        self._clock.m += self.slow
        return dict(self.info) if self.info else None


class Clock:
    def __init__(self):
        self.t = 1_760_000_000.0
        self.m = 500.0


class Ctx:
    def __init__(self, wireless=True, name="linux", cfg=None):
        self.cfg = cfg or {"wifi": {"enabled": "auto", "interval_s": 5}}
        self.state = State(cfg=self.cfg)
        self.platform = FakePlatform(wireless, name)
        self.route = self.platform.default_route()
        self.components = {}

    def component(self, n):
        return self.components.get(n)


def make(wireless=True, name="linux", cfg=None):
    ctx = Ctx(wireless, name, cfg)
    clk = Clock()
    ctx.platform._clock = clk
    wc = WifiCollector(ctx, clock=lambda: clk.t, mono=lambda: clk.m)
    return ctx, clk, wc


class WifiTests(unittest.TestCase):
    def test_wired_is_disabled(self):
        ctx, _, wc = make(wireless=False)
        wc.start()
        self.assertFalse(wc.enabled)
        self.assertIsNone(wc.thread)
        self.assertEqual(ctx.state.collector("wifi"), {"status": "disabled", "reason": "wired interface", "since": ctx.state.collector("wifi")["since"]})
        wc.stop()

    def test_forced_on_wired(self):
        ctx, _, wc = make(wireless=False, cfg={"wifi": {"enabled": True, "interval_s": 5}})
        self.assertTrue(wc._is_wireless() is False)
        wc.start()
        self.assertTrue(wc.enabled)
        ctx.state.stop_event.set()
        wc.stop(3.0)

    def test_reading_and_latest(self):
        ctx, _, wc = make()
        wc.iface = "wlan0"
        row = wc.step()
        self.assertEqual(row, {"rssi": -58, "noise": -92, "chan": 36, "bssid": "aa:bb:cc:11:22:33", "rate_mbps": 866.0, "ssid": "HomeNet5"})
        self.assertEqual(ctx.state.latest("wifi")["rssi"], -58)
        self.assertEqual(wc.interval_s, 5.0)

    def test_drop_and_roam_notes(self):
        ctx, clk, wc = make()
        wc.iface = "wlan0"
        wc.step()
        clk.t += 5
        ctx.platform.info["rssi"] = -63
        wc.step()
        self.assertEqual(ctx.state.drain_notes(), [])
        clk.t += 4
        ctx.platform.info["rssi"] = -69  # 11 dB below the -58 seen 9 s ago
        wc.step()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["wifi_drop"])
        self.assertEqual(notes[0]["severity"], 2)
        self.assertEqual(notes[0]["peak"]["peak"], -58)
        clk.t += 5
        ctx.platform.info["rssi"] = -70
        wc.step()
        self.assertEqual(ctx.state.drain_notes(), [])  # rate-limited and -58 aged out
        clk.t += 5
        ctx.platform.info["bssid"] = "aa:bb:cc:11:22:44"
        wc.step()
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["wifi_roam"])
        self.assertEqual(notes[0]["peak"]["new"], "aa:bb:cc:11:22:44")

    def test_failure_degrades_then_recovers(self):
        ctx, _, wc = make()
        wc.iface = "wlan0"
        ctx.platform.info = None
        self.assertIsNone(wc.step())
        c = ctx.state.collector("wifi")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("iw and /proc/net/wireless", c["reason"])
        ctx.platform.info = {"rssi": -50, "noise": None, "chan": 1, "bssid": None, "ssid": None, "rate_mbps": None}
        wc.step()
        self.assertEqual(ctx.state.collector("wifi")["status"], "ok")

    def test_macos_cadence_backs_off(self):
        ctx, clk, wc = make(name="darwin")
        wc.iface = "en0"
        self.assertEqual(wc.interval_s, MAC_INTERVAL_S)
        wc.step()
        self.assertEqual(wc.interval_s, MAC_INTERVAL_S)
        ctx.platform.slow = 2.5
        wc.step()
        self.assertEqual(wc.interval_s, MAC_SLOW_INTERVAL_S)
        ctx.platform.info = None
        wc.step()
        self.assertEqual(ctx.state.collector("wifi")["reason"], "system_profiler failed")


if __name__ == "__main__":
    unittest.main()
