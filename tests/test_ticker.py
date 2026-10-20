"""Ticker tests (INTERFACES §2, SPEC §8.2): lagging windows, publishes, status pill vocabulary, gap, close_final."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers_detection import BEYOND_GW, INTERNET, T0, Session, feed, make_cfg, make_ticker, run_episode  # noqa: E402
from laglens.engine import ticker as tm  # noqa: E402
from laglens.engine.rollup import WINDOW5_LAG_S, second_close_lag_s  # noqa: E402
from laglens.state import (  # noqa: E402
    STATUS_DEGRADED,
    STATUS_GAP,
    STATUS_LOADTEST,
    STATUS_OK,
    STATUS_RECENT,
    STATUS_TROUBLE,
    STATUS_WARMUP,
)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(self.s.close)
        self.tk = make_ticker(self.s)

    def test_windows_lag_wall_time_and_rows_are_written(self):
        s, tk = self.s, self.tk
        feed(s, tk.tick, T0, T0 + 22, keys=["gw4", "inet4_cf"])
        names = s.published_names()
        self.assertEqual(names.count("tick"), 22)
        # windows [t-10, t-5) close at t % 5 == 0: t = 10 -> [0,5), t = 15 -> [5,10), t = 20 -> [10,15)
        self.assertEqual(names.count("rollup5"), 3)
        rows = s.rows("rollups")
        ts = sorted({r["t"] for r in rows})
        self.assertEqual(ts, [int(T0), int(T0) + 5, int(T0) + 10])
        self.assertTrue(any("slots" in r for r in rows))
        probe_rows = [r for r in rows if "id" in r]
        self.assertEqual({r["id"] for r in probe_rows}, {s.ids["gw4"], s.ids["inet4_cf"]})
        self.assertTrue(all(r["n"] == 20 for r in probe_rows))
        # 1 s rollups exist for every second older than the lag
        lag = second_close_lag_s(s.cfg)
        r1 = s.state.rollups(1, T0, T0 + 30, [s.ids["gw4"]])[s.ids["gw4"]]
        self.assertEqual(r1[-1].t, int(T0) + 22 - lag - 1)
        self.assertEqual(tk.errors, 0)
        tick = [o for n, o in s.published if n == "tick"][-1]
        for key in ("t", "state", "pill", "headline", "health", "targets", "iface", "wan", "xbox", "stall", "slots_lost"):
            self.assertIn(key, tick)
        self.assertEqual(tick["state"], STATUS_WARMUP)  # 22 s into a 30 s warm-up
        self.assertIn(str(s.ids["gw4"]), tick["targets"])
        self.assertIsNotNone(s.state.w5m.get(s.ids["gw4"]))
        self.assertIsNotNone(s.state.health["now"])

    def test_status_pill_vocabulary_through_an_episode(self):
        s, tk = self.s, self.tk
        seen = {}

        def per(t):
            seen[int(t - T0)] = (s.state.status, s.state.pill, dict(s.state.headline))

        run_episode(s, tk.tick, baseline_s=40, lost_keys=BEYOND_GW, fault_s=4, quiet_s=25, per_second=per)
        self.assertEqual(seen[5][0], STATUS_WARMUP)
        self.assertTrue(seen[5][1].startswith("Learning your normal… "), seen[5][1])
        self.assertEqual(seen[5][2]["text"], "Can't tell yet")
        self.assertEqual(seen[35][0], STATUS_OK)
        self.assertTrue(seen[35][1].startswith("All clear — monitoring "), seen[35][1])
        self.assertEqual(seen[35][2], {"answer": "no_sign", "text": "No sign of it yet", "action": "Keep running"})
        trouble = [v for k, v in seen.items() if v[0] == STATUS_TROUBLE]
        self.assertTrue(trouble)
        self.assertEqual(trouble[-1][1], "Trouble now: packets lost past your gateway (cable line)")
        after = seen[max(seen)]
        self.assertEqual(after[0], STATUS_RECENT)
        self.assertEqual(after[1], "Trouble moments ago: Comcast hop")
        self.assertEqual(after[2]["answer"], "yes_comcast")
        names = s.published_names()
        for n in ("episode_open", "episode_update", "episode_close", "verdict", "event", "rollup5", "tick"):
            self.assertIn(n, names)
        self.assertEqual(names.count("episode_close"), 1)
        self.assertEqual(s.state.snapshot()["state"], STATUS_RECENT)
        self.assertEqual(s.state.health["session"] is not None, True)

    def test_recent_ages_out_after_ten_minutes(self):
        s, tk = self.s, self.tk
        run_episode(s, tk.tick, baseline_s=40, lost_keys=INTERNET, fault_s=4, quiet_s=15)
        self.assertEqual(s.state.status, STATUS_RECENT)
        t1 = s.state.episodes[-1].t1
        feed(s, tk.tick, s.clock.t, t1 + 4 * 60 + 1, keys=["gw4"])
        self.assertEqual((s.state.status, s.state.pill), (STATUS_RECENT, "Trouble 4 min ago: internet"))
        feed(s, tk.tick, s.clock.t, t1 + tm.RECENT_S + 2, keys=["gw4"])
        self.assertEqual(s.state.status, STATUS_OK)

    def test_verdict_every_thirty_seconds_and_on_episode_close(self):
        s, tk = self.s, self.tk
        feed(s, tk.tick, T0, T0 + 65, keys=["gw4"])
        self.assertEqual(tk._next_verdict, int(T0) + 91)  # first tick at t0+1, then every 30 s
        calls = []
        orig = tm.verdictmod.compute_verdict

        def spy(ctx, now=None):
            calls.append(now)
            return orig(ctx, now=now)

        tm.verdictmod.compute_verdict = spy
        try:
            feed(s, tk.tick, T0 + 65, T0 + 100, keys=["gw4"])
            self.assertEqual(len(calls), 1)
            tk.detector.verdict_due = True
            tk.tick(int(T0 + 101))
            self.assertEqual(len(calls), 2)
        finally:
            tm.verdictmod.compute_verdict = orig


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.s = Session(cfg=make_cfg(warmup_s=0))
        self.addCleanup(self.s.close)
        self.tk = make_ticker(self.s)

    def test_loadtest_gap_and_degraded(self):
        s, tk = self.s, self.tk
        st = s.state
        s.clock.set(T0 + 10)
        tk.tick(int(T0 + 10))
        self.assertEqual(st.status, STATUS_OK)
        self.assertEqual(st.pill, "All clear — monitoring 10 s")
        st.loadtest = {"running": True, "last": None}
        s.clock.set(T0 + 11)
        tk.tick(int(T0 + 11))
        self.assertEqual((st.status, st.pill), (STATUS_LOADTEST, "Load test running"))
        st.loadtest = {"running": False, "last": None}
        # configuration choices are not degradation; real failures are
        st.set_collector("docsis", "disabled", reason="docsis.password not set")
        st.set_collector("wifi", "disabled", reason="wired interface")
        st.set_collector("notify", "disabled", reason="not configured")
        st.set_collector("plex", "disabled", reason="off (start with --plex, or turn Plex mode on in Setup)")
        s.clock.set(T0 + 12)
        tk.tick(int(T0 + 12))
        self.assertEqual(st.status, STATUS_OK)
        self.assertEqual(tk.degraded_collectors(), [])
        st.set_collector("igd", "degraded", reason="SOAP timeout")
        st.set_collector("xbox", "disabled", reason="thread exited early")
        s.clock.set(T0 + 13)
        tk.tick(int(T0 + 13))
        self.assertEqual(st.status, STATUS_DEGRADED)
        self.assertEqual(tk.degraded_collectors(), ["igd (SOAP timeout)", "xbox (thread exited early)"])
        self.assertEqual(st.pill, "All clear — monitoring 13 s\nDegraded: igd (SOAP timeout), xbox (thread exited early)")
        # a late tick (sleep) raises monitor_gap and shows GAP for 30 s
        s.clock.set(T0 + 25)
        tk.tick(int(T0 + 25))
        self.assertEqual(st.status, STATUS_GAP)
        self.assertEqual(st.pill.split("\n")[0], "Monitor paused/resumed")
        gaps = s.events("monitor_gap")
        self.assertEqual(len(gaps), 1)
        self.assertTrue(gaps[0].stall)
        self.assertAlmostEqual(gaps[0].peak["gap_s"], 12.0, delta=0.1)
        feed(s, tk.tick, s.clock.t, T0 + 25 + tm.GAP_SHOW_S + 2, keys=["gw4"])  # no second gap: tick every second
        self.assertEqual(st.status, STATUS_DEGRADED)
        # windows missed during the gap are closed on the next ticks (one batch per pending window)
        self.assertGreaterEqual(s.published_names().count("rollup5"), 5)

    def test_warmup_counts_down(self):
        s = Session(cfg=make_cfg(warmup_s=45))
        self.addCleanup(s.close)
        tk = make_ticker(s)
        s.clock.set(T0 + 3)
        tk.tick(int(T0 + 3))
        self.assertEqual((s.state.status, s.state.pill), (STATUS_WARMUP, "Learning your normal… 42 s"))

    def test_a_failing_stage_never_stops_the_tick(self):
        s, tk = self.s, self.tk

        def boom(t):
            raise RuntimeError("detector exploded")

        tk.detector.step = boom  # type: ignore[assignment]
        s.clock.set(T0 + 5)
        tk.tick(int(T0 + 5))
        self.assertEqual(tk.errors, 1)
        self.assertEqual(s.published_names()[-1], "tick")
        self.assertEqual(s.state.status, STATUS_OK)


class CloseFinalTests(unittest.TestCase):
    def test_close_final_flushes_windows_events_episode_and_verdict(self):
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        tk = make_ticker(s)
        f0 = T0 + 40
        feed(s, tk.tick, T0, f0 + 8, lost=lambda k, ts: k in INTERNET and ts >= f0)
        self.assertIsNotNone(tk.detector.open_episode())
        before = s.published_names().count("rollup5")
        tk.close_final()
        tk.close_final()  # idempotent
        self.assertIsNone(tk.detector.open_episode())
        ep = s.episodes()[0]
        self.assertIsNotNone(ep.t1)
        self.assertTrue(all(e.t1 is not None for e in s.state.events))
        rows = s.rows("rollups")
        self.assertEqual(max(r["t"] for r in rows), int(f0 + 8) // 5 * 5)
        self.assertGreater(s.published_names().count("rollup5"), before)
        self.assertEqual(s.state.verdict["top"][0]["class"], ep.cls)
        self.assertTrue((s.store.dir / "comcast_evidence.txt").exists())
        self.assertIsNotNone(s.state.health["session"])
        last_sec = s.state.rollups(1, T0, f0 + 10, [s.ids["gw4"]])[s.ids["gw4"]][-1].t
        self.assertEqual(last_sec, int(f0 + 7))  # every pending second closed

    def test_replay_rebuilds_the_same_episodes_offline(self):
        live = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(live.close)
        run_episode(live, make_ticker(live).tick, baseline_s=40, lost_keys=BEYOND_GW, fault_s=3)
        live_eps = [e.to_dict() for e in live.episodes()]
        self.assertEqual(len(live_eps), 1)
        live.store.flush()
        rows = live.store.read_samples(max_rows=200000)
        self.assertGreater(len(rows), 1000)
        off = Session(cfg=make_cfg(warmup_s=30), with_store=False)
        self.addCleanup(off.close)
        tk = make_ticker(off)
        n = tk.replay(rows)
        self.assertGreaterEqual(n, 60)
        eps = [e.to_dict() for e in off.episodes()]
        self.assertEqual(len(eps), 1)
        for key in ("class", "subclass", "targets", "onset_order", "evidence"):
            self.assertEqual(eps[0][key], live_eps[0][key], key)
        self.assertAlmostEqual(eps[0]["t0"], live_eps[0]["t0"], delta=0.01)
        self.assertAlmostEqual(eps[0]["t1"], live_eps[0]["t1"], delta=0.01)
        self.assertEqual(len(off.rows("rollups")), 0)  # no store: nothing written
        self.assertEqual(off.state.verdict["top"][0]["class"], "docsis_access")
        self.assertTrue(all(e.t1 is not None for e in off.state.events))

    def test_thread_start_stop(self):
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        # a real wait (on the stop event) here: make_ticker's fake wait returns at once, so the thread
        # body could finish before stop is requested and the supervisor would flag an early exit
        from laglens.engine.ticker import Ticker
        tk = Ticker(s.ctx, clock=s.clock)
        tk.start()
        s.state.stop_event.set()
        tk.stop(timeout=2.0)
        self.assertFalse(tk.thread.is_alive())
        self.assertEqual(s.state.collector("ticker")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
