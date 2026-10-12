"""Tests for laglens.state: targets, rings, slot bitmasks, pub/sub, snapshot."""
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.state import (  # noqa: E402
    F_LATE,
    F_LOST,
    F_ERROR,
    F_STALL,
    KIND_ICMP,
    KIND_TTL,
    RAW_RING_S,
    RING1_LEN,
    Episode,
    Event,
    Mark,
    Rollup,
    Sample,
    State,
    Target,
    extra_of,
    with_extra,
)

T0 = 1_760_000_000.0


def mk_target(key: str, tid: int = -1, **kw) -> Target:
    d = dict(id=tid, key=key, role="anycast", addr="1.1.1.1", family=4, kind="icmp", label=key)
    d.update(kw)
    return Target(**d)


def mk_sample(state: State, tid: int, offset_ms: int, value: int = 10_000, flags: int = 0, kind: int = KIND_ICMP, seq: int = 0) -> Sample:
    return Sample(ts_ms=state.t0_ms + offset_ms, target_id=tid, kind=kind, flags=flags, seq=seq, value=value)


class TargetTests(unittest.TestCase):
    def test_ids_assigned_in_order(self):
        st = State(T0, "s")
        a = st.add_target(mk_target("gw4"))
        b = st.add_target(mk_target("inet4_cf"))
        self.assertEqual((a.id, b.id), (0, 1))
        self.assertIs(st.target("gw4"), a)
        self.assertIs(st.target_by_id(1), b)
        self.assertEqual([t.key for t in st.targets_list()], ["gw4", "inet4_cf"])

    def test_explicit_ids_kept_and_collisions_resolved(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4", 5))
        c = st.add_target(mk_target("xbox"))
        self.assertEqual(c.id, 6)
        d = st.add_target(mk_target("other", 5))  # id 5 is taken by gw4
        self.assertEqual(d.id, 7)
        self.assertEqual(st.target("gw4").id, 5)

    def test_set_target_state_publishes(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))
        seen = []
        st.subscribe(lambda n, o: seen.append((n, o)))
        st.set_target_state("gw4", enabled=False, reason="local network permission")
        self.assertFalse(st.target("gw4").enabled)
        self.assertEqual(seen[-1][0], "target")
        self.assertEqual(seen[-1][1]["reason"], "local network permission")

    def test_set_target_state_keeps_reason_unless_passed(self):
        st = State(T0, "s")
        st.add_target(mk_target("tcp_xbl_auth4", addr=None, enabled=False, reason="cannot resolve"))
        st.set_target_state("tcp_xbl_auth4", addr="1.2.3.4")  # a re-resolver refreshing only addr
        t = st.target("tcp_xbl_auth4")
        self.assertEqual((t.addr, t.enabled, t.reason), ("1.2.3.4", False, "cannot resolve"))
        st.set_target_state("tcp_xbl_auth4", enabled=True, reason=None)  # explicit clear
        self.assertEqual((t.enabled, t.reason), (True, None))
        st.set_target_state("nope", enabled=True)  # unknown key is a no-op

    def test_round_trip_dict(self):
        t = mk_target("gw4", 0, extra={"name": "x"})
        self.assertEqual(Target.from_dict(t.to_dict()), t)
        self.assertTrue(t.on_grid)
        self.assertFalse(mk_target("h", 1, mode="ttl_expiry").on_grid)


class SampleTests(unittest.TestCase):
    def test_flags_and_extra(self):
        f = with_extra(F_LOST | F_STALL, 3)
        self.assertEqual(extra_of(f), 3)
        self.assertTrue(f & F_LOST)
        s = Sample(ts_ms=1, target_id=0, kind=KIND_ICMP, flags=F_LOST, seq=1, value=-1)
        self.assertTrue(s.lost)
        self.assertFalse(s.received)
        self.assertIsNone(s.rtt_ms)
        s2 = Sample(ts_ms=1, target_id=0, kind=KIND_ICMP, flags=0, seq=1, value=12_500)
        self.assertEqual(s2.rtt_ms, 12.5)
        self.assertEqual(s2.to_row(), [1, 0, 0, 0, 12_500])

    def test_slot_computed_for_on_grid_kinds(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))
        s = mk_sample(st, 0, 1_000)
        st.add_sample(s)
        self.assertEqual(s.slot, 4)
        ttl = mk_sample(st, 0, 1_000, kind=KIND_TTL)
        st.add_sample(ttl)
        self.assertEqual(ttl.slot, 0)
        self.assertEqual(st.slot_time(4), T0 + 1.0)

    def test_slot_origin_is_aligned_to_the_5s_grid(self):
        # t0 = ...03.7 s: slot 0 must start at ...00.0 so a 5 s window's 20 slots start at its t
        st = State(T0 + 3.7, "s")
        self.assertEqual(st.slot_origin_ms, int(T0) * 1000)
        self.assertEqual(st.slot_for(int(T0 + 5) * 1000), 20)
        self.assertEqual(st.slot_for(int(T0 + 5) * 1000 + 249), 20)
        self.assertEqual(st.slot_for(int(T0 + 5) * 1000 + 250), 21)
        self.assertEqual(st.slot_time(20), T0 + 5.0)
        self.assertEqual(st.slot_for(int(T0) * 1000 - 1), 0)  # before the origin
        aligned = State(T0, "s")
        self.assertEqual(aligned.slot_origin_ms, aligned.t0_ms)

    def test_raw_window_and_prune(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))
        for i in range(10):
            st.add_sample(mk_sample(st, 0, i * 250, value=1000 * i))
        win = st.raw_window(0, T0 + 1.0, T0 + 2.0)
        self.assertEqual([s.value for s in win], [4000, 5000, 6000, 7000])
        self.assertEqual(st.last_sample(0).value, 9000)
        # a sample 15 min later evicts the old ones
        st.add_sample(mk_sample(st, 0, RAW_RING_S * 1000 + 3000))
        self.assertEqual(len(st.raw_window(0, T0, T0 + 10)), 0)
        self.assertEqual(st.sample_count, 11)

    def test_raw_all_sorted_across_targets(self):
        st = State(T0, "s")
        st.add_target(mk_target("a"))
        st.add_target(mk_target("b"))
        st.add_sample(mk_sample(st, 1, 500))
        st.add_sample(mk_sample(st, 0, 250))
        self.assertEqual([s.target_id for s in st.raw_all(T0, T0 + 5)], [0, 1])

    def test_accumulators_and_slot_bitmasks(self):
        st = State(T0, "s")
        for k in ("gw4", "x", "y", "z"):
            st.add_target(mk_target(k))
        st.add_sample(mk_sample(st, 3, 1_000, flags=F_LOST, value=-1))  # slot 4
        st.add_sample(mk_sample(st, 0, 1_100, value=900))  # same second
        st.add_sample(mk_sample(st, 3, 1_250, flags=F_LATE, value=2_500_000))  # slot 5 late
        st.add_sample(mk_sample(st, 1, 1_300, flags=F_ERROR, value=65))
        self.assertEqual(st.slots(4, 2), [1 << 3, 0])
        self.assertEqual(st.slots(4, 2, late=True), [0, 1 << 3])
        self.assertEqual(st.pending_seconds(), [int(T0) + 1])
        taken = st.take_accumulators(int(T0) + 2)
        acc = taken[int(T0) + 1]
        self.assertEqual((acc[3].n, acc[3].lost, acc[3].late), (1, 1, 1))
        self.assertEqual(acc[0].rtts, [0.9])
        self.assertEqual(acc[1].err, 1)
        self.assertEqual(st.pending_seconds(), [])
        tot = st.totals[3]
        self.assertEqual((tot.sent, tot.lost, tot.late, tot.max_run), (1, 1, 1, 1))
        st.prune_slots(5)
        self.assertEqual(st.slots(4, 1), [0])

    def test_samples_for_unknown_target_do_not_crash(self):
        st = State(T0, "s")
        st.add_sample(mk_sample(st, 42, 100))
        self.assertEqual(len(st.raw_window(42, T0, T0 + 1)), 1)

    def test_concurrent_add_sample(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))

        def work(n):
            for i in range(500):
                st.add_sample(mk_sample(st, 0, i * 10 + n, seq=i))

        threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(st.sample_count, 2000)
        self.assertEqual(st.totals[0].sent, 2000)


class RollupRingTests(unittest.TestCase):
    def test_rollup_rings_by_resolution(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))
        r1 = Rollup(t=int(T0), id=0, n=4, lost=0, late=0, err=0, min=1, p50=1, p95=2, max=2, jit=0.1, stall=0)
        r5 = Rollup(t=int(T0), id=0, n=20, lost=1, late=0, err=0, min=1, p50=1, p95=2, max=2, jit=0.1, stall=0)
        st.add_rollup(1, r1)
        st.add_rollup(5, r5)
        self.assertEqual(st.rollups(1, T0 - 1, T0 + 1)[0], [r1])
        self.assertEqual(st.rollups(5, T0 - 1, T0 + 1)[0], [r5])
        self.assertEqual(st.rollups(1, T0 + 1, T0 + 2)[0], [])
        self.assertIs(st.last_rollup(5, 0), r5)
        self.assertEqual(r5.loss_pct, 5.0)
        with self.assertRaises(ValueError):
            st.rollups(2, 0, 1)

    def test_add_rollup_merges_same_second_and_keeps_time_order(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))
        S = int(T0)
        base = dict(id=0, late=0, err=0, stall=0)
        st.add_rollup(1, Rollup(t=S, n=3, lost=0, min=10, p50=11, p95=12, max=12, jit=1.0, **base))
        st.add_rollup(1, Rollup(t=S + 1, n=4, lost=0, min=9, p50=9, p95=9, max=9, jit=0.0, **base))
        # the lost verdict of the 4th probe of second S arrives after S was closed
        st.add_rollup(1, Rollup(t=S, n=1, lost=1, min=None, p50=None, p95=None, max=None, jit=None, **base))
        rows = st.rollups(1, S, S + 2)[0]
        self.assertEqual([(r.t, r.n, r.lost) for r in rows], [(S, 4, 1), (S + 1, 4, 0)])
        self.assertEqual((rows[0].p50, rows[0].min, rows[0].max), (11, 10, 12))
        # a late reply merges its count; percentiles combine as a weighted average
        st.add_rollup(1, Rollup(t=S, n=1, lost=0, min=20, p50=20, p95=20, max=20, jit=None, late=1, id=0, err=0, stall=0))
        r = st.rollups(1, S, S + 1)[0][0]
        self.assertEqual((r.n, r.lost, r.late, r.received), (5, 1, 1, 4))
        self.assertEqual((r.min, r.max), (10, 20))
        self.assertAlmostEqual(r.p50, (11 * 3 + 20 * 1) / 4.0, places=2)
        # an older second arriving after a newer one is inserted in order, not appended
        st.add_rollup(1, Rollup(t=S - 1, n=4, lost=0, min=1, p50=1, p95=1, max=1, jit=0.0, **base))
        self.assertEqual([r.t for r in st.rollups(1, S - 5, S + 5)[0]], [S - 1, S, S + 1])
        self.assertEqual(st.last_rollup(1, 0).t, S + 1)

    def test_rollups_short_window_does_not_scan_the_whole_ring(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))
        base = dict(id=0, lost=0, late=0, err=0, min=1, p50=1, p95=1, max=1, jit=0.0, stall=0)
        now = int(time.time())  # the sparkline window is relative to the state's clock
        st.clock = lambda: now + 0.5  # pinned: a slow runner crossing a second boundary must not shift the window
        for i in range(RING1_LEN):  # a full 2 h ring ending now
            st.add_rollup(1, Rollup(t=now - RING1_LEN + i, n=4, **base))
        small = State(T0, "s")
        small.add_target(mk_target("gw4"))
        for i in range(120):
            small.add_rollup(1, Rollup(t=now - 120 + i, n=4, **base))

        def timed(state):
            best = float("inf")
            for _ in range(5):
                t = time.perf_counter()
                for _ in range(20):
                    out = state.rollups(1, now - 60, now)
                best = min(best, time.perf_counter() - t)
            return best, out

        t_full, out_full = timed(st)
        t_small, out_small = timed(small)
        self.assertEqual(len(out_full[0]), 60)
        self.assertEqual(len(out_small[0]), 60)
        self.assertEqual([r.t for r in out_full[0]], [r.t for r in out_small[0]])
        # a 60 s window on a 7200-entry ring must cost about the same as on a 120-entry ring
        self.assertLess(t_full, max(t_small * 4, 0.01), "rollups() scaled with ring length: %.4f vs %.4f" % (t_full, t_small))
        # the sparkline scan is bounded the same way
        snap = st.snapshot()
        self.assertEqual(len(snap["targets"][0]["spark"]), 60)

    def test_rows5(self):
        st = State(T0, "s")
        st.add_row5("iface", {"t": int(T0), "iface": {"rx_mbps": 1}})
        st.add_row5("custom", {"t": int(T0) + 5, "custom": {}})
        self.assertEqual(len(st.rows5("iface", T0, T0 + 5)), 1)
        self.assertEqual(len(st.rows5("custom", T0, T0 + 5)), 0)
        self.assertEqual(len(st.rows5("custom", T0, T0 + 10)), 1)


class RegistryTests(unittest.TestCase):
    def test_collectors_and_publish_on_change(self):
        st = State(T0, "s")
        seen = []
        st.subscribe(lambda n, o: seen.append((n, o)))
        st.set_collector("docsis", "disabled", reason="docsis.password not set")
        st.set_collector("docsis", "disabled", reason="docsis.password not set")
        st.set_collector("docsis", "ok", trusted=True)
        self.assertEqual([o["status"] for n, o in seen if n == "collector"], ["disabled", "ok"])
        self.assertEqual(st.collectors()["docsis"]["trusted"], True)
        self.assertIsNone(st.collector("nope"))
        self.assertIn("since", st.collector("docsis"))

    def test_latest(self):
        st = State(T0, "s")
        self.assertIsNone(st.latest("iface"))
        st.set_latest("iface", {"rx_mbps": 1.0})
        row = st.latest("iface")
        row["rx_mbps"] = 99
        self.assertEqual(st.latest("iface")["rx_mbps"], 1.0)

    def test_subscribe_unsubscribe_and_bad_listener(self):
        st = State(T0, "s")
        got = []

        def bad(n, o):
            raise RuntimeError("listener bug")

        unsub = st.subscribe(bad)
        st.subscribe(lambda n, o: got.append(n))
        st.publish("tick", {})
        unsub()
        st.publish("tick", {})
        self.assertEqual(got, ["tick", "tick"])

    def test_ids_events_episodes_marks(self):
        st = State(T0, "s")
        self.assertEqual(st.next_event_id(), "ev-000001")
        st.seed_ids(events=41, episodes=2, marks=7)
        self.assertEqual(st.next_event_id(), "ev-000042")
        self.assertEqual(st.next_episode_id(), "ep-000003")
        self.assertEqual(st.next_mark_id(), "mk-8")
        ev = st.add_event(Event(id="ev-1", t0=T0, t1=None, type="loss_burst", target=0, severity=2))
        ep = st.add_episode(Episode(id="ep-1", t0=T0, targets=[0], events=[ev.id], cls="docsis_access"))
        mk = st.add_mark(Mark(id="mk-1", t_pressed=T0 + 30, offset_s=30, t_est=T0))
        self.assertIs(st.episode("ep-1"), ep)
        self.assertEqual(st.open_episodes(), [ep])
        self.assertIs(st.mark("mk-1"), mk)
        d = ep.to_dict()
        self.assertEqual(d["class"], "docsis_access")
        self.assertNotIn("cls", d)
        self.assertIn("sweep", d)
        self.assertNotIn("sweep", ep.to_dict(brief=True))
        self.assertEqual(Episode.from_dict(d), ep)

    def test_activity_tags(self):
        st = State(T0, "s")
        st.set_activity("bf6", source="phone")
        st.set_activity("idle")
        self.assertEqual(st.activity["current"], "idle")
        self.assertIsNotNone(st.tags[0]["t1"])
        self.assertEqual(len(st.activity_spans("bf6")), 1)

    def test_request_stop(self):
        st = State(T0, "s")
        seen = []
        st.subscribe(lambda n, o: seen.append(n))
        st.request_stop("sigint")
        st.request_stop("api")
        self.assertTrue(st.stop_event.is_set())
        self.assertEqual(st.stop_reason, "sigint")
        self.assertEqual(seen, ["stopping", "stopping"])

    def test_request_stop_without_publish(self):
        st = State(T0, "s")
        seen = []
        st.subscribe(lambda n, o: seen.append(n))
        st.request_stop("sigterm", publish=False)
        self.assertTrue(st.stop_event.is_set())
        self.assertEqual(st.stop_reason, "sigterm")
        self.assertEqual(seen, [])


class SnapshotTests(unittest.TestCase):
    def test_snapshot_shape(self):
        st = State(T0, "20261011-190000", cfg={"label": "lbl"})
        st.add_target(mk_target("gw4"))
        st.add_sample(mk_sample(st, 0, 100, value=900))
        st.add_rollup(1, Rollup(t=int(st.now()) - 1, id=0, n=4, lost=0, late=0, err=0, min=1, p50=1.2, p95=2, max=2, jit=0.1, stall=0))
        st.set_collector("engine", "ok")
        snap = st.snapshot()
        expected = {
            "version", "session", "state", "pill", "headline", "health", "host", "targets", "xbox", "collectors", "path",
            "activity", "activities", "episodes_open", "episodes_recent", "marks_recent", "verdict", "loadtest", "doctor",
            "disk", "update", "token_required", "sse_clients", "now",
        }
        self.assertEqual(set(snap), expected)
        self.assertEqual(snap["activities"], list(st.cfg.get("activities") or []))
        self.assertEqual(snap["session"]["id"], "20261011-190000")
        self.assertEqual(snap["session"]["label"], "lbl")
        self.assertEqual(snap["state"], "STARTING")
        t = snap["targets"][0]
        self.assertEqual(t["last"]["rtt"], 0.9)
        self.assertEqual(t["spark"], [1.2])
        self.assertIn("w5m", t)
        json.dumps(snap)  # must be serialisable

    def test_tick_payload(self):
        st = State(T0, "s")
        st.add_target(mk_target("gw4"))
        st.add_sample(mk_sample(st, 0, 100, flags=F_LOST, value=-1))
        p = st.tick_payload(now=T0 + 1)
        self.assertEqual(set(p), {"t", "state", "pill", "headline", "health", "targets", "iface", "wan", "xbox", "stall", "slots_lost"})
        self.assertEqual(len(p["slots_lost"]), 4)
        # now = t0 + 1 s is slot 4; the payload carries slots 0..3 and slot 0 lost target 0
        self.assertEqual(p["slots_lost"], [1, 0, 0, 0])
        self.assertEqual(p["targets"]["0"]["rtt"], None)
        json.dumps(p)


if __name__ == "__main__":
    unittest.main()


class NotesTests(unittest.TestCase):
    def test_raise_and_drain_notes(self):
        from laglens.state import State
        st = State()
        d = st.raise_note("route_change", t=123.0, target=3, severity=2, note="x", old=["a"], new=["b"])
        self.assertEqual(d["type"], "route_change")
        self.assertEqual(d["peak"], {"old": ["a"], "new": ["b"]})
        self.assertEqual(d["t"], 123.0)
        notes = st.drain_notes()
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["severity"], 2)
        self.assertEqual(st.drain_notes(), [])

    def test_raise_note_default_time_and_bound(self):
        import time
        from laglens.state import State
        st = State()
        before = time.time()
        d = st.raise_note("link_flap")
        self.assertGreaterEqual(d["t"], before - 1)
        for i in range(10500):
            st.raise_note("x", t=float(i))
        notes = st.drain_notes()
        self.assertEqual(len(notes), 10000)
        self.assertEqual(notes[0]["t"], 500.0)
