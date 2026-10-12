"""Tests for laglens.loadtest: phase sequencing with a fake HTTP transfer and a fake clock, grade
thresholds, refusal while an episode is open / while busy, the state.loadtest shape, abort, the
latency sources and run_cli without an engine (fake sampler, no network)."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import loadtest as lt  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.state import KIND_ICMP, F_LOST, Episode, Sample, State, Target  # noqa: E402

T0 = 1_760_000_000.0
PHASE_S = 20.0


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


class FakeTransfer:
    """Delivers ``per_call`` bytes per worker as soon as a phase starts, then idles until stop()."""

    def __init__(self, per_call=2_500_000):
        self.per_call = per_call
        self.calls = []
        self._lock = threading.Lock()

    def _run(self, kind, url, stop, on_bytes):
        with self._lock:
            self.calls.append((kind, url))
        on_bytes(self.per_call)
        while not stop():
            time.sleep(0.001)

    def download(self, url, stop, on_bytes):
        self._run("down", url, stop, on_bytes)

    def upload(self, url, stop, on_bytes):
        self._run("up", url, stop, on_bytes)


class FakeStore:
    def __init__(self):
        self.rows = []

    def append_json(self, name, obj):
        import json

        json.dumps(obj)
        self.rows.append((name, obj))


class Ctx:
    def __init__(self, cfg=None):
        self.cfg = cfg if cfg is not None else {"loadtest": {"phase_s": PHASE_S, "threads": 2}}
        self.state = State(cfg=self.cfg)
        self.store = FakeStore()
        self.platform = None
        self.components = {}

    def component(self, n):
        return self.components.get(n)


# p50 per phase as seen by the fake latency source (idle 20, down 50, up 25, recover 21)
PHASE_P50 = {"idle": 20.0, "down": 50.0, "up": 25.0, "recover": 21.0}


def latency_for(clk, t0_holder):
    def source(t_from, t_to):
        t0 = t0_holder["t0"]
        idx = int((t_from - t0) // PHASE_S)
        idx = max(0, min(idx, len(lt.PHASES) - 1))
        p50 = PHASE_P50[lt.PHASES[idx]]
        return [p50 - 1.0, p50, p50 + 1.0]

    return source


def make(cfg=None, gate=None):
    ctx = Ctx(cfg)
    clk = Clock()
    holder = {"t0": clk.t}
    transfer = FakeTransfer()

    def wait(s):
        if gate is not None:
            gate.wait()
        clk.t += s

    test = lt.LoadTest(ctx, transfer=transfer, latency_source=latency_for(clk, holder), clock=clk, wait=wait)
    return ctx, clk, transfer, test


class GradeTests(unittest.TestCase):
    def test_thresholds(self):
        self.assertIsNone(lt.grade_for(None))
        self.assertEqual(lt.grade_for(0.0), "A")
        self.assertEqual(lt.grade_for(14.9), "A")
        self.assertEqual(lt.grade_for(15.0), "B")
        self.assertEqual(lt.grade_for(39.9), "B")
        self.assertEqual(lt.grade_for(40.0), "C")
        self.assertEqual(lt.grade_for(99.9), "C")
        self.assertEqual(lt.grade_for(100.0), "D")
        self.assertEqual(lt.grade_for(249.9), "D")
        self.assertEqual(lt.grade_for(250.0), "F")
        self.assertEqual(lt.grade_for(1000.0), "F")

    def test_latency_summary(self):
        s = lt.latency_summary([10.0, 20.0, 30.0, 40.0, 50.0])
        self.assertEqual((s["p50"], s["n"]), (30.0, 5))
        self.assertAlmostEqual(s["p95"], 48.0, places=2)
        self.assertEqual(lt.latency_summary([]), {"p50": None, "p95": None, "n": 0})
        self.assertEqual(lt.latency_summary([7.0])["p95"], 7.0)


class SequenceTests(unittest.TestCase):
    def test_phases_in_order_with_grade_and_row(self):
        ctx, clk, transfer, test = make()
        row = test.run_sync()
        self.assertEqual(list(row["phases"]), list(lt.PHASES))
        # the fake clock advanced exactly four phases
        self.assertAlmostEqual(row["t1"] - row["t0"], 4 * PHASE_S, delta=0.3)
        for ph in lt.PHASES:
            self.assertAlmostEqual(row["phases"][ph]["dur_s"], PHASE_S, delta=0.3)
            self.assertEqual(row["phases"][ph]["p50"], PHASE_P50[ph])
            self.assertEqual(row["phases"][ph]["n"], 3)
        # transfers only in the load phases, with the Cloudflare URLs; 2 worker threads each
        kinds = [k for k, _ in transfer.calls]
        self.assertEqual(kinds.count("down"), 2)
        self.assertEqual(kinds.count("up"), 2)
        self.assertEqual({u for k, u in transfer.calls if k == "down"}, {lt.DOWN_URL})
        self.assertEqual({u for k, u in transfer.calls if k == "up"}, {lt.UP_URL})
        self.assertNotIn("mbps", row["phases"]["idle"])
        self.assertNotIn("mbps", row["phases"]["recover"])
        # 2 workers x 2.5 MB over 20 s = 2 Mb/s
        self.assertAlmostEqual(row["phases"]["down"]["mbps"], 2.0, delta=0.05)
        self.assertEqual(row["phases"]["down"]["bytes"], 5_000_000)
        self.assertAlmostEqual(row["phases"]["up"]["mbps"], 2.0, delta=0.05)
        # added latency: down 50-20 = 30 (B), up 25-20 = 5 (A) -> worst is B
        self.assertEqual(row["added_ms"], {"down": 30.0, "up": 5.0})
        self.assertEqual(row["grade"], "B")
        self.assertFalse(row["aborted"])
        self.assertEqual((row["phase_s"], row["threads"], row["id"]), (PHASE_S, 2, "lt-1"))
        # stored once in loadtests.jsonl
        self.assertEqual([n for n, _ in ctx.store.rows], ["loadtests"])
        self.assertIs(ctx.store.rows[0][1], row)
        # one loadtest_phase note per phase, in order
        notes = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["loadtest_phase"] * 4)
        self.assertEqual([n["peak"]["phase"] for n in notes], list(lt.PHASES))
        self.assertEqual(notes[0]["peak"]["id"], "lt-1")

    def test_state_shape_during_and_after(self):
        seen = []
        ctx, clk, transfer, test = make()

        def on_phase(phase, res):
            seen.append((phase, test.status(), dict(ctx.state.loadtest)))

        test._on_phase = on_phase
        published = []
        ctx.state.subscribe(lambda name, obj: published.append((name, obj)) if name == "loadtest" else None)
        row = test.run_sync()
        self.assertEqual([p for p, _, _ in seen], list(lt.PHASES))
        for phase, status, raw in seen:
            self.assertTrue(status["running"])
            self.assertEqual(status["phase"], phase)
            self.assertIn("elapsed_s", status)
            self.assertIn("live", status)
            self.assertEqual(status["id"], "lt-1")
            self.assertEqual(set(raw) >= {"running", "phase", "elapsed_s", "live", "last", "id"}, True)
        down_status = [s for p, s, _ in seen if p == "down"][0]
        self.assertIsNotNone(down_status["live"]["mbps"])
        self.assertEqual(down_status["live"]["p95"], 50.9)  # p95 of [49, 50, 51], interpolated
        final = test.status()
        self.assertFalse(final["running"])
        self.assertIsNone(final["phase"])
        self.assertIsNone(final["live"])
        self.assertIs(final["last"], row)
        self.assertAlmostEqual(final["elapsed_s"], 4 * PHASE_S, delta=0.5)
        self.assertEqual(ctx.state.loadtest["last"]["grade"], "B")
        names = [n for n, _ in published]
        self.assertGreaterEqual(len(names), 5)
        self.assertEqual(published[-1][1]["running"], False)
        self.assertEqual(published[0][1]["phase"], "idle")

    def test_refuses_while_episode_open_unless_forced(self):
        gate = threading.Event()
        ctx, clk, transfer, test = make(gate=gate)
        ctx.state.add_episode(Episode(id="ep-000001", t0=clk.t))
        with self.assertRaises(lt.EpisodeOpen):
            test.start()
        self.assertFalse(test.status()["running"])
        self.assertEqual(transfer.calls, [])
        res = test.start(force=True)
        self.assertEqual((res["ok"], res["id"], res["phases"], res["eta_s"]), (True, "lt-1", list(lt.PHASES), 80))
        with self.assertRaises(lt.LoadTestBusy):
            test.start(force=True)
        gate.set()
        test._thread.join(10.0)
        self.assertFalse(test._thread.is_alive())
        self.assertEqual(test.last["grade"], "B")
        self.assertFalse(test.status()["running"])
        # a second run gets a new id
        ctx.state.episodes[0].t1 = clk.t
        res2 = test.start()
        test._thread.join(10.0)
        self.assertEqual(res2["id"], "lt-2")

    def test_stop_aborts_without_storing(self):
        gate = threading.Event()
        ctx, clk, transfer, test = make(gate=gate)
        test.start()
        self.assertTrue(test.status()["running"])
        test.stop(timeout=0.01)
        gate.set()
        test._thread.join(10.0)
        row = test.last
        self.assertTrue(row["aborted"])
        self.assertIsNone(row["grade"])
        self.assertEqual(ctx.store.rows, [])
        self.assertFalse(ctx.state.loadtest["running"])
        self.assertLess(len(row["phases"]), 4)

    def test_stop_event_aborts(self):
        ctx, clk, transfer, test = make()
        ctx.state.stop_event.set()
        row = test.run_sync()
        self.assertTrue(row["aborted"])
        self.assertEqual(row["phases"], {})

    def test_config_fallbacks(self):
        ctx = Ctx({"loadtest": {"phase_s": "bogus", "threads": 0}})
        test = lt.LoadTest(ctx, transfer=FakeTransfer(), latency_source=lambda a, b: [])
        self.assertEqual((test.phase_s, test.threads), (20.0, 1))
        ctx2 = Ctx({})
        test2 = lt.LoadTest(ctx2, transfer=FakeTransfer(), latency_source=lambda a, b: [])
        self.assertEqual((test2.phase_s, test2.threads), (20.0, 4))

    def test_no_latency_means_no_grade(self):
        ctx = Ctx({"loadtest": {"phase_s": 1, "threads": 1}})
        clk = Clock()
        test = lt.LoadTest(ctx, transfer=FakeTransfer(), latency_source=lambda a, b: [], clock=clk,
                           wait=lambda s: setattr(clk, "t", clk.t + s))
        row = test.run_sync()
        self.assertIsNone(row["grade"])
        self.assertEqual(row["added_ms"], {"down": None, "up": None})
        self.assertEqual(row["phases"]["idle"]["n"], 0)


class LatencySourceTests(unittest.TestCase):
    def test_state_source_uses_reference_targets_only(self):
        st = State(t0=T0, cfg={})
        cf = st.add_target(Target(id=-1, key="inet4_cf", role="inet", addr="1.1.1.1", family=4, kind="icmp", label="CF"))
        g = st.add_target(Target(id=-1, key="inet4_g", role="inet", addr="8.8.8.8", family=4, kind="icmp", label="G"))
        gw = st.add_target(Target(id=-1, key="gw4", role="gateway", addr="10.0.0.1", family=4, kind="icmp", label="GW"))
        base = int(T0 * 1000)
        st.add_sample(Sample(ts_ms=base + 100, target_id=cf.id, kind=KIND_ICMP, flags=0, seq=1, value=12_000))
        st.add_sample(Sample(ts_ms=base + 350, target_id=g.id, kind=KIND_ICMP, flags=0, seq=1, value=18_500))
        st.add_sample(Sample(ts_ms=base + 600, target_id=cf.id, kind=KIND_ICMP, flags=F_LOST, seq=2, value=-1))
        st.add_sample(Sample(ts_ms=base + 700, target_id=gw.id, kind=KIND_ICMP, flags=0, seq=1, value=1_000))
        st.add_sample(Sample(ts_ms=base + 5000, target_id=cf.id, kind=KIND_ICMP, flags=0, seq=3, value=30_000))
        src = lt.state_latency_source(st)
        self.assertEqual(sorted(src(T0, T0 + 1.0)), [12.0, 18.5])
        self.assertEqual(src(T0 + 4.0, T0 + 6.0), [30.0])
        self.assertEqual(src(T0 + 100, T0 + 200), [])


class FakePlatform(Platform):
    name = "darwin"

    def __init__(self, output="64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.3 ms\n", rc=0):
        super().__init__(runner=self._run, reader=lambda p: None, exists=lambda p: False, env={}, which=lambda n: None)
        self.output = output
        self.rc = rc
        self.argvs = []

    def _run(self, argv, timeout):
        self.argvs.append((list(argv), timeout))
        return (self.rc, self.output, "")


class PingSamplerTests(unittest.TestCase):
    def test_argv_and_once(self):
        p = FakePlatform()
        s = lt.PingSampler(p, targets=("1.1.1.1",), clock=lambda: T0)
        self.assertEqual(s.argv("1.1.1.1"), ["ping", "-n", "-c", "1", "-t", "1", "1.1.1.1"])
        self.assertEqual(s.once("1.1.1.1"), 12.3)
        self.assertEqual(p.argvs[-1][1], 3.0)
        p.name = "linux"
        self.assertEqual(s.argv("1.1.1.1"), ["ping", "-n", "-c", "1", "-W", "1", "1.1.1.1"])
        self.assertEqual(s.argv("2606:4700:4700::1111")[:2], ["ping", "-6"])
        bad = lt.PingSampler(FakePlatform(output="", rc=1), clock=lambda: T0)
        self.assertIsNone(bad.once("1.1.1.1"))
        self.assertEqual(bad.errors, 1)

    def test_rtts_window(self):
        s = lt.PingSampler(FakePlatform(), clock=lambda: T0)
        s._samples = [(T0, 10.0), (T0 + 1, None), (T0 + 2, 12.0), (T0 + 3, 14.0)]
        self.assertEqual(s.rtts(T0, T0 + 3), [10.0, 12.0])


class FakeEvent:
    """A stop_event whose wait() advances a fake clock instead of sleeping."""

    def __init__(self, clk):
        self.clk = clk
        self._set = False

    def wait(self, s=None):
        if s:
            self.clk.t += s
        return self._set

    def is_set(self):
        return self._set

    def set(self):
        self._set = True


class FakeSampler:
    def __init__(self, rtts):
        self._rtts = rtts
        self.errors = 0
        self.stopped = False

    def rtts(self, t_from, t_to):
        return list(self._rtts)

    def stop(self):
        self.stopped = True


class RunCliTests(unittest.TestCase):
    def test_run_cli_without_engine(self):
        cfg = {"loadtest": {"phase_s": 2, "threads": 1}}
        clk = Clock()
        st = State(cfg=cfg)
        st.stop_event = FakeEvent(clk)
        lines = []
        sampler = FakeSampler([30.0, 31.0, 32.0])
        rc = lt.run_cli(cfg, platform=FakePlatform(), transfer=FakeTransfer(per_call=1_000_000), sampler=sampler,
                        out=lines.append, state=st, clock=clk)
        self.assertEqual(rc, 0)
        text = "\n".join(lines)
        self.assertIn("4 phases x 2 s (1 threads)", text)
        self.assertIn("latency via engine", text)
        for ph in lt.PHASES:
            self.assertIn("%-8s done:" % ph, text)
        self.assertIn("PHASE", text)
        self.assertIn("grade: A", text)
        self.assertIn("added latency under load: down 0.0 ms, up 0.0 ms", text)
        self.assertIn("down            4.0      31.0      31.9      3", text)  # 1 MB over 2 s = 4 Mb/s
        self.assertFalse(sampler.stopped)  # an injected sampler is the caller's
        self.assertFalse(st.loadtest["running"])
        self.assertEqual(st.loadtest["last"]["grade"], "A")

    def test_run_cli_reports_ping_failure(self):
        cfg = {"loadtest": {"phase_s": 1, "threads": 1}}
        clk = Clock()
        st = State(cfg=cfg)
        st.stop_event = FakeEvent(clk)
        lines = []
        sampler = FakeSampler([])
        sampler.errors = 3
        rc = lt.run_cli(cfg, platform=FakePlatform(), transfer=FakeTransfer(), sampler=sampler, out=lines.append,
                        state=st, clock=clk)
        self.assertEqual(rc, 0)
        self.assertIn("grade: n/a", "\n".join(lines))
        self.assertNotIn("warning: no latency samples", "\n".join(lines))  # only for the built-in sampler

    def test_format_table(self):
        row = {"phases": {"idle": {"p50": 20.0, "p95": 22.0, "n": 80}, "down": {"mbps": 95.5, "p50": 40.0, "p95": 60.0, "n": 80}},
               "added_ms": {"down": 20.0, "up": None}, "grade": "B", "aborted": True}
        text = lt.format_table(row)
        self.assertIn("idle              -      20.0      22.0     80", text)
        self.assertIn("down           95.5      40.0      60.0     80", text)
        self.assertIn("up                -         -         -      0", text)
        self.assertIn("grade: B (aborted)", text)


if __name__ == "__main__":
    unittest.main()
