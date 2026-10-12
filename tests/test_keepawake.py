"""Tests for laglens.keepawake: command selection per platform, spawn/respawn watchdog, warnings, stop."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import keepawake as k  # noqa: E402
from laglens.platform import get_platform  # noqa: E402
from laglens.state import State  # noqa: E402


class FakeChild:
    def __init__(self, argv, pid=1234):
        self.argv = argv
        self.pid = pid
        self.rc = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.rc

    def terminate(self):
        self.terminated = True
        self.rc = -15

    def wait(self, timeout=None):
        return self.rc

    def kill(self):
        self.killed = True


class FakePopen:
    def __init__(self, fail=False):
        self.children = []
        self.fail = fail

    def __call__(self, argv):
        if self.fail:
            raise FileNotFoundError(argv[0])
        c = FakeChild(list(argv), pid=1000 + len(self.children))
        self.children.append(c)
        return c


class Ctx:
    def __init__(self, platform):
        self.cfg = {}
        self.state = State(cfg={})
        self.platform = platform
        self.components = {}

    def component(self, n):
        return self.components.get(n)


def runner_table(table):
    def runner(argv, timeout):
        key = tuple(argv)
        if key in table:
            v = table[key]
            return (0, v, "") if isinstance(v, str) else v
        raise FileNotFoundError(argv[0])

    return runner


def plat(name, which=None, table=None, env=None):
    return get_platform(name, runner=runner_table(table or {}), reader=lambda p: None, exists=lambda p: False,
                        env=env or {}, which=which or (lambda n: None))


class Clock:
    m = 0.0


class KeepAwakeTests(unittest.TestCase):
    def test_darwin_caffeinate(self):
        p = plat("darwin", which=lambda n: "/usr/bin/caffeinate" if n == "caffeinate" else None, table={("pmset", "-g", "batt"): "Now drawing from 'AC Power'\n"})
        ctx = Ctx(p)
        pop = FakePopen()
        ka = k.KeepAwake(ctx, popen=pop, pid=4242)
        ka.start()
        self.assertEqual(pop.children[0].argv, ["/usr/bin/caffeinate", "-i", "-s", "-w", "4242"])
        c = ctx.state.collector("keepawake")
        self.assertEqual((c["status"], c["method"]), ("ok", "caffeinate"))
        ctx.state.stop_event.set()
        ka.stop(1.0)
        self.assertTrue(pop.children[0].terminated)
        self.assertIsNone(ka.child)

    def test_linux_order_kde_then_systemd(self):
        p = plat("linux", which=lambda n: "/usr/bin/" + n if n in ("kde-inhibit", "systemd-inhibit") else None)
        pop = FakePopen()
        ka = k.KeepAwake(Ctx(p), popen=pop, pid=1)
        ka.start()
        self.assertEqual(pop.children[0].argv[:3], ["kde-inhibit", "--power", "sleep"])
        p2 = plat("linux", which=lambda n: "/usr/bin/" + n if n == "systemd-inhibit" else None)
        pop2 = FakePopen()
        ka2 = k.KeepAwake(Ctx(p2), popen=pop2, pid=1)
        ka2.start()
        self.assertEqual(pop2.children[0].argv[0], "systemd-inhibit")
        self.assertIn("--mode=block", pop2.children[0].argv)
        self.assertEqual(ka2.method, "systemd-inhibit")
        for x in (ka, ka2):
            x.ctx.state.stop_event.set()
            x.stop(1.0)

    def test_linux_nothing_available_warns(self):
        ctx = Ctx(plat("linux"))
        ka = k.KeepAwake(ctx, popen=FakePopen(), pid=1)
        ka.start()
        c = ctx.state.collector("keepawake")
        self.assertEqual(c["status"], "disabled")
        self.assertEqual(c["reason"], k.LINUX_WARN)
        self.assertIsNone(ka.thread)
        ka.stop()

    def test_battery_and_game_mode_warnings(self):
        p = plat("darwin", which=lambda n: "/usr/bin/caffeinate", table={("pmset", "-g", "batt"): "Now drawing from 'Battery Power'\n"})
        ctx = Ctx(p)
        ka = k.KeepAwake(ctx, popen=FakePopen(), pid=1)
        ka.start()
        c = ctx.state.collector("keepawake")
        self.assertEqual(c["status"], "degraded")
        self.assertEqual(c["reason"], k.BATTERY_WARN)
        self.assertEqual(c["method"], "caffeinate")
        ctx.state.stop_event.set()
        ka.stop(1.0)
        pg = plat("linux", which=lambda n: "/usr/bin/kde-inhibit" if n == "kde-inhibit" else None, env={"XDG_CURRENT_DESKTOP": "gamescope"})
        ctx2 = Ctx(pg)
        ka2 = k.KeepAwake(ctx2, popen=FakePopen(), pid=1)
        ka2.start()
        self.assertIn("Game Mode", ctx2.state.collector("keepawake")["reason"])
        ctx2.state.stop_event.set()
        ka2.stop(1.0)

    def test_spawn_failure_disables(self):
        p = plat("darwin", which=lambda n: "/usr/bin/caffeinate")
        ctx = Ctx(p)
        ka = k.KeepAwake(ctx, popen=FakePopen(fail=True), pid=1)
        ka.start()
        c = ctx.state.collector("keepawake")
        self.assertEqual(c["status"], "disabled")
        self.assertIn("failed to start", c["reason"])

    def test_watchdog_respawns_then_gives_up(self):
        p = plat("darwin", which=lambda n: "/usr/bin/caffeinate", table={("pmset", "-g", "batt"): "AC Power"})
        ctx = Ctx(p)
        pop = FakePopen()
        clk = Clock()
        ka = k.KeepAwake(ctx, popen=pop, pid=1, mono=lambda: clk.m)
        ka.start()
        self.assertTrue(ka.check())
        clk.m += 30
        pop.children[-1].rc = 0  # exited after a healthy run
        self.assertTrue(ka.check())
        self.assertEqual(len(pop.children), 2)
        self.assertEqual(ka.respawns, 1)
        self.assertEqual(ctx.state.collector("keepawake")["respawns"], 1)
        for i in range(k.MAX_FAST_FAILURES):
            pop.children[-1].rc = 1  # dies immediately
            clk.m += 1
            ok = ka.check()
        self.assertFalse(ok)
        c = ctx.state.collector("keepawake")
        self.assertEqual(c["status"], "disabled")
        self.assertIn("keeps exiting", c["reason"])
        ctx.state.stop_event.set()
        ka.stop(1.0)


if __name__ == "__main__":
    unittest.main()
