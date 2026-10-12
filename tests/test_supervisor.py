"""Tests for laglens.supervisor: backoff, disable after 10 failures, engine exception."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.supervisor import BACKOFF_MAX_S, start_thread, supervised  # noqa: E402
from laglens.state import State  # noqa: E402


class FakeState:
    def __init__(self):
        self.calls = []
        self.stop_event = threading.Event()

    def set_collector(self, name, status, reason=None, **kv):
        self.calls.append((name, status, reason, kv))

    def statuses(self):
        return [c[1] for c in self.calls]


class SupervisedTests(unittest.TestCase):
    def test_restart_with_backoff_then_clean_return(self):
        st = FakeState()
        ev = threading.Event()
        waits = []
        n = {"c": 0}

        def body():
            n["c"] += 1
            if n["c"] <= 2:
                raise RuntimeError("boom %d" % n["c"])
            ev.set()

        rc = supervised("tcp", body, st, ev, sleep=waits.append, clock=lambda: 0.0)
        self.assertEqual(rc, "ok")
        self.assertEqual(n["c"], 3)
        self.assertEqual(waits, [1.0, 2.0])
        self.assertEqual(st.statuses(), ["ok", "degraded", "ok", "degraded", "ok"])
        self.assertIn("boom 1", st.calls[1][2])
        self.assertEqual(st.calls[1][3]["failures"], 1)

    def test_disabled_after_ten_failures_in_window(self):
        st = FakeState()
        ev = threading.Event()
        waits = []
        n = {"c": 0}

        def body():
            n["c"] += 1
            raise ValueError("always")

        rc = supervised("docsis", body, st, ev, sleep=waits.append, clock=lambda: 0.0)
        self.assertEqual(rc, "disabled")
        self.assertEqual(n["c"], 10)
        self.assertEqual(len(waits), 9)
        last = st.calls[-1]
        self.assertEqual(last[1], "disabled")
        self.assertIn("10 failures in 10 min", last[2])
        self.assertIn("ValueError: always", last[2])
        self.assertEqual(last[3]["failures"], 10)

    def test_engine_is_never_disabled_and_backoff_caps(self):
        st = FakeState()
        ev = threading.Event()
        waits = []
        n = {"c": 0}

        def body():
            n["c"] += 1
            if n["c"] <= 12:
                raise OSError("socket died")
            ev.set()

        rc = supervised("engine", body, st, ev, engine=True, sleep=waits.append, clock=lambda: 0.0)
        self.assertEqual(rc, "ok")
        self.assertEqual(n["c"], 13)
        self.assertNotIn("disabled", st.statuses())
        self.assertEqual(waits[:7], [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0])
        self.assertEqual(waits[-1], BACKOFF_MAX_S)

    def test_old_failures_fall_out_of_the_window_and_backoff_resets(self):
        st = FakeState()
        ev = threading.Event()
        waits = []
        t = {"v": 0.0}
        n = {"c": 0}

        def body():
            n["c"] += 1
            t["v"] += 70.0  # each run "lasts" 70 s: a healthy run resets the backoff
            if n["c"] <= 10:
                raise RuntimeError("flaky")
            ev.set()

        rc = supervised("wifi", body, st, ev, sleep=waits.append, clock=lambda: t["v"])
        self.assertEqual(rc, "ok")
        self.assertEqual(n["c"], 11)
        self.assertNotIn("disabled", st.statuses())
        self.assertTrue(all(w == 1.0 for w in waits), waits)

    def test_stop_event_interrupts_backoff(self):
        st = FakeState()
        ev = threading.Event()
        n = {"c": 0}

        def body():
            n["c"] += 1
            raise RuntimeError("once")

        threading.Timer(0.1, ev.set).start()
        t0 = time.monotonic()
        rc = supervised("x", body, st, ev)  # default sleep waits on the event (backoff would be 1 s)
        self.assertLess(time.monotonic() - t0, 0.9)
        self.assertEqual(rc, "ok")
        self.assertEqual(n["c"], 1)

    def test_no_state_and_stop_already_set(self):
        ev = threading.Event()
        ev.set()
        called = []
        self.assertEqual(supervised("x", lambda: called.append(1), None, ev), "ok")
        self.assertEqual(called, [])

    def test_bad_registry_does_not_kill_supervision(self):
        class Broken:
            stop_event = threading.Event()

            def set_collector(self, *a, **k):
                raise RuntimeError("registry bug")

        ev = threading.Event()
        self.assertEqual(supervised("x", lambda: None, Broken(), ev), "ok")


class StartThreadTests(unittest.TestCase):
    def test_start_thread_uses_state_stop_event(self):
        st = State(1.0, "s")
        ran = threading.Event()

        def body():
            ran.set()

        t = start_thread("host", body, st)
        t.join(2.0)
        self.assertTrue(ran.is_set())
        self.assertEqual(t.name, "host")
        self.assertTrue(t.daemon)
        # the body returned while stop was not requested: the dead thread is visible
        c = st.collector("host")
        self.assertEqual(c["status"], "degraded")
        self.assertEqual(c["reason"], "thread exited early")

    def test_early_return_is_degraded_but_clean_stop_is_ok(self):
        st = FakeState()
        ev = threading.Event()
        self.assertEqual(supervised("wan", lambda: None, st, ev, clock=lambda: 0.0), "ok")
        self.assertEqual(st.calls[-1][1:3], ("degraded", "thread exited early"))
        st2 = FakeState()
        self.assertEqual(supervised("wan", ev.set, st2, ev, clock=lambda: 0.0), "ok")
        self.assertEqual(st2.statuses(), ["ok"])

    def test_start_thread_reports_failures_in_registry(self):
        st = State(1.0, "s")
        n = {"c": 0}

        def body():
            n["c"] += 1
            if n["c"] == 1:
                raise RuntimeError("first")
            st.stop_event.set()

        t = start_thread("igd", body, st, sleep=lambda s: None)
        t.join(2.0)
        self.assertEqual(n["c"], 2)
        c = st.collector("igd")
        self.assertEqual(c["status"], "ok")
        self.assertEqual(c.get("restarted"), 1)


if __name__ == "__main__":
    unittest.main()
