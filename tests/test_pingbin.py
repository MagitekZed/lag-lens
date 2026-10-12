"""Tests for laglens.probes.pingbin: parsers, argv, loss/late accounting, restart, stop."""
import errno
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.probes import pingbin  # noqa: E402
from laglens.state import F_ERROR, F_FALLBACK, F_LATE, F_LOST, KIND_ICMP, State, Target  # noqa: E402


class FakeClock:
    def __init__(self, mono=1000.0, wall=1_760_000_000.0):
        self.m = mono
        self.w = wall

    def mono(self):
        return self.m

    def wall(self):
        return self.w

    def advance(self, s):
        self.m += s
        self.w += s


class ParserTests(unittest.TestCase):
    def test_iputils_lines(self):
        pl = pingbin.parse_ping_line("[1760223600.123456] 64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms")
        self.assertEqual((pl.kind, pl.seq, pl.rtt_ms, pl.ts), ("reply", 1, 12.3, 1760223600.123456))
        pl = pingbin.parse_ping_line("64 bytes from 2606:4700:4700::1111: icmp_seq=7 ttl=57 time=12 ms")
        self.assertEqual((pl.kind, pl.seq, pl.rtt_ms), ("reply", 7, 12.0))
        pl = pingbin.parse_ping_line("no answer yet for icmp_seq=5")
        self.assertEqual((pl.kind, pl.seq), ("noanswer", 5))
        pl = pingbin.parse_ping_line("[1760223601.5] no answer yet for icmp_seq=6")
        self.assertEqual((pl.kind, pl.seq, pl.ts), ("noanswer", 6, 1760223601.5))
        pl = pingbin.parse_ping_line("From 10.0.0.1 icmp_seq=1 Destination Host Unreachable")
        self.assertEqual((pl.kind, pl.seq, pl.errno), ("error", 1, errno.EHOSTUNREACH))
        pl = pingbin.parse_ping_line("From 10.0.0.1: icmp_seq=2 Destination Net Unreachable")
        self.assertEqual((pl.kind, pl.seq, pl.errno), ("error", 2, errno.ENETUNREACH))

    def test_macos_lines(self):
        pl = pingbin.parse_ping_line("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.345 ms")
        self.assertEqual((pl.kind, pl.seq, pl.rtt_ms), ("reply", 0, 12.345))
        pl = pingbin.parse_ping_line("16 bytes from 2606:4700:4700::1111, icmp_seq=0 hlim=57 time=12.345 ms")
        self.assertEqual((pl.kind, pl.seq, pl.rtt_ms), ("reply", 0, 12.345))
        pl = pingbin.parse_ping_line("Request timeout for icmp_seq 3")
        self.assertEqual((pl.kind, pl.seq), ("timeout", 3))
        pl = pingbin.parse_ping_line("ping: sendto: No route to host")
        self.assertEqual((pl.kind, pl.errno), ("sendto", errno.EHOSTUNREACH))
        pl = pingbin.parse_ping_line("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms (DUP!)")
        self.assertEqual(pl.kind, "dup")

    def test_uninteresting_lines(self):
        for line in ("PING 1.1.1.1 (1.1.1.1): 56 data bytes", "", "--- 1.1.1.1 ping statistics ---",
                     "round-trip min/avg/max/stddev = 10/11/12/1 ms", "   "):
            self.assertIsNone(pingbin.parse_ping_line(line), line)

    def test_summary(self):
        pl = pingbin.parse_ping_line("5 packets transmitted, 3 packets received, 40.0% packet loss")
        self.assertEqual(pl.kind, "summary")
        self.assertEqual(pingbin.parse_ping_summary("5 packets transmitted, 3 received, 40% packet loss, time 804ms"), (5, 3))
        self.assertEqual(pingbin.parse_ping_summary("5 packets transmitted, 3 packets received, 40.0% packet loss"), (5, 3))
        self.assertIsNone(pingbin.parse_ping_summary("nothing"))


class ArgvTests(unittest.TestCase):
    def test_linux(self):
        self.assertEqual(pingbin.ping_argv("linux", "1.1.1.1", 4),
                         ["ping", "-n", "-O", "-i", "0.25", "-W", "2", "-D", "1.1.1.1"])
        self.assertEqual(pingbin.ping_argv("linux", "2606::1", 6, binary="/usr/bin/ping"),
                         ["/usr/bin/ping", "-6", "-n", "-O", "-i", "0.25", "-W", "2", "-D", "2606::1"])

    def test_darwin(self):
        self.assertEqual(pingbin.ping_argv("darwin", "10.0.0.1", 4), ["/sbin/ping", "-n", "-i", "0.25", "10.0.0.1"])
        self.assertEqual(pingbin.ping_argv("darwin", "fe80::1%en0", 6), ["/sbin/ping6", "-n", "-i", "0.25", "fe80::1%en0"])

    def test_interval_from_rate_and_floor(self):
        self.assertEqual(pingbin.ping_argv("darwin", "1.1.1.1", 4, interval_s=0.5)[3], "0.5")
        self.assertEqual(pingbin.ping_argv("darwin", "1.1.1.1", 4, interval_s=0.01)[3], "0.2")
        self.assertEqual(pingbin.ping_argv("linux", "1.1.1.1", 4, interval_s=1.0)[4], "1")

    def test_find_binary(self):
        class P:
            name = "darwin"

            def exists(self, p):
                return p in ("/sbin/ping", "/sbin/ping6")

            def which(self, n):
                return None

        self.assertEqual(pingbin.find_ping_binary(P(), 4), "/sbin/ping")
        self.assertEqual(pingbin.find_ping_binary(P(), 6), "/sbin/ping6")

        class L:
            name = "linux"

            def exists(self, p):
                return False

            def which(self, n):
                return "/usr/bin/ping" if n == "ping" else None

        self.assertEqual(pingbin.find_ping_binary(L(), 6), "/usr/bin/ping")

        class N(L):
            def which(self, n):
                return None

        self.assertIsNone(pingbin.find_ping_binary(N(), 4))


def mk_proc(clock, emitted, interval=0.25, timeout=2.0, late=10.0):
    t = Target(id=3, key="inet4_cf", role="anycast", addr="1.1.1.1", family=4, kind="icmp", label="cf")
    return pingbin.PingProcess(t, ["ping"], emitted.append, spawn=None, clock=clock.mono, wall=clock.wall,
                               interval_s=interval, timeout_s=timeout, late_window_s=late)


class AccountingTests(unittest.TestCase):
    def test_reply_sample_and_send_time_estimate(self):
        clock = FakeClock()
        out = []
        p = mk_proc(clock, out)
        clock.advance(0.0123)
        s = p.handle_line("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.3 ms")
        self.assertEqual(len(out), 1)
        self.assertEqual((s.target_id, s.kind, s.seq, s.value), (3, KIND_ICMP, 0, 12300))
        self.assertTrue(s.flags & F_FALLBACK)
        self.assertFalse(s.flags & (F_LOST | F_LATE | F_ERROR))
        # ts_ms = recv − rtt, i.e. the anchor (spawn) wall time
        self.assertEqual(s.ts_ms, int(round(1_760_000_000.0 * 1000)))
        clock.advance(0.25)
        s = p.handle_line("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms")
        self.assertEqual(s.ts_ms, int(round(1_760_000_000.25 * 1000)))
        self.assertEqual(p.received, 2)

    def test_gap_becomes_lost_after_timeout_then_late(self):
        clock = FakeClock()
        out = []
        p = mk_proc(clock, out)
        for seq in (0, 1):
            clock.advance(0.25 if seq else 0.012)
            p.handle_line("64 bytes from 1.1.1.1: icmp_seq=%d ttl=57 time=12.0 ms" % seq)
        self.assertEqual(p.sweep(), [])
        clock.advance(1.0)  # seq 2,3 sent at +0.5/+0.75 are not yet 2 s old
        self.assertEqual(p.sweep(), [])
        clock.advance(1.3)  # now 2.56 s: seq 2 (sent 0.5) is 2.06 s old → lost; seq 3 (0.75) is 1.8 s → not yet
        lost = p.sweep()
        self.assertEqual([s.seq for s in lost], [2])
        self.assertTrue(lost[0].flags & F_LOST and lost[0].flags & F_FALLBACK)
        self.assertEqual(lost[0].value, -1)
        self.assertEqual(lost[0].ts_ms, int(round((1_760_000_000.0 + 0.5) * 1000)))
        clock.advance(0.3)
        self.assertEqual([s.seq for s in p.sweep()], [3])
        # a late reply for seq 2 within the late window → F_LATE with the real RTT
        s = p.handle_line("64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=2300 ms")
        self.assertTrue(s.flags & F_LATE)
        self.assertEqual(s.value, 2_300_000)
        self.assertEqual(p.late, 1)
        # a second reply for an already-counted seq is ignored
        self.assertIsNone(p.handle_line("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.0 ms"))
        # beyond the late window the reply is dropped
        clock.advance(11.0)
        p.sweep()
        self.assertIsNone(p.handle_line("64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=12000 ms"))
        self.assertEqual(p.late, 1)

    def test_iputils_numbering_from_one_does_not_invent_seq_zero(self):
        # iputils ping counts icmp_seq from 1; the first seq-bearing line fixes the base
        clock = FakeClock()
        out = []
        p = mk_proc(clock, out)
        clock.advance(0.012)
        s = p.handle_line("[1760000000.012] 64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.0 ms")
        self.assertEqual(s.seq, 1)
        clock.advance(3.0)
        lost = p.sweep()
        self.assertNotIn(0, [x.seq for x in lost])
        self.assertEqual([x.seq for x in lost][:1], [2])
        # a hint line also teaches the base when it comes first (total outage with -O)
        clock2 = FakeClock()
        out2 = []
        q = mk_proc(clock2, out2)
        clock2.advance(0.3)
        self.assertIsNone(q.handle_line("no answer yet for icmp_seq=1"))
        clock2.advance(3.0)
        self.assertEqual([x.seq for x in q.sweep()][0], 1)

    def test_settled_seq_is_not_counted_twice(self):
        clock = FakeClock()
        out = []
        p = mk_proc(clock, out)
        clock.advance(2.5)
        self.assertEqual([x.seq for x in p.sweep()], [0, 1, 2])
        clock.advance(11.0)
        p.sweep()  # seq 0/1 are past the late window → settled
        self.assertIsNone(p.handle_line("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=13000 ms"))
        self.assertIsNone(p.handle_line("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=13000 ms"))
        self.assertEqual((p.received, p.late, p.lost), (0, 0, len(out)))
        self.assertTrue(all(x.flags & F_LOST for x in out))

    def test_total_outage_without_any_reply_marks_losses_from_spawn_anchor(self):
        clock = FakeClock()
        out = []
        p = mk_proc(clock, out)
        clock.advance(3.1)
        lost = p.sweep()
        # seqs sent at 0, 0.25, 0.5, 0.75, 1.0 are ≥ 2 s old
        self.assertEqual([s.seq for s in lost], [0, 1, 2, 3, 4])
        self.assertEqual(p.lost, 5)

    def test_hints_and_errors(self):
        clock = FakeClock()
        out = []
        p = mk_proc(clock, out)
        self.assertIsNone(p.handle_line("no answer yet for icmp_seq=0"))
        self.assertIsNone(p.handle_line("Request timeout for icmp_seq 0"))
        self.assertEqual(p.hints, 2)
        self.assertEqual(out, [])
        s = p.handle_line("From 10.0.0.1 icmp_seq=0 Destination Host Unreachable")
        self.assertTrue(s.flags & F_ERROR)
        self.assertEqual(s.value, errno.EHOSTUNREACH)
        # that seq is settled: no lost sample later
        clock.advance(5)
        self.assertNotIn(0, [x.seq for x in p.sweep()])
        self.assertIsNone(p.handle_line("ping: sendto: No route to host"))
        self.assertEqual(p.errors, 2)
        self.assertIsNone(p.handle_line("64 bytes from 1.1.1.1: icmp_seq=9 ttl=57 time=1 ms (DUP!)"))
        self.assertIsNone(p.handle_line("garbage line"))


class FakePopen:
    """A ``ping`` child whose stdout is a pipe the test writes to."""

    instances = []

    def __init__(self, argv, **kw):
        self.argv = argv
        r, w = os.pipe()
        self.stdout = os.fdopen(r, "rb", buffering=0)
        self.w = w
        self.rc = None
        self.terminated = False
        FakePopen.instances.append(self)

    def write(self, text):
        os.write(self.w, text.encode())

    def exit(self, rc=0):
        self.rc = rc
        try:
            os.close(self.w)
        except OSError:
            pass

    def poll(self):
        return self.rc

    def wait(self, timeout=None):
        return self.rc if self.rc is not None else 0

    def terminate(self):
        self.terminated = True
        self.exit(-15)

    def kill(self):
        self.terminate()


class ProcessThreadTests(unittest.TestCase):
    def setUp(self):
        FakePopen.instances = []
        self._backoff = pingbin.RESTART_BACKOFF_MIN_S
        pingbin.RESTART_BACKOFF_MIN_S = 0.05

    def tearDown(self):
        pingbin.RESTART_BACKOFF_MIN_S = self._backoff

    def test_reads_lines_restarts_on_exit_and_stop_terminates(self):
        st = State(1_760_000_000.0, "s")
        out = []
        lock = threading.Lock()

        def emit(s):
            with lock:
                out.append(s)

        t = Target(id=0, key="gw4", role="gateway", addr="10.0.0.1", family=4, kind="icmp", label="gw")
        p = pingbin.PingProcess(t, ["ping", "10.0.0.1"], emit, spawn=FakePopen)
        p.start(st)
        deadline = time.monotonic() + 3
        while not FakePopen.instances and time.monotonic() < deadline:
            time.sleep(0.01)
        child = FakePopen.instances[0]
        child.write("PING 10.0.0.1: 56 data bytes\n64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=1.5 ms\n")
        child.write("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=1.7 ms\n")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with lock:
                if len(out) >= 2:
                    break
            time.sleep(0.01)
        with lock:
            self.assertEqual([s.seq for s in out], [0, 1])
            self.assertEqual(out[1].value, 1700)
            self.assertTrue(all(s.flags & F_FALLBACK for s in out))
        child.exit(1)  # child dies → restart
        deadline = time.monotonic() + 3
        while len(FakePopen.instances) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(FakePopen.instances), 2)
        self.assertEqual(p.restarts, 1)
        p.stop(2.0)
        self.assertTrue(FakePopen.instances[1].terminated)
        self.assertFalse(p.thread.is_alive())
        self.assertEqual(st.collector("pingbin-gw4")["status"], "ok")


class BackendTests(unittest.TestCase):
    def setUp(self):
        FakePopen.instances = []

    def test_sync_starts_and_stops_children(self):
        st = State(1_760_000_000.0, "s")

        class Ctx:
            pass

        ctx = Ctx()
        ctx.state = st
        ctx.cfg = {"timeout_ms": 2000, "late_window_ms": 10000}
        ctx.platform = None
        be = pingbin.PingBackend(ctx, 4, lambda s: None, binary="/sbin/ping", spawn=FakePopen, platform_name="darwin")
        gw = Target(id=0, key="gw4", role="gateway", addr="10.0.0.1", family=4, kind="icmp", label="gw")
        cf = Target(id=2, key="inet4_cf", role="anycast", addr="1.1.1.1", family=4, kind="icmp", label="cf", rate_hz=2)
        v6 = Target(id=4, key="inet6_cf", role="anycast", addr="2606::1", family=6, kind="icmp", label="cf6")
        off = Target(id=5, key="xbox", role="xbox", addr="10.0.0.23", family=4, kind="icmp", label="xbox", enabled=False)
        be.sync([gw, cf, v6, off])
        self.assertEqual(sorted(be.procs), [0, 2])  # v6 and disabled targets are not this backend's
        deadline = time.monotonic() + 3
        while len(FakePopen.instances) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        argvs = sorted(i.argv for i in FakePopen.instances)
        self.assertEqual(argvs, [["/sbin/ping", "-n", "-i", "0.25", "10.0.0.1"], ["/sbin/ping", "-n", "-i", "0.5", "1.1.1.1"]])
        self.assertEqual(be.stats()["processes"], 2)
        cf.enabled = False
        be.sync([gw, cf, v6, off])
        self.assertEqual(sorted(be.procs), [0])
        be.stop(2.0)
        self.assertEqual(be.procs, {})
        self.assertTrue(all(i.terminated for i in FakePopen.instances))
        be.sync([gw])  # after stop: no new children
        self.assertEqual(be.procs, {})


if __name__ == "__main__":
    unittest.main()
