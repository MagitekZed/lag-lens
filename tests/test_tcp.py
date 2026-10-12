"""Tests for laglens.probes.tcp: connect timing, refused/timeout, backoff, re-resolution."""
import argparse
import errno
import os
import selectors
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.probes import tcp as tcpmod  # noqa: E402
from laglens.probes.tcp import TcpProber  # noqa: E402
from laglens.state import F_ERROR, F_LOADTEST, F_LOST, KIND_TCP, State, Target  # noqa: E402


# ---------------------------------------------------------------- fakes
class FakeClock:
    def __init__(self, mono=5000.0, wall=1_700_000_000.0):
        self.mono = mono
        self.wall = wall

    def advance(self, s):
        self.mono += s
        self.wall += s


class FakeSock:
    _next_fd = 300

    def __init__(self, family, type_):
        self.family = family
        self.type = type_
        self.blocking = True
        self.connect_rc = errno.EINPROGRESS
        self.connect_exc = None
        self.so_error = 0
        self.ready = False
        self.addr = None
        self.linger = None
        self.closed = False
        FakeSock._next_fd += 1
        self._fd = FakeSock._next_fd

    def fileno(self):
        return self._fd

    def setblocking(self, flag):
        self.blocking = flag

    def connect_ex(self, addr):
        self.addr = addr
        if self.connect_exc is not None:
            raise self.connect_exc
        return self.connect_rc

    def getsockopt(self, level, opt):
        assert (level, opt) == (socket.SOL_SOCKET, socket.SO_ERROR)
        return self.so_error

    def setsockopt(self, level, opt, value):
        if (level, opt) == (socket.SOL_SOCKET, socket.SO_LINGER):
            self.linger = value

    def close(self):
        self.closed = True


class FakeFactory:
    def __init__(self):
        self.socks = []
        self.script = []  # callables applied to each new socket

    def __call__(self, family, type_):
        s = FakeSock(family, type_)
        if self.script:
            self.script.pop(0)(s)
        self.socks.append(s)
        return s


class FakeKey:
    def __init__(self, fileobj):
        self.fileobj = fileobj


class FakeSelector:
    def __init__(self):
        self.registered = {}
        self.closed = False

    def register(self, sock, events):
        assert events == selectors.EVENT_WRITE
        self.registered[sock.fileno()] = sock

    def unregister(self, sock):
        del self.registered[sock.fileno()]

    def select(self, timeout):
        return [(FakeKey(s), selectors.EVENT_WRITE) for s in list(self.registered.values()) if s.ready]

    def close(self):
        self.closed = True


class FakeStore:
    def __init__(self):
        self.samples = []

    def append_sample(self, s):
        self.samples.append(s)


class FakeCtx:
    def __init__(self, wall):
        self.cfg = {}
        self.args = argparse.Namespace()
        self.state = State(t0=wall, session_id="test")
        self.store = FakeStore()
        self.platform = None
        self.route = {}


def add_tcp(state, key, addr, family=4, port=443, extra=None, enabled=True, reason=None):
    t = Target(id=-1, key=key, role="tcp", addr=addr, family=family, kind="tcp", label=key, rate_hz=0.5, port=port,
               extra=extra or {}, enabled=enabled, reason=reason)
    return state.add_target(t)


class TcpProberTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.ctx = FakeCtx(self.clock.wall)
        self.state = self.ctx.state
        self.t = add_tcp(self.state, "tcp_cf4", "1.1.1.1")
        self.factory = FakeFactory()
        self.sel = FakeSelector()
        self.gai_calls = []
        self.gai_result = {}

        def gai(name, port, family, type_):
            self.gai_calls.append((name, family))
            res = self.gai_result.get((name, family))
            if res is None:
                raise socket.gaierror(8, "no such host")
            return [(family, type_, 6, "", (res, 0))]

        self.p = TcpProber(self.ctx, sock_factory=self.factory, selector_factory=lambda: self.sel,
                           clock=lambda: self.clock.mono, wall=lambda: self.clock.wall, getaddrinfo=gai)

    def samples(self):
        return self.ctx.store.samples

    # ------------------------------------------------------------ outcomes
    def test_successful_connect_times_handshake_and_rst_closes(self):
        self.p.step()
        self.assertEqual(len(self.factory.socks), 1)
        s = self.factory.socks[0]
        self.assertFalse(s.blocking)
        self.assertEqual(s.addr, ("1.1.1.1", 443))
        self.assertIn(s.fileno(), self.sel.registered)
        self.clock.advance(0.0215)
        s.ready = True
        self.p.step()
        self.assertEqual(len(self.samples()), 1)
        smp = self.samples()[0]
        self.assertEqual(smp.kind, KIND_TCP)
        self.assertEqual(smp.target_id, self.t.id)
        self.assertTrue(smp.received)
        self.assertAlmostEqual(smp.value, 21500, delta=2)
        self.assertEqual(s.linger, struct.pack("ii", 1, 0))
        self.assertTrue(s.closed)
        self.assertNotIn(s.fileno(), self.sel.registered)
        self.assertEqual(len(self.state.raw_window(self.t.id, 0, self.clock.wall + 10)), 1)

    def test_refused_is_error_with_errno(self):
        self.p.step()
        s = self.factory.socks[0]
        s.so_error = errno.ECONNREFUSED
        s.ready = True
        self.p.step()
        smp = self.samples()[0]
        self.assertTrue(smp.flags & F_ERROR)
        self.assertEqual(smp.value, errno.ECONNREFUSED)
        self.assertTrue(s.closed)
        self.assertIsNone(s.linger)

    def test_timeout_is_lost(self):
        self.p.step()
        s = self.factory.socks[0]
        self.clock.advance(2.9)
        self.p.step()
        self.assertEqual(self.samples(), [])
        self.clock.advance(0.2)
        self.p.step()
        smp = self.samples()[0]
        self.assertTrue(smp.lost)
        self.assertEqual(smp.value, -1)
        self.assertTrue(s.closed)
        self.assertNotIn(s.fileno(), self.sel.registered)

    def test_immediate_connect_error_is_error_sample(self):
        self.factory.script.append(lambda s: setattr(s, "connect_rc", errno.EHOSTUNREACH))
        self.p.step()
        smp = self.samples()[0]
        self.assertTrue(smp.flags & F_ERROR)
        self.assertEqual(smp.value, errno.EHOSTUNREACH)
        self.assertTrue(self.factory.socks[0].closed)

    def test_connect_ex_exception_is_error_sample(self):
        self.factory.script.append(lambda s: setattr(s, "connect_exc", OSError(errno.ENETUNREACH, "unreachable")))
        self.p.step()
        smp = self.samples()[0]
        self.assertTrue(smp.flags & F_ERROR)
        self.assertEqual(smp.value, errno.ENETUNREACH)

    def test_immediate_success_rc_zero(self):
        self.factory.script.append(lambda s: setattr(s, "connect_rc", 0))
        self.p.step()
        smp = self.samples()[0]
        self.assertTrue(smp.received)
        self.assertEqual(self.factory.socks[0].linger, tcpmod.LINGER_RST)

    # ------------------------------------------------------------ schedule
    def test_one_connect_per_two_seconds_and_no_overlap(self):
        self.p.step()
        self.clock.advance(1.0)
        self.p.step()
        self.assertEqual(len(self.factory.socks), 1)
        self.clock.advance(1.0)
        self.p.step()  # due again but the first connect is still in flight (no overlap)
        self.assertEqual(len(self.factory.socks), 1)
        self.clock.advance(1.0)
        self.p.step()  # 3 s: first times out; next due at t=4
        self.assertEqual(len(self.factory.socks), 1)
        self.clock.advance(1.0)
        self.p.step()
        self.assertEqual(len(self.factory.socks), 2)

    def test_staggered_start(self):
        add_tcp(self.state, "tcp_gw", "10.0.0.1", port=80)
        self.p.step()
        self.assertEqual(len(self.factory.socks), 1)
        self.clock.advance(1.0)
        self.p.step()
        self.assertEqual(len(self.factory.socks), 2)
        self.assertEqual(self.factory.socks[1].addr, ("10.0.0.1", 80))

    def test_ipv6_address_tuple(self):
        self.state.set_target_state("tcp_cf4", enabled=False)
        add_tcp(self.state, "tcp_cf6", "2606:4700:4700::1111", family=6)
        self.p.step()
        self.clock.advance(1.0)  # second target is staggered by half the interval
        self.p.step()
        s = self.factory.socks[0]
        self.assertEqual(s.family, socket.AF_INET6)
        self.assertEqual(s.addr, ("2606:4700:4700::1111", 443, 0, 0))

    def test_disabled_and_unresolved_targets_are_skipped(self):
        add_tcp(self.state, "tcp_xbl_auth4", None, extra={"name": "xsts.auth.xboxlive.com"}, enabled=False,
                reason="cannot resolve")
        add_tcp(self.state, "tcp_off", "9.9.9.9", enabled=False, reason="off")
        for _ in range(4):
            self.p.step()
            self.clock.advance(1.0)
        self.assertTrue(all(s.addr[0] == "1.1.1.1" for s in self.factory.socks))

    def test_backoff_after_five_refusals_and_recovery(self):
        for i in range(5):
            self.p.step()
            s = self.factory.socks[-1]
            s.so_error = errno.ECONNREFUSED
            s.ready = True
            self.p.step()
            self.clock.advance(2.0)
        self.assertEqual(sum(1 for x in self.samples() if x.flags & F_ERROR), 5)
        self.assertEqual(self.state.target("tcp_cf4").reason, "connection refused")
        self.assertTrue(self.state.target("tcp_cf4").enabled)
        n = len(self.factory.socks)
        # the 6th connect is due now (2 s after the 5th) - it goes out, then the next one waits 30 s
        self.p.step()
        self.assertEqual(len(self.factory.socks), n + 1)
        s = self.factory.socks[-1]
        s.so_error = errno.ECONNREFUSED
        s.ready = True
        self.p.step()
        self.clock.advance(10.0)
        self.p.step()
        self.assertEqual(len(self.factory.socks), n + 1)
        self.clock.advance(20.5)
        self.p.step()
        self.assertEqual(len(self.factory.socks), n + 2)
        s = self.factory.socks[-1]
        s.ready = True
        self.p.step()
        self.assertIsNone(self.state.target("tcp_cf4").reason)
        self.clock.advance(2.0)
        self.p.step()
        self.assertEqual(len(self.factory.socks), n + 3)

    def test_tcp_timeout_note_after_five_timeouts(self):
        for i in range(5):
            self.p.step()
            self.clock.advance(3.0)
            self.p.step()
            self.clock.advance(1.0)
        notes = self.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["tcp_timeout"])
        self.assertEqual(notes[0]["target"], self.t.id)
        self.assertEqual(sum(1 for x in self.samples() if x.lost), 5)

    def test_loadtest_flag(self):
        self.state.loadtest["running"] = True
        self.p.step()
        s = self.factory.socks[0]
        s.ready = True
        self.p.step()
        self.assertTrue(self.samples()[0].flags & F_LOADTEST)

    # ------------------------------------------------------------ resolve
    def test_resolve_updates_address_and_enables(self):
        t4 = add_tcp(self.state, "tcp_xbl_auth4", None, extra={"name": "xsts.auth.xboxlive.com"}, enabled=False,
                     reason="cannot resolve")
        t6 = add_tcp(self.state, "tcp_xbl_auth6", "2a01::1", family=6, extra={"name": "xsts.auth.xboxlive.com"})
        self.gai_result[("xsts.auth.xboxlive.com", socket.AF_INET)] = "20.1.2.3"
        self.gai_result[("xsts.auth.xboxlive.com", socket.AF_INET6)] = "2a01::2"
        out = self.p.resolve_names()
        self.assertEqual(out, {"tcp_xbl_auth4": "20.1.2.3", "tcp_xbl_auth6": "2a01::2"})
        self.assertEqual(self.state.target("tcp_xbl_auth4").addr, "20.1.2.3")
        self.assertTrue(self.state.target("tcp_xbl_auth4").enabled)
        self.assertIsNone(self.state.target("tcp_xbl_auth4").reason)
        self.assertEqual(self.state.target("tcp_xbl_auth6").addr, "2a01::2")
        self.assertEqual(sorted(self.gai_calls), sorted([("xsts.auth.xboxlive.com", socket.AF_INET),
                                                         ("xsts.auth.xboxlive.com", socket.AF_INET6)]))
        self.assertEqual(t4.id, self.state.target("tcp_xbl_auth4").id)
        self.assertEqual(t6.id, self.state.target("tcp_xbl_auth6").id)

    def test_resolve_failure_keeps_last_ip_and_disabled_stays_disabled(self):
        add_tcp(self.state, "tcp_xbl_profile4", "20.9.9.9", extra={"name": "profile.xboxlive.com"})
        add_tcp(self.state, "tcp_live4", None, extra={"name": "login.live.com"}, enabled=False, reason="cannot resolve")
        out = self.p.resolve_names()
        self.assertEqual(out, {"tcp_xbl_profile4": "20.9.9.9", "tcp_live4": None})
        self.assertEqual(self.state.target("tcp_xbl_profile4").addr, "20.9.9.9")
        self.assertTrue(self.state.target("tcp_xbl_profile4").enabled)
        self.assertFalse(self.state.target("tcp_live4").enabled)
        self.assertEqual(self.state.target("tcp_live4").reason, "cannot resolve")

    def test_only_unresolved_mode_skips_resolved_targets(self):
        add_tcp(self.state, "tcp_xbl_profile4", "20.9.9.9", extra={"name": "profile.xboxlive.com"})
        add_tcp(self.state, "tcp_live4", None, extra={"name": "login.live.com"}, enabled=False, reason="cannot resolve")
        self.gai_result[("login.live.com", socket.AF_INET)] = "40.1.1.1"
        self.p.resolve_names(only_unresolved=True)
        self.assertEqual(self.gai_calls, [("login.live.com", socket.AF_INET)])
        self.assertEqual(self.state.target("tcp_live4").addr, "40.1.1.1")
        self.assertTrue(self.state.target("tcp_live4").enabled)

    def test_v4_mapped_answer_is_not_an_aaaa(self):
        from laglens.probes.tcp import REASON_NO_AAAA, is_v4_mapped

        self.assertTrue(is_v4_mapped("::ffff:40.90.8.102"))
        self.assertFalse(is_v4_mapped("2a01::2"))
        self.assertFalse(is_v4_mapped("40.90.8.102"))
        self.assertFalse(is_v4_mapped(None))
        add_tcp(self.state, "tcp_xbl_auth6", "::ffff:40.90.8.102", family=6, extra={"name": "xsts.auth.xboxlive.com"})
        add_tcp(self.state, "tcp_live6", "2a01::9", family=6, extra={"name": "login.live.com"})
        self.gai_result[("xsts.auth.xboxlive.com", socket.AF_INET6)] = "::ffff:40.90.8.102"
        self.gai_result[("login.live.com", socket.AF_INET6)] = "::ffff:20.190.190.130"
        out = self.p.resolve_names()
        self.assertEqual(out, {"tcp_xbl_auth6": None, "tcp_live6": "2a01::9"})
        t = self.state.target("tcp_xbl_auth6")
        self.assertFalse(t.enabled)
        self.assertEqual(t.reason, REASON_NO_AAAA)
        self.assertEqual(t.addr, "::ffff:40.90.8.102")
        # a target that had a real AAAA keeps it on a mapped-only answer
        self.assertTrue(self.state.target("tcp_live6").enabled)
        # a real AAAA later re-enables the disabled one
        self.gai_result[("xsts.auth.xboxlive.com", socket.AF_INET6)] = "2a01::5"
        self.p.resolve_names()
        t = self.state.target("tcp_xbl_auth6")
        self.assertEqual((t.addr, t.enabled, t.reason), ("2a01::5", True, None))

    def test_unchanged_address_does_not_republish(self):
        add_tcp(self.state, "tcp_xbl_profile4", "20.9.9.9", extra={"name": "profile.xboxlive.com"})
        self.gai_result[("profile.xboxlive.com", socket.AF_INET)] = "20.9.9.9"
        seen = []
        self.state.subscribe(lambda name, obj: seen.append(name))
        self.p.resolve_names()
        self.assertEqual(seen, [])

    def test_start_and_stop_threads(self):
        p = TcpProber(self.ctx, sock_factory=FakeFactory(), selector_factory=FakeSelector,
                      getaddrinfo=lambda *a, **k: [])
        p.start()
        self.assertTrue(p.thread.is_alive())
        self.state.stop_event.set()
        p.stop(timeout=3.0)
        self.assertFalse(p.thread.is_alive())
        self.assertFalse(p.resolve_thread.is_alive())
        self.assertEqual(self.state.collector("tcp")["status"], "ok")
        self.assertEqual(self.state.collector("tcp_resolve")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
