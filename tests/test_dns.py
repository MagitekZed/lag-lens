"""Tests for laglens.probes.dns: query bytes, response parsing, scheduling, timeouts, latest row."""
import argparse
import os
import random
import re
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.probes import dns as dnsmod  # noqa: E402
from laglens.probes.dns import DnsProber, build_query, encode_name, parse_response, random_test_name  # noqa: E402
from laglens.state import F_ERROR, F_LOADTEST, F_LOST, KIND_DNS, State, Target, extra_of  # noqa: E402


# ---------------------------------------------------------------- fakes
class FakeClock:
    def __init__(self, mono=1000.0, wall=1_700_000_000.0):
        self.mono = mono
        self.wall = wall

    def advance(self, s):
        self.mono += s
        self.wall += s


class FakeSocket:
    _next_fd = 100

    def __init__(self, family, type_):
        self.family = family
        self.type = type_
        self.sent = []
        self.inbox = []
        self.closed = False
        self.blocking = True
        FakeSocket._next_fd += 1
        self._fd = FakeSocket._next_fd
        self.send_error = None

    def fileno(self):
        return self._fd

    def setblocking(self, flag):
        self.blocking = flag

    def sendto(self, data, addr):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append((data, addr))
        return len(data)

    def recvfrom(self, n):
        if not self.inbox:
            raise BlockingIOError()
        return self.inbox.pop(0), ("1.1.1.1", 53)

    def close(self):
        self.closed = True


class FakeFactory:
    def __init__(self):
        self.socks = []
        self.send_error = None

    def __call__(self, family, type_):
        s = FakeSocket(family, type_)
        s.send_error = self.send_error
        self.socks.append(s)
        return s


def fake_select(socks, _w, _x, timeout):
    return [s for s in socks if s.inbox], [], []


class FakeStore:
    def __init__(self):
        self.samples = []

    def append_sample(self, s):
        self.samples.append(s)


class FakeCtx:
    def __init__(self, cfg=None, wall=1_700_000_000.0):
        self.cfg = cfg or {"targets": {"dns_names": ["xboxlive.com", "hbomax.com", "cloudflare.com"]}}
        self.args = argparse.Namespace()
        self.state = State(t0=wall, session_id="test")
        self.store = FakeStore()
        self.platform = None
        self.route = {}

    def component(self, name):
        return None


def qname_of(pkt):
    """Decode the QNAME of a query packet."""
    i = 12
    labels = []
    while True:
        n = pkt[i]
        i += 1
        if n == 0:
            break
        labels.append(pkt[i:i + n].decode())
        i += n
    qtype, qclass = struct.unpack(">HH", pkt[i:i + 4])
    return ".".join(labels), qtype, qclass


def make_response(query, rcode=0, tc=False, ancount=1):
    qid = struct.unpack(">H", query[:2])[0]
    flags = 0x8180 | (rcode & 0xF) | (0x0200 if tc else 0)
    return struct.pack(">HHHHHH", qid, flags, 1, ancount, 0, 0) + query[12:]


def prober(ctx, clock, names=None):
    p = DnsProber(ctx, sock_factory=FakeFactory(), select_fn=fake_select, clock=lambda: clock.mono,
                  wall=lambda: clock.wall, getaddrinfo=lambda *a, **k: [], rng=random.Random(7))
    return p


def add_dns_target(state, key="dns_cf4", addr="1.1.1.1", family=4, enabled=True, reason=None):
    t = Target(id=-1, key=key, role="dns", addr=addr, family=family, kind="dns", label=key, rate_hz=1 / 3.0, port=53,
               enabled=enabled, reason=reason)
    return state.add_target(t)


# ---------------------------------------------------------------- wire format
class WireTests(unittest.TestCase):
    def test_encode_name(self):
        self.assertEqual(encode_name("xboxlive.com"), b"\x08xboxlive\x03com\x00")
        self.assertEqual(encode_name("a.b."), b"\x01a\x01b\x00")

    def test_build_query_layout(self):
        pkt = build_query(0x1234, "cloudflare.com", dnsmod.QTYPE_A)
        self.assertEqual(pkt[:12], struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(qname_of(pkt), ("cloudflare.com", 1, 1))
        pkt6 = build_query(1, "cloudflare.com", dnsmod.QTYPE_AAAA)
        self.assertEqual(qname_of(pkt6), ("cloudflare.com", 28, 1))

    def test_parse_response_fields(self):
        q = build_query(0xBEEF, "x.example", 1)
        r = parse_response(make_response(q, rcode=3, tc=True, ancount=0))
        self.assertEqual(r["id"], 0xBEEF)
        self.assertEqual(r["qr"], 1)
        self.assertEqual(r["tc"], 1)
        self.assertEqual(r["rcode"], 3)
        self.assertEqual(r["ancount"], 0)
        self.assertIsNone(parse_response(b"short"))

    def test_random_test_name(self):
        n = random_test_name(random.Random(1))
        self.assertRegex(n, r"^[0-9a-f]{8}\.laglens-test\.example\.com$")
        self.assertNotEqual(n, random_test_name(random.Random(2)))


# ---------------------------------------------------------------- prober
class DnsProberTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.ctx = FakeCtx(wall=self.clock.wall)
        self.state = self.ctx.state
        self.t = add_dns_target(self.state)
        self.p = prober(self.ctx, self.clock)

    def socks(self):
        return self.p.sock_factory.socks

    def test_first_query_sent_immediately_with_a_type(self):
        self.p.step()
        self.assertEqual(len(self.socks()), 1)
        s = self.socks()[0]
        self.assertFalse(s.blocking)
        self.assertEqual(s.family, socket.AF_INET)
        pkt, addr = s.sent[0]
        self.assertEqual(addr, ("1.1.1.1", 53))
        self.assertEqual(qname_of(pkt), ("xboxlive.com", dnsmod.QTYPE_A, 1))

    def test_reply_makes_received_sample_with_rcode_and_latest(self):
        self.p.step()
        s = self.socks()[0]
        pkt = s.sent[0][0]
        self.clock.advance(0.0123)
        s.inbox.append(make_response(pkt, rcode=0))
        self.p.step()
        self.assertEqual(len(self.ctx.store.samples), 1)
        smp = self.ctx.store.samples[0]
        self.assertEqual(smp.kind, KIND_DNS)
        self.assertEqual(smp.target_id, self.t.id)
        self.assertTrue(smp.received)
        self.assertAlmostEqual(smp.value, 12300, delta=2)
        self.assertEqual(extra_of(smp.flags), 0)
        self.assertEqual(smp.seq, 1)
        self.assertTrue(s.closed)
        row = self.state.latest("dns")
        self.assertAlmostEqual(row["dns_cf4"]["rtt_ms"], 12.3, places=1)
        self.assertEqual(row["dns_cf4"]["rcode"], 0)
        self.assertTrue(row["dns_cf4"]["ok"])
        self.assertIn("sys_ms", row)
        self.assertIn("t", row)
        # the same sample reached the state ring
        self.assertEqual(len(self.state.raw_window(self.t.id, 0, self.clock.wall + 10)), 1)

    def test_nxdomain_rcode_in_extra_bits(self):
        self.p.step()
        s = self.socks()[0]
        s.inbox.append(make_response(s.sent[0][0], rcode=3))
        self.p.step()
        smp = self.ctx.store.samples[0]
        self.assertTrue(smp.received)
        self.assertEqual(extra_of(smp.flags), 3)
        self.assertEqual(self.state.latest("dns")["dns_cf4"]["rcode"], 3)

    def test_truncated_reply_is_error(self):
        self.p.step()
        s = self.socks()[0]
        s.inbox.append(make_response(s.sent[0][0], rcode=0, tc=True))
        self.p.step()
        smp = self.ctx.store.samples[0]
        self.assertTrue(smp.flags & F_ERROR)
        self.assertFalse(self.state.latest("dns")["dns_cf4"]["ok"])

    def test_wrong_id_reply_is_ignored_and_then_timeout(self):
        self.p.step()
        s = self.socks()[0]
        other = build_query(0xFFFF, "xboxlive.com", 1)
        s.inbox.append(make_response(other))
        self.p.step()
        self.assertEqual(self.ctx.store.samples, [])
        self.clock.advance(3.0)
        self.p.step()
        smp = self.ctx.store.samples[0]
        self.assertTrue(smp.lost)
        self.assertEqual(smp.value, -1)
        self.assertTrue(s.closed)

    def test_schedule_one_query_per_three_seconds(self):
        self.p.step()
        self.clock.advance(1.0)
        self.p.step()
        self.assertEqual(len(self.socks()), 1)
        self.clock.advance(2.0)
        self.p.step()
        self.assertEqual(len(self.socks()), 2)

    def test_qtype_alternates_and_tenth_query_forces_recursion(self):
        names = []
        types = []
        for i in range(10):
            self.p.step()
            s = self.socks()[-1]
            n, qt, _ = qname_of(s.sent[0][0])
            names.append(n)
            types.append(qt)
            s.inbox.append(make_response(s.sent[0][0]))
            self.p.step()
            self.clock.advance(3.0)
        self.assertEqual(types, [1, 28] * 5)
        self.assertEqual(names[:3], ["xboxlive.com", "hbomax.com", "cloudflare.com"])
        self.assertRegex(names[9], r"^[0-9a-f]{8}\.laglens-test\.example\.com$")
        for n in names[:9]:
            self.assertNotIn("laglens-test", n)

    def test_five_timeouts_mark_unreachable_then_recover(self):
        for i in range(5):
            self.p.step()
            self.clock.advance(3.0)
            self.p.step()  # expires the pending query and sends the next one
        lost = [s for s in self.ctx.store.samples if s.lost]
        self.assertEqual(len(lost), 5)
        self.assertEqual(self.state.target("dns_cf4").reason, "unreachable")
        self.assertTrue(self.state.target("dns_cf4").enabled)
        notes = self.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["dns_fail"])
        self.assertEqual(notes[0]["target"], self.t.id)
        # still probing: the 6th query is pending; answer it
        s = self.socks()[-1]
        s.inbox.append(make_response(s.sent[0][0]))
        self.p.step()
        self.assertIsNone(self.state.target("dns_cf4").reason)
        self.assertEqual(self.state.drain_notes(), [])

    def test_disabled_or_unresolved_targets_are_skipped(self):
        add_dns_target(self.state, key="dns_gw", addr=None, enabled=False, reason="no resolver found")
        add_dns_target(self.state, key="dns_x", addr="10.0.0.9", enabled=False, reason="off")
        self.p.step()
        self.clock.advance(3.0)
        self.p.step()
        keys = {self.state.target_by_id(s.target_id).key for s in self.ctx.store.samples}
        for s in self.socks():
            self.assertEqual(s.sent[0][1][0], "1.1.1.1")
        self.assertTrue(keys <= {"dns_cf4"})

    def test_ipv6_resolver_uses_inet6_socket(self):
        add_dns_target(self.state, key="dns_cf6", addr="2606:4700:4700::1111", family=6)
        self.p.step()
        self.clock.advance(3.0)
        self.p.step()
        fams = {s.family for s in self.socks()}
        self.assertEqual(fams, {socket.AF_INET, socket.AF_INET6})
        s6 = [s for s in self.socks() if s.family == socket.AF_INET6][0]
        self.assertEqual(s6.sent[0][1], ("2606:4700:4700::1111", 53, 0, 0))

    def test_staggered_start_for_several_targets(self):
        add_dns_target(self.state, key="dns_gw", addr="10.0.0.1")
        self.p.step()
        self.assertEqual(len(self.socks()), 1)
        self.clock.advance(1.5)
        self.p.step()
        self.assertEqual(len(self.socks()), 2)

    def test_send_error_is_error_sample(self):
        self.p.sock_factory.send_error = OSError(65, "No route to host")
        self.p.step()
        smp = self.ctx.store.samples[0]
        self.assertTrue(smp.flags & F_ERROR)
        self.assertEqual(smp.value, 65)
        self.assertFalse(self.state.latest("dns")["dns_cf4"]["ok"])

    def test_loadtest_flag(self):
        self.state.loadtest["running"] = True
        self.p.step()
        s = self.socks()[0]
        s.inbox.append(make_response(s.sent[0][0]))
        self.p.step()
        self.assertTrue(self.ctx.store.samples[0].flags & F_LOADTEST)

    def test_system_resolver_timing(self):
        calls = []

        def gai(name, port):
            calls.append(name)
            self.clock.advance(0.004)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]

        self.p.getaddrinfo = gai
        ms = self.p.measure_system_resolver()
        self.assertEqual(calls, ["xboxlive.com"])
        self.assertAlmostEqual(ms, 4.0, places=1)
        self.assertAlmostEqual(self.state.latest("dns")["sys_ms"], 4.0, places=1)
        self.assertTrue(self.state.latest("dns")["sys_ok"])

        def bad(name, port):
            raise socket.gaierror(8, "nodename nor servname provided")

        self.p.getaddrinfo = bad
        self.assertIsNone(self.p.measure_system_resolver())
        self.assertIsNone(self.state.latest("dns")["sys_ms"])
        self.assertFalse(self.state.latest("dns")["sys_ok"])

    def test_start_and_stop_threads(self):
        p = DnsProber(self.ctx, sock_factory=FakeFactory(), select_fn=fake_select,
                      getaddrinfo=lambda *a, **k: [])
        p.start()
        self.assertTrue(p.thread.is_alive())
        self.state.stop_event.set()
        p.stop(timeout=3.0)
        self.assertFalse(p.thread.is_alive())
        self.assertFalse(p.sys_thread.is_alive())
        self.assertEqual(self.state.collector("dns")["status"], "ok")
        self.assertEqual(self.state.collector("dns_sys")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
