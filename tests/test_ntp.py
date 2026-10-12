"""Tests for laglens.probes.ntp: packet format, δ/θ math, direction rules, KoD and silence handling."""
import argparse
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.probes import ntp as ntpmod  # noqa: E402
from laglens.probes.ntp import (  # noqa: E402
    NtpProber, build_packet, combine_direction, delay_offset, direction_for, from_ntp, parse_packet, short_key,
    to_ntp, upstream_share,
)
from laglens.state import F_ERROR, F_LOST, KIND_NTP, State, Target  # noqa: E402


# ---------------------------------------------------------------- fakes
class FakeClock:
    def __init__(self, mono=100.0, wall=1_700_000_000.0):
        self.mono = mono
        self.wall = wall

    def advance(self, s):
        self.mono += s
        self.wall += s


class FakeSocket:
    _next_fd = 500

    def __init__(self, family, type_):
        self.family = family
        self.type = type_
        self.sent = []
        self.inbox = []
        self.closed = False
        FakeSocket._next_fd += 1
        self._fd = FakeSocket._next_fd

    def fileno(self):
        return self._fd

    def setblocking(self, flag):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        return len(data)

    def recvfrom(self, n):
        if not self.inbox:
            raise BlockingIOError()
        return self.inbox.pop(0), ("162.159.200.1", 123)

    def close(self):
        self.closed = True


class FakeFactory:
    def __init__(self):
        self.socks = []

    def __call__(self, family, type_):
        s = FakeSocket(family, type_)
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
    def __init__(self, wall):
        self.cfg = {}
        self.args = argparse.Namespace()
        self.state = State(t0=wall, session_id="test")
        self.store = FakeStore()
        self.platform = None
        self.route = {}


def add_ntp(state, key="ntp_cf", addr="162.159.200.1"):
    return state.add_target(Target(id=-1, key=key, role="ntp", addr=addr, family=4, kind="ntp", label=key,
                                   rate_hz=0.2, port=123, extra={"name": key}))


def server_reply(request, t2, t3, stratum=3, ref_id=b"GPS\x00"):
    """A mode-4 reply echoing the request's transmit as originate."""
    originate = struct.unpack(">Q", request[40:48])[0]
    first = (0 << 6) | (4 << 3) | 4
    head = struct.pack(">BBbb", first, stratum, 6, -20) + b"\x00" * 8 + ref_id
    return head + struct.pack(">QQQQ", to_ntp(t2 - 1), originate, to_ntp(t2), to_ntp(t3))


# ---------------------------------------------------------------- pure helpers
class FormatTests(unittest.TestCase):
    def test_ntp_timestamp_roundtrip(self):
        for t in (0.0, 1_700_000_000.123456, 1_700_000_000.999999):
            self.assertAlmostEqual(from_ntp(to_ntp(t)), t, places=6)
        self.assertEqual(to_ntp(0.0) >> 32, ntpmod.NTP_EPOCH_OFFSET)

    def test_build_packet_layout(self):
        pkt = build_packet(0x1122334455667788)
        self.assertEqual(len(pkt), 48)
        self.assertEqual(pkt[0], 0x23)  # LI 0, VN 4, mode 3
        self.assertEqual(pkt[1:40], b"\x00" * 39)
        self.assertEqual(pkt[40:48], bytes.fromhex("1122334455667788"))

    def test_parse_packet(self):
        req = build_packet(to_ntp(1_700_000_000.5))
        rep = server_reply(req, 1_700_000_000.51, 1_700_000_000.511, stratum=2)
        p = parse_packet(rep)
        self.assertEqual(p["mode"], 4)
        self.assertEqual(p["vn"], 4)
        self.assertEqual(p["stratum"], 2)
        self.assertEqual(p["originate"], to_ntp(1_700_000_000.5))
        self.assertAlmostEqual(from_ntp(p["receive"]), 1_700_000_000.51, places=5)
        self.assertEqual(p["ref_id"], b"GPS\x00")
        self.assertIsNone(parse_packet(rep[:47]))

    def test_delay_offset_math(self):
        d, o = delay_offset(100.0, 100.010, 100.011, 100.020)
        self.assertAlmostEqual(d, 0.019, places=9)
        self.assertAlmostEqual(o, 0.0005, places=9)
        # upstream-only extra delay of 40 ms: offset grows by 20 ms, delay by 40 ms
        d2, o2 = delay_offset(100.0, 100.050, 100.051, 100.060)
        self.assertAlmostEqual(d2 - d, 0.040, places=9)
        self.assertAlmostEqual(o2 - o, 0.020, places=9)
        # downstream-only extra delay of 40 ms: offset shrinks by 20 ms
        d3, o3 = delay_offset(100.0, 100.010, 100.011, 100.060)
        self.assertAlmostEqual(d3 - d, 0.040, places=9)
        self.assertAlmostEqual(o3 - o, -0.020, places=9)

    def test_upstream_share_rules(self):
        self.assertIsNone(upstream_share(10.0, 19.9))
        self.assertIsNone(upstream_share(None, 50.0))
        self.assertAlmostEqual(upstream_share(20.0, 40.0), 1.0)
        self.assertAlmostEqual(upstream_share(-20.0, 40.0), 0.0)
        self.assertAlmostEqual(upstream_share(0.0, 40.0), 0.5)
        self.assertAlmostEqual(upstream_share(60.0, 40.0), 1.0)  # clamped

    def test_direction_rules(self):
        self.assertEqual(direction_for(None), "n/a")
        self.assertEqual(direction_for(0.7), "upstream")
        self.assertEqual(direction_for(0.3), "downstream")
        self.assertEqual(direction_for(0.5), "symmetric")
        self.assertEqual(combine_direction({}), ("n/a", None))
        self.assertEqual(combine_direction({"a": None, "b": None}), ("n/a", None))
        self.assertEqual(combine_direction({"a": 0.9, "b": None}), ("upstream", 0.9))
        self.assertEqual(combine_direction({"a": 0.9, "b": 0.8}), ("upstream", 0.85))
        self.assertEqual(combine_direction({"a": 0.9, "b": 0.6}), ("mixed", 0.75))
        self.assertEqual(combine_direction({"a": 0.2, "b": 0.3}), ("downstream", 0.25))

    def test_short_key(self):
        self.assertEqual(short_key("ntp_cf"), "cf")
        self.assertEqual(short_key("ntp_g"), "g")
        self.assertEqual(short_key("other"), "other")


# ---------------------------------------------------------------- prober
class NtpProberTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.ctx = FakeCtx(self.clock.wall)
        self.state = self.ctx.state
        self.cf = add_ntp(self.state, "ntp_cf", "162.159.200.1")
        self.factory = FakeFactory()
        self.p = NtpProber(self.ctx, sock_factory=self.factory, select_fn=fake_select,
                           clock=lambda: self.clock.mono, wall=lambda: self.clock.wall)

    def sock(self):
        return self.factory.socks[0]

    def exchange(self, server_offset_s=0.0, up_s=0.010, down_s=0.010, proc_s=0.001, stratum=3, target_addr=None):
        """Send the due query, synthesize the reply and read it.

        ``up_s``/``down_s`` are the one-way delays; ``server_offset_s`` the
        server clock minus ours.
        """
        before = len(self.factory.socks[0].sent) if self.factory.socks else 0
        self.p.step()
        sent = [x for x in self.sock().sent[before:] if target_addr is None or x[1][0] == target_addr]
        self.assertEqual(len(sent), 1, "expected exactly one query")
        req = sent[0][0]
        t1 = from_ntp(struct.unpack(">Q", req[40:48])[0])
        t2 = t1 + up_s + server_offset_s
        t3 = t2 + proc_s
        self.clock.advance(up_s + proc_s + down_s)
        self.sock().inbox.append(server_reply(req, t2, t3, stratum=stratum))
        self.p.step()
        return self.ctx.store.samples[-1]

    def test_request_packet_and_destination(self):
        self.p.step()
        pkt, addr = self.sock().sent[0]
        self.assertEqual(addr, ("162.159.200.1", 123))
        self.assertEqual(len(pkt), 48)
        self.assertEqual(pkt[0], 0x23)
        self.assertAlmostEqual(from_ntp(struct.unpack(">Q", pkt[40:48])[0]), self.clock.wall, places=5)
        self.assertEqual(self.sock().family, socket.AF_INET)

    def test_reply_gives_delay_sample_and_latest_row(self):
        smp = self.exchange(server_offset_s=0.5, up_s=0.010, down_s=0.010, proc_s=0.001)
        self.assertEqual(smp.kind, KIND_NTP)
        self.assertEqual(smp.target_id, self.cf.id)
        self.assertTrue(smp.received)
        self.assertAlmostEqual(smp.value, 20000, delta=20)  # δ = 21 ms rtt − 1 ms processing
        row = self.state.latest("ntp")
        self.assertAlmostEqual(row["cf"]["rtt"], 20.0, delta=0.05)
        self.assertAlmostEqual(row["cf"]["offset"], 500.0, delta=0.05)
        self.assertIsNone(row["cf"]["d_rtt"])  # no baseline yet
        self.assertEqual(row["cf"]["direction"], "n/a")
        self.assertEqual(row["direction"], "n/a")
        self.assertIsNone(row["share"])
        self.assertIn("t", row)
        self.assertEqual(len(self.state.raw_window(self.cf.id, 0, self.clock.wall + 10)), 1)

    def test_timeout_is_lost_and_unmatched_reply_ignored(self):
        self.p.step()
        req = self.sock().sent[0][0]
        bogus = bytearray(server_reply(req, self.clock.wall, self.clock.wall))
        bogus[24:32] = b"\x00" * 8  # originate does not match
        self.sock().inbox.append(bytes(bogus))
        self.p.step()
        self.assertEqual(self.ctx.store.samples, [])
        self.clock.advance(2.1)
        self.p.step()
        smp = self.ctx.store.samples[0]
        self.assertTrue(smp.lost)
        self.assertEqual(smp.value, -1)

    def test_one_query_per_five_seconds(self):
        self.p.step()
        self.clock.advance(4.0)
        self.p.step()
        self.assertEqual(len(self.sock().sent), 1)
        self.clock.advance(1.0)
        self.p.step()
        self.assertEqual(len(self.sock().sent), 2)

    def test_baseline_then_upstream_direction(self):
        for _ in range(4):
            self.exchange(up_s=0.010, down_s=0.010)
            self.clock.advance(5.0)
        row = self.state.latest("ntp")
        self.assertAlmostEqual(row["cf"]["d_rtt"], 0.0, delta=0.05)
        self.assertEqual(row["cf"]["direction"], "n/a")  # ΔRTT below 20 ms
        # an extra 40 ms on the way UP only
        self.exchange(up_s=0.050, down_s=0.010)
        row = self.state.latest("ntp")
        self.assertAlmostEqual(row["cf"]["d_rtt"], 40.0, delta=0.1)
        self.assertAlmostEqual(row["cf"]["d_offset"], 20.0, delta=0.1)
        self.assertAlmostEqual(row["cf"]["share"], 1.0, delta=0.01)
        self.assertEqual(row["cf"]["direction"], "upstream")
        self.assertEqual(row["direction"], "upstream")
        self.clock.advance(5.0)
        # an extra 40 ms on the way DOWN only
        self.exchange(up_s=0.010, down_s=0.050)
        row = self.state.latest("ntp")
        self.assertAlmostEqual(row["cf"]["share"], 0.0, delta=0.01)
        self.assertEqual(row["cf"]["direction"], "downstream")
        self.clock.advance(5.0)
        # 20 ms each way → symmetric
        self.exchange(up_s=0.030, down_s=0.030)
        row = self.state.latest("ntp")
        self.assertAlmostEqual(row["cf"]["share"], 0.5, delta=0.02)
        self.assertEqual(row["cf"]["direction"], "symmetric")

    def test_two_servers_disagree_is_mixed(self):
        g = add_ntp(self.state, "ntp_g", "216.239.35.0")
        # both servers start in the same instant; answer each in turn
        for _ in range(4):
            self.p.step()
            reqs = self.sock().sent[-2:] if len(self.sock().sent) >= 2 else self.sock().sent[-1:]
            for req, addr in reqs:
                t1 = from_ntp(struct.unpack(">Q", req[40:48])[0])
                self.sock().inbox.append(server_reply(req, t1 + 0.010, t1 + 0.011))
            self.clock.advance(0.021)
            self.p.step()
            self.clock.advance(5.0)
        self.p.step()
        reqs = {addr[0]: req for req, addr in self.sock().sent[-2:]}
        self.assertEqual(set(reqs), {"162.159.200.1", "216.239.35.0"})
        t1 = from_ntp(struct.unpack(">Q", reqs["162.159.200.1"][40:48])[0])
        # cf: +40 ms upstream; g: +40 ms downstream
        self.sock().inbox.append(server_reply(reqs["162.159.200.1"], t1 + 0.050, t1 + 0.051))
        self.sock().inbox.append(server_reply(reqs["216.239.35.0"], t1 + 0.010, t1 + 0.011))
        self.clock.advance(0.061)
        self.p.step()
        row = self.state.latest("ntp")
        self.assertEqual(row["cf"]["direction"], "upstream")
        self.assertEqual(row["g"]["direction"], "downstream")
        self.assertEqual(row["direction"], "mixed")
        self.assertEqual(g.id, self.state.target("ntp_g").id)

    def test_kiss_of_death_marks_unreliable_and_backs_off(self):
        self.p.step()
        req = self.sock().sent[0][0]
        rep = server_reply(req, self.clock.wall, self.clock.wall, stratum=0, ref_id=b"RATE")
        self.sock().inbox.append(rep)
        self.p.step()
        smp = self.ctx.store.samples[0]
        self.assertTrue(smp.flags & F_ERROR)
        t = self.state.target("ntp_cf")
        self.assertTrue(t.enabled)
        self.assertIn("unreliable", t.reason)
        self.assertIn("RATE", t.reason)
        self.assertEqual(self.state.drain_notes(), [])
        self.clock.advance(10.0)
        self.p.step()
        self.assertEqual(len(self.sock().sent), 1)  # backed off to 1/60 s
        self.clock.advance(51.0)
        self.p.step()
        self.assertEqual(len(self.sock().sent), 2)
        # a good reply clears the reason
        req = self.sock().sent[1][0]
        t1 = from_ntp(struct.unpack(">Q", req[40:48])[0])
        self.sock().inbox.append(server_reply(req, t1 + 0.01, t1 + 0.011))
        self.clock.advance(0.02)
        self.p.step()
        self.assertIsNone(self.state.target("ntp_cf").reason)

    def test_five_minutes_of_loss_marks_unreliable(self):
        for _ in range(60):
            self.p.step()
            self.clock.advance(5.0)
        self.assertIsNone(self.state.target("ntp_cf").reason)
        self.clock.advance(1.0)
        self.p.step()
        self.assertIn("unreliable", self.state.target("ntp_cf").reason)
        lost = [s for s in self.ctx.store.samples if s.flags & F_LOST]
        self.assertGreaterEqual(len(lost), 59)
        self.assertEqual(self.state.drain_notes(), [])
        # then it answers → reason cleared
        req = self.sock().sent[-1][0]
        t1 = from_ntp(struct.unpack(">Q", req[40:48])[0])
        self.sock().inbox.append(server_reply(req, t1 + 0.01, t1 + 0.011))
        self.clock.advance(0.02)
        self.p.step()
        self.assertIsNone(self.state.target("ntp_cf").reason)

    def test_unique_transmit_values_in_the_same_instant(self):
        add_ntp(self.state, "ntp_g", "216.239.35.0")
        self.p._ensure_states(self.p._ntp_targets(), self.clock.mono)
        for ts in self.p._targets.values():
            ts.next_due = self.clock.mono
        self.p.step()
        txs = [struct.unpack(">Q", r[40:48])[0] for r, _ in self.sock().sent]
        self.assertEqual(len(txs), 2)
        self.assertNotEqual(txs[0], txs[1])
        self.assertEqual(len(self.p._pending), 2)

    def test_start_and_stop_thread(self):
        p = NtpProber(self.ctx, sock_factory=FakeFactory(), select_fn=fake_select)
        p.start()
        self.assertTrue(p.thread.is_alive())
        self.state.stop_event.set()
        p.stop(timeout=3.0)
        self.assertFalse(p.thread.is_alive())
        self.assertEqual(self.state.collector("ntp")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
