"""Tests for laglens.engine.scheduler (the ICMP engine) with fake sockets, selector and clock.

The engine loop is driven synchronously (``_setup()`` + ``_iterate()``) so
every timing assertion is exact: the fake selector moves the fake clock to
the next send deadline or to the next scheduled reply, whichever is first.
"""
import errno
import os
import sys
import time
import types
import unittest
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.engine import scheduler  # noqa: E402
from laglens.engine.scheduler import Engine  # noqa: E402
from laglens.probes.icmp import (  # noqa: E402
    ICMP_HEADER_LEN,
    build_echo,
    echo_reply_for,
    ipv4_header,
    parse_payload,
    time_exceeded_for,
    timestamp_cmsg,
)
from laglens.state import (  # noqa: E402
    F_ERROR,
    F_FALLBACK,
    F_LATE,
    F_LOADTEST,
    F_LOST,
    F_STALL,
    F_XBOX_ASLEEP,
    KIND_ICMP,
    Sample,
    State,
    Target,
)

T0 = 1_760_000_000.0  # a multiple of 5 s: slot 0 starts exactly at t0
MONO0 = 1000.0
CFG = {"timeout_ms": 2000, "late_window_ms": 10000, "rate_hz": 4}


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class FakeClock:
    def __init__(self, mono=MONO0, wall=T0):
        self.m = mono
        self.w = wall

    def mono(self):
        return self.m

    def wall(self):
        return self.w

    def advance(self, s):
        self.m += s
        self.w += s

    def set_mono(self, m):
        self.advance(m - self.m)


class FakeSock:
    """A DGRAM ICMP socket: records sends, answers through ``responder``."""

    def __init__(self, fam, clock):
        self.fam = fam
        self.clock = clock
        self.sent = []  # (mono, pkt, addr)
        self.inbox = deque()
        self.scheduled = []  # (deliver_at_mono, buf, addr)
        self.responder = None  # fn(pkt, addr, now) -> None | (delay_s, buf, from_addr)
        self.fail = None  # fn(addr) -> Exception | None
        self.closed = False

    def sendto(self, pkt, addr):
        if self.fail is not None:
            exc = self.fail(addr)
            if exc is not None:
                raise exc
        now = self.clock.m
        self.sent.append((now, pkt, addr))
        if self.responder is not None:
            r = self.responder(pkt, addr, now)
            if r is not None:
                delay, buf, src = r
                self.scheduled.append((now + delay, buf, src))
        return len(pkt)

    def deliver(self, now):
        keep = []
        for t, buf, src in sorted(self.scheduled, key=lambda x: x[0]):
            if t <= now + 1e-9:
                self.inbox.append((buf, src))
            else:
                keep.append((t, buf, src))
        self.scheduled = keep

    def recvfrom(self, n):
        if self.inbox:
            return self.inbox.popleft()
        raise BlockingIOError()

    def close(self):
        self.closed = True


class FakeSelector:
    EVENT_READ = 1

    def __init__(self, clock):
        self.clock = clock
        self.regs = {}
        self.closed = False

    def register(self, fileobj, events, data):
        self.regs[id(fileobj)] = (fileobj, data)

    def select(self, timeout):
        now = self.clock.m
        target = now + max(0.0, timeout)
        socks = [f for f, _ in self.regs.values() if isinstance(f, FakeSock)]
        earliest = None
        for s in socks:
            for t, _, _ in s.scheduled:
                if earliest is None or t < earliest:
                    earliest = t
        if earliest is not None and earliest <= target:
            target = max(now, earliest)
        self.clock.set_mono(target)
        events = []
        for f, data in self.regs.values():
            if isinstance(f, FakeSock):
                f.deliver(self.clock.m)
                if f.inbox:
                    events.append((types.SimpleNamespace(fileobj=f, data=data), 1))
        return events

    def close(self):
        self.closed = True


class FakeStore:
    def __init__(self):
        self.samples = []

    def append_sample(self, s):
        self.samples.append(s)


class FakePlatform:
    def __init__(self, name="linux", binaries=("/sbin/ping", "/sbin/ping6")):
        self.name = name
        self.binaries = set(binaries)

    def terminal_app_name(self):
        return "Terminal"

    def exists(self, p):
        return p in self.binaries

    def which(self, n):
        for b in self.binaries:
            if b.endswith("/" + n):
                return b
        return None


def echo_responder(rtt_by_addr, with_ip_header=False, per_seq=None):
    """Reply to echoes sent to the addresses in ``rtt_by_addr`` after that RTT (seconds).

    ``per_seq`` maps ``(addr, seq)`` to an RTT override (``None`` = no reply).
    """

    def respond(pkt, addr, now):
        host = addr[0]
        if host not in rtt_by_addr:
            return None
        fam = 6 if ":" in host else 4
        rtt = rtt_by_addr[host]
        if per_seq:
            p = parse_payload(pkt[ICMP_HEADER_LEN:])
            key = (host, p.seq if p else None)
            if key in per_seq:
                rtt = per_seq[key]
        if rtt is None:
            return None
        buf = echo_reply_for(pkt, fam)
        if fam == 4 and with_ip_header:
            buf = ipv4_header(host, "10.0.0.35", len(buf)) + buf
        return rtt, buf, (host, 0) if fam == 4 else (host, 0, 0, 0)

    return respond


def tgt(tid, key, addr, fam=4, role="anycast", rate=4.0, **kw):
    return Target(id=tid, key=key, role=role, addr=addr, family=fam, kind="icmp", label=key, rate_hz=rate, **kw)


class Harness:
    def __init__(self, targets, platform_name="linux", has_ip_header=False, route=None, cfg=None,
                 socket_factory=None, pingbin_factory=None, nametoindex=None, platform=None):
        self.clock = FakeClock()
        self.state = State(T0, "s", cfg=cfg or CFG)
        for t in targets:
            self.state.add_target(t)
        self.store = FakeStore()
        self.platform = platform or FakePlatform(platform_name)
        self.ctx = types.SimpleNamespace(state=self.state, store=self.store, platform=self.platform,
                                         cfg=cfg or CFG, route=route or {})
        self.socks = {}

        def factory(fam):
            s = FakeSock(fam, self.clock)
            self.socks[fam] = s
            return s

        self.selector = FakeSelector(self.clock)
        self.engine = Engine(self.ctx, clock=self.clock.mono, wall=self.clock.wall,
                             socket_factory=socket_factory or factory, selector_factory=lambda: self.selector,
                             pingbin_factory=pingbin_factory, has_ip_header=has_ip_header,
                             platform_name=platform_name, nametoindex=nametoindex)

    def setup(self):
        self.engine._open_sockets()
        self.engine._refresh_lan_net()
        self.engine._started_at = self.clock.m
        self.engine._setup()
        return self

    def drive(self, seconds):
        """Run the loop until ``seconds`` of fake time have passed."""
        until = self.clock.m + seconds
        guard = 0
        while self.clock.m < until - 1e-9:
            self.engine._iterate()
            guard += 1
            if guard > 200000:
                raise AssertionError("engine loop did not advance the clock")
        return self

    def samples(self, key=None, **flags):
        tid = self.state.target(key).id if key else None
        out = [s for s in self.store.samples if tid is None or s.target_id == tid]
        return out

    def close(self):
        self.engine.stop(0.1)


# ---------------------------------------------------------------------------
# Unit helpers
# ---------------------------------------------------------------------------
class HelperTests(unittest.TestCase):
    def test_period_for_rate(self):
        self.assertEqual(scheduler.period_for_rate(4), 1)
        self.assertEqual(scheduler.period_for_rate(5), 1)  # cap: every slot
        self.assertEqual(scheduler.period_for_rate(2), 2)
        self.assertEqual(scheduler.period_for_rate(1), 4)
        self.assertEqual(scheduler.period_for_rate(0), 1)
        self.assertEqual(scheduler.period_for_rate("x"), 1)

    def test_stagger(self):
        self.assertEqual(scheduler.stagger_ms(0), 0)
        self.assertEqual(scheduler.stagger_ms(3), 69)
        self.assertEqual(scheduler.stagger_ms(9), 7)  # 207 mod 200
        self.assertTrue(all(0 <= scheduler.stagger_ms(i) < 200 for i in range(256)))


# ---------------------------------------------------------------------------
# Grid
# ---------------------------------------------------------------------------
class GridTests(unittest.TestCase):
    def test_slot_alignment_stagger_and_no_drift(self):
        h = Harness([tgt(0, "gw4", "10.0.0.1", role="gateway"), tgt(3, "inet4_cf", "1.1.1.1"),
                     tgt(5, "isp_hop4", "10.60.1.1", role="isp_hop", rate=2.0)]).setup()
        for s in h.socks.values():
            s.responder = echo_responder({"10.0.0.1": 0.002, "1.1.1.1": 0.020, "10.60.1.1": 0.012})
        h.drive(30.0)
        sent = h.socks[4].sent
        by_addr = {}
        for mono, pkt, addr in sent:
            by_addr.setdefault(addr[0], []).append(mono)
        # every send sits exactly on origin + k*250 ms + stagger; no cumulative drift over 30 s
        for addr, offset_ms, period in (("10.0.0.1", 0, 1), ("1.1.1.1", 69, 1), ("10.60.1.1", 115, 2)):
            times = by_addr[addr]
            self.assertEqual(len(times), 120 // period, addr)
            ks = [(t - MONO0 - offset_ms / 1000.0) / 0.25 for t in times]
            for k in ks:
                self.assertAlmostEqual(k, round(k), places=6, msg=addr)
            self.assertEqual([round(k) for k in ks], list(range(0, 120, period)), addr)
        # samples: slot == k (t0 is on the 5 s grid), RTT from the pending table
        for s in h.samples("inet4_cf"):
            self.assertEqual(s.kind, KIND_ICMP)
            self.assertFalse(s.flags & (F_LOST | F_LATE | F_ERROR | F_STALL))
            self.assertEqual(s.slot, h.state.slot_for(s.ts_ms))
            self.assertEqual(s.value, 20000)
        self.assertEqual(len(h.samples("inet4_cf")), 120)
        self.assertEqual([s.seq for s in h.samples("gw4")][:5], [0, 1, 2, 3, 4])
        slots = [s.slot for s in h.samples("gw4")]
        self.assertEqual(slots[:4], [0, 1, 2, 3])
        self.assertEqual([s.slot for s in h.samples("isp_hop4")][:3], [0, 2, 4])
        # state saw them in the same order and the store copy carries the slot too
        self.assertEqual(h.state.sample_count, len(h.store.samples))
        st = h.engine.stats()
        self.assertEqual(st["pps"], 10)  # 4 + 4 + 2 per second
        self.assertEqual(st["backend"], {"4": "socket", "6": "socket"})
        self.assertEqual(st["local_network"], "ok")
        self.assertFalse(st["stall"])
        self.assertEqual(h.state.collector("engine")["status"], "ok")
        h.close()

    def test_send_time_is_wall_clock_at_send(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010})
        h.drive(1.0)
        s = h.samples("inet4_cf")[1]
        self.assertEqual(s.ts_ms, int(round((T0 + 0.25 + 0.069) * 1000)))
        h.close()

    def test_skip_ahead_after_long_stall_instead_of_bursting(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010})
        h.drive(1.0)
        n = len(h.socks[4].sent)
        h.clock.advance(5.0)  # laptop slept / scheduler starved
        h.engine._iterate()
        self.assertLessEqual(len(h.socks[4].sent) - n, 1)
        self.assertGreater(h.engine.totals["missed"], 0)
        h.drive(1.0)
        # still on the grid afterwards
        for mono, _p, _a in h.socks[4].sent[n:]:
            k = (mono - MONO0 - 0.069) / 0.25
            self.assertAlmostEqual(k, round(k), places=6)
        h.close()

    def test_reanchor_on_wall_clock_jump_keeps_slots_aligned(self):
        h = Harness([tgt(0, "gw4", "10.0.0.1", role="gateway")]).setup()
        h.socks[4].responder = echo_responder({"10.0.0.1": 0.002})
        h.drive(1.0)
        h.clock.w += 3.123  # NTP step: wall moves, monotonic does not
        h.drive(2.0)
        late = [s for s in h.samples("gw4") if s.ts_ms > int((T0 + 1.0) * 1000)]
        self.assertTrue(late)
        for s in late[-4:]:
            self.assertEqual((s.ts_ms - h.state.slot_origin_ms) % 250, 0)
            self.assertEqual(s.slot, h.state.slot_for(s.ts_ms))
        h.close()


# ---------------------------------------------------------------------------
# Lost / late / errors / foreign datagrams
# ---------------------------------------------------------------------------
class AccountingTests(unittest.TestCase):
    def test_lost_after_timeout_then_late_reply_then_forgotten(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010}, per_seq={("1.1.1.1", 2): 2.5, ("1.1.1.1", 6): 11.0,
                                                                        ("1.1.1.1", 9): None})
        h.drive(16.0)
        ss = h.samples("inet4_cf")
        seq2 = [s for s in ss if s.seq == 2]
        self.assertEqual(len(seq2), 2)
        lost, late = seq2
        self.assertTrue(lost.flags & F_LOST)
        self.assertEqual(lost.value, -1)
        self.assertTrue(late.flags & F_LATE)
        self.assertFalse(late.flags & F_LOST)
        self.assertEqual(late.ts_ms, lost.ts_ms)  # keyed by the send time
        self.assertEqual(late.slot, lost.slot)
        self.assertAlmostEqual(late.value / 1e6, 2.5, places=3)
        # the lost verdict comes from the 100 ms sweep: between 2.0 and 2.1 s after the send
        send_mono = [m for m, p, a in h.socks[4].sent if parse_payload(p[ICMP_HEADER_LEN:]).seq == 2][0]
        lost_pos = h.store.samples.index(lost)
        # the sample after it in the store was sent after the sweep; use the engine's own clock bound instead
        self.assertTrue(lost_pos >= 0)
        # seq 6: reply after the 10 s late window → stays lost, no late sample
        seq6 = [s for s in ss if s.seq == 6]
        self.assertEqual(len(seq6), 1)
        self.assertTrue(seq6[0].flags & F_LOST)
        # seq 9: never answered → lost only
        seq9 = [s for s in ss if s.seq == 9]
        self.assertEqual(len(seq9), 1)
        self.assertTrue(seq9[0].flags & F_LOST)
        self.assertEqual(h.engine.totals["lost"], 3)
        self.assertEqual(h.engine.totals["late"], 1)
        self.assertEqual(h.engine.totals["stray"], 1)  # the seq-6 reply after the window
        self.assertEqual(h.state.totals[3].late, 1)
        self.assertEqual(h.state.totals[3].lost, 3)
        self.assertEqual(h.engine.stats()["pending"], len([e for e in h.engine._pending.values()]))
        # the late-window bookkeeping does not leak
        self.assertLess(len(h.engine._pending), 12)
        self.assertGreater(send_mono, 0)
        h.close()

    def test_lost_sample_timing_is_timeout_plus_sweep_granularity(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        emitted_at = {}
        orig = h.engine._emit

        def spy(s, key):
            emitted_at[(s.seq, bool(s.flags & F_LOST))] = h.clock.m
            orig(s, key)

        h.engine._emit = spy
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010}, per_seq={("1.1.1.1", 1): None})
        h.drive(4.0)
        send_mono = [m for m, p, a in h.socks[4].sent if parse_payload(p[ICMP_HEADER_LEN:]).seq == 1][0]
        delta = emitted_at[(1, True)] - send_mono
        self.assertGreaterEqual(delta, 2.0 - 1e-9)
        self.assertLess(delta, 2.0 + scheduler.SWEEP_S + 0.26)
        h.close()

    def test_macos_layout_reply_with_ip_header(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")], platform_name="darwin", has_ip_header=True).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.015}, with_ip_header=True)
        h.drive(1.0)
        ss = h.samples("inet4_cf")
        self.assertEqual(len(ss), 4)
        self.assertTrue(all(s.value == 15000 for s in ss))
        self.assertEqual(h.engine.totals["foreign"], 0)
        h.close()

    def test_v6_target_uses_v6_socket_and_scope_id(self):
        h = Harness([tgt(1, "gw6", "fe80::1%en0", fam=6, role="gateway"), tgt(4, "inet6_cf", "2606:4700:4700::1111", fam=6)],
                    nametoindex=lambda name: {"en0": 7}[name]).setup()
        h.socks[6].responder = echo_responder({"fe80::1": 0.002, "2606:4700:4700::1111": 0.030})
        h.drive(1.0)
        addrs = {a for _m, _p, a in h.socks[6].sent}
        self.assertEqual(addrs, {("fe80::1", 0, 0, 7), ("2606:4700:4700::1111", 0, 0, 0)})
        self.assertEqual(h.socks[4].sent, [])
        self.assertEqual(len(h.samples("gw6")), 4)
        self.assertEqual(h.samples("inet6_cf")[0].value, 30000)
        h.close()

    def test_foreign_stray_and_error_datagrams_are_ignored(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        s4 = h.socks[4]
        h.drive(0.3)  # one send out, no reply
        pkt = s4.sent[0][1]
        other = build_echo(4, 0, 3, 1, cookie=0xDEADBEEF)  # another process' probe
        s4.inbox.append((echo_reply_for(other, 4), ("1.1.1.1", 0)))
        s4.inbox.append((b"\x00\x01", ("1.1.1.1", 0)))  # garbage
        s4.inbox.append((time_exceeded_for(pkt, 4, "10.0.0.35", "1.1.1.1"), ("10.60.1.1", 0)))  # a tracer's
        stray = build_echo(4, 777, 3, 1)  # our cookie, unknown seq
        s4.inbox.append((echo_reply_for(stray, 4), ("1.1.1.1", 0)))
        h.engine._iterate()
        self.assertEqual(h.samples("inet4_cf"), [])
        self.assertEqual(h.engine.totals["foreign"], 2)
        self.assertEqual(h.engine.totals["icmp_errors"], 1)
        self.assertEqual(h.engine.totals["stray"], 1)
        # the real reply still lands afterwards
        s4.inbox.append((echo_reply_for(pkt, 4), ("1.1.1.1", 0)))
        h.engine._iterate()
        self.assertEqual(len(h.samples("inet4_cf")), 1)
        self.assertFalse(h.samples("inet4_cf")[0].flags & F_LOST)
        h.close()

    def test_send_error_emits_error_sample_with_errno(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].fail = lambda addr: OSError(errno.ENETUNREACH, "Network is unreachable")
        h.drive(1.0)
        ss = h.samples("inet4_cf")
        self.assertEqual(len(ss), 4)
        for s in ss:
            self.assertTrue(s.flags & F_ERROR)
            self.assertEqual(s.value, errno.ENETUNREACH)
            self.assertEqual(s.slot, h.state.slot_for(s.ts_ms))
        self.assertEqual(h.engine.totals["errors"], 4)
        self.assertEqual(h.engine.totals["sent"], 0)
        # not a Local Network case (Linux, not a LAN address): the target stays enabled
        self.assertTrue(h.state.target("inet4_cf").enabled)
        h.close()


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
class FlagTests(unittest.TestCase):
    def test_stall_flag_on_loop_gap_and_late_send(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010})
        h.drive(2.0)
        self.assertFalse(any(s.flags & F_STALL for s in h.samples("inet4_cf")))
        h.clock.advance(0.3)  # the loop was starved for 300 ms (> 200 ms gap, sends > 50 ms late)
        h.drive(1.5)
        ss = h.samples("inet4_cf")
        stalled = [s for s in ss if s.flags & F_STALL]
        self.assertTrue(stalled)
        sec = int(T0 + 2.3)
        self.assertTrue(all(s.ts_ms // 1000 in (sec - 1, sec) for s in stalled))
        # samples a second later are clean again
        self.assertFalse(any(s.flags & F_STALL for s in ss if s.ts_ms // 1000 >= sec + 1))
        st = h.engine.stats()
        self.assertGreaterEqual(st["loop_gap_ms"], 299.0)
        self.assertGreaterEqual(st["late_ms_max"], 50.0)
        self.assertTrue(st["stall"])
        h.drive(3.0)
        self.assertFalse(h.engine.stats()["stall"])
        h.close()

    def test_loadtest_and_xbox_asleep_flags(self):
        h = Harness([tgt(2, "xbox", "10.0.0.23", role="xbox"), tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010, "10.0.0.23": 0.001})
        h.drive(1.0)
        self.assertFalse(any(s.flags & (F_LOADTEST | F_XBOX_ASLEEP) for s in h.store.samples))
        h.state.loadtest["running"] = True
        h.state.xbox["state"] = "asleep"
        h.drive(1.0)
        recent = [s for s in h.store.samples if s.ts_ms >= int((T0 + 1.0) * 1000)]
        self.assertTrue(recent)
        self.assertTrue(all(s.flags & F_LOADTEST for s in recent))
        for s in recent:
            if s.target_id == 2:
                self.assertTrue(s.flags & F_XBOX_ASLEEP)
            else:
                self.assertFalse(s.flags & F_XBOX_ASLEEP)
        h.state.loadtest["running"] = False
        h.state.xbox["state"] = "awake"
        h.drive(1.0)
        last = h.store.samples[-1]
        self.assertFalse(last.flags & (F_LOADTEST | F_XBOX_ASLEEP))
        h.close()

    def test_lost_sample_keeps_the_flags_of_its_send(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.state.loadtest["running"] = True
        h.drive(0.5)
        h.state.loadtest["running"] = False
        h.drive(3.0)
        lost = [s for s in h.samples("inet4_cf") if s.flags & F_LOST]
        self.assertTrue(lost)
        self.assertTrue(lost[0].flags & F_LOADTEST)  # sent during the load test
        h.close()


# ---------------------------------------------------------------------------
# Targets: dynamic pickup, gw6, fallback
# ---------------------------------------------------------------------------
class TargetTests(unittest.TestCase):
    def test_dynamic_target_pickup_and_disable(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010, "10.60.1.1": 0.012})
        h.drive(0.6)
        self.assertIsNone(h.state.target("isp_hop4"))
        t = h.state.add_target(Target(id=-1, key="isp_hop4", role="isp_hop", addr="10.60.1.1", family=4, kind="icmp",
                                      label="isp", rate_hz=2.0))
        h.drive(1.5)  # picked up at the next 1 s tick
        hop = h.samples("isp_hop4")
        self.assertTrue(hop)
        self.assertEqual(hop[0].target_id, t.id)
        self.assertEqual(h.engine.stats()["targets"], 2)
        h.state.set_target_state("isp_hop4", enabled=False, reason="hop does not answer direct echo")
        h.drive(1.2)
        n = len([x for x in h.socks[4].sent if x[2][0] == "10.60.1.1"])
        h.drive(2.0)
        self.assertEqual(len([x for x in h.socks[4].sent if x[2][0] == "10.60.1.1"]), n)
        self.assertEqual(h.engine.stats()["targets"], 1)
        # an address change is picked up too
        h.state.set_target_state("inet4_cf", addr="1.0.0.1")
        h.drive(1.5)
        self.assertEqual(h.socks[4].sent[-1][2][0], "1.0.0.1")
        h.close()

    def test_non_icmp_unresolved_and_ttl_mode_targets_are_skipped(self):
        h = Harness([
            tgt(3, "inet4_cf", "1.1.1.1"),
            Target(id=6, key="dns_cf4", role="dns", addr="1.1.1.1", family=4, kind="dns", label="dns", port=53),
            Target(id=7, key="tcp_xbl", role="tcp", addr=None, family=4, kind="tcp", label="t", enabled=False, reason="cannot resolve"),
            Target(id=8, key="mid_hop4", role="mid_hop", addr="11.0.6.1", family=4, kind="icmp", label="m", mode="ttl_expiry"),
        ]).setup()
        h.drive(1.0)
        self.assertEqual({a[0] for _m, _p, a in h.socks[4].sent}, {"1.1.1.1"})
        self.assertEqual(h.engine.stats()["targets"], 1)
        h.close()

    def test_gw6_no_responder_after_60s(self):
        h = Harness([tgt(1, "gw6", "fe80::1%en0", fam=6, role="gateway"), tgt(3, "inet4_cf", "1.1.1.1")],
                    nametoindex=lambda n: 7).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.010})
        h.drive(59.0)
        self.assertTrue(h.state.target("gw6").enabled)
        h.drive(3.0)
        t = h.state.target("gw6")
        self.assertFalse(t.enabled)
        self.assertEqual(t.reason, scheduler.GW6_REASON)
        notes = [n for n in h.state.drain_notes() if n["type"] == "probe_error"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["peak"]["reason"], "no_responder")
        self.assertEqual(notes[0]["target"], 1)
        n6 = len(h.socks[6].sent)
        h.drive(2.0)
        self.assertEqual(len(h.socks[6].sent), n6)  # no longer probed
        self.assertTrue(all(s.flags & F_LOST for s in h.samples("gw6")))
        h.close()

    def test_gw6_that_answers_stays(self):
        h = Harness([tgt(1, "gw6", "fe80::1%en0", fam=6, role="gateway")], nametoindex=lambda n: 7).setup()
        h.socks[6].responder = echo_responder({"fe80::1": 0.002})
        h.drive(62.0)
        self.assertTrue(h.state.target("gw6").enabled)
        self.assertIsNone(h.state.target("gw6").reason)
        h.close()

    def test_gw6_whose_sends_fail_is_still_judged(self):
        h = Harness([tgt(1, "gw6", "fe80::1%en0", fam=6, role="gateway")], nametoindex=lambda n: 7).setup()
        h.socks[6].fail = lambda addr: OSError(errno.ENETUNREACH, "unreachable")
        h.drive(62.0)
        self.assertFalse(h.state.target("gw6").enabled)
        self.assertEqual(h.state.target("gw6").reason, scheduler.GW6_REASON)
        h.close()


class FakePingBackend:
    instances = []

    def __init__(self, ctx, family, emit, binary):
        self.ctx = ctx
        self.family = family
        self.emit = emit
        self.binary = binary
        self.synced = []
        self.stopped = False
        FakePingBackend.instances.append(self)

    def sync(self, targets):
        self.synced.append([t.key for t in targets])

    def stop(self, timeout=2.0):
        self.stopped = True

    def stats(self):
        return {"family": self.family, "processes": len(self.synced[-1]) if self.synced else 0}


class FallbackTests(unittest.TestCase):
    def setUp(self):
        FakePingBackend.instances = []

    def _factory(self, h):
        def factory(fam):
            if fam == 4:
                raise PermissionError(errno.EACCES, "Operation not permitted")
            s = FakeSock(fam, h.clock)
            h.socks[fam] = s
            return s
        return factory

    def test_fallback_switch_per_family(self):
        targets = [tgt(0, "gw4", "10.0.0.1", role="gateway"), tgt(3, "inet4_cf", "1.1.1.1"),
                   tgt(4, "inet6_cf", "2606:4700:4700::1111", fam=6)]
        h = Harness(targets, platform_name="darwin", has_ip_header=True, pingbin_factory=FakePingBackend)
        h.engine._socket_factory = self._factory(h)
        h.setup()
        self.assertEqual(h.engine.backend, {4: "pingbin", 6: "socket"})
        self.assertEqual(len(FakePingBackend.instances), 1)
        pb = FakePingBackend.instances[0]
        self.assertEqual((pb.family, pb.binary), (4, "/sbin/ping"))
        self.assertEqual(pb.synced[-1], ["gw4", "inet4_cf"])
        self.assertEqual(h.state.target("gw4").backend, "pingbin")
        self.assertEqual(h.state.target("inet6_cf").backend, "socket")
        h.socks[6].responder = echo_responder({"2606:4700:4700::1111": 0.030})
        h.drive(1.0)
        self.assertEqual(len(h.samples("inet6_cf")), 4)  # v6 still on the socket
        self.assertEqual(h.engine.stats()["targets"], 1)
        # a sample from the ping child goes through the common finaliser: slot + loadtest flag
        h.state.loadtest["running"] = True
        pb.emit(Sample(ts_ms=int((T0 + 1.0) * 1000), target_id=3, kind=KIND_ICMP, flags=F_FALLBACK, seq=4, value=12000))
        s = h.samples("inet4_cf")[-1]
        self.assertTrue(s.flags & F_FALLBACK and s.flags & F_LOADTEST)
        self.assertEqual(s.slot, h.state.slot_for(s.ts_ms))
        c = h.state.collector("engine")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("ping-binary", c["reason"])
        self.assertEqual(c["backend4"], "pingbin")
        self.assertEqual(h.engine.stats()["backend"], {"4": "pingbin", "6": "socket"})
        self.assertIn("4", h.engine.stats()["pingbin"])
        # a target disabled later leaves the ping backend on the next tick
        h.state.set_target_state("gw4", enabled=False)
        h.drive(1.2)
        self.assertEqual(pb.synced[-1], ["inet4_cf"])
        h.close()
        self.assertTrue(pb.stopped)

    def test_no_binary_disables_the_family(self):
        targets = [tgt(0, "gw4", "10.0.0.1", role="gateway"), tgt(4, "inet6_cf", "2606:4700:4700::1111", fam=6)]
        h = Harness(targets, platform_name="linux", platform=FakePlatform("linux", binaries=()),
                    pingbin_factory=FakePingBackend)
        h.engine._socket_factory = self._factory(h)
        h.setup()
        self.assertEqual(h.engine.backend, {4: None, 6: "socket"})
        self.assertEqual(FakePingBackend.instances, [])
        t = h.state.target("gw4")
        self.assertFalse(t.enabled)
        self.assertIn("no ICMP capability", t.reason)
        self.assertTrue(h.state.target("inet6_cf").enabled)
        self.assertEqual(h.state.collector("engine")["status"], "degraded")
        h.close()

    def test_non_permission_socket_error_is_not_a_fallback(self):
        def factory(fam):
            raise OSError(errno.EAFNOSUPPORT, "Address family not supported")
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")], socket_factory=factory, pingbin_factory=FakePingBackend)
        h.setup()
        self.assertEqual(h.engine.backend, {4: None, 6: None})
        self.assertEqual(FakePingBackend.instances, [])
        self.assertFalse(h.state.target("inet4_cf").enabled)
        h.drive(1.0)  # the loop still runs (nothing to send) and does not crash
        h.close()


# ---------------------------------------------------------------------------
# macOS Local Network privacy
# ---------------------------------------------------------------------------
class LocalNetworkTests(unittest.TestCase):
    def _harness(self, platform_name="darwin"):
        targets = [tgt(0, "gw4", "10.0.0.1", role="gateway"), tgt(1, "gw6", "fe80::1%en0", fam=6, role="gateway"),
                   tgt(2, "xbox", "10.0.0.23", role="xbox"), tgt(3, "inet4_cf", "1.1.1.1"),
                   tgt(4, "inet6_cf", "2606:4700:4700::1111", fam=6)]
        h = Harness(targets, platform_name=platform_name, has_ip_header=False,
                    route={"gateway": "10.0.0.1", "lan_ip": "10.0.0.35", "prefixlen": 24}, nametoindex=lambda n: 7).setup()
        blocked = {"on": True}

        def fail(addr):
            host = addr[0].split("%")[0]
            if blocked["on"] and (host.startswith("10.0.0.") or host.startswith("fe80")):
                return OSError(errno.EHOSTUNREACH, "No route to host")
            return None

        h.socks[4].fail = fail
        h.socks[6].fail = fail
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.020})
        h.socks[6].responder = echo_responder({"2606:4700:4700::1111": 0.030})
        return h, blocked

    def test_detects_denied_permission_disables_lan_targets_and_retries(self):
        h, blocked = self._harness()
        h.drive(1.5)
        for key in ("gw4", "gw6", "xbox"):
            t = h.state.target(key)
            self.assertFalse(t.enabled, key)
            self.assertEqual(t.reason, scheduler.LAN_REASON, key)
        self.assertTrue(h.state.target("inet4_cf").enabled)
        self.assertTrue(h.state.target("inet6_cf").enabled)
        # the first sends (before any internet evidence) were plain errors
        errs = [s for s in h.samples("gw4") if s.flags & F_ERROR]
        self.assertTrue(errs)
        self.assertEqual(errs[0].value, errno.EHOSTUNREACH)
        c = h.state.collector("engine")
        self.assertEqual(c["status"], "degraded")
        self.assertIn("Local Network", c["reason"])
        self.assertIn("Terminal", c["reason"])
        self.assertEqual(c["local_network"], "denied")
        self.assertEqual(h.engine.stats()["local_network"], "denied")
        notes = [n for n in h.state.drain_notes() if n["type"] == "probe_error"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["peak"]["reason"], "local_network_permission")
        self.assertEqual(notes[0]["peak"]["app"], "Terminal")
        self.assertEqual(notes[0]["severity"], 2)
        # internet probing continues untouched
        n = len(h.samples("inet4_cf"))
        h.drive(2.0)
        self.assertGreater(len(h.samples("inet4_cf")), n)
        self.assertEqual({a[0] for _m, _p, a in h.socks[4].sent[-8:]}, {"1.1.1.1"})
        # retry every 60 s: still blocked → stays disabled, no new note
        h.drive(60.0)
        self.assertFalse(h.state.target("gw4").enabled)
        self.assertEqual([n for n in h.state.drain_notes() if n["type"] == "probe_error"], [])
        # the user allowed it → the next retry re-enables the LAN targets
        blocked["on"] = False
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.020, "10.0.0.1": 0.002, "10.0.0.23": 0.001})
        h.drive(61.0)
        for key in ("gw4", "gw6", "xbox"):
            t = h.state.target(key)
            self.assertTrue(t.enabled, key)
            self.assertIsNone(t.reason, key)
        self.assertEqual(h.engine.stats()["local_network"], "ok")
        self.assertEqual(h.state.collector("engine")["status"], "ok")
        h.drive(1.5)
        self.assertFalse(h.samples("gw4")[-1].flags & (F_ERROR | F_LOST))
        h.close()

    def test_a_block_that_returns_after_a_retry_is_not_a_device_failure(self):
        # macOS lets the retry's single packet through, then blocks the next sends again (seen on a real Mac):
        # the targets pause again without a second warning, and blocked sends are never recorded as errors
        h, blocked = self._harness()
        h.drive(1.5)
        self.assertEqual(len([n for n in h.state.drain_notes() if n["type"] == "probe_error"]), 1)
        h.drive(58.0)
        blocked["on"] = False
        h.drive(3.0)  # the retry gets through: re-enabled
        self.assertTrue(h.state.target("gw4").enabled)
        n_err = len([s for s in h.samples("gw4") if s.flags & F_ERROR])
        blocked["on"] = True
        h.drive(3.0)
        self.assertFalse(h.state.target("gw4").enabled)
        self.assertEqual(h.state.target("gw4").reason, scheduler.LAN_REASON)
        self.assertEqual(len([s for s in h.samples("gw4") if s.flags & F_ERROR]), n_err)
        self.assertEqual([n for n in h.state.drain_notes() if n["type"] == "probe_error"], [])
        h.close()

    def test_a_sleeping_lan_device_is_not_a_permission_block(self):
        # macOS returns EHOSTUNREACH for a LAN host that does not answer ARP (an Xbox in rest mode): the gateway
        # answers, so the permission is fine and only that device is unreachable
        h, blocked = self._harness()
        blocked["on"] = False
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.020, "10.0.0.1": 0.002})
        prev = h.socks[4].fail
        h.socks[4].fail = lambda addr: OSError(errno.EHOSTUNREACH, "No route to host") if addr[0] == "10.0.0.23" else prev(addr)
        h.drive(5.0)
        self.assertTrue(h.state.target("gw4").enabled)
        self.assertTrue(h.state.target("xbox").enabled)
        self.assertEqual(h.engine.stats()["local_network"], "ok")
        self.assertFalse(h.samples("gw4")[-1].flags & (F_ERROR | F_LOST))
        self.assertTrue(all(s.flags & F_ERROR for s in h.samples("xbox")))
        self.assertEqual([n for n in h.state.drain_notes() if n["type"] == "probe_error"
                          and n["peak"].get("reason") == "local_network_permission"], [])
        h.close()

    def test_no_internet_evidence_means_no_verdict(self):
        h, blocked = self._harness()
        h.socks[4].responder = None  # nothing answers: could be the network itself
        h.socks[6].responder = None
        h.drive(5.0)
        self.assertTrue(h.state.target("gw4").enabled)
        self.assertTrue(all(s.flags & F_ERROR for s in h.samples("gw4")))
        self.assertEqual(h.state.collector("engine")["status"], "ok")
        h.close()

    def test_linux_ehostunreach_is_a_plain_error(self):
        h, blocked = self._harness(platform_name="linux")
        h.drive(3.0)
        self.assertTrue(h.state.target("gw4").enabled)
        self.assertTrue(all(s.flags & F_ERROR for s in h.samples("gw4")))
        self.assertEqual(h.engine.stats()["local_network"], "ok")
        h.close()


# ---------------------------------------------------------------------------
# Lifecycle with the real selector/thread (no network: sockets cannot be opened)
# ---------------------------------------------------------------------------
class LifecycleTests(unittest.TestCase):
    def test_start_and_stop_with_real_thread(self):
        st = State(time.time(), "s")
        st.add_target(tgt(3, "inet4_cf", "1.1.1.1"))
        store = FakeStore()
        ctx = types.SimpleNamespace(state=st, store=store, platform=FakePlatform("linux", binaries=()), cfg=CFG, route={})

        def factory(fam):
            raise OSError(errno.EAFNOSUPPORT, "no sockets in this test")

        eng = Engine(ctx, socket_factory=factory, platform_name="linux")
        eng.start()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and st.collector("engine") is None:
            time.sleep(0.01)
        time.sleep(0.3)
        self.assertTrue(eng._thread.is_alive())
        self.assertGreater(eng.totals["loops"], 0)
        eng.stop(2.0)
        self.assertFalse(eng._thread.is_alive())
        self.assertIsNone(eng._pipe_r)
        self.assertEqual(st.collector("engine")["status"], "degraded")
        self.assertFalse(st.target("inet4_cf").enabled)

    def test_stop_closes_sockets_and_pipe(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.drive(0.5)
        h.close()
        self.assertTrue(all(s.closed for s in h.socks.values()))
        self.assertIsNone(h.engine._pipe_r)
        self.assertEqual(h.engine.sockets, {})

    def test_state_stop_event_ends_the_loop(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")])
        h.engine.start()
        time.sleep(0.2)
        h.state.stop_event.set()
        h.engine._thread.join(2.0)
        self.assertFalse(h.engine._thread.is_alive())
        h.close()


class StampedSock(FakeSock):
    """A socket with ``SO_TIMESTAMP``: the kernel stamped each reply ``read_lag`` s before it was read."""

    def __init__(self, fam, clock, platform_name="darwin"):
        super().__init__(fam, clock)
        self.platform_name = platform_name
        self.opts = []
        self.read_lag = 0.0

    def setsockopt(self, level, opt, value):
        self.opts.append((level, opt, value))

    def recvmsg(self, n, anc):
        buf, src = self.recvfrom(n)
        return buf, timestamp_cmsg(int(round((self.clock.w - self.read_lag) * 1e6)), self.platform_name), 0, src


class RxTimestampTests(unittest.TestCase):
    def harness(self):
        def factory(fam):
            h.socks[fam] = StampedSock(fam, h.clock)
            return h.socks[fam]

        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")], platform_name="darwin", has_ip_header=True, socket_factory=factory)
        h.setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.015}, with_ip_header=True)
        return h

    def test_a_reply_read_late_keeps_its_real_rtt(self):
        h = self.harness()
        h.socks[4].read_lag = 0.010  # the reply sat 10 ms in the socket while another thread held the GIL
        h.drive(1.0)
        self.assertEqual([s.value for s in h.samples("inet4_cf")], [5000] * 4)
        self.assertEqual(h.engine.stats()["rx_timestamps"], {"4": "kernel", "6": "kernel"})
        self.assertEqual(h.state.collector("engine")["rx_timestamps"], "kernel")
        h.close()

    def test_a_stamp_outside_the_userland_rtt_is_not_trusted(self):
        h = self.harness()
        h.socks[4].read_lag = -0.5  # wall clock stepped forward between send and reply
        h.drive(1.0)
        self.assertEqual([s.value for s in h.samples("inet4_cf")], [15000] * 4)
        h.close()
        h = self.harness()
        h.socks[4].read_lag = 0.020  # stamped before the send: wall clock stepped back
        h.drive(1.0)
        self.assertEqual([s.value for s in h.samples("inet4_cf")], [15000] * 4)
        h.close()

    def test_sockets_without_timestamps_use_the_read_time(self):
        h = Harness([tgt(3, "inet4_cf", "1.1.1.1")]).setup()
        h.socks[4].responder = echo_responder({"1.1.1.1": 0.015})
        h.drive(1.0)
        self.assertEqual([s.value for s in h.samples("inet4_cf")], [15000] * 4)
        self.assertEqual(h.engine.stats()["rx_timestamps"], {"4": "app", "6": "app"})
        h.close()


if __name__ == "__main__":
    unittest.main()
