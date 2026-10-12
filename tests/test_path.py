"""Tests for laglens.probes.path: parsers (fixtures), native TTL probing on fake sockets,
command fallbacks, role assignment, route-change detection, hop gating and the Tracer component."""
import errno
import ipaddress
import os
import socket
import sys
import threading
import time
import types
import unittest
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.probes import path as pathmod  # noqa: E402
from laglens.probes.icmp import (  # noqa: E402
    ICMP_HEADER_LEN,
    IDENT,
    PKIND_TTL,
    echo_reply_for,
    errqueue_cmsg,
    ipv4_header,
    ipv6_header,
    parse_payload,
    time_exceeded_for,
)
from laglens.probes.path import (  # noqa: E402
    CommandTracer,
    Hop,
    NativeTracer,
    Tracer,
    assign_roles,
    parse_mtr,
    parse_ping_ttl,
    parse_traceroute,
    parse_tracepath,
    path_changed,
)
from laglens.state import Episode, State, Target  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "path")


def fixture(name):
    with open(os.path.join(FIX, name), "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
class ParserTests(unittest.TestCase):
    def test_tracepath_linux(self):
        hops = parse_tracepath(fixture("tracepath_linux.txt"), 12)
        self.assertEqual([h.ttl for h in hops], [1, 2, 3, 4, 5])
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", None, "11.0.5.1", "1.1.1.1"])
        self.assertEqual(hops[0].rtt, [1.234, 0.987])
        self.assertEqual(hops[2].rtt, [None])
        self.assertEqual(hops[2].loss_pct, 100)
        self.assertTrue(hops[4].reached)
        self.assertFalse(hops[3].reached)
        self.assertEqual(hops[0].median_ms, 1.1105)
        self.assertEqual(parse_tracepath(""), [])
        self.assertEqual(parse_tracepath(" 1?: [LOCALHOST]  pmtu 1500\n     Resume: pmtu 1500 hops 0 back 0"), [])

    def test_ping_ttl_macos(self):
        self.assertEqual(parse_ping_ttl(fixture("ping_m_macos_ttl2.txt")), ("10.60.12.1", None, False))
        self.assertEqual(parse_ping_ttl(fixture("ping_m_macos_reached.txt")), ("1.1.1.1", 30.348, True))
        # macOS ping6 -h prints nothing for a hop-limit-exceeded: no hop, not reached
        self.assertEqual(parse_ping_ttl(fixture("ping6_h_macos_ttl2.txt")), (None, None, False))

    def test_ping_ttl_linux(self):
        self.assertEqual(parse_ping_ttl(fixture("ping_t_linux_ttl2.txt")), ("10.60.12.1", None, False))
        self.assertEqual(parse_ping_ttl(fixture("ping_t_linux_reached.txt")), ("1.1.1.1", 18.4, True))
        self.assertEqual(parse_ping_ttl("From 2001:558::1 icmp_seq=1 Time exceeded: Hop limit"), ("2001:558::1", None, False))
        self.assertEqual(parse_ping_ttl(""), (None, None, False))

    def test_traceroute_macos_and_linux(self):
        hops = parse_traceroute(fixture("traceroute_macos.txt"), 12)
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.235.27", "11.0.1.157", "11.0.2.9", "11.0.3.74"])
        self.assertEqual(hops[0].rtt, [3.5])
        self.assertEqual(hops[1].median_ms, 52.198)
        hops = parse_traceroute(fixture("traceroute_linux.txt"), 12)
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", None, "11.0.5.1", "1.1.1.1"])
        self.assertEqual(hops[2].rtt, [None])
        self.assertEqual(hops[4].rtt, [18.23])
        # max_ttl truncates
        self.assertEqual(len(parse_traceroute(fixture("traceroute_linux.txt"), 3)), 3)
        self.assertEqual(parse_traceroute("traceroute to 1.1.1.1 (1.1.1.1), 12 hops max\n"), [])
        # multi-probe lines with mixed answers
        hops = parse_traceroute(" 1  10.0.0.1  1.0 ms  1.2 ms *\n", 12)
        self.assertEqual(hops[0].rtt, [1.0, 1.2, None])

    def test_mtr(self):
        hops = parse_mtr(fixture("mtr_linux.txt"), 12)
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", None, "11.0.5.1", "1.1.1.1"])
        self.assertEqual(hops[0].rtt, [1.1])
        self.assertEqual(hops[2].rtt, [None])
        self.assertEqual(parse_mtr("garbage"), [])

    def test_hop_helpers(self):
        h = Hop(2, ip="10.60.1.1", rtt=[10.0, None, 12.0])
        self.assertEqual(h.median_ms, 11.0)
        self.assertEqual(h.loss_pct, 33)
        self.assertEqual(h.to_dict(), {"ttl": 2, "ip": "10.60.1.1", "rdns": None, "rtt": [10.0, None, 12.0]})
        h.reached = True
        self.assertTrue(h.to_dict()["reached"])
        self.assertIsNone(Hop(3).median_ms)
        self.assertEqual(Hop(3).loss_pct, 100)

    def test_finish_truncates_after_destination(self):
        res = {1: Hop(1, ip="10.0.0.1"), 2: Hop(2, ip="1.1.1.1", reached=True), 3: Hop(3, ip="9.9.9.9")}
        hops = pathmod._finish(res, 12)
        self.assertEqual([h.ttl for h in hops], [1, 2])
        # a gap between answering hops is "no answer"; TTLs after the last listed one are not padded
        res = {1: Hop(1, ip="10.0.0.1"), 3: Hop(3, ip="9.9.9.9")}
        hops = pathmod._finish(res, 4)
        self.assertEqual([(h.ttl, h.ip) for h in hops], [(1, "10.0.0.1"), (2, None), (3, "9.9.9.9")])
        # the native tracer pre-populates every probed TTL, so its silent tail survives
        res = {t: Hop(t, rtt=[None, None]) for t in range(1, 5)}
        self.assertEqual(len(pathmod._finish(res, 4)), 4)
        self.assertEqual(pathmod._finish({}, 4), [])


# ---------------------------------------------------------------------------
# Native tracer on a fake socket
# ---------------------------------------------------------------------------
class FakeClock:
    def __init__(self):
        self.m = 500.0

    def __call__(self):
        return self.m


class FakeNet:
    """Scripted hops: ``hops[ttl] = (ip, rtt_s)`` or ``None``; ``reach`` is the destination's TTL."""

    def __init__(self, clock, family=4, layout="darwin", quote=8, hops=None, reach=5, dst="1.1.1.1",
                 echo=None, src="10.0.0.35"):
        self.clock = clock
        self.family = family
        self.layout = layout
        self.quote = quote
        self.hops = hops or {}
        self.reach = reach
        self.dst = dst
        self.src = src
        self.echo = dict(echo or {})  # ip -> replies left for direct echoes
        self.ttl = None
        self.sent = []
        self.inbox = deque()
        self.errq = deque()
        self.scheduled = []
        self.closed = False
        self.setsockopts = []

    def setsockopt(self, level, opt, val):
        self.setsockopts.append((level, opt, val))
        if opt in (socket.IP_TTL, socket.IPV6_UNICAST_HOPS):
            self.ttl = val

    def sendto(self, pkt, addr):
        now = self.clock()
        self.sent.append((now, self.ttl, pkt, addr))
        host = addr[0]
        if self.ttl == 64 or host != self.dst:
            left = self.echo.get(host, 0)
            if left > 0:
                self.echo[host] = left - 1
                self.scheduled.append((now + 0.003, "reply", echo_reply_for(pkt, self.family), host))
            return len(pkt)
        if self.ttl >= self.reach:
            self.scheduled.append((now + 0.020, "reply", echo_reply_for(pkt, self.family), self.dst))
            return len(pkt)
        ent = self.hops.get(self.ttl)
        if ent is None:
            return len(pkt)
        ip, rtt = ent
        if self.layout == "linux":
            self.scheduled.append((now + rtt, "errq", pkt, ip))
        else:
            self.scheduled.append((now + rtt, "exceeded", time_exceeded_for(pkt, self.family, self.src, self.dst, self.quote), ip))
        return len(pkt)

    def deliver(self):
        now = self.clock()
        keep = []
        for t, what, buf, ip in sorted(self.scheduled, key=lambda x: x[0]):
            if t > now + 1e-9:
                keep.append((t, what, buf, ip))
                continue
            if what == "errq":
                self.errq.append((buf, errqueue_cmsg(self.family, 3 if self.family == 6 else 11, 0, ip), 0, (ip, 0)))
                continue
            if what == "exceeded" and self.family == 4 and self.layout == "darwin":
                buf = ipv4_header(ip, self.src, len(buf), ttl=250) + buf
            elif what == "reply" and self.family == 4 and self.layout == "darwin":
                buf = ipv4_header(ip, self.src, len(buf)) + buf
            self.inbox.append((buf, (ip, 0) if self.family == 4 else (ip, 0, 0, 0)))
        self.scheduled = keep

    def recvfrom(self, n):
        if self.inbox:
            return self.inbox.popleft()
        raise BlockingIOError()

    def recvmsg(self, n, anc, flags):
        if self.errq:
            return self.errq.popleft()
        raise BlockingIOError()

    def close(self):
        self.closed = True

    def waiter(self, sock, timeout):
        now = self.clock()
        target = now + timeout
        if self.scheduled:
            target = min(target, max(now, min(t for t, _, _, _ in self.scheduled)))
        self.clock.m = target
        self.deliver()
        return bool(self.inbox or self.errq)


HOPS4 = {1: ("10.0.0.1", 0.002), 2: ("10.60.12.1", 0.014), 3: None, 4: ("11.0.1.157", 0.021)}


def native(net, family=4, platform_name="darwin"):
    nt = NativeTracer(family, platform_name, socket_factory=lambda fam: net, clock=net.clock, waiter=net.waiter,
                      nametoindex=lambda n: 7)
    nt.open()
    return nt


class NativeTracerTests(unittest.TestCase):
    def test_macos_v4_trace_with_8_byte_quote(self):
        clock = FakeClock()
        net = FakeNet(clock, hops=HOPS4, reach=5, quote=8)
        nt = native(net)
        hops = nt.trace("1.1.1.1", 12, probes=2)
        self.assertEqual(nt.method, "native")
        self.assertEqual([h.ttl for h in hops], [1, 2, 3, 4, 5])
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", None, "11.0.1.157", "1.1.1.1"])
        self.assertEqual(hops[2].rtt, [None, None])
        self.assertTrue(hops[4].reached)
        self.assertFalse(hops[3].reached)
        self.assertAlmostEqual(hops[1].rtt[0], 14.0, places=1)
        self.assertAlmostEqual(hops[1].rtt[1], 14.0, places=1)
        self.assertAlmostEqual(hops[4].median_ms, 20.0, places=1)
        # TTLs beyond the destination are skipped as soon as its reply is in (ttl 5 sent at +40 ms, reply +60 ms)
        ttls = [t for _n, t, _p, _a in net.sent]
        self.assertEqual(ttls, [1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5])
        # probes carry the tracer payload: kind ttl, extra = ttl, target 0xFFFF, our ident
        p = parse_payload(net.sent[1][2][ICMP_HEADER_LEN:])
        self.assertEqual((p.kind, p.extra, p.target_id), (PKIND_TTL, 2, pathmod.TRACER_TARGET))
        self.assertTrue(p.matches())
        self.assertEqual(int.from_bytes(net.sent[1][2][4:6], "big"), IDENT)
        # IP_TTL was set per probe
        self.assertIn((socket.IPPROTO_IP, socket.IP_TTL, 3), net.setsockopts)

    def test_macos_v4_trace_with_full_quote_and_foreign_datagrams(self):
        clock = FakeClock()
        net = FakeNet(clock, hops=HOPS4, reach=5, quote=200)
        nt = native(net)
        # a foreign echo reply and a foreign time-exceeded (other ident, other cookie) are ignored
        other = echo_reply_for(b"\x08\x00\x00\x00\xab\xcd\x00\x01" + b"\x00" * 56, 4)
        net.inbox.append((ipv4_header("1.1.1.1", "10.0.0.35", len(other)) + other, ("1.1.1.1", 0)))
        exc = time_exceeded_for(b"\x08\x00\x00\x00\xab\xcd\x00\x01" + b"\x00" * 56, 4, "10.0.0.35", "1.1.1.1", 64)
        net.inbox.append((ipv4_header("10.0.0.1", "10.0.0.35", len(exc)) + exc, ("10.0.0.1", 0)))
        net.inbox.append((b"\x45\x00", ("10.0.0.1", 0)))
        hops = nt.trace("1.1.1.1", 6, probes=1)
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", None, "11.0.1.157", "1.1.1.1"])

    def test_linux_errqueue_trace(self):
        clock = FakeClock()
        net = FakeNet(clock, layout="linux", hops=HOPS4, reach=5)
        nt = native(net, platform_name="linux")
        self.assertEqual(nt.method, "errqueue")
        self.assertIn((pathmod.SOL_IP if hasattr(pathmod, "SOL_IP") else 0, 11, 1), net.setsockopts)
        hops = nt.trace("1.1.1.1", 12, probes=2)
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", None, "11.0.1.157", "1.1.1.1"])
        self.assertTrue(hops[4].reached)
        self.assertAlmostEqual(hops[3].rtt[0], 21.0, places=1)

    def test_v6_trace(self):
        clock = FakeClock()
        hops6 = {1: ("fe80::211:22ff:fe33:4455", 0.002), 2: ("2001:558:4000::1", 0.015)}
        net = FakeNet(clock, family=6, hops=hops6, reach=3, dst="2606:4700:4700::1111", src="2601:abcd::1")
        nt = native(net, family=6)
        hops = nt.trace("2606:4700:4700::1111", 8, probes=1)
        self.assertEqual([h.ip for h in hops], ["fe80::211:22ff:fe33:4455", "2001:558:4000::1", "2606:4700:4700::1111"])
        self.assertTrue(hops[2].reached)
        self.assertIn((socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 2), net.setsockopts)
        # link-local destinations carry the scope id
        nt.echo_check("fe80::1%en0", n=1)
        self.assertEqual(net.sent[-1][3], ("fe80::1", 0, 0, 7))

    def test_nothing_answers(self):
        clock = FakeClock()
        net = FakeNet(clock, hops={}, reach=99)
        nt = native(net)
        hops = nt.trace("1.1.1.1", 4, probes=2)
        self.assertEqual([h.ip for h in hops], [None] * 4)
        self.assertTrue(all(h.rtt == [None, None] for h in hops))
        # the trace waited the full timeout after the last send, not forever
        self.assertLess(clock.m - 500.0, 0.15 + 3 * 0.01 + 1.5 + 0.3)

    def test_echo_check_counts_direct_replies(self):
        clock = FakeClock()
        net = FakeNet(clock, hops=HOPS4, echo={"10.60.12.1": 3, "11.0.1.157": 5})
        nt = native(net)
        self.assertEqual(nt.echo_check("10.60.12.1"), 3)
        self.assertEqual(nt.echo_check("11.0.1.157"), 5)
        self.assertEqual(nt.echo_check("11.0.2.9"), 0)
        self.assertTrue(all(ttl == 64 for _n, ttl, _p, _a in net.sent))

    def test_send_error_is_recorded_not_raised(self):
        clock = FakeClock()
        net = FakeNet(clock, hops=HOPS4)

        def boom(pkt, addr):
            raise OSError(errno.EHOSTUNREACH, "No route to host")

        net.sendto = boom
        nt = native(net)
        hops = nt.trace("1.1.1.1", 3, probes=1)
        self.assertEqual([h.ip for h in hops], [None, None, None])
        self.assertIn("No route to host", nt.last_error)

    def test_stop_event_aborts_a_running_trace_promptly(self):
        clock = FakeClock()
        net = FakeNet(clock, hops={}, reach=99)  # nothing answers: would otherwise wait the full timeout
        stop = threading.Event()
        nt = NativeTracer(4, "darwin", socket_factory=lambda fam: net, clock=clock, waiter=net.waiter, stop_event=stop)
        nt.open()
        calls = {"n": 0}
        orig = net.waiter

        def waiter(sock, timeout):
            calls["n"] += 1
            if calls["n"] == 3:
                stop.set()
            return orig(sock, timeout)

        nt._waiter = waiter
        hops = nt.trace("1.1.1.1", 12, probes=2)
        self.assertLess(clock.m - 500.0, 0.5)  # not the ~1.8 s a full trace takes
        self.assertEqual(len(hops), 12)
        self.assertEqual(nt.echo_check("10.0.0.1"), 0)  # already stopped: returns at once, nothing sent
        self.assertFalse(any(ttl == 64 for _n, ttl, _p, _a in net.sent))

    def test_socket_closed_under_a_running_trace_ends_it_gracefully(self):
        clock = FakeClock()
        net = FakeNet(clock, hops=HOPS4, reach=5)
        nt = native(net)
        orig = net.waiter

        def waiter(sock, timeout):
            r = orig(sock, timeout)
            nt.close()  # Tracer.stop() from another thread
            return r

        nt._waiter = waiter
        hops = nt.trace("1.1.1.1", 12, probes=2)  # no exception
        self.assertTrue(net.closed)
        self.assertLessEqual(len([h for h in hops if h.ip]), 2)

    def test_open_failure_propagates_and_recverr_failure_closes(self):
        def factory(fam):
            raise PermissionError(errno.EACCES, "nope")

        nt = NativeTracer(4, "darwin", socket_factory=factory)
        with self.assertRaises(OSError):
            nt.open()
        net = FakeNet(FakeClock(), layout="linux")

        def bad_setsockopt(level, opt, val):
            raise OSError(errno.ENOPROTOOPT, "no RECVERR")

        net.setsockopt = bad_setsockopt
        nt = NativeTracer(4, "linux", socket_factory=lambda fam: net)
        with self.assertRaises(OSError):
            nt.open()
        self.assertTrue(net.closed)


# ---------------------------------------------------------------------------
# Command fallbacks
# ---------------------------------------------------------------------------
class FakePlatform:
    def __init__(self, name="darwin", have=(), route=None):
        self.name = name
        self.have = set(have)
        self.calls = []
        self._route = route or {"gateway": "10.0.0.1", "iface": "en0", "gateway6": "fe80::211:22ff:fe33:4455%en0",
                                "iface6": "en0", "lan_ip": "10.0.0.35", "prefixlen": 24}
        self.ping_m = {
            1: (2, "PING 1.1.1.1 (1.1.1.1): 56 data bytes\n92 bytes from 10.0.0.1: Time to live exceeded\n", ""),
            2: (2, fixture("ping_m_macos_ttl2.txt"), ""),
            3: (0, fixture("ping_m_macos_reached.txt"), ""),
        }

    def default_route(self):
        return dict(self._route)

    def exists(self, p):
        return p in self.have

    def which(self, n):
        for b in self.have:
            if b.endswith("/" + n) or b == n:
                return b
        return None

    def terminal_app_name(self):
        return "Terminal"

    def run_rc(self, argv, timeout=5.0):
        self.calls.append(list(argv))
        b = argv[0]
        if b.endswith("ping") and "-m" in argv:
            ttl = int(argv[argv.index("-m") + 1])
            return self.ping_m.get(ttl, (2, "PING 1.1.1.1 (1.1.1.1): 56 data bytes\n\n--- 1.1.1.1 ping statistics ---\n1 packets transmitted, 0 packets received, 100.0% packet loss\n", ""))
        if b.endswith("ping") and "-t" in argv and "-c" in argv:
            ttl = int(argv[argv.index("-t") + 1])
            if ttl == 1:
                return (1, "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\nFrom 10.0.0.1 icmp_seq=1 Time to live exceeded\n", "")
            if ttl == 2:
                return (1, fixture("ping_t_linux_ttl2.txt"), "")
            return (0, fixture("ping_t_linux_reached.txt"), "")
        if b.endswith("ping6") and "-h" in argv:
            return (2, fixture("ping6_h_macos_ttl2.txt"), "")
        if b.endswith("ping") and "-c" in argv:
            return (0, fixture("ping_macos_c3.txt"), "")
        if b.endswith("traceroute"):
            return (0, fixture("traceroute_macos.txt" if self.name == "darwin" else "traceroute_linux.txt"), "")
        if b.endswith("traceroute6"):
            return (0, "traceroute6 to 2606:4700:4700::1111 (2606:4700:4700::1111) from 2601::1, 12 hops max\n 1  fe80::211:22ff:fe33:4455%en0  2.1 ms\n 2  2001:558:4000::1  15.0 ms\n 3  2606:4700:4700::1111  18.0 ms\n", "")
        if b == "tracepath":
            return (0, fixture("tracepath_linux.txt"), "")
        if b == "mtr":
            return (0, fixture("mtr_linux.txt"), "")
        return None

    def run(self, argv, timeout=5.0):
        r = self.run_rc(argv, timeout)
        return r[1] if r and r[0] == 0 else None


class CommandTracerTests(unittest.TestCase):
    def test_macos_ping_ttl_trick_first(self):
        plat = FakePlatform("darwin", have=("/sbin/ping", "/sbin/ping6", "/usr/sbin/traceroute"))
        ct = CommandTracer(plat)
        hops, method = ct.trace("1.1.1.1", 4, 12)
        self.assertEqual(method, "ping_ttl")
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", "1.1.1.1"])
        self.assertTrue(hops[2].reached)
        self.assertEqual(hops[2].rtt, [30.348])
        self.assertEqual(plat.calls[0], ["/sbin/ping", "-n", "-c", "1", "-m", "1", "-t", "1", "1.1.1.1"])

    def test_macos_v6_falls_through_to_traceroute6(self):
        plat = FakePlatform("darwin", have=("/sbin/ping", "/sbin/ping6", "/usr/sbin/traceroute", "/usr/sbin/traceroute6"))
        ct = CommandTracer(plat)
        hops, method = ct.trace("2606:4700:4700::1111", 6, 12)
        self.assertEqual(method, "traceroute")
        self.assertEqual([h.ip for h in hops], ["fe80::211:22ff:fe33:4455%en0", "2001:558:4000::1", "2606:4700:4700::1111"])
        self.assertTrue(any("ping TTL trick" in e for e in ct.errors))

    def test_destination_is_marked_reached_in_fallback_output(self):
        plat = FakePlatform("linux", have=("traceroute",))
        hops, method = CommandTracer(plat).trace("1.1.1.1", 4, 12)
        self.assertEqual(method, "traceroute")
        self.assertTrue(hops[-1].reached)
        self.assertEqual(hops[-1].ip, "1.1.1.1")
        r = assign_roles(hops, 4, "10.0.0.1", LAN, lambda ip: 5)
        self.assertEqual(r.roles["mid_hop"], "11.0.5.1")  # never 1.1.1.1 itself

    def test_macos_without_ping_uses_traceroute(self):
        plat = FakePlatform("darwin", have=("/usr/sbin/traceroute",))
        ct = CommandTracer(plat)
        hops, method = ct.trace("1.1.1.1", 4, 12)
        self.assertEqual(method, "traceroute")
        self.assertEqual(hops[1].ip, "10.60.235.27")
        self.assertEqual(plat.calls[-1][:3], ["/usr/sbin/traceroute", "-n", "-q"])

    def test_linux_order_tracepath_ping_traceroute_mtr(self):
        plat = FakePlatform("linux", have=("tracepath", "ping", "traceroute", "mtr"))
        hops, method = CommandTracer(plat).trace("1.1.1.1", 4, 12)
        self.assertEqual(method, "tracepath")
        self.assertEqual(hops[1].ip, "10.60.12.1")
        plat = FakePlatform("linux", have=("ping", "traceroute", "mtr"))
        hops, method = CommandTracer(plat).trace("1.1.1.1", 4, 12)
        self.assertEqual(method, "ping_ttl")
        self.assertEqual([h.ip for h in hops], ["10.0.0.1", "10.60.12.1", "1.1.1.1"])
        self.assertEqual(plat.calls[0], ["ping", "-n", "-c", "1", "-t", "1", "-W", "1", "1.1.1.1"])
        plat = FakePlatform("linux", have=("traceroute", "mtr"))
        hops, method = CommandTracer(plat).trace("1.1.1.1", 4, 12)
        self.assertEqual(method, "traceroute")
        plat = FakePlatform("linux", have=("mtr",))
        hops, method = CommandTracer(plat).trace("1.1.1.1", 4, 12)
        self.assertEqual(method, "mtr")
        self.assertEqual(hops[2].ip, None)

    def test_nothing_available(self):
        ct = CommandTracer(FakePlatform("linux", have=()))
        self.assertEqual(ct.trace("1.1.1.1", 4, 12), ([], None))

    def test_echo_check_via_ping_binary(self):
        plat = FakePlatform("darwin", have=("/sbin/ping",))
        ct = CommandTracer(plat)
        self.assertEqual(ct.echo_check("1.1.1.1", 4), 3)
        self.assertEqual(plat.calls[-1], ["/sbin/ping", "-n", "-c", "5", "-i", "0.2", "1.1.1.1"])
        self.assertIsNone(CommandTracer(FakePlatform("darwin", have=())).echo_check("1.1.1.1", 4))


# ---------------------------------------------------------------------------
# Roles / change detection
# ---------------------------------------------------------------------------
def hops_v4(reach=True):
    hs = [Hop(1, "10.0.0.1", [2.0, 2.1]), Hop(2, "10.60.12.1", [14.0, 14.5]), Hop(3, "11.0.1.157", [20.0, 21.0]),
          Hop(4, "11.0.2.9", [16.0, 17.0]), Hop(5, "11.0.3.74", [36.0, 37.0]), Hop(6, "1.1.1.1", [19.0, 20.0])]
    hs[5].reached = reach
    return hs


LAN = ipaddress.ip_network("10.0.0.0/24")


class RoleTests(unittest.TestCase):
    def test_roles_mid_hop_prefers_5ms_farther_hop_that_answers(self):
        counts = {"10.60.12.1": 5, "11.0.1.157": 5, "11.0.2.9": 4, "11.0.3.74": 5}
        asked = []

        def echo(ip):
            asked.append(ip)
            return counts.get(ip, 0)

        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, echo)
        self.assertEqual(r.roles, {"gw": "10.0.0.1", "isp_hop": "10.60.12.1", "mid_hop": "11.0.1.157"})
        self.assertTrue(r.info["isp_hop"]["probed"])
        self.assertEqual(r.info["isp_hop"]["echo_replies"], 5)
        self.assertTrue(r.info["mid_hop"]["probed"])
        self.assertIsNone(r.info["mid_hop"]["reason"])
        self.assertEqual(r.anomalies, [])
        self.assertEqual(asked, ["10.60.12.1", "11.0.1.157"])  # stops at the first qualifying hop

    def test_mid_hop_falls_back_to_first_public_answering_hop(self):
        # 11.0.1.157 (+6 ms) does not answer; 11.0.2.9 is only +2 ms → fallback rule
        counts = {"10.60.12.1": 5, "11.0.1.157": 1, "11.0.2.9": 5, "11.0.3.74": 2}
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: counts.get(ip, 0))
        self.assertEqual(r.roles["mid_hop"], "11.0.2.9")
        self.assertTrue(r.info["mid_hop"]["probed"])
        self.assertIn("first that answers", r.info["mid_hop"]["reason"])

    def test_mid_hop_none_found(self):
        counts = {"10.60.12.1": 5}
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: counts.get(ip, 0))
        self.assertIsNone(r.roles["mid_hop"])
        self.assertFalse(r.info["mid_hop"]["probed"])
        self.assertEqual(r.info["mid_hop"]["reason"], "mid-path hop: none found")
        # the destination itself is never a mid hop
        r = assign_roles([Hop(1, "10.0.0.1", [2.0]), Hop(2, "10.60.1.1", [14.0]), Hop(3, "1.1.1.1", [20.0], reached=True)],
                         4, "10.0.0.1", LAN, lambda ip: 5)
        self.assertIsNone(r.roles["mid_hop"])

    def test_mid_hop_is_sticky_while_the_previous_pick_still_qualifies(self):
        counts = {"10.60.12.1": 5, "11.0.1.157": 5, "11.0.2.9": 5, "11.0.3.74": 5}
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: counts.get(ip, 0), prefer_mid="11.0.2.9")
        self.assertEqual(r.roles["mid_hop"], "11.0.2.9")  # not the +5 ms rule's 11.0.1.157
        self.assertTrue(r.info["mid_hop"]["kept"])
        self.assertIsNone(r.info["mid_hop"]["reason"])
        # the previous pick stopped answering → normal selection
        counts["11.0.2.9"] = 1
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: counts.get(ip, 0), prefer_mid="11.0.2.9")
        self.assertEqual(r.roles["mid_hop"], "11.0.1.157")
        self.assertNotIn("kept", r.info["mid_hop"])
        # the previous pick left the path → normal selection
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: 5, prefer_mid="9.9.9.9")
        self.assertEqual(r.roles["mid_hop"], "11.0.1.157")
        # the isp hop itself can never be kept as the mid hop
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: 5, prefer_mid="10.60.12.1")
        self.assertEqual(r.roles["mid_hop"], "11.0.1.157")

    def test_isp_hop_not_answering_direct_echo_is_listed_not_probed(self):
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: 2)
        self.assertEqual(r.roles["isp_hop"], "10.60.12.1")
        self.assertFalse(r.info["isp_hop"]["probed"])
        self.assertIn("does not answer direct echo (2/5)", r.info["isp_hop"]["reason"])
        r = assign_roles(hops_v4(), 4, "10.0.0.1", LAN, lambda ip: None)  # no method at all
        self.assertFalse(r.info["isp_hop"]["probed"])
        self.assertIn("?/5", r.info["isp_hop"]["reason"])
        self.assertIsNone(r.roles["mid_hop"])

    def test_isp_hop_skips_lan_hops_and_accepts_any_address(self):
        hs = [Hop(1, "10.0.0.1", [2.0]), Hop(2, "10.0.0.254", [3.0]), Hop(3, "73.1.2.3", [15.0]), Hop(4, "1.1.1.1", [20.0], reached=True)]
        r = assign_roles(hs, 4, "10.0.0.1", LAN, lambda ip: 5)
        self.assertEqual(r.roles["isp_hop"], "73.1.2.3")
        hs = [Hop(1, "10.0.0.1", [2.0]), Hop(2, None, [None]), Hop(3, "10.60.1.1", [15.0]), Hop(4, "1.1.1.1", [20.0], reached=True)]
        r = assign_roles(hs, 4, "10.0.0.1", LAN, lambda ip: 5)
        self.assertEqual(r.roles["isp_hop"], "10.60.1.1")
        hs = [Hop(1, "10.0.0.1", [2.0]), Hop(2, None, [None]), Hop(3, None, [None])]
        r = assign_roles(hs, 4, "10.0.0.1", LAN, lambda ip: 5)
        self.assertIsNone(r.roles["isp_hop"])
        self.assertIn("no hop past the gateway", r.info["isp_hop"]["reason"])

    def test_gateway_anomalies(self):
        r = assign_roles(hops_v4(), 4, "10.0.0.254", LAN, lambda ip: 5)
        self.assertEqual(len(r.anomalies), 1)
        self.assertIn("not your gateway", r.anomalies[0])
        self.assertIn("VPN", r.anomalies[0])
        # a silent TTL-1 with a known default gateway is NOT an anomaly (ICMP-error rate limiting on the
        # XB7 was observed live): the gateway is assumed and the isp hop is still found
        hs = hops_v4()
        hs[0] = Hop(1, None, [None, None])
        r = assign_roles(hs, 4, "10.0.0.1", LAN, lambda ip: 5)
        self.assertEqual(r.anomalies, [])
        self.assertEqual(r.roles["gw"], "10.0.0.1")
        self.assertTrue(r.info["gw"]["assumed"])
        self.assertEqual(len(r.reasons), 1)
        self.assertIn("assuming the default gateway 10.0.0.1", r.reasons[0])
        self.assertEqual(r.roles["isp_hop"], "10.60.12.1")
        # without any known gateway it is an anomaly
        r = assign_roles(hs, 4, None, LAN, lambda ip: 5)
        self.assertIn("did not answer TTL-1", r.anomalies[0])
        self.assertIsNone(r.roles["gw"])
        r = assign_roles([], 4, "10.0.0.1", LAN, lambda ip: 5)
        self.assertEqual(r.roles["gw"], "10.0.0.1")
        self.assertIsNone(r.roles["isp_hop"])

    def test_v6_roles(self):
        hs = [Hop(1, "fe80::211:22ff:fe33:4455", [2.0]), Hop(2, "2001:558:4000::1", [15.0]),
              Hop(3, "2001:558:4000::2", [25.0]), Hop(4, "2606:4700:4700::1111", [18.0], reached=True)]
        r = assign_roles(hs, 6, "fe80::211:22ff:fe33:4455", None, lambda ip: 5)
        self.assertEqual(r.roles, {"gw6": "fe80::211:22ff:fe33:4455", "isp_hop6": "2001:558:4000::1"})
        self.assertNotIn("mid_hop6", r.roles)
        self.assertTrue(r.info["isp_hop6"]["probed"])

    def test_v6_gateway_global_address_matches_by_interface_id(self):
        # live: the TTL-1 responder is the XB7's global address, the default route names its link-local one
        hs = [Hop(1, "2601:abcd:4321:abe0:211:22ff:fe33:4455", [4.8, 3.7]), Hop(2, "2001:558:aaaa:bbbb::2", [22.0, 83.2]),
              Hop(3, "2001:558:aaaa:cccc::1", [22.8, 80.1]), Hop(4, "2606:4700:4700::1111", [27.7], reached=True)]
        r = assign_roles(hs, 6, "fe80::211:22ff:fe33:4455", None, lambda ip: 5)
        self.assertEqual(r.anomalies, [])
        self.assertEqual(r.roles["gw6"], "2601:abcd:4321:abe0:211:22ff:fe33:4455")
        self.assertEqual(r.roles["isp_hop6"], "2001:558:aaaa:bbbb::2")
        # a different router at TTL 1 is still an anomaly
        hs[0] = Hop(1, "2601:abcd:4321:abe0::1", [4.0])
        r = assign_roles(hs, 6, "fe80::211:22ff:fe33:4455", None, lambda ip: 5)
        self.assertEqual(len(r.anomalies), 1)
        self.assertFalse(pathmod._same_iid("10.0.0.1", "fe80::1"))
        self.assertFalse(pathmod._same_iid("fe80::1", "garbage"))

    def test_path_changed(self):
        new = hops_v4()
        roles = {"gw": "10.0.0.1", "isp_hop": "10.60.12.1", "mid_hop": "11.0.1.157"}
        old = [h.to_dict() for h in hops_v4()]
        self.assertFalse(path_changed(None, new, None, roles))
        self.assertFalse(path_changed(old, new, roles, roles))
        flaky = hops_v4()
        flaky[2] = Hop(3, None, [None, None])
        self.assertFalse(path_changed(old, flaky, roles, dict(roles, mid_hop=None)))
        self.assertFalse(path_changed([h.to_dict() for h in flaky], new, dict(roles, mid_hop=None), roles))
        moved = hops_v4()
        moved[1] = Hop(2, "10.60.99.1", [14.0])
        self.assertTrue(path_changed(old, moved, roles, dict(roles, isp_hop="10.60.99.1")))
        # a mid-hop re-pick along the same path is not a route change; a mid hop that left the path is
        self.assertFalse(path_changed(old, new, dict(roles, mid_hop="11.0.2.9"), roles))
        self.assertTrue(path_changed(old, new, dict(roles, mid_hop="9.9.9.9"), roles))


# ---------------------------------------------------------------------------
# Tracer component
# ---------------------------------------------------------------------------
class FakeNative:
    """A scripted NativeTracer stand-in: ``script[dst]`` = hops; ``echo[ip]`` = replies to 5 echoes."""

    def __init__(self, family, script, echo, fail_open=False, method=None):
        self.family = family
        self.script = script
        self.echo = echo
        self.fail_open = fail_open
        self.method = method or ("native" if family == 4 else "native")
        self.last_error = None
        self.opened = False
        self.closed = False
        self.traces = []
        self.checks = []

    def open(self):
        if self.fail_open:
            raise PermissionError(errno.EACCES, "no tracer socket")
        self.opened = True

    def close(self):
        self.closed = True

    def trace(self, dst, max_ttl, probes=2, **kw):
        self.traces.append((dst, max_ttl, probes))
        hops = self.script.get(dst)
        if callable(hops):
            hops = hops()
        return [Hop(h.ttl, h.ip, list(h.rtt), reached=h.reached) for h in (hops or [])]

    def echo_check(self, ip, **kw):
        self.checks.append(ip)
        return self.echo.get(ip, 0)


class FakeStore:
    def __init__(self, rows=None):
        self.rows = {"path": list(rows or [])}
        self.saved = {}

    def read_json(self, name):
        return list(self.rows.get(name, []))

    def append_json(self, name, obj):
        self.rows.setdefault(name, []).append(dict(obj))

    def write_json_atomic(self, name, obj, indent=1):
        self.saved[name] = obj


def rdns(ip):
    if ip.startswith("10.60."):
        return ("be-1-cr01.comcast.net", [], [ip])
    if ip.startswith("96."):
        return ("ae-1.cbr01.ibone.comcast.net", [], [ip])
    raise socket.herror(1, "unknown")


HOPS6 = [Hop(1, "fe80::211:22ff:fe33:4455", [2.0, 2.2]), Hop(2, "2001:558:4000::1", [15.0, 15.5]),
         Hop(3, "2606:4700:4700::1111", [18.0, 18.2], reached=True)]


class TracerHarness:
    def __init__(self, script=None, echo=None, store=None, cfg=None, platform=None, route=None, fail_open=False,
                 with_engine=True):
        self.state = State(1_760_000_000.0, "s", cfg=cfg or {})
        self.store = store or FakeStore()
        self.platform = platform or FakePlatform("darwin", have=("/sbin/ping", "/sbin/ping6", "/usr/sbin/traceroute", "/usr/sbin/traceroute6"))
        self.cfg = cfg or {"path": {"discover_interval_s": 1800, "max_ttl": 12, "sweep_on_episode": True}, "hop_rate_hz": 2}
        route = route if route is not None else self.platform.default_route()
        self.ctx = types.SimpleNamespace(state=self.state, store=self.store, platform=self.platform, cfg=self.cfg,
                                         route=route, component=lambda n: object() if (n == "engine" and with_engine) else None)
        self.script = script if script is not None else {pathmod.DST4: hops_v4(), pathmod.DST6: HOPS6}
        self.echo = echo if echo is not None else {"10.60.12.1": 5, "11.0.1.157": 5, "2001:558:4000::1": 4}
        self.natives = {}
        self.clock = FakeClock()
        self.wall = {"t": 1_760_000_100.0}

        def factory(fam):
            nt = FakeNative(fam, self.script, self.echo, fail_open=fail_open)
            self.natives[fam] = nt
            return nt

        self.tracer = Tracer(self.ctx, native_factory=factory, clock=self.clock, wall=lambda: self.wall["t"], rdns=rdns,
                             engine_wait_s=0.2)

    def notes(self, kind=None):
        return [n for n in self.state.drain_notes() if kind is None or n["type"] == kind]


class TracerTests(unittest.TestCase):
    def test_discovery_assigns_roles_adds_gated_targets_and_publishes(self):
        h = TracerHarness()
        doc = h.tracer.discover("start")
        self.assertIsNotNone(doc)
        self.assertEqual(doc["roles"], {"gw": "10.0.0.1", "isp_hop": "10.60.12.1", "mid_hop": "11.0.1.157",
                                        "gw6": "fe80::211:22ff:fe33:4455", "isp_hop6": "2001:558:4000::1"})
        self.assertEqual(doc["method"], "native")
        self.assertEqual(doc["method6"], "native")
        self.assertEqual([x["ip"] for x in doc["v4"]], [x.ip for x in hops_v4()])
        self.assertEqual(doc["v4"][1]["rdns"], "be-1-cr01.comcast.net")
        self.assertEqual([x["ip"] for x in doc["v6"]], [x.ip for x in HOPS6])
        self.assertEqual(doc["discovered_at"], 1_760_000_100.0)
        self.assertEqual(doc["changes"], 0)
        self.assertEqual(len(doc["history"]), 2)
        self.assertFalse(doc["running"])
        for k in ("v4", "v6", "roles", "discovered_at", "changes", "history", "method"):
            self.assertIn(k, doc)
        # targets: isp_hop4 + mid_hop4 + isp_hop6 (all answer ≥ 3/5 direct echoes)
        isp = h.state.target("isp_hop4")
        self.assertEqual((isp.role, isp.addr, isp.family, isp.kind, isp.rate_hz, isp.mode), ("isp_hop", "10.60.12.1", 4, "icmp", 2.0, "direct"))
        self.assertEqual(isp.label, "Comcast hop 10.60.12.1")
        self.assertTrue(isp.enabled)
        self.assertEqual(isp.extra["rdns"], "be-1-cr01.comcast.net")
        self.assertEqual(h.state.target("mid_hop4").addr, "11.0.1.157")
        self.assertEqual(h.state.target("mid_hop4").label, "Mid-path hop 11.0.1.157")
        self.assertEqual(h.state.target("isp_hop6").addr, "2001:558:4000::1")
        self.assertEqual(h.state.target("isp_hop6").family, 6)
        self.assertIn("targets.json", h.store.saved)
        keys = [t["key"] for t in h.store.saved["targets.json"]["targets"]]
        self.assertEqual(keys, ["isp_hop4", "mid_hop4", "isp_hop6"])
        self.assertEqual(doc["role_info"]["isp_hop"]["target"], "isp_hop4")
        # state.path mirrors current(); the latest 'path' row exists; path.jsonl has one row per destination
        self.assertEqual(h.state.path["roles"], doc["roles"])
        self.assertEqual(h.state.latest("path")["roles"], doc["roles"])
        rows = h.store.rows["path"]
        self.assertEqual([r["dst"] for r in rows], [pathmod.DST4, pathmod.DST6])
        self.assertEqual(rows[0]["method"], "native")
        self.assertFalse(rows[0]["changed"])
        self.assertEqual(rows[0]["reason"], "start")
        self.assertEqual(rows[0]["hops"][0]["ip"], "10.0.0.1")
        self.assertEqual(h.notes(), [])
        self.assertEqual(h.natives[4].checks, ["10.60.12.1", "11.0.1.157"])
        self.assertEqual(h.tracer.current()["next_discovery"], 1_760_000_100.0 + 1800)

    def test_hop_not_answering_direct_echo_is_listed_but_not_probed(self):
        h = TracerHarness(echo={"10.60.12.1": 2, "11.0.1.157": 5, "11.0.2.9": 5})
        doc = h.tracer.discover()
        self.assertEqual(doc["roles"]["isp_hop"], "10.60.12.1")
        self.assertIsNone(h.state.target("isp_hop4"))
        self.assertFalse(doc["role_info"]["isp_hop"]["probed"])
        self.assertIn("does not answer direct echo (2/5)", doc["role_info"]["isp_hop"]["reason"])
        self.assertEqual(h.state.target("mid_hop4").addr, "11.0.1.157")
        # later the hop stops answering → its target is disabled with the reason, not removed
        h.echo["11.0.1.157"] = 0
        h.echo["11.0.2.9"] = 0
        h.tracer.discover()
        t = h.state.target("mid_hop4")
        self.assertFalse(t.enabled)
        self.assertIn("none found", t.reason)
        # and comes back when it answers again
        h.echo["11.0.1.157"] = 5
        h.tracer.discover()
        self.assertTrue(h.state.target("mid_hop4").enabled)
        self.assertIsNone(h.state.target("mid_hop4").reason)

    def test_route_change_note_and_counter(self):
        h = TracerHarness()
        h.tracer.discover("start")
        self.assertEqual(h.notes("route_change"), [])
        moved = hops_v4()
        moved[1] = Hop(2, "10.60.99.1", [14.0, 14.1])
        h.script[pathmod.DST4] = moved
        h.echo["10.60.99.1"] = 5
        h.wall["t"] += 1800
        doc = h.tracer.discover("interval")
        notes = h.notes("route_change")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["severity"], 2)
        self.assertEqual(notes[0]["peak"]["old"][1], "10.60.12.1")
        self.assertEqual(notes[0]["peak"]["new"][1], "10.60.99.1")
        self.assertEqual(notes[0]["peak"]["dst"], pathmod.DST4)
        self.assertEqual(doc["changes"], 1)
        self.assertTrue(h.store.rows["path"][-2]["changed"])
        # the isp_hop4 target follows the new address in place (same id)
        t = h.state.target("isp_hop4")
        self.assertEqual(t.addr, "10.60.99.1")
        self.assertEqual(len([k for k in h.state.by_key if k.startswith("isp_hop")]), 2)
        # a hop that merely stops answering is not a route change
        flaky = hops_v4()
        flaky[1] = Hop(2, "10.60.99.1", [14.0, 14.1])
        flaky[2] = Hop(3, None, [None, None])
        h.script[pathmod.DST4] = flaky
        h.tracer.discover("interval")
        self.assertEqual(h.notes("route_change"), [])
        self.assertEqual(h.tracer.current()["changes"], 1)

    def test_mid_hop_stays_put_across_discoveries(self):
        # +5 ms rule: 11.0.1.157 (+6 ms) is silent, 11.0.2.9 is only +2 ms → 11.0.3.74 (+22 ms)
        h = TracerHarness(echo={"10.60.12.1": 5, "11.0.1.157": 1, "11.0.2.9": 5, "11.0.3.74": 5})
        h.tracer.discover("start")
        self.assertEqual(h.state.target("mid_hop4").addr, "11.0.3.74")
        # next time 11.0.1.157 answers and would win the +5 ms rule; the previous pick is kept
        h.echo["11.0.1.157"] = 5
        h.wall["t"] += 1800
        doc = h.tracer.discover("interval")
        self.assertEqual(doc["roles"]["mid_hop"], "11.0.3.74")
        self.assertTrue(doc["role_info"]["mid_hop"]["kept"])
        self.assertEqual(h.notes("route_change"), [])
        self.assertEqual(doc["changes"], 0)
        # once it stops answering the role moves (still along the same path → no route_change)
        h.echo["11.0.3.74"] = 0
        doc = h.tracer.discover("interval")
        self.assertEqual(doc["roles"]["mid_hop"], "11.0.1.157")
        self.assertEqual(h.state.target("mid_hop4").addr, "11.0.1.157")
        self.assertEqual(h.notes("route_change"), [])

    def test_resume_seeds_history_and_detects_change_against_the_last_row(self):
        prev = {"t": 1_760_000_000.0, "dst": pathmod.DST4, "family": 4, "hops": [x.to_dict() for x in hops_v4()],
                "roles": {"gw": "10.0.0.1", "isp_hop": "10.60.12.1", "mid_hop": "11.0.1.157"}, "method": "native"}
        store = FakeStore(rows=[prev, {"t": 1_760_000_050.0, "sweep": True, "hops": []}])
        h = TracerHarness(store=store)
        h.state.path["changes"] = 3
        h.tracer = Tracer(h.ctx, native_factory=lambda fam: FakeNative(fam, h.script, h.echo), clock=h.clock,
                          wall=lambda: h.wall["t"], rdns=rdns, engine_wait_s=0.2)
        cur = h.tracer.current()
        self.assertEqual(cur["history"], [prev])
        self.assertEqual(cur["discovered_at"], 1_760_000_000.0)
        self.assertEqual(cur["changes"], 3)
        moved = hops_v4()
        moved[2] = Hop(3, "11.0.1.200", [20.0, 21.0])
        h.script[pathmod.DST4] = moved
        h.echo["11.0.1.200"] = 5
        h.tracer.discover("start")
        self.assertEqual(len(h.notes("route_change")), 1)
        self.assertEqual(h.tracer.current()["changes"], 4)

    def test_path_anomaly_when_first_hop_is_not_the_gateway(self):
        h = TracerHarness(route={"gateway": "10.0.0.254", "iface": "en0", "lan_ip": "10.0.0.35", "prefixlen": 24,
                                 "gateway6": None})
        h.platform._route = dict(h.ctx.route)
        h.tracer.discover()
        notes = h.notes("path_anomaly")
        self.assertEqual(len(notes), 1)
        self.assertIn("not your gateway", notes[0]["note"])
        self.assertEqual(notes[0]["peak"]["family"], 4)
        # v6 skipped without a v6 default route
        self.assertEqual(h.natives.get(6), None)
        self.assertIn("IPv6 path skipped: no IPv6 default route", h.tracer.current()["reasons"])

    def test_silent_gateway_is_a_reason_not_an_anomaly(self):
        hs = hops_v4()
        hs[0] = Hop(1, None, [None, None])
        h = TracerHarness(script={pathmod.DST4: hs, pathmod.DST6: HOPS6})
        doc = h.tracer.discover()
        self.assertEqual(h.notes("path_anomaly"), [])
        self.assertEqual(doc["roles"]["gw"], "10.0.0.1")
        self.assertTrue(doc["role_info"]["gw"]["assumed"])
        self.assertTrue(any("assuming the default gateway" in r for r in doc["reasons"]))
        self.assertEqual(doc["roles"]["isp_hop"], "10.60.12.1")

    def test_native_unavailable_falls_back_to_commands(self):
        h = TracerHarness(fail_open=True)
        doc = h.tracer.discover()
        self.assertEqual(doc["method"], "ping_ttl")
        self.assertEqual([x["ip"] for x in doc["v4"]], ["10.0.0.1", "10.60.12.1", "1.1.1.1"])
        self.assertEqual(doc["method6"], "traceroute")
        self.assertIn("native TTL probing unavailable (IPv4)", doc["errors"]["4"][0])
        # echo gating through the ping binary (fixture: 3/3 answered → probed)
        self.assertIsNotNone(h.state.target("isp_hop4"))
        self.assertEqual(h.state.target("isp_hop4").addr, "10.60.12.1")

    def test_native_answers_nothing_then_commands(self):
        h = TracerHarness(script={pathmod.DST4: [Hop(t) for t in range(1, 13)], pathmod.DST6: []},
                          route={"gateway": "10.0.0.1", "iface": "en0", "lan_ip": "10.0.0.35", "prefixlen": 24, "gateway6": None})
        h.platform._route = dict(h.ctx.route)
        doc = h.tracer.discover()
        self.assertEqual(doc["method"], "ping_ttl")
        self.assertTrue(any("native: no hop answered" in e for e in doc["errors"]["4"]))

    def test_no_method_at_all_records_the_reason(self):
        plat = FakePlatform("darwin", have=())
        h = TracerHarness(fail_open=True, platform=plat)
        doc = h.tracer.discover()
        self.assertIsNone(doc["method"])
        self.assertEqual(doc["v4"], [])
        self.assertTrue(any(r.startswith("IPv4: no hop answered") for r in doc["reasons"]))
        self.assertIn("error", h.store.rows["path"][0])
        self.assertEqual(h.state.target("isp_hop4"), None)

    def test_rediscover_is_async_and_refuses_while_running(self):
        h = TracerHarness()
        self.assertTrue(h.tracer.rediscover("api"))
        self.assertFalse(h.tracer.rediscover("api"))  # already queued
        h.tracer._jobs.clear()
        h.tracer.running = True
        self.assertFalse(h.tracer.rediscover())
        self.assertIsNone(h.tracer.discover())
        h.tracer.running = False

    def test_sweep_rate_limit_and_episode_attachment(self):
        h = TracerHarness()
        ep = h.state.add_episode(Episode(id="ep-000001", t0=1_760_000_090.0))
        closed = h.state.add_episode(Episode(id="ep-000002", t0=1_760_000_095.0, t1=1_760_000_099.0))
        self.assertTrue(h.tracer.sweep("episode"))
        self.assertFalse(h.tracer.sweep("episode"))  # queued already / rate-limited
        kind, reason = h.tracer._jobs.popleft()
        self.assertEqual((kind, reason), ("sweep", "episode"))
        doc = h.tracer.run_sweep(reason)
        self.assertEqual(doc["episode"], "ep-000001")
        self.assertEqual(ep.sweep["dst"], pathmod.DST4)
        self.assertEqual([x["ip"] for x in ep.sweep["hops"]], [x.ip for x in hops_v4()])
        self.assertEqual(ep.sweep["hops"][0]["loss"], 0)
        self.assertEqual(ep.sweep["method"], "native")
        self.assertIsNone(closed.sweep)
        self.assertEqual(h.natives[4].traces[-1], (pathmod.DST4, 12, 1))
        row = h.store.rows["path"][-1]
        self.assertTrue(row["sweep"])
        self.assertEqual(row["episode"], "ep-000001")
        self.assertEqual(h.tracer.current()["last_sweep"]["episode"], "ep-000001")
        # a sweep does not touch the roles / history
        self.assertEqual(h.tracer.current()["history"], [])
        # rate limit: 59 s later still refused, 60 s later accepted
        h.clock.m += 59
        self.assertFalse(h.tracer.sweep())
        h.clock.m += 1.5
        self.assertTrue(h.tracer.sweep())
        # no open episode: the sweep still runs and is written, without an episode id
        h.tracer._jobs.clear()
        ep.t1 = 1_760_000_120.0
        doc = h.tracer.run_sweep("manual")
        self.assertNotIn("episode", doc)

    def test_sweep_disabled_by_config(self):
        h = TracerHarness(cfg={"path": {"sweep_on_episode": False}, "hop_rate_hz": 2})
        self.assertFalse(h.tracer.sweep("episode"))
        self.assertEqual(list(h.tracer._jobs), [])

    def test_periodic_triggers(self):
        h = TracerHarness()
        h.tracer.discover("start")
        # interval
        h.clock.m = h.tracer._next_discovery + 1
        h.tracer._periodic()
        self.assertEqual(list(h.tracer._jobs), [("discover", "interval")])
        h.tracer._jobs.clear()
        # gateway change
        h.platform._route["gateway"] = "10.0.0.254"
        h.clock.m += pathmod.ROUTE_POLL_S + 1
        h.tracer._periodic()
        self.assertEqual(list(h.tracer._jobs), [("discover", "gateway change")])
        h.tracer._jobs.clear()
        # isp_hop4 silent for 5 min (no received sample since it was added)
        h.wall["t"] += pathmod.ISP_SILENT_S + 1
        h.clock.m += pathmod.ISP_SILENT_S + 1
        h.tracer._periodic()
        self.assertIn(("discover", "isp_hop4 silent for 5 min"), list(h.tracer._jobs))

    def test_stop_during_a_slow_discovery_is_not_an_error(self):
        h = TracerHarness()
        started = threading.Event()
        release = threading.Event()

        def slow():
            started.set()
            release.wait(5)
            if h.tracer._stop.is_set():
                raise RuntimeError("socket closed under us")  # an OSError would merely trigger the command fallback
            return hops_v4()

        h.script[pathmod.DST4] = slow
        with self.assertLogs("laglens.path", level="INFO") as cm:
            h.tracer.start()
            self.assertTrue(started.wait(5))
            h.tracer._stop.set()
            release.set()
            h.tracer.stop(3.0)
        self.assertFalse(h.tracer._thread.is_alive())
        self.assertFalse(any("failed" in line for line in cm.output), cm.output)
        self.assertTrue(any("interrupted by shutdown" in line for line in cm.output), cm.output)
        self.assertFalse(h.tracer.running)

    def test_thread_lifecycle_runs_the_start_discovery(self):
        h = TracerHarness()
        h.tracer.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and h.tracer.current()["discovered_at"] is None:
            time.sleep(0.02)
        self.assertIsNotNone(h.tracer.current()["discovered_at"])
        self.assertEqual(h.state.collector("tracer")["status"], "ok")
        self.assertTrue(h.tracer.rediscover("api"))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(h.store.rows["path"]) < 4:
            time.sleep(0.02)
        self.assertEqual(len(h.store.rows["path"]), 4)
        h.tracer.stop(2.0)
        self.assertFalse(h.tracer._thread.is_alive())
        self.assertTrue(all(nt.closed for nt in h.natives.values()))

    def test_discovery_exception_does_not_kill_the_thread(self):
        h = TracerHarness()

        def boom():
            raise RuntimeError("tracer bug")

        h.script[pathmod.DST4] = boom
        h.tracer.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not h.natives.get(4):
            time.sleep(0.02)
        time.sleep(0.2)
        self.assertTrue(h.tracer._thread.is_alive())
        self.assertFalse(h.tracer.running)
        h.script[pathmod.DST4] = hops_v4()
        self.assertTrue(h.tracer.rediscover())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and h.tracer.current()["discovered_at"] is None:
            time.sleep(0.02)
        self.assertIsNotNone(h.tracer.current()["discovered_at"])
        h.tracer.stop(2.0)


if __name__ == "__main__":
    unittest.main()
