"""Tests for laglens.probes.icmp: echo build, reply/TTL-exceeded parsing, errqueue, sockaddr."""
import errno
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.probes import icmp  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "icmp")
COOKIE = 0x11223344


def fixture_bytes(name: str) -> bytes:
    with open(os.path.join(FIX, name + ".hex"), "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                return bytes.fromhex(line)
    raise AssertionError("empty fixture %s" % name)


class ChecksumTests(unittest.TestCase):
    def test_known_vector(self):
        # IPv4 header example (RFC 1071 style), checksum field zeroed → 0xB1E6
        hdr = bytes.fromhex("4500003c1c4640004006" + "0000" + "ac100a63ac100a0c")
        self.assertEqual(icmp.checksum(hdr), 0xB1E6)

    def test_odd_length_padded(self):
        self.assertEqual(icmp.checksum(b"\x01\x02\x03"), icmp.checksum(b"\x01\x02\x03\x00"))

    def test_packet_with_checksum_verifies_to_zero(self):
        pkt = icmp.build_echo(4, 5, 1, 99, cookie=COOKIE)
        self.assertEqual(icmp.checksum(pkt), 0)


class BuildTests(unittest.TestCase):
    def test_v4_echo_layout(self):
        pkt = icmp.build_echo(4, 0x1_0005, 3, 123456789, ident=0xBEEF, cookie=COOKIE)
        self.assertEqual(len(pkt), 8 + icmp.PAYLOAD_SIZE_NORMAL)
        t, c, cs, ident, seq = icmp.ICMP_HEADER.unpack_from(pkt, 0)
        self.assertEqual((t, c, ident, seq), (8, 0, 0xBEEF, 0x0005))  # header seq is 16 bit
        self.assertNotEqual(cs, 0)
        p = icmp.parse_payload(pkt[8:])
        self.assertEqual((p.magic, p.cookie, p.target_id, p.seq, p.t_send_ns, p.kind, p.extra),
                         (b"LGLN", COOKIE, 3, 0x1_0005, 123456789, 0, 0))
        self.assertTrue(p.matches(COOKIE))
        self.assertFalse(p.matches(COOKIE + 1))

    def test_v6_echo_leaves_checksum_to_kernel(self):
        pkt = icmp.build_echo(6, 1, 2, 3, ident=7, cookie=COOKIE, kind=icmp.PKIND_TTL, extra=9)
        t, c, cs, ident, seq = icmp.ICMP_HEADER.unpack_from(pkt, 0)
        self.assertEqual((t, c, cs, ident, seq), (128, 0, 0, 7, 1))
        p = icmp.parse_payload(pkt[8:])
        self.assertEqual((p.kind, p.extra), (icmp.PKIND_TTL, 9))

    def test_payload_padding_and_minimum(self):
        self.assertEqual(len(icmp.build_payload(1, 1, 1, size=56)), 56)
        self.assertEqual(len(icmp.build_payload(1, 1, 1, size=10)), icmp.PAYLOAD_MIN)
        self.assertEqual(icmp.build_payload(1, 1, 1, size=56)[28:], b"\x00" * 28)

    def test_default_cookie_and_ident(self):
        pkt = icmp.build_echo(4, 1, 1, 1)
        p = icmp.parse_payload(pkt[8:])
        self.assertTrue(p.matches())
        self.assertEqual(icmp.ICMP_HEADER.unpack_from(pkt, 0)[3], icmp.IDENT)
        self.assertEqual(icmp.IDENT, os.getpid() & 0xFFFF)

    def test_parse_payload_short(self):
        self.assertIsNone(icmp.parse_payload(b"LGLN" + b"\x00" * 10))


class ParseReplyTests(unittest.TestCase):
    def setUp(self):
        self.req = icmp.build_echo(4, 42, 7, 1000, ident=0xBEEF, cookie=COOKIE)
        self.req6 = icmp.build_echo(6, 43, 8, 2000, ident=0xBEEF, cookie=COOKIE)

    def test_macos_style_ihl5(self):
        buf = icmp.ipv4_header("1.1.1.1", "10.0.0.35", len(self.req), ttl=57) + icmp.echo_reply_for(self.req, 4)
        r = icmp.parse_reply(4, buf, has_ip_header=True)
        self.assertTrue(r.is_echo_reply)
        self.assertEqual((r.ident, r.seq, r.ttl), (0xBEEF, 42, 57))
        self.assertEqual((r.payload.target_id, r.payload.seq), (7, 42))
        self.assertTrue(r.payload.matches(COOKIE))
        self.assertFalse(r.is_error)

    def test_macos_style_ihl6_options(self):
        buf = icmp.ipv4_header("1.1.1.1", "10.0.0.35", len(self.req), ihl_words=6) + icmp.echo_reply_for(self.req, 4)
        self.assertEqual(buf[0] & 0x0F, 6)
        r = icmp.parse_reply(4, buf, has_ip_header=True)
        self.assertTrue(r.is_echo_reply)
        self.assertEqual((r.payload.target_id, r.payload.seq), (7, 42))

    def test_linux_style_no_header(self):
        buf = icmp.echo_reply_for(self.req, 4)
        r = icmp.parse_reply(4, buf, has_ip_header=False)
        self.assertTrue(r.is_echo_reply)
        self.assertIsNone(r.ttl)
        self.assertEqual(r.payload.seq, 42)

    def test_wrong_layout_assumption_is_rejected(self):
        # Linux bytes parsed as macOS: first nibble is the ICMP type 0, not IP version 4 → None
        self.assertIsNone(icmp.parse_reply(4, icmp.echo_reply_for(self.req, 4), has_ip_header=True))
        self.assertIsNone(icmp.parse_reply(4, b"\x45\x00", has_ip_header=True))
        self.assertIsNone(icmp.parse_reply(6, b"\x81\x00\x00", has_ip_header=False))

    def test_v6_echo_reply(self):
        r = icmp.parse_reply(6, icmp.echo_reply_for(self.req6, 6), has_ip_header=False)
        self.assertTrue(r.is_echo_reply)
        self.assertEqual((r.type, r.seq, r.payload.target_id, r.payload.seq), (129, 43, 8, 43))

    def test_v4_time_exceeded_8_byte_quote(self):
        te = icmp.time_exceeded_for(self.req, 4, "10.0.0.35", "1.1.1.1", quote=8)
        buf = icmp.ipv4_header("10.60.1.1", "10.0.0.35", len(te)) + te
        r = icmp.parse_reply(4, buf, has_ip_header=True)
        self.assertTrue(r.is_time_exceeded)
        self.assertTrue(r.is_error)
        self.assertFalse(r.is_echo_reply)
        self.assertEqual((r.inner.type, r.inner.ident, r.inner.seq), (8, 0xBEEF, 42))
        self.assertIsNone(r.inner.payload)  # only 8 bytes quoted
        self.assertEqual(r.inner.dst, "1.1.1.1")

    def test_v4_time_exceeded_full_quote_linux_layout(self):
        te = icmp.time_exceeded_for(self.req, 4, "10.0.0.35", "1.1.1.1", quote=len(self.req))
        r = icmp.parse_reply(4, te, has_ip_header=False)
        self.assertTrue(r.is_time_exceeded)
        self.assertEqual(r.inner.payload.seq, 42)
        self.assertTrue(r.inner.payload.matches(COOKIE))

    def test_v4_unreachable(self):
        te = icmp.time_exceeded_for(self.req, 4, "10.0.0.35", "10.0.0.23", quote=8)
        te = bytes([icmp.ICMP4_DEST_UNREACH, 1]) + te[2:]
        r = icmp.parse_reply(4, te, has_ip_header=False)
        self.assertTrue(r.is_unreachable)
        self.assertEqual(r.code, 1)
        self.assertEqual((r.inner.ident, r.inner.seq, r.inner.dst), (0xBEEF, 42, "10.0.0.23"))

    def test_v6_time_exceeded_with_and_without_quote(self):
        te = icmp.time_exceeded_for(self.req6, 6, "2601::1", "2606:4700:4700::1111", quote=8)
        r = icmp.parse_reply(6, te, has_ip_header=False)
        self.assertTrue(r.is_time_exceeded)
        self.assertEqual((r.inner.type, r.inner.ident, r.inner.seq), (128, 0xBEEF, 43))
        self.assertIsNone(r.inner.payload)
        self.assertEqual(r.inner.dst, "2606:4700:4700::1111")
        te = icmp.time_exceeded_for(self.req6, 6, "2601::1", "2606:4700:4700::1111", quote=64)
        r = icmp.parse_reply(6, te, has_ip_header=False)
        self.assertEqual(r.inner.payload.seq, 43)

    def test_v6_inner_with_extension_header(self):
        # inner IPv6 header → hop-by-hop ext header (8 bytes) → ICMPv6
        ext = bytes([58, 0]) + b"\x00" * 6
        ip = icmp.ipv6_header("2601::1", "2606:4700:4700::1111", len(ext) + 8, nxt=0)
        body = struct.pack("!BBHI", icmp.ICMP6_TIME_EXCEEDED, 0, 0, 0) + ip + ext + self.req6[:8]
        r = icmp.parse_reply(6, body, has_ip_header=False)
        self.assertEqual((r.inner.ident, r.inner.seq), (0xBEEF, 43))
        bad = struct.pack("!BBHI", icmp.ICMP6_TIME_EXCEEDED, 0, 0, 0) + icmp.ipv6_header("2601::1", "::1", 8, nxt=17) + self.req6[:8]
        self.assertIsNone(icmp.parse_reply(6, bad, has_ip_header=False).inner)

    def test_truncated_inner_is_none_not_crash(self):
        te = icmp.time_exceeded_for(self.req, 4, "10.0.0.35", "1.1.1.1", quote=8)[:20]
        r = icmp.parse_reply(4, te, has_ip_header=False)
        self.assertTrue(r.is_time_exceeded)
        self.assertIsNone(r.inner)

    def test_other_types_parse_without_payload(self):
        buf = struct.pack("!BBHHH", 13, 0, 0, 1, 2) + b"\x00" * 12  # timestamp request
        r = icmp.parse_reply(4, buf, has_ip_header=False)
        self.assertEqual(r.type, 13)
        self.assertIsNone(r.payload)
        self.assertIsNone(r.inner)


class RealCaptureTests(unittest.TestCase):
    """Datagrams captured on macOS 26 (BUILD_PLAN §0): the IP header is present on v4."""

    def test_v4_echo_reply_capture(self):
        buf = fixture_bytes("macos_v4_echo_reply")
        self.assertEqual(buf[0] >> 4, 4)
        r = icmp.parse_reply(4, buf, has_ip_header=True)
        self.assertTrue(r.is_echo_reply)
        self.assertEqual((r.ident, r.seq), (0xBEEF, 42))  # macOS honours our id
        self.assertEqual((r.payload.target_id, r.payload.seq, r.payload.cookie), (7, 42, COOKIE))
        self.assertIsNone(icmp.parse_reply(4, buf, has_ip_header=False).payload if icmp.parse_reply(4, buf, False) else None)

    def test_v4_time_exceeded_capture(self):
        buf = fixture_bytes("macos_v4_time_exceeded")
        r = icmp.parse_reply(4, buf, has_ip_header=True)
        self.assertTrue(r.is_time_exceeded)
        self.assertEqual((r.inner.type, r.inner.ident, r.inner.seq), (8, 0xBEEF, 42))
        self.assertEqual(r.inner.dst, "1.1.1.1")
        self.assertIsNotNone(r.inner.payload)  # the hop quoted the whole datagram
        self.assertEqual(r.inner.payload.extra, 2)  # TTL we set

    def test_v6_echo_reply_capture(self):
        buf = fixture_bytes("macos_v6_echo_reply")
        r = icmp.parse_reply(6, buf, has_ip_header=False)
        self.assertTrue(r.is_echo_reply)
        self.assertEqual((r.type, r.ident, r.seq, r.payload.seq), (129, 0xBEEF, 42, 42))

    def test_v6_time_exceeded_capture(self):
        buf = fixture_bytes("macos_v6_time_exceeded")
        r = icmp.parse_reply(6, buf, has_ip_header=False)
        self.assertTrue(r.is_time_exceeded)
        self.assertEqual((r.inner.type, r.inner.ident, r.inner.seq), (128, 0xBEEF, 42))
        self.assertEqual(r.inner.dst, "2606:4700:4700::1111")


class ErrQueueTests(unittest.TestCase):
    def test_v4_time_exceeded_cmsg(self):
        anc = icmp.errqueue_cmsg(4, 11, 0, "10.60.12.1")
        info = icmp.parse_errqueue(anc, 4)
        self.assertEqual(tuple(info), (11, 0, "10.60.12.1"))
        self.assertTrue(icmp.errqueue_is_time_exceeded(4, info))
        self.assertFalse(icmp.errqueue_is_unreachable(4, info))
        full = icmp.parse_sock_extended_err(anc, 4)
        self.assertEqual((full["origin"], full["type"], full["errno"]), (icmp.SO_EE_ORIGIN_ICMP, 11, errno.EHOSTUNREACH))

    def test_v6_time_exceeded_cmsg(self):
        anc = icmp.errqueue_cmsg(6, 3, 0, "2001:558:aaaa:bbbb::2")
        info = icmp.parse_errqueue(anc, 6)
        self.assertEqual(tuple(info), (3, 0, "2001:558:aaaa:bbbb::2"))
        self.assertTrue(icmp.errqueue_is_time_exceeded(6, info))

    def test_struct_layout_matches_build_plan(self):
        # '=IBBBBII' (16 B) then sockaddr_in '=HH4s' / sockaddr_in6 '=HHI16sI'
        data = icmp.errqueue_cmsg(4, 3, 1, "10.0.0.1")[0][2]
        self.assertEqual(data[:16], struct.pack("=IBBBBII", errno.EHOSTUNREACH, 2, 3, 1, 0, 0, 0))
        fam, port, raw = struct.unpack_from("=HH4s", data, 16)
        self.assertEqual((fam, raw), (socket.AF_INET, socket.inet_aton("10.0.0.1")))
        data6 = icmp.errqueue_cmsg(6, 3, 0, "fe80::1")[0][2]
        self.assertEqual(len(data6), 16 + struct.calcsize("=HHI16sI"))

    def test_wrong_level_and_family_mix(self):
        self.assertIsNone(icmp.parse_errqueue([(1, 2, b"\x00" * 40)], 4))
        self.assertIsNone(icmp.parse_errqueue(icmp.errqueue_cmsg(6, 3, 0, "::1"), 4))
        self.assertIsNone(icmp.parse_errqueue([], 6))

    def test_local_origin_has_no_offender(self):
        anc = icmp.errqueue_cmsg(4, 0, 0, "10.0.0.1", ee_errno=errno.ENETUNREACH, origin=icmp.SO_EE_ORIGIN_LOCAL)
        self.assertEqual(tuple(icmp.parse_errqueue(anc, 4)), (0, 0, None))

    def test_truncated_cmsg(self):
        anc = [(icmp.SOL_IP, icmp.IP_RECVERR, b"\x00" * 10)]
        self.assertIsNone(icmp.parse_errqueue(anc, 4))
        anc = [(icmp.SOL_IP, icmp.IP_RECVERR, struct.pack("=IBBBBII", 0, 2, 11, 0, 0, 0, 0) + b"\x02")]
        self.assertEqual(tuple(icmp.parse_errqueue(anc, 4)), (11, 0, None))


class SocketHelperTests(unittest.TestCase):
    def test_sockaddr_for(self):
        self.assertEqual(icmp.sockaddr_for("10.0.0.1", 4), ("10.0.0.1", 0))
        self.assertEqual(icmp.sockaddr_for("2606:4700:4700::1111", 6), ("2606:4700:4700::1111", 0, 0, 0))
        self.assertEqual(icmp.sockaddr_for("fe80::1%14", 6), ("fe80::1", 0, 0, 14))
        self.assertEqual(icmp.sockaddr_for("fe80::1%en0", 6, nametoindex=lambda n: {"en0": 14}[n]), ("fe80::1", 0, 0, 14))

        def boom(name):
            raise OSError("no such interface")

        self.assertEqual(icmp.sockaddr_for("fe80::1%nope", 6, nametoindex=boom), ("fe80::1", 0, 0, 0))

    def test_open_icmp_socket_propagates_oserror(self):
        def factory(*a):
            raise PermissionError(errno.EACCES, "Operation not permitted")

        with self.assertRaises(OSError):
            icmp.open_icmp_socket(4, factory=factory)

    def test_open_icmp_socket_uses_dgram_and_nonblocking(self):
        calls = []

        class Fake:
            def setblocking(self, flag):
                calls.append(("blocking", flag))

        def factory(fam, typ, proto):
            calls.append((fam, typ, proto))
            return Fake()

        icmp.open_icmp_socket(4, factory=factory)
        icmp.open_icmp_socket(6, factory=factory)
        self.assertIn((socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP), calls)
        self.assertIn((socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6), calls)
        self.assertIn(("blocking", False), calls)

    def test_is_fallback_error(self):
        self.assertTrue(icmp.is_fallback_error(PermissionError(errno.EACCES, "x")))
        self.assertTrue(icmp.is_fallback_error(OSError(errno.EPROTONOSUPPORT, "x")))
        self.assertTrue(icmp.is_fallback_error(OSError(errno.EPERM, "x")))
        self.assertFalse(icmp.is_fallback_error(OSError(errno.EAFNOSUPPORT, "x")))

    def test_set_ttl_and_recverr_levels(self):
        class Fake:
            def __init__(self):
                self.opts = []

            def setsockopt(self, level, name, value):
                self.opts.append((level, name, value))

        s = Fake()
        icmp.set_ttl(s, 4, 3)
        icmp.set_ttl(s, 6, 4)
        icmp.enable_recverr(s, 4)
        icmp.enable_recverr(s, 6)
        self.assertEqual(s.opts, [
            (socket.IPPROTO_IP, socket.IP_TTL, 3), (socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 4),
            (0, 11, 1), (41, 25, 1),
        ])


if __name__ == "__main__":
    unittest.main()
