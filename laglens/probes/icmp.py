"""ICMP echo packets for the unprivileged DGRAM sockets (SPEC_FULL §5.1, BUILD_PLAN §0).

Pure functions (no I/O except :func:`open_icmp_socket`), so every layout can
be unit-tested from synthetic bytes:

* :func:`build_echo` — echo request, type 8 (v4, checksum computed here) or
  type 128 (v6, checksum left to the kernel), with the 28-byte Lag Lens
  payload padded to the 56-byte size class;
* :func:`parse_reply` — echo replies (type 0 / 129) **and** the error
  datagrams a tracer needs: TTL exceeded (v4 type 11 / ICMPv6 type 3) and
  destination unreachable (v4 type 3 / ICMPv6 type 1), extracting the quoted
  inner echo header (id + seq); routers may quote as little as 8 bytes of
  the inner ICMP header, so the inner payload is optional;
* ``has_ip_header``: macOS (and the other BSDs) deliver IPv4 replies with
  the IP header in front (skip ``(buf[0] & 0x0F) * 4``); Linux delivers the
  ICMP header at offset 0; v6 starts at the ICMPv6 header on both;
* :func:`enable_recverr` / :func:`parse_errqueue` — the Linux
  ``IP_RECVERR``/``IPV6_RECVERR`` error-queue helpers (``sock_extended_err``
  followed by the offender ``sockaddr``);
* :func:`sockaddr_for` — IPv6 link-local addresses (``fe80::1%en0``) become
  ``(addr, 0, 0, scope_id)`` through ``socket.if_nametoindex``.

Payload layout (network byte order, 28 bytes, zero-padded to the size class)::

    magic   4 B  b'LGLN'
    cookie  4 B  random per process (u32)
    target  2 B  target id (u16)
    seq     4 B  (u32)
    t_send  8 B  monotonic ns (u64)
    kind    1 B  0 normal, 1 big, 2 train, 3 ttl
    extra   1 B  train index, or the TTL for kind 3
    pad     4 B
"""
from __future__ import annotations

import errno
import os
import random
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, NamedTuple, Optional, Tuple

MAGIC = b"LGLN"
PAYLOAD_STRUCT = struct.Struct("!4sIHIQBB4s")
PAYLOAD_MIN = PAYLOAD_STRUCT.size  # 28
#: Size class ``normal``: total payload bytes (ICMP header excluded).
PAYLOAD_SIZE_NORMAL = 56
ICMP_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, id, seq
ICMP_HEADER_LEN = ICMP_HEADER.size  # 8
IPV6_HEADER_LEN = 40

ICMP4_ECHO_REPLY = 0
ICMP4_DEST_UNREACH = 3
ICMP4_ECHO_REQUEST = 8
ICMP4_TIME_EXCEEDED = 11
ICMP4_PARAM_PROBLEM = 12
ICMP6_DEST_UNREACH = 1
ICMP6_PACKET_TOO_BIG = 2
ICMP6_TIME_EXCEEDED = 3
ICMP6_PARAM_PROBLEM = 4
ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129

#: Payload ``kind`` byte.
PKIND_NORMAL = 0
PKIND_BIG = 1
PKIND_TRAIN = 2
PKIND_TTL = 3

#: Per-process cookie and the echo id (honoured by macOS, rewritten by Linux).
COOKIE: int = random.SystemRandom().getrandbits(32)
IDENT: int = os.getpid() & 0xFFFF

#: Linux error-queue constants (BUILD_PLAN §0); not exported by ``socket`` on every build.
SOL_IP = 0
IP_RECVERR = 11
SOL_IPV6 = 41
IPV6_RECVERR = 25
SO_EE_ORIGIN_LOCAL = 1
SO_EE_ORIGIN_ICMP = 2
SO_EE_ORIGIN_ICMP6 = 3
EXT_ERR_STRUCT = struct.Struct("=IBBBBII")  # ee_errno, ee_origin, ee_type, ee_code, ee_pad, ee_info, ee_data
SOCKADDR_IN = struct.Struct("=HH4s")  # sin_family, sin_port, sin_addr (then 8 B zero)
SOCKADDR_IN6 = struct.Struct("=HHI16sI")  # sin6_family, port, flowinfo, addr, scope_id

#: Whether this OS delivers IPv4 replies with the IP header (BSD) or not (Linux).
REPLIES_HAVE_IP_HEADER: bool = not sys.platform.startswith("linux")
#: v6 extension headers we can skip to find the quoted inner ICMPv6 header.
_V6_EXT_HEADERS = {0, 43, 60, 135}  # hop-by-hop, routing, destination options, mobility
_V6_ICMP = 58


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------
def checksum(data: bytes) -> int:
    """RFC 1071 one's-complement checksum of ``data`` (odd length zero-padded)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_payload(
    target_id: int,
    seq: int,
    t_send_ns: int,
    kind: int = PKIND_NORMAL,
    extra: int = 0,
    cookie: Optional[int] = None,
    size: int = PAYLOAD_SIZE_NORMAL,
) -> bytes:
    """The Lag Lens payload, zero-padded to ``size`` bytes (never truncated below 28)."""
    body = PAYLOAD_STRUCT.pack(
        MAGIC,
        (COOKIE if cookie is None else cookie) & 0xFFFFFFFF,
        target_id & 0xFFFF,
        seq & 0xFFFFFFFF,
        t_send_ns & 0xFFFFFFFFFFFFFFFF,
        kind & 0xFF,
        extra & 0xFF,
        b"\x00\x00\x00\x00",
    )
    if size > len(body):
        body += b"\x00" * (size - len(body))
    return body


def build_echo(
    family: int,
    seq: int,
    target_id: int,
    t_send_ns: int,
    kind: int = PKIND_NORMAL,
    extra: int = 0,
    ident: Optional[int] = None,
    cookie: Optional[int] = None,
    size: int = PAYLOAD_SIZE_NORMAL,
) -> bytes:
    """An echo request datagram for ``family`` 4 or 6 (header + payload).

    The v4 checksum is computed here; v6 leaves it zero for the kernel (it
    needs the pseudo-header). ``ident`` defaults to :data:`IDENT`; the header
    ``seq`` is ``seq & 0xFFFF`` while the payload keeps the full u32.
    """
    ident = IDENT if ident is None else ident
    payload = build_payload(target_id, seq, t_send_ns, kind, extra, cookie, size)
    if family == 6:
        return ICMP_HEADER.pack(ICMP6_ECHO_REQUEST, 0, 0, ident & 0xFFFF, seq & 0xFFFF) + payload
    head = ICMP_HEADER.pack(ICMP4_ECHO_REQUEST, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    csum = checksum(head + payload)
    return ICMP_HEADER.pack(ICMP4_ECHO_REQUEST, 0, csum, ident & 0xFFFF, seq & 0xFFFF) + payload


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
@dataclass
class Payload:
    """The decoded Lag Lens payload of an echo (request or reply)."""

    magic: bytes
    cookie: int
    target_id: int
    seq: int
    t_send_ns: int
    kind: int
    extra: int

    def matches(self, cookie: Optional[int] = None) -> bool:
        """Whether magic and cookie are ours (macOS delivers other processes' replies too)."""
        return self.magic == MAGIC and self.cookie == ((COOKIE if cookie is None else cookie) & 0xFFFFFFFF)


def parse_payload(body: bytes) -> Optional[Payload]:
    """Decode the first 28 bytes of ``body``; ``None`` when too short."""
    if len(body) < PAYLOAD_MIN:
        return None
    magic, cookie, target_id, seq, t_send_ns, kind, extra, _pad = PAYLOAD_STRUCT.unpack_from(body, 0)
    return Payload(magic, cookie, target_id, seq, t_send_ns, kind, extra)


@dataclass
class InnerHeader:
    """The quoted original echo header inside an ICMP error datagram."""

    type: int
    code: int
    ident: int
    seq: int
    payload: Optional[Payload]  # only when the router quoted enough bytes
    dst: Optional[str] = None  # original destination from the quoted IP header


@dataclass
class Reply:
    """One parsed ICMP datagram as delivered by a DGRAM ICMP socket."""

    family: int
    type: int
    code: int
    ident: int
    seq: int
    payload: Optional[Payload] = None  # echo replies
    inner: Optional[InnerHeader] = None  # error datagrams
    ttl: Optional[int] = None  # outer IP TTL (v4 with IP header only)

    @property
    def is_echo_reply(self) -> bool:
        return self.type == (ICMP6_ECHO_REPLY if self.family == 6 else ICMP4_ECHO_REPLY)

    @property
    def is_time_exceeded(self) -> bool:
        return self.type == (ICMP6_TIME_EXCEEDED if self.family == 6 else ICMP4_TIME_EXCEEDED)

    @property
    def is_unreachable(self) -> bool:
        return self.type == (ICMP6_DEST_UNREACH if self.family == 6 else ICMP4_DEST_UNREACH)

    @property
    def is_error(self) -> bool:
        if self.family == 6:
            return self.type in (ICMP6_DEST_UNREACH, ICMP6_PACKET_TOO_BIG, ICMP6_TIME_EXCEEDED, ICMP6_PARAM_PROBLEM)
        return self.type in (ICMP4_DEST_UNREACH, ICMP4_TIME_EXCEEDED, ICMP4_PARAM_PROBLEM)


def _parse_inner4(body: bytes) -> Optional[InnerHeader]:
    """Quoted IPv4 datagram: IP header (IHL*4) + at least 8 bytes of ICMP."""
    if len(body) < 20 or (body[0] >> 4) != 4:
        return None
    ihl = (body[0] & 0x0F) * 4
    if ihl < 20 or len(body) < ihl + ICMP_HEADER_LEN:
        return None
    if body[9] != socket.IPPROTO_ICMP:
        return None
    try:
        dst: Optional[str] = socket.inet_ntop(socket.AF_INET, body[16:20])
    except (OSError, ValueError):
        dst = None
    t, c, _cs, ident, seq = ICMP_HEADER.unpack_from(body, ihl)
    return InnerHeader(t, c, ident, seq, parse_payload(body[ihl + ICMP_HEADER_LEN:]), dst)


def _parse_inner6(body: bytes) -> Optional[InnerHeader]:
    """Quoted IPv6 datagram: 40-byte header (+ extension headers) + ICMPv6."""
    if len(body) < IPV6_HEADER_LEN or (body[0] >> 4) != 6:
        return None
    nxt = body[6]
    off = IPV6_HEADER_LEN
    try:
        dst: Optional[str] = socket.inet_ntop(socket.AF_INET6, body[24:40])
    except (OSError, ValueError):
        dst = None
    hops = 0
    while nxt != _V6_ICMP:
        if nxt not in _V6_EXT_HEADERS or len(body) < off + 2 or hops > 8:
            return None
        ext_len = (body[off + 1] + 1) * 8
        nxt = body[off]
        off += ext_len
        hops += 1
    if len(body) < off + ICMP_HEADER_LEN:
        return None
    t, c, _cs, ident, seq = ICMP_HEADER.unpack_from(body, off)
    return InnerHeader(t, c, ident, seq, parse_payload(body[off + ICMP_HEADER_LEN:]), dst)


def parse_reply(family: int, buf: bytes, has_ip_header: Optional[bool] = None) -> Optional[Reply]:
    """Parse a datagram read from a DGRAM ICMP socket; ``None`` if malformed.

    ``has_ip_header`` (v4 only) says whether ``buf`` starts with the IPv4
    header (macOS) or with the ICMP header (Linux); it defaults to
    :data:`REPLIES_HAVE_IP_HEADER`. Echo replies carry ``payload``; TTL
    exceeded / unreachable datagrams carry ``inner`` (id + seq of the quoted
    echo, plus its payload when enough bytes were quoted).
    """
    off = 0
    ttl: Optional[int] = None
    if family == 4:
        if has_ip_header is None:
            has_ip_header = REPLIES_HAVE_IP_HEADER
        if has_ip_header:
            if len(buf) < 20 or (buf[0] >> 4) != 4:
                return None
            ihl = (buf[0] & 0x0F) * 4
            if ihl < 20 or len(buf) < ihl + ICMP_HEADER_LEN:
                return None
            ttl = buf[8]
            off = ihl
    if len(buf) < off + ICMP_HEADER_LEN:
        return None
    t, c, _cs, ident, seq = ICMP_HEADER.unpack_from(buf, off)
    body = buf[off + ICMP_HEADER_LEN:]
    reply = Reply(family=family, type=t, code=c, ident=ident, seq=seq, ttl=ttl)
    if reply.is_echo_reply:
        reply.payload = parse_payload(body)
    elif reply.is_error:
        reply.inner = _parse_inner6(body) if family == 6 else _parse_inner4(body)
    return reply


# ---------------------------------------------------------------------------
# Sockets
# ---------------------------------------------------------------------------
def open_icmp_socket(family: int, factory: Callable[..., Any] = socket.socket) -> Any:
    """A non-blocking unconnected DGRAM ICMP socket; the ``OSError`` propagates.

    Callers decide the fallback: ``PermissionError``/``EACCES``/
    ``EPROTONOSUPPORT`` → ping-binary backend (SPEC_FULL §5.1).
    """
    if family == 6:
        s = factory(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
    else:
        s = factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    s.setblocking(False)
    return s


def is_fallback_error(exc: BaseException) -> bool:
    """Whether a socket-open failure means "use the ping binary for this family"."""
    if isinstance(exc, PermissionError):
        return True
    code = getattr(exc, "errno", None)
    return code in (errno.EACCES, errno.EPERM, errno.EPROTONOSUPPORT)


def sockaddr_for(
    addr: str, family: int, port: int = 0, nametoindex: Callable[[str], int] = socket.if_nametoindex
) -> Tuple[Any, ...]:
    """``sendto`` address: ``(host, port)`` for v4, ``(host, port, 0, scope_id)`` for v6.

    A ``%scope`` suffix (``fe80::1%en0`` or ``fe80::1%14``) becomes the
    numeric scope id; an unknown interface name yields scope 0 (the kernel
    then picks the default route interface, or rejects the send).
    """
    if family != 6:
        return (addr, port)
    host, _, scope = addr.partition("%")
    scope_id = 0
    if scope:
        if scope.isdigit():
            scope_id = int(scope)
        else:
            try:
                scope_id = int(nametoindex(scope))
            except (OSError, ValueError, TypeError):
                scope_id = 0
    return (host, port, 0, scope_id)


def set_ttl(sock: Any, family: int, ttl: int) -> None:
    """Set the outgoing hop limit on ``sock`` (``IP_TTL`` / ``IPV6_UNICAST_HOPS``)."""
    if family == 6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, int(ttl))
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, int(ttl))


# ---------------------------------------------------------------------------
# Linux error queue (tracer only; never on the engine sockets)
# ---------------------------------------------------------------------------
def enable_recverr(sock: Any, family: int) -> None:
    """Enable ``IP_RECVERR`` (v4) / ``IPV6_RECVERR`` (v6); raises ``OSError`` elsewhere."""
    if family == 6:
        sock.setsockopt(SOL_IPV6, IPV6_RECVERR, 1)
    else:
        sock.setsockopt(SOL_IP, IP_RECVERR, 1)


class ErrQueue(NamedTuple):
    """``(ee_type, ee_code, offender_addr)`` from one ``MSG_ERRQUEUE`` read."""

    ee_type: int
    ee_code: int
    offender: Optional[str]


def parse_sock_extended_err(ancdata: Iterable[Tuple[int, int, bytes]], family: int) -> Optional[dict]:
    """Full decode of the ``sock_extended_err`` cmsg (+ offender sockaddr) or ``None``.

    Keys: ``errno, origin, type, code, info, data, offender``. ``origin`` 2 is
    ICMP, 3 is ICMPv6; ``type``/``code`` are the ICMP values the router sent.
    """
    want = (SOL_IPV6, IPV6_RECVERR) if family == 6 else (SOL_IP, IP_RECVERR)
    for level, ctype, data in ancdata:
        if (level, ctype) != want or len(data) < EXT_ERR_STRUCT.size:
            continue
        ee_errno, origin, ee_type, ee_code, _pad, info, extra = EXT_ERR_STRUCT.unpack_from(data, 0)
        offender: Optional[str] = None
        rest = data[EXT_ERR_STRUCT.size:]
        try:
            if family == 6 and len(rest) >= SOCKADDR_IN6.size:
                fam, _port, _flow, raw, scope = SOCKADDR_IN6.unpack_from(rest, 0)
                if fam == socket.AF_INET6:
                    offender = socket.inet_ntop(socket.AF_INET6, raw)
                    if scope and offender.lower().startswith("fe80"):
                        offender = "%s%%%d" % (offender, scope)
            elif family != 6 and len(rest) >= SOCKADDR_IN.size:
                fam, _port, raw = SOCKADDR_IN.unpack_from(rest, 0)
                if fam == socket.AF_INET:
                    offender = socket.inet_ntop(socket.AF_INET, raw)
        except (OSError, ValueError):
            offender = None
        return {
            "errno": ee_errno, "origin": origin, "type": ee_type, "code": ee_code, "info": info, "data": extra,
            "offender": offender,
        }
    return None


def parse_errqueue(ancdata: Iterable[Tuple[int, int, bytes]], family: int) -> Optional[ErrQueue]:
    """``(ee_type, ee_code, offender_addr)`` of an error-queue message; ``None`` if absent.

    Only ICMP-originated errors (``ee_origin`` 2/3) carry a meaningful type;
    a local error (origin 1, e.g. ``ENETUNREACH`` on send) returns type/code 0
    with ``offender`` ``None``.
    """
    d = parse_sock_extended_err(ancdata, family)
    if d is None:
        return None
    if d["origin"] in (SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6):
        return ErrQueue(d["type"], d["code"], d["offender"])
    return ErrQueue(0, 0, None)


def errqueue_is_time_exceeded(family: int, info: ErrQueue) -> bool:
    """Whether an error-queue entry is a TTL/hop-limit exceeded from ``info.offender``."""
    return info.offender is not None and info.ee_type == (ICMP6_TIME_EXCEEDED if family == 6 else ICMP4_TIME_EXCEEDED)


def errqueue_is_unreachable(family: int, info: ErrQueue) -> bool:
    return info.offender is not None and info.ee_type == (ICMP6_DEST_UNREACH if family == 6 else ICMP4_DEST_UNREACH)


# ---------------------------------------------------------------------------
# Test / fixture helpers (synthetic datagrams)
# ---------------------------------------------------------------------------
def ipv4_header(src: str, dst: str, payload_len: int, proto: int = socket.IPPROTO_ICMP, ttl: int = 64, ihl_words: int = 5) -> bytes:
    """A synthetic IPv4 header with ``ihl_words`` 32-bit words (5 = no options)."""
    ihl_words = max(5, min(15, ihl_words))
    total = ihl_words * 4 + payload_len
    head = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl_words, 0, total, 0, 0, ttl, proto, 0,
        socket.inet_pton(socket.AF_INET, src), socket.inet_pton(socket.AF_INET, dst),
    )
    head += b"\x00" * (ihl_words * 4 - 20)
    return head[:10] + struct.pack("!H", checksum(head)) + head[12:]


def ipv6_header(src: str, dst: str, payload_len: int, nxt: int = _V6_ICMP, hlim: int = 64) -> bytes:
    return struct.pack("!IHBB16s16s", 6 << 28, payload_len, nxt, hlim,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst))


def echo_reply_for(request: bytes, family: int) -> bytes:
    """Turn an echo request datagram into the matching echo reply (ICMP part only)."""
    t, c, _cs, ident, seq = ICMP_HEADER.unpack_from(request, 0)
    body = request[ICMP_HEADER_LEN:]
    rtype = ICMP6_ECHO_REPLY if family == 6 else ICMP4_ECHO_REPLY
    head = ICMP_HEADER.pack(rtype, 0, 0, ident, seq)
    if family == 6:
        return head + body
    return ICMP_HEADER.pack(rtype, 0, checksum(head + body), ident, seq) + body


def time_exceeded_for(request: bytes, family: int, src: str, dst: str, quote: int = 8) -> bytes:
    """An ICMP TTL-exceeded datagram quoting ``quote`` bytes of the original echo ``request``.

    ``src`` is the original sender, ``dst`` the original destination (they
    go into the quoted inner IP header). Returns the ICMP part only (the v4
    caller prepends an outer IP header when simulating macOS).
    """
    inner = request[:max(8, quote)]
    if family == 6:
        ip = ipv6_header(src, dst, len(request))
        return struct.pack("!BBHI", ICMP6_TIME_EXCEEDED, 0, 0, 0) + ip + inner
    ip = ipv4_header(src, dst, len(request))
    head = struct.pack("!BBHI", ICMP4_TIME_EXCEEDED, 0, 0, 0)
    body = ip + inner
    return struct.pack("!BBHI", ICMP4_TIME_EXCEEDED, 0, checksum(head + body), 0) + body


def errqueue_cmsg(family: int, ee_type: int, ee_code: int, offender: str, ee_errno: int = errno.EHOSTUNREACH,
                  origin: Optional[int] = None) -> List[Tuple[int, int, bytes]]:
    """Synthetic ``recvmsg`` ancillary data for one error-queue entry (tests)."""
    if family == 6:
        origin = SO_EE_ORIGIN_ICMP6 if origin is None else origin
        sa = SOCKADDR_IN6.pack(socket.AF_INET6, 0, 0, socket.inet_pton(socket.AF_INET6, offender.split("%")[0]), 0)
        level, ctype = SOL_IPV6, IPV6_RECVERR
    else:
        origin = SO_EE_ORIGIN_ICMP if origin is None else origin
        sa = SOCKADDR_IN.pack(socket.AF_INET, 0, socket.inet_pton(socket.AF_INET, offender)) + b"\x00" * 8
        level, ctype = SOL_IP, IP_RECVERR
    return [(level, ctype, EXT_ERR_STRUCT.pack(ee_errno, origin, ee_type, ee_code, 0, 0, 0) + sa)]


__all__ = [
    "MAGIC", "COOKIE", "IDENT", "PAYLOAD_STRUCT", "PAYLOAD_MIN", "PAYLOAD_SIZE_NORMAL", "ICMP_HEADER", "ICMP_HEADER_LEN",
    "ICMP4_ECHO_REPLY", "ICMP4_DEST_UNREACH", "ICMP4_ECHO_REQUEST", "ICMP4_TIME_EXCEEDED",
    "ICMP6_DEST_UNREACH", "ICMP6_TIME_EXCEEDED", "ICMP6_ECHO_REQUEST", "ICMP6_ECHO_REPLY",
    "PKIND_NORMAL", "PKIND_BIG", "PKIND_TRAIN", "PKIND_TTL", "REPLIES_HAVE_IP_HEADER",
    "SOL_IP", "IP_RECVERR", "SOL_IPV6", "IPV6_RECVERR", "SO_EE_ORIGIN_ICMP", "SO_EE_ORIGIN_ICMP6",
    "checksum", "build_payload", "build_echo", "Payload", "parse_payload", "InnerHeader", "Reply", "parse_reply",
    "open_icmp_socket", "is_fallback_error", "sockaddr_for", "set_ttl", "enable_recverr", "ErrQueue",
    "parse_sock_extended_err", "parse_errqueue", "errqueue_is_time_exceeded", "errqueue_is_unreachable",
    "ipv4_header", "ipv6_header", "echo_reply_for", "time_exceeded_for", "errqueue_cmsg",
]
