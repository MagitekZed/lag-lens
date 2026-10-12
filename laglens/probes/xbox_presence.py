"""Xbox presence probe over UDP 5050 (SmartGlass discovery, SPEC_FULL §5.5).

An Xbox One / Series console that is on (or in instant-on standby) answers a
SmartGlass *discovery request* on UDP port 5050 with a *discovery response*.
We only care whether *any* response comes back, so the request is vendored as
a constant and the reply is checked by its message type alone.

Protocol reference: the xbox-smartglass-core project's description of the
"simple message" framing (``packer/simple.py`` / ``protocol/packets.py``).
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Any, Callable, Iterable, List, Optional

log = logging.getLogger("laglens.xbox_presence")

PORT = 5050
DEFAULT_TIMEOUT_S = 2.0

#: SmartGlass "simple message" discovery request, 16 bytes:
#:
#: header (6 bytes)
#:   ``dd 00``   message type ``DiscoveryRequest`` (0xDD00)
#:   ``00 0a``   unprotected payload length (10 bytes follow the header)
#:   ``00 00``   version (0)
#: payload (10 bytes)
#:   ``00 00 00 00``  flags (none)
#:   ``00 08``        client type 8 (``Android`` in the SmartGlass enum; any value works)
#:   ``00 00``        minimum protocol version 0
#:   ``00 02``        maximum protocol version 2
#:
#: A console replies with a ``DiscoveryResponse`` whose first two bytes are
#: ``dd 01`` (its payload carries the console name, UUID and certificate,
#: which we ignore).
DISCOVERY_REQUEST = bytes.fromhex("dd00000a0000" + "00000000" + "0008" + "0000" + "0002")
RESPONSE_TYPE = b"\xdd\x01"
RECV_SIZE = 2048


def is_discovery_response(data: bytes) -> bool:
    """``True`` when ``data`` starts with the DiscoveryResponse type ``dd 01``."""
    return len(data) >= 2 and bytes(data[:2]) == RESPONSE_TYPE


def probe(ip: str, timeout: float = DEFAULT_TIMEOUT_S, sock_factory: Callable[..., Any] = socket.socket) -> bool:
    """Send one discovery request to ``ip:5050``; ``True`` on any ``dd 01`` reply.

    Never raises: any socket error, a missing reply or garbage yields
    ``False``. Stray datagrams that are not a discovery response are skipped
    until the timeout runs out.
    """
    if not ip:
        return False
    sock = None
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = sock_factory(fam, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        addr = (ip, PORT, 0, 0) if fam == socket.AF_INET6 else (ip, PORT)
        sock.sendto(DISCOVERY_REQUEST, addr)
        for _ in range(8):  # a few stray datagrams at most; the socket timeout bounds the total
            data, _peer = sock.recvfrom(RECV_SIZE)
            if is_discovery_response(data):
                return True
        return False
    except (OSError, ValueError, TypeError) as exc:
        log.debug("presence probe to %s failed: %s", ip, exc)
        return False
    except Exception:  # noqa: BLE001 - this helper must never raise
        log.exception("presence probe to %s failed unexpectedly", ip)
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


def sweep(ips: Iterable[str], broadcast: Iterable[str] = ("255.255.255.255",), timeout: float = 1.5,
          sock_factory: Callable[..., Any] = socket.socket, clock: Callable[[], float] = time.monotonic) -> List[str]:
    """Send the discovery request to every address in ``ips`` and ``broadcast``; return who answered.

    This is how the Xbox app finds consoles, and it works whatever the console's hardware vendor prefix
    is. One UDP socket, IPv4 only; replies are collected until ``timeout``. Never raises.
    """
    found: List[str] = []
    sock = None
    try:
        sock = sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        targets = [ip for ip in ips if ip and ":" not in ip] + [b for b in broadcast if b]
        for ip in dict.fromkeys(targets):  # de-duplicated, order kept
            try:
                sock.sendto(DISCOVERY_REQUEST, (ip, PORT))
            except OSError as exc:
                log.debug("xbox sweep: send to %s failed: %s", ip, exc)
        deadline = clock() + timeout
        while True:
            left = deadline - clock()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data, peer = sock.recvfrom(RECV_SIZE)
            except socket.timeout:
                break
            except OSError as exc:
                log.debug("xbox sweep: receive failed: %s", exc)
                break
            ip = peer[0] if isinstance(peer, tuple) and peer else None
            if ip and is_discovery_response(data) and ip not in found:
                found.append(ip)
    except Exception:  # noqa: BLE001 - this helper must never raise
        log.exception("xbox sweep failed")
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
    return found


__all__ = ["DISCOVERY_REQUEST", "RESPONSE_TYPE", "PORT", "DEFAULT_TIMEOUT_S", "probe", "sweep", "is_discovery_response"]
