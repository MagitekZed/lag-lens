"""Doctor (SPEC_FULL §11.3): environment checks printed as a table and kept in ``doctor.json``.

Three entry points (INTERFACES §10.2):

* :func:`run_cli(cfg, platform, no_net)` — the full table (checks 1–19 minus
  STUN / PMTU / calibration, which v1 defers); returns 0 (nothing is fatal
  except a Python older than 3.9).
* :func:`fast(ctx)` — the subset that finishes in well under 3 s, run by the
  app before the components start: python/OS, ICMP sockets, the macOS Local
  Network provocation (3 echoes to the gateway and 3 to 1.1.1.1 **first**),
  route/interface/type, link, VPN, sleep inhibitor, port, disk, binaries.
  Writes ``doctor.json`` and ``state.doctor``.
* :func:`selftest()` — the offline unit tests (skipped when the caller is
  ``laglens.app.cmd_selftest``, which already ran them) plus loopback echo
  checks to 127.0.0.1 and ::1; returns 0/1.

Every check is ``{"check", "status": "ok|warn|fail|skip", "detail", "fallback"}``.
The ICMP echoes use the same unprivileged DGRAM sockets as the engine (own
minimal implementation here so the doctor works even when the probe modules
are absent) and fall back to the ping binary through the platform layer.
"""
from __future__ import annotations

import inspect
import logging
import os
import platform as pyplatform
import select
import shutil
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("laglens.doctor")

OK = "ok"
WARN = "warn"
FAIL = "fail"
SKIP = "skip"
MIN_PYTHON = (3, 9)
ECHO_TIMEOUT_S = 0.5
ECHO_COUNT = 3
EHOSTUNREACH = 65
INET4 = "1.1.1.1"
INET6 = "2606:4700:4700::1111"
BINARIES = ("ping", "ping6", "tracepath", "traceroute", "mtr", "ip", "route", "netstat", "iw", "nmcli", "arp", "ndp",
            "system_profiler", "unzip", "curl")
LOCAL_NETWORK_MSG = (
    "macOS blocked traffic to your local network for this app. Open System Settings > Privacy & Security > "
    "Local Network and enable **{app}**, then restart Lag Lens. (The first run usually shows a prompt — click Allow.)"
)
WIFI_WARN = "Wi-Fi results are weaker evidence"
ROOT = Path(__file__).resolve().parent.parent


def check(name: str, status: str, detail: str = "", fallback: Optional[str] = None) -> Dict[str, Any]:
    return {"check": name, "status": status, "detail": detail, "fallback": fallback}


# ---------------------------------------------------------------------------
# ICMP echo (unprivileged DGRAM), ping-binary fallback
# ---------------------------------------------------------------------------
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_echo(ident: int, seq: int, payload: bytes, v6: bool = False) -> bytes:
    """ICMP echo request (type 8, or 128 for ICMPv6 whose checksum the kernel fills in)."""
    typ = 128 if v6 else 8
    hdr = struct.pack("!BBHHH", typ, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    if v6:
        return hdr + payload
    csum = _checksum(hdr + payload)
    return struct.pack("!BBHHH", typ, 0, csum, ident & 0xFFFF, seq & 0xFFFF) + payload


def strip_ip_header(data: bytes) -> bytes:
    """macOS DGRAM ICMP replies include the IPv4 header; Linux ones do not."""
    if len(data) > 20 and (data[0] >> 4) == 4:
        ihl = (data[0] & 0x0F) * 4
        if 20 <= ihl < len(data):
            return data[ihl:]
    return data


def icmp_echo(addr: str, count: int = ECHO_COUNT, timeout: float = ECHO_TIMEOUT_S, platform: Optional[Any] = None,
              use_socket: bool = True) -> Dict[str, Any]:
    """Send ``count`` echoes; ``{"sent","received","errno","rtts","method","error"}``."""
    v6 = ":" in addr
    res: Dict[str, Any] = {"addr": addr, "sent": 0, "received": 0, "errno": None, "rtts": [], "method": None, "error": None}
    sock = None
    if use_socket:
        try:
            sock = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
        except OSError as exc:
            res["errno"] = exc.errno
            res["error"] = "socket: %s" % exc
            sock = None
    if sock is not None:
        res["method"] = "socket"
        ident = os.getpid() & 0xFFFF
        cookie = os.urandom(8)
        try:
            sock.setblocking(False)
            for seq in range(count):
                pkt = build_echo(ident, seq, cookie + struct.pack("!H", seq) + b"laglens-doctor".ljust(22, b"\0"), v6)
                t_send = time.monotonic()
                res["sent"] += 1
                try:
                    sock.sendto(pkt, (addr, 0))
                except OSError as exc:
                    res["errno"] = exc.errno
                    res["error"] = "sendto: %s" % exc
                    continue
                deadline = t_send + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    r, _, _ = select.select([sock], [], [], remaining)
                    if not r:
                        break
                    try:
                        data, _ = sock.recvfrom(2048)
                    except OSError as exc:
                        res["errno"] = exc.errno
                        res["error"] = "recv: %s" % exc
                        break
                    body = data if v6 else strip_ip_header(data)
                    if len(body) >= 8 + len(cookie) and body[0] == (129 if v6 else 0) and body[8:8 + len(cookie)] == cookie \
                            and struct.unpack("!H", body[6:8])[0] == seq:
                        res["rtts"].append(round((time.monotonic() - t_send) * 1000.0, 2))
                        res["received"] += 1
                        break
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return res
    if platform is None:
        return res
    res["method"] = "ping"
    for _ in range(count):
        if platform.name == "darwin":
            argv = ["ping6" if v6 else "ping", "-n", "-c", "1"] + ([] if v6 else ["-t", "1"]) + [addr]
        else:
            argv = ["ping", "-6" if v6 else "-4", "-n", "-c", "1", "-W", "1", addr]
        res["sent"] += 1
        out = platform.run_rc(argv, timeout=max(2.0, timeout + 1.5))
        if not out:
            continue
        rc, stdout, stderr = out
        text = (stdout or "") + (stderr or "")
        if "No route to host" in text or "sendto" in text and "65" in text:
            res["errno"] = EHOSTUNREACH
        import re as _re

        m = _re.search(r"time[=<]\s*([\d.]+)\s*ms", text)
        if m and rc == 0:
            res["rtts"].append(float(m.group(1)))
            res["received"] += 1
    return res


def echo_parallel(addrs: Sequence[str], count: int = ECHO_COUNT, timeout: float = ECHO_TIMEOUT_S,
                  platform: Optional[Any] = None, echo: Optional[Callable[..., Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
    """Echo several addresses concurrently (keeps the fast doctor under 3 s)."""
    fn = echo or icmp_echo
    out: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()

    def worker(a: str) -> None:
        try:
            r = fn(a, count=count, timeout=timeout, platform=platform)
        except Exception as exc:  # noqa: BLE001
            r = {"addr": a, "sent": count, "received": 0, "errno": None, "rtts": [], "method": None, "error": str(exc)}
        with lock:
            out[a] = r

    threads = [threading.Thread(target=worker, args=(a,), daemon=True, name="doctor-echo") for a in addrs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout * (count + 1) + 2.0)
    for a in addrs:
        out.setdefault(a, {"addr": a, "sent": count, "received": 0, "errno": None, "rtts": [], "method": None, "error": "timeout"})
    return out


# ---------------------------------------------------------------------------
# Small network helpers (DNS, SNTP, v6 address, port, mDNS name, TTL-2 hop)
# ---------------------------------------------------------------------------
def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\0"


def _skip_name(data: bytes, off: int) -> int:
    while off < len(data):
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln
    return off


def dns_query(server: str, name: str, timeout: float = 2.0) -> Dict[str, Any]:
    """Hand-built UDP A query → ``{"ok","rcode","addr","ms","error"}``."""
    res: Dict[str, Any] = {"ok": False, "rcode": None, "addr": None, "ms": None, "error": None}
    qid = os.getpid() & 0xFFFF ^ int(time.time()) & 0xFFFF
    pkt = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", 1, 1)
    try:
        fam = socket.AF_INET6 if ":" in server else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            t0 = time.monotonic()
            s.sendto(pkt, (server, 53))
            data, _ = s.recvfrom(2048)
            res["ms"] = round((time.monotonic() - t0) * 1000.0, 1)
        finally:
            s.close()
    except (OSError, socket.timeout) as exc:
        res["error"] = str(exc) or type(exc).__name__
        return res
    if len(data) < 12:
        res["error"] = "short reply"
        return res
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    res["rcode"] = flags & 0xF
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            break
        typ, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if typ == 1 and rdlen == 4 and res["addr"] is None:
            res["addr"] = socket.inet_ntoa(data[off:off + 4])
        off += rdlen
    res["ok"] = res["rcode"] == 0 and res["addr"] is not None
    return res


def sntp_offset(host: str = "time.cloudflare.com", timeout: float = 2.0) -> Optional[float]:
    """Clock offset (s, server − local) from one SNTP exchange; ``None`` on failure."""
    pkt = b"\x1b" + 47 * b"\0"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            t1 = time.time()
            s.sendto(pkt, (host, 123))
            data, _ = s.recvfrom(256)
            t4 = time.time()
        finally:
            s.close()
    except (OSError, socket.timeout):
        return None
    if len(data) < 48:
        return None
    secs, frac = struct.unpack("!II", data[40:48])
    t3 = secs - 2208988800 + frac / 4294967296.0
    return round(t3 - (t1 + t4) / 2.0, 3)


def v6_global_addr() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.connect((INET6, 9))
            a = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None
    if a.startswith("fe80") or a == "::":
        return None
    return a


def bind_port(port: int, host: str = "0.0.0.0") -> Optional[str]:
    """``None`` when the port can be bound, else the error text."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # same option the HTTP server uses (allow_reuse_address): a port the previous run just
            # closed (TIME_WAIT) is free for the server, so it must not be reported as busy
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        finally:
            s.close()
        return None
    except OSError as exc:
        return str(exc)


def resolves(name: str, timeout: float = 1.0) -> bool:
    result = {"ok": False}

    def worker() -> None:
        try:
            socket.getaddrinfo(name, None)
            result["ok"] = True
        except (socket.gaierror, OSError, UnicodeError):
            result["ok"] = False

    t = threading.Thread(target=worker, daemon=True, name="doctor-resolve")
    t.start()
    t.join(timeout)
    return result["ok"]


def ttl2_hop(platform: Any, dst: str = INET4) -> Tuple[Optional[str], Optional[str]]:
    """``(method, hop_ip)`` for the hop at TTL 2 using the fallback binaries (SPEC §4.8)."""
    import re as _re

    if platform.name == "darwin":
        attempts = [
            ("ping -m", ["ping", "-n", "-c", "1", "-m", "2", "-t", "1", dst], r"from (\d+\.\d+\.\d+\.\d+).*Time to live exceeded"),
            ("traceroute", ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "2", dst], r"^\s*2\s+(\d+\.\d+\.\d+\.\d+)"),
        ]
    else:
        attempts = [
            ("tracepath", ["tracepath", "-n", "-m", "2", dst], r"^\s*2:\s+(\d+\.\d+\.\d+\.\d+)"),
            ("ping -t", ["ping", "-n", "-c", "1", "-t", "2", "-W", "1", dst], r"From (\d+\.\d+\.\d+\.\d+).*Time to live exceeded"),
            ("traceroute", ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "2", dst], r"^\s*2\s+(\d+\.\d+\.\d+\.\d+)"),
        ]
    for method, argv, rx in attempts:
        out = platform.run_rc(argv, timeout=6.0)
        if not out:
            continue
        text = (out[1] or "") + (out[2] or "")
        m = _re.search(rx, text, _re.M)
        if m:
            return method, m.group(1)
    return None, None


def microsoft_ouis() -> List[str]:
    try:
        text = (ROOT / "laglens" / "data" / "oui_microsoft.txt").read_text(encoding="utf-8")
    except OSError:
        return []
    return [ln.strip().upper() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
class Doctor:
    """Builds the check list; every I/O helper is injectable for tests."""

    def __init__(self, cfg: dict, platform: Any, no_net: bool = False, root: Optional[Path] = None,
                 echo: Optional[Callable[..., Dict[str, Any]]] = None, dns: Optional[Callable[..., Dict[str, Any]]] = None,
                 sntp: Optional[Callable[..., Optional[float]]] = None, v6addr: Optional[Callable[[], Optional[str]]] = None,
                 bind: Optional[Callable[..., Optional[str]]] = None, resolve: Optional[Callable[..., bool]] = None,
                 ttl2: Optional[Callable[..., Tuple[Optional[str], Optional[str]]]] = None,
                 docsis_probe: Optional[Callable[[dict], Dict[str, Any]]] = None,
                 igd_probe: Optional[Callable[[str], Dict[str, Any]]] = None,
                 disk_usage: Optional[Callable[[str], Any]] = None, env: Optional[Dict[str, str]] = None,
                 pid: Optional[int] = None) -> None:
        self.cfg = cfg or {}
        self.platform = platform
        self.no_net = no_net
        self.root = Path(root) if root else ROOT
        self._echo = echo or icmp_echo
        self._dns = dns or dns_query
        self._sntp = sntp or sntp_offset
        self._v6addr = v6addr or v6_global_addr
        self._bind = bind or bind_port
        self._resolve = resolve or resolves
        self._ttl2 = ttl2 or ttl2_hop
        self._docsis_probe = docsis_probe or _docsis_probe
        self._igd_probe = igd_probe or _igd_probe
        self._disk_usage = disk_usage or shutil.disk_usage
        self._env = env if env is not None else dict(os.environ)
        self._pid = pid if pid is not None else os.getpid()
        self.route: Dict[str, Any] = {}
        self.link: Dict[str, Any] = {}
        self.echoes: Dict[str, Dict[str, Any]] = {}
        self.local_network_denied = False

    # ----------------------------------------------------------- helpers
    def _skip(self, name: str, why: str = "skipped (--no-net)") -> Dict[str, Any]:
        return check(name, SKIP, why)

    def _safe(self, fn: Callable[[], List[Dict[str, Any]]], name: str) -> List[Dict[str, Any]]:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - the doctor itself must never crash
            log.exception("doctor: %s failed", name)
            return [check(name, FAIL, "check crashed: %s: %s" % (type(exc).__name__, exc))]

    # ------------------------------------------------------------ checks
    def c_python(self) -> List[Dict[str, Any]]:
        v = sys.version_info
        ok = (v.major, v.minor) >= MIN_PYTHON
        session = "desktop"
        if self._env.get("SSH_CONNECTION") or self._env.get("SSH_TTY"):
            session = "SSH"
        try:
            if self.platform.is_game_mode():
                session = "Game Mode"
        except Exception:  # noqa: BLE001
            pass
        osi = self.platform.os_info() if hasattr(self.platform, "os_info") else {}
        detail = "Python %d.%d.%d at %s; %s %s %s; session: %s" % (
            v.major, v.minor, v.micro, sys.executable, osi.get("system") or pyplatform.system(), osi.get("release", ""),
            osi.get("machine") or pyplatform.machine(), session)
        out = [check("python", OK if ok else FAIL, detail, None if ok else "install Python 3.9 or newer")]
        if session == "Game Mode":
            out.append(check("session", WARN, "Bazzite Game Mode: no browser/inhibitor", "use Desktop Mode or --install-service"))
        return out

    def c_sockets(self) -> List[Dict[str, Any]]:
        out = []
        for name, addr in (("icmp_v4_socket", "127.0.0.1"), ("icmp_v6_socket", "::1")):
            r = self._echo(addr, count=1, timeout=ECHO_TIMEOUT_S, platform=self.platform)
            if r.get("method") == "socket" and r.get("received"):
                out.append(check(name, OK, "unprivileged DGRAM ICMP works (echo to %s %.1f ms)" % (addr, r["rtts"][0])))
            elif r.get("method") == "socket":
                out.append(check(name, WARN, "socket opened but no echo reply from %s (%s)" % (addr, r.get("error") or "timeout"),
                                 "ping-binary backend"))
            else:
                detail = "cannot open DGRAM ICMP socket: %s" % (r.get("error") or "errno %s" % r.get("errno"))
                if self.platform.name == "linux":
                    rng = self.platform.read_stripped("/proc/sys/net/ipv4/ping_group_range") or "unreadable"
                    detail += "; net.ipv4.ping_group_range = %s" % rng
                out.append(check(name, WARN, detail, "ping-binary backend (fewer features)"))
        if self.platform.name == "linux":
            rng = self.platform.read_stripped("/proc/sys/net/ipv4/ping_group_range")
            if rng:
                out.append(check("ping_group_range", OK, rng))
        return out

    def c_local_network(self) -> List[Dict[str, Any]]:
        """macOS Local Network privacy provocation: gateway and 1.1.1.1 echoes first."""
        self.route = self.route or (self.platform.default_route() or {})
        gw = self.route.get("gateway")
        if self.no_net:
            return [self._skip("local_network")]
        addrs = [a for a in (gw, INET4) if a]
        self.echoes = echo_parallel(addrs, platform=self.platform, echo=self._echo) if addrs else {}
        if not gw:
            return [check("local_network", WARN, "no default gateway: is the network up?")]
        g = self.echoes.get(gw, {})
        i = self.echoes.get(INET4, {})
        if self.platform.name != "darwin":
            return [check("local_network", OK, "n/a (not macOS)")]
        if g.get("errno") == EHOSTUNREACH and g.get("received", 0) == 0 and i.get("received", 0) > 0:
            self.local_network_denied = True
            app = self.platform.terminal_app_name()
            return [check("local_network", FAIL, "denied: gateway sends fail with errno 65 while 1.1.1.1 replies",
                          LOCAL_NETWORK_MSG.format(app=app))]
        if g.get("received", 0) > 0:
            return [check("local_network", OK, "allowed (%d/%d gateway echoes answered)" % (g["received"], g["sent"]))]
        return [check("local_network", WARN, "gateway did not answer (%s); internet %d/%d" % (
            g.get("error") or "timeout", i.get("received", 0), i.get("sent", 0)), "check the LAN; Local Network looks allowed")]

    def c_route(self) -> List[Dict[str, Any]]:
        self.route = self.route or (self.platform.default_route() or {})
        r = self.route
        if not r.get("iface"):
            return [check("default_route", FAIL, "no default route: is the network up?", "connect to the network and restart")]
        self.link = self.platform.link_info(r["iface"]) or {}
        wifi = bool(self.link.get("wireless"))
        detail = "iface %s (%s), lan %s/%s, gw %s, gw6 %s" % (
            r["iface"], "Wi-Fi" if wifi else "wired", r.get("lan_ip"), r.get("prefixlen"), r.get("gateway"), r.get("gateway6") or "none")
        out = [check("default_route", OK if r.get("gateway") else WARN, detail)]
        out.append(check("interface_type", WARN if wifi else OK, "Wi-Fi: %s" % WIFI_WARN if wifi else "wired link",
                         "plug the probe host into the XB7 with a cable for stronger evidence" if wifi else None))
        return out

    def c_link(self) -> List[Dict[str, Any]]:
        if not self.route.get("iface"):
            return [self._skip("link", "no interface")]
        lk = self.link or self.platform.link_info(self.route["iface"]) or {}
        speed, duplex = lk.get("speed"), lk.get("duplex")
        detail = "speed %s Mb/s, duplex %s, carrier %s, carrier_changes %s" % (speed, duplex, lk.get("carrier"), lk.get("carrier_changes"))
        if not lk.get("wireless") and ((speed is not None and speed < 1000) or (duplex is not None and duplex != "full")):
            return [check("link", WARN, "negotiated %s Mb/s / %s duplex: suspect cable or port" % (speed, duplex or "?"),
                          "try another cable/port on the XB7")]
        return [check("link", OK, detail)]

    def c_vpn(self) -> List[Dict[str, Any]]:
        v = self.platform.vpn_routes(INET4) or {}
        if v.get("via_tunnel"):
            return [check("vpn", WARN, "route to 1.1.1.1 goes via %s: probes would go through the VPN, not the XB7" % v.get("iface"),
                          "disconnect the VPN (or exclude 1.1.1.1/8.8.8.8 from it) for a clean measurement")]
        return [check("vpn", OK, "no tunnel on the path to 1.1.1.1 (via %s)" % (v.get("iface") or "?"))]

    def c_reachability(self) -> List[Dict[str, Any]]:
        if self.no_net:
            return [self._skip("gateway"), self._skip("internet_v4"), self._skip("internet_v6")]
        out = []
        gw = self.route.get("gateway")
        if gw:
            g = self.echoes.get(gw) or self._echo(gw, platform=self.platform)
            if g.get("received"):
                out.append(check("gateway", OK, "%s answered %d/%d (min %.1f ms)" % (gw, g["received"], g["sent"], min(g["rtts"]))))
            else:
                out.append(check("gateway", FAIL, "%s did not answer (%s)" % (gw, g.get("error") or "timeout"),
                                 "Local Network permission?" if self.platform.name == "darwin" else "check the cable/Wi-Fi"))
        else:
            out.append(check("gateway", FAIL, "no gateway"))
        i4 = self.echoes.get(INET4) or self._echo(INET4, platform=self.platform)
        out.append(check("internet_v4", OK if i4.get("received") else FAIL,
                         "%s %d/%d%s" % (INET4, i4.get("received", 0), i4.get("sent", 0), (" min %.1f ms" % min(i4["rtts"])) if i4.get("rtts") else ""),
                         None if i4.get("received") else "no IPv4 internet reachability"))
        a6 = self._v6addr()
        if self.route.get("gateway6") or a6:
            i6 = self._echo(INET6, platform=self.platform)
            out.append(check("internet_v6", OK if i6.get("received") else WARN,
                             "%s %d/%d; global address %s" % (INET6, i6.get("received", 0), i6.get("sent", 0), a6 or "none"),
                             None if i6.get("received") else "IPv6 targets will be disabled"))
        else:
            out.append(check("internet_v6", WARN, "no IPv6 default route or global address", "IPv6 targets disabled (fine if Comcast gave none)"))
        return out

    def c_ttl(self) -> List[Dict[str, Any]]:
        if self.no_net:
            return [self._skip("ttl_probe")]
        method, hop = self._ttl2(self.platform, INET4)
        if hop:
            return [check("ttl_probe", OK, "hop at TTL 2: %s (via %s)" % (hop, method))]
        return [check("ttl_probe", WARN, "no TTL-2 hop found with the ping/tracepath/traceroute binaries",
                      "the tracer will try its native socket method; otherwise only gateway and internet targets are probed")]

    def c_dns(self) -> List[Dict[str, Any]]:
        servers = self.platform.resolvers() or []
        out = [check("resolvers", OK if servers else WARN, ", ".join(servers) if servers else "no resolver found")]
        if self.no_net:
            return out + [self._skip("dns")]
        name = "xboxlive.com"
        parts = []
        ok = False
        # the same preference as targets.static_targets: a resolver that is the gateway or inside the
        # LAN prefix, then the gateway itself, then whatever the system lists first (VPN/MagicDNS)
        gw_dns = None
        try:
            from laglens.targets import lan_resolver

            gw_dns = lan_resolver(list(servers), self.route)
        except Exception:  # noqa: BLE001
            gw_dns = None
        gw_dns = gw_dns or self.route.get("gateway") or (servers[0] if servers else None)
        for label, server in (("gateway", gw_dns), ("1.1.1.1", INET4)):
            if not server:
                continue
            r = self._dns(server, name)
            if r.get("ok"):
                ok = True
                parts.append("%s (%s): %s in %s ms" % (label, server, r["addr"], r["ms"]))
            else:
                parts.append("%s (%s): failed (%s)" % (label, server, r.get("error") or "rcode %s" % r.get("rcode")))
        return out + [check("dns", OK if ok else FAIL, "; ".join(parts), None if ok else "DNS probes will report failures")]

    def c_xbox(self) -> List[Dict[str, Any]]:
        ip = (self.cfg.get("targets") or {}).get("xbox_ip")
        if ip:
            return [check("xbox", OK, "configured %s" % ip, "give the Xbox a DHCP reservation on the XB7 so the address stays put")]
        cands = []
        if not self.no_net:
            ouis = set(microsoft_ouis())
            for n in self.platform.neighbors() or []:
                mac = (n.get("mac") or "").upper()
                if mac and mac[:8] in ouis:
                    cands.append(n.get("ip"))
        if cands:
            return [check("xbox", WARN, "not configured; Microsoft OUI neighbours: %s" % ", ".join(str(c) for c in cands),
                          "set targets.xbox_ip or run with --xbox IP; add a DHCP reservation")]
        return [check("xbox", WARN, "no Xbox IP configured (discovery will watch the neighbour table)",
                      "set targets.xbox_ip or --xbox IP; wake the Xbox once so it shows up")]

    def c_xb7(self) -> List[Dict[str, Any]]:
        d = self.cfg.get("docsis") or {}
        if not d.get("password"):
            return [check("xb7_login", SKIP, "docsis.password not set (XB7 scraping off)", "set docsis.password in config.json to collect modem stats")]
        if self.no_net:
            return [self._skip("xb7_login")]
        r = self._docsis_probe(self.cfg)
        if not r.get("ok"):
            return [check("xb7_login", FAIL, r.get("error") or "login failed", "check docsis.password / docsis.url")]
        return [check("xb7_login", OK if r.get("tables") else WARN, "logged in via %s; %d tables recognised (%s); log page %s" % (
            r.get("login_path"), r.get("tables", 0), ", ".join(r.get("kinds") or []) or "none", "found" if r.get("log_page") else "not found"),
            None if r.get("tables") else "run --docsis-dump and share the pages")]

    def c_igd(self) -> List[Dict[str, Any]]:
        if self.no_net:
            return [self._skip("igd")]
        gw = self.route.get("gateway")
        if not gw:
            return [check("igd", SKIP, "no gateway")]
        r = self._igd_probe(gw)
        if not r.get("found"):
            return [check("igd", WARN, r.get("error") or "no IGD responded (UPnP off on the XB7?)",
                          "enable UPnP on the XB7 (Advanced > Device Discovery) for WAN counters; optional")]
        detail = "%s; services %s; counters %s; external IP %s" % (
            r.get("location"), ", ".join(r.get("services") or []) or "none",
            "incrementing (accuracy is checked against this computer's own upload while running)" if r.get("counters_move")
            else "static", r.get("ext_ip") or "?")
        status = OK if r.get("wancic") else WARN
        return [check("igd", status, detail, None if r.get("wancic") else "IGD found but no WANCommonInterfaceConfig")]

    def c_inhibitor(self) -> List[Dict[str, Any]]:
        cmd = self.platform.keepawake_cmd(self._pid)
        out = []
        if cmd:
            out.append(check("sleep_inhibitor", OK, os.path.basename(cmd[0])))
        else:
            why = "caffeinate not found" if self.platform.name == "darwin" else "kde-inhibit / systemd-inhibit not found"
            out.append(check("sleep_inhibitor", WARN, why, "set the power settings to never suspend for this run"))
        batt = self.platform.on_battery()
        if batt:
            out.append(check("battery", WARN, "on battery: lid-closed sleep is not prevented", "plug the machine in"))
        elif batt is False:
            out.append(check("battery", OK, "on AC power"))
        return out

    def c_firewall(self) -> List[Dict[str, Any]]:
        if self.platform.name != "linux":
            return [check("firewall", OK, "n/a (not Linux)")]
        info = self.platform.firewall_info() or {}
        if not info:
            return [check("firewall", OK, "firewalld not present")]
        port = int(self.cfg.get("port", 8787) or 8787)
        zone = info.get("zone")
        ports = info.get("ports") or []
        if zone == "FedoraWorkstation" or ("%d/tcp" % port) in ports:
            return [check("firewall", OK, "zone %s; ports %s" % (zone, " ".join(ports) or "default"))]
        return [check("firewall", WARN, "zone %s does not open %d/tcp (ports: %s)" % (zone, port, " ".join(ports) or "none"),
                      "sudo firewall-cmd --add-port=%d/tcp && sudo firewall-cmd --permanent --add-port=%d/tcp" % (port, port))]

    def c_port(self) -> List[Dict[str, Any]]:
        port = int(self.cfg.get("port", 8787) or 8787)
        bind = str(self.cfg.get("bind", "0.0.0.0") or "0.0.0.0")
        err = self._bind(port, bind)
        chosen = port
        if err:
            for p in range(port + 1, port + 11):
                if self._bind(p, bind) is None:
                    chosen = p
                    break
        lan = self.route.get("lan_ip") or "127.0.0.1"
        url = "http://%s:%d" % (lan, chosen)
        out = []
        if err and chosen == port:
            out.append(check("port", FAIL, "port %d busy (%s) and %d-%d too" % (port, err, port + 1, port + 10), "free the port or pass --port N"))
        elif err:
            out.append(check("port", WARN, "port %d busy (%s); will use %d" % (port, err, chosen), url))
        else:
            out.append(check("port", OK, "%d bindable; LAN URL %s" % (port, url)))
        host = self.platform.hostname()
        local = host + ".local"
        if self.no_net:
            out.append(self._skip("local_name"))
        elif self._resolve(local):
            out.append(check("local_name", OK, "http://%s:%d" % (local, chosen)))
        else:
            out.append(check("local_name", WARN, "%s does not resolve; use the LAN IP URL" % local))
        return out

    def c_disk(self) -> List[Dict[str, Any]]:
        out = []
        sessions = self.root / "sessions"
        try:
            free_mb = self._disk_usage(str(self.root)).free / (1024 * 1024)
        except OSError as exc:
            free_mb = None
            out.append(check("disk", WARN, "cannot stat %s: %s" % (self.root, exc)))
        min_free = float((self.cfg.get("disk") or {}).get("min_free_mb", 500) or 500)
        if free_mb is not None:
            out.append(check("disk", OK if free_mb > min_free else FAIL, "%.0f MB free at %s (min %.0f MB)" % (free_mb, self.root, min_free),
                             None if free_mb > min_free else "free disk space; writing stops below disk.min_free_mb"))
        try:
            sessions.mkdir(parents=True, exist_ok=True)
            probe = sessions / (".doctor-write-%d" % self._pid)
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            out.append(check("sessions_writable", OK, str(sessions)))
        except OSError as exc:
            out.append(check("sessions_writable", FAIL, "%s: %s" % (sessions, exc), "fix the permissions of sessions/"))
        return out

    def c_clock(self) -> List[Dict[str, Any]]:
        if self.no_net:
            return [self._skip("clock")]
        off = self._sntp()
        if off is None:
            return [check("clock", WARN, "no SNTP reply from time.cloudflare.com", "NTP probes will report")]
        if abs(off) > 5.0:
            return [check("clock", WARN, "clock offset %+.1f s vs time.cloudflare.com" % off, "enable automatic time setting")]
        return [check("clock", OK, "offset %+.3f s vs time.cloudflare.com" % off)]

    def c_binaries(self) -> List[Dict[str, Any]]:
        found = self.platform.binaries(BINARIES)
        present = [n for n in BINARIES if found.get(n)]
        missing = [n for n in BINARIES if not found.get(n)]
        status = OK if "ping" in present else WARN
        return [check("binaries", status, "present: %s; missing: %s" % (", ".join(present) or "none", ", ".join(missing) or "none"),
                      None if "ping" in present else "ping binary missing: no ICMP fallback")]

    # -------------------------------------------------------------- suites
    def run(self, fast: bool = False) -> List[Dict[str, Any]]:
        """The ordered check list (``fast`` = the < 3 s subset used at startup)."""
        checks: List[Dict[str, Any]] = []
        checks += self._safe(self.c_python, "python")
        checks += self._safe(self.c_sockets, "sockets")
        checks += self._safe(self.c_local_network, "local_network")
        checks += self._safe(self.c_route, "route")
        checks += self._safe(self.c_link, "link")
        checks += self._safe(self.c_vpn, "vpn")
        if not fast:
            checks += self._safe(self.c_reachability, "reachability")
            checks += self._safe(self.c_ttl, "ttl_probe")
            checks += self._safe(self.c_dns, "dns")
            checks += self._safe(self.c_xbox, "xbox")
            checks += self._safe(self.c_xb7, "xb7_login")
            checks += self._safe(self.c_igd, "igd")
        checks += self._safe(self.c_inhibitor, "sleep_inhibitor")
        if not fast:
            checks += self._safe(self.c_firewall, "firewall")
        checks += self._safe(self.c_port, "port")
        checks += self._safe(self.c_disk, "disk")
        if not fast:
            checks += self._safe(self.c_clock, "clock")
        checks += self._safe(self.c_binaries, "binaries")
        return checks


def _docsis_probe(cfg: dict) -> Dict[str, Any]:
    """Log in to the XB7 and count recognised tables (used by check 11)."""
    try:
        from laglens.collectors import docsis as dmod
    except ImportError as exc:
        return {"ok": False, "error": "docsis module unavailable: %s" % exc}
    dcfg = cfg.get("docsis") or {}
    cli = dmod.Xb7Client(dcfg)
    try:
        if not cli.login():
            return {"ok": False, "error": "XB7 rejected the login (user %s)" % cli.username}
        kinds: List[str] = []
        tables = 0
        log_page = False
        for path in dcfg.get("pages") or []:
            code, html = cli.fetch(path)
            if code != 200 or dmod.logged_out(html):
                continue
            res = dmod.parse_page(html)
            for t in res["tables"]:
                if t["kind"]:
                    tables += 1
                    kinds.append("%s:%s" % (path.strip("/"), t["kind"]))
                    if t["kind"] == "log":
                        log_page = True
        return {"ok": True, "login_path": cli.login_path_used, "tables": tables, "kinds": kinds, "log_page": log_page}
    except dmod.Xb7Error as exc:
        return {"ok": False, "error": str(exc)}


def _igd_probe(gw: str) -> Dict[str, Any]:
    """SSDP discovery, services, counters moving?, external IP (check 12)."""
    try:
        from laglens.collectors import igd as imod
    except ImportError as exc:
        return {"found": False, "error": "igd module unavailable: %s" % exc}
    locs, err = imod.ssdp_discover(gw)
    if not locs:
        if err == EHOSTUNREACH:
            return {"found": False, "error": "SSDP send blocked (errno 65): Local Network permission"}
        return {"found": False, "error": imod.NO_IGD_REASON}
    import urllib.request

    for loc in locs:
        try:
            resp = urllib.request.urlopen(loc, timeout=5.0)
            try:
                xml_text = resp.read(512 * 1024).decode("utf-8", "replace")
            finally:
                resp.close()
        except Exception:  # noqa: BLE001
            continue
        dev = imod.parse_device_xml(xml_text, loc)
        svcs = dev.get("services") or {}
        out: Dict[str, Any] = {"found": True, "location": loc, "services": sorted(s.rsplit(":", 2)[-2] for s in svcs),
                               "wancic": imod.WANCIC in svcs, "counters_move": None, "ext_ip": None}
        if imod.WANCIC in svcs:
            try:
                a = int(imod.soap_call(svcs[imod.WANCIC], imod.WANCIC, "GetTotalBytesReceived").get("NewTotalBytesReceived", "0"))
                time.sleep(2.0)
                b = int(imod.soap_call(svcs[imod.WANCIC], imod.WANCIC, "GetTotalBytesReceived").get("NewTotalBytesReceived", "0"))
                out["counters_move"] = b != a
            except Exception:  # noqa: BLE001
                out["counters_move"] = None
        for st in (imod.WANIP2, imod.WANIP1):
            if st in svcs:
                try:
                    out["ext_ip"] = imod.soap_call(svcs[st], st, "GetExternalIPAddress").get("NewExternalIPAddress")
                except Exception:  # noqa: BLE001
                    pass
                break
        return out
    return {"found": False, "error": "IGD description could not be fetched"}


# ---------------------------------------------------------------------------
# Rendering and entry points
# ---------------------------------------------------------------------------
def format_table(checks: Sequence[Dict[str, Any]]) -> str:
    """``CHECK | STATUS | DETAIL | FALLBACK/ACTION`` with aligned columns."""
    rows = [("CHECK", "STATUS", "DETAIL", "FALLBACK/ACTION")]
    for c in checks:
        rows.append((str(c.get("check", "")), str(c.get("status", "")).upper(), str(c.get("detail", "")), str(c.get("fallback") or "")))
    w0 = max(len(r[0]) for r in rows)
    w1 = max(len(r[1]) for r in rows)
    w2 = min(90, max(len(r[2]) for r in rows))
    out = []
    for i, r in enumerate(rows):
        out.append("%-*s | %-*s | %-*s | %s" % (w0, r[0], w1, r[1], w2, r[2], r[3]))
        if i == 0:
            out.append("-" * (w0 + w1 + w2 + 9 + max(len(r[3]) for r in rows[:1])))
    return "\n".join(out).rstrip()


def run_cli(cfg: dict, platform: Any, no_net: bool = False, out: Callable[[str], Any] = print, **fakes: Any) -> int:
    """Print the full doctor table; 0 unless Python is too old."""
    doc = Doctor(cfg, platform, no_net=no_net, **fakes)
    checks = doc.run(fast=False)
    out(format_table(checks))
    counts = {s: sum(1 for c in checks if c.get("status") == s) for s in (OK, WARN, FAIL, SKIP)}
    out("%d ok, %d warn, %d fail, %d skipped" % (counts[OK], counts[WARN], counts[FAIL], counts[SKIP]))
    if any(c.get("check") == "python" and c.get("status") == FAIL for c in checks):
        return 1
    return 0


def fast(ctx: Any, **fakes: Any) -> List[Dict[str, Any]]:
    """The startup subset; sets ``state.doctor`` and writes ``doctor.json``."""
    doc = Doctor(ctx.cfg, ctx.platform, no_net=False, root=getattr(ctx, "root", None), **fakes)
    route = getattr(ctx, "route", None)
    if route:
        doc.route = dict(route)
    checks = doc.run(fast=True)
    now = time.time()
    for c in checks:
        c["t"] = round(now, 3)
    try:
        ctx.state.doctor = checks
    except Exception:  # noqa: BLE001
        pass
    if doc.local_network_denied:
        try:
            ctx.state.set_collector("local_network", "disabled", reason=LOCAL_NETWORK_MSG.format(app=ctx.platform.terminal_app_name()))
        except Exception:  # noqa: BLE001
            pass
    try:
        ctx.store.write_json_atomic("doctor.json", checks)
    except Exception:  # noqa: BLE001
        log.debug("doctor: cannot write doctor.json", exc_info=True)
    for c in checks:
        if c.get("status") in (WARN, FAIL):
            log.warning("doctor: %s %s: %s%s", c["check"], c["status"].upper(), c.get("detail"),
                        (" -> " + c["fallback"]) if c.get("fallback") else "")
    return checks


def loopback_checks(echo: Optional[Callable[..., Dict[str, Any]]] = None, out: Callable[[str], Any] = print) -> int:
    """Echo 127.0.0.1 and ::1 with DGRAM ICMP sockets; skipped (0) when sockets are unavailable."""
    fn = echo or icmp_echo
    rc = 0
    for addr in ("127.0.0.1", "::1"):
        r = fn(addr, count=2, timeout=1.0, platform=None)
        if r.get("method") != "socket":
            out("loopback %s: skipped (no DGRAM ICMP socket: %s)" % (addr, r.get("error")))
            continue
        if r.get("received"):
            out("loopback %s: ok (%d/%d, %.2f ms)" % (addr, r["received"], r["sent"], min(r["rtts"])))
        else:
            out("loopback %s: FAIL (no reply: %s)" % (addr, r.get("error") or "timeout"))
            rc = 1
    return rc


def selftest(run_tests: Optional[bool] = None, out: Callable[[str], Any] = print, echo: Optional[Callable[..., Dict[str, Any]]] = None) -> int:
    """Unit tests (unless the caller already ran them) + loopback echo checks; 0/1."""
    rc = 0
    if run_tests is None:
        caller = inspect.currentframe()
        caller_mod = caller.f_back.f_globals.get("__name__") if caller and caller.f_back else None
        run_tests = caller_mod != "laglens.app"
    if run_tests:
        import unittest

        tests_dir = ROOT / "tests"
        if tests_dir.is_dir():
            suite = unittest.defaultTestLoader.discover(str(tests_dir), top_level_dir=str(tests_dir))
            result = unittest.TextTestRunner(verbosity=1).run(suite)
            rc = 0 if result.wasSuccessful() else 1
        else:
            out("selftest: tests/ not found (zip build); unit tests skipped")
    return rc or loopback_checks(echo=echo, out=out)


__all__ = ["Doctor", "run_cli", "fast", "selftest", "loopback_checks", "icmp_echo", "echo_parallel", "dns_query", "sntp_offset",
           "ttl2_hop", "format_table", "check", "build_echo", "strip_ip_header", "LOCAL_NETWORK_MSG", "OK", "WARN", "FAIL", "SKIP"]
