"""UPnP IGD household witness (SPEC_FULL §4.10, S3): WAN byte counters, status, port mappings.

Discovery: SSDP ``M-SEARCH`` for ``InternetGatewayDevice:1`` and ``:2``
(``IP_MULTICAST_TTL`` 2, replies collected for 3 s; the search is also sent
unicast to the gateway, which the XB7 answers), keeping only ``LOCATION``
URLs that live on the gateway IP. The device description XML yields the
``controlURL`` of ``WANCommonInterfaceConfig:1`` and ``WANIPConnection:1|2``.

Polling (all SOAP POSTs over ``urllib`` with a 5 s timeout):

* every ``igd.counter_interval_s``: ``GetTotalBytesSent`` / ``GetTotalBytesReceived``
  (u32, wrap at 2^32 handled) → WAN ``rx_mbps`` / ``tx_mbps``;
* every ``igd.status_interval_s``: ``GetStatusInfo`` (uptime, connection
  status) and ``GetExternalIPAddress``; one ``igd.jsonl`` row;
* every ``igd.mappings_interval_s``: ``GetGenericPortMappingEntry`` 0.. until
  SOAP fault 713 (``nat_mapping_change`` note when the set changes).

Trust validation: within the first 5 minutes the counters must rise by at
least 1 KB over some 60 s window while this host itself sent traffic;
otherwise ``trusted`` becomes ``False`` (chip "IGD: counters static, not
trusted") and the ``wan_saturated`` rule (trusted tx > 80 % of
``link.up_mbps`` for 3 s) stays silent.
"""
from __future__ import annotations

import http.client
import logging
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from laglens.supervisor import start_thread

log = logging.getLogger("laglens.igd")

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_COLLECT_S = 3.0
SSDP_TARGETS = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2")
SOAP_TIMEOUT_S = 5.0
WANCIC = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
WANIP1 = "urn:schemas-upnp-org:service:WANIPConnection:1"
WANIP2 = "urn:schemas-upnp-org:service:WANIPConnection:2"
U32 = 1 << 32
TRUST_WINDOW_S = 60.0
TRUST_MIN_BYTES = 1024
TRUST_DEADLINE_S = 300.0
TRUST_HOST_MIN_BYTES = 1024
# Some firmware (the Arris TG4482A XB7 among them) clamps a byte counter at INT32/UINT32 max instead of
# wrapping; a counter that sits on one of these values across polls carries no rate information.
PEGGED_VALUES = frozenset({2 ** 31 - 1, 2 ** 32 - 1})
SATURATION_SHARE = 0.80
SATURATION_HOLD_S = 3.0
MAPPINGS_MAX = 64
REDISCOVER_S = 600.0
NO_IGD_REASON = "no IGD responded (UPnP off on the XB7?)"
NO_WANCIC_REASON = "IGD found but no WANCommonInterfaceConfig"
NOT_TRUSTED_CHIP = "IGD: counters static, not trusted"
# Moving counters are not enough: the Arris TG4482A's upload counter moves but counts ~4 % of real traffic.
# The counters become trusted only once they account for a known upload from this computer.
NOT_VERIFIED_CHIP = "IGD: upload counter not verified yet"
MISCOUNT_REASON = "IGD upload counter counted only %d%% of this computer's own %.1f MB upload; not trusted"
VERIFY_MIN_BYTES = 1_000_000      # passive check: this computer uploaded at least this much in the window
VERIFY_WINDOW_S = 40.0
VERIFY_QUIET_S = 6.0              # ...and has been quiet since, so the gateway's counter has caught up
VERIFY_QUIET_MBPS = 0.5
VERIFY_PASS = 0.8                 # counted share of the known upload, after taking off the background below
VERIFY_FAIL = 0.5                 # raw counted share: household traffic can only add to it, so less is proof
VERIFY_BG_WINDOW_S = 120.0        # background: what the counter adds beyond this computer's own traffic
VERIFY_BG_MIN_S = 20.0            # ...measured over at least this much quiet time before the upload
SELFCHECK_DELAY_S = 60.0          # active check this long after discovery (once), unless disabled
SELFCHECK_BYTES = 1_500_000
SELFCHECK_RATE_BPS = 3_000_000    # ~12 % of a 25 Mb/s upstream for ~4 s
SELFCHECK_SETTLE_S = 4.0
SELFCHECK_RETRY_S = 600.0
SELFCHECK_MAX_TRIES = 3
SELFCHECK_HOST = "speed.cloudflare.com"
SELFCHECK_PATH = "/__up"
LOCAL_NET_REASON = "local network permission (macOS blocked multicast to the LAN)"

_HDR_RE = re.compile(r"^([A-Za-z0-9-]+)\s*:\s*(.*?)\s*$")


class SoapFault(Exception):
    """A SOAP fault; ``code`` is the UPnP ``errorCode`` (713 = index out of range)."""

    def __init__(self, code: Optional[int], desc: str = "") -> None:
        super().__init__("UPnP error %s %s" % (code, desc))
        self.code = code
        self.desc = desc


# ---------------------------------------------------------------------------
# SSDP
# ---------------------------------------------------------------------------
def msearch_payload(st: str, mx: int = 2) -> bytes:
    return ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: %d\r\nST: %s\r\n\r\n" % (mx, st)).encode("ascii")


def parse_ssdp_reply(data: bytes) -> Dict[str, str]:
    """Headers of an SSDP response (lower-case keys); ``{}`` when it is not a 200 reply."""
    try:
        text = data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return {}
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or "200" not in lines[0]:
        return {}
    out: Dict[str, str] = {}
    for ln in lines[1:]:
        m = _HDR_RE.match(ln)
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out


def _host_of(url: str) -> Optional[str]:
    try:
        return urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None


def ssdp_discover(gateway_ip: str, socket_factory: Optional[Callable[[], Any]] = None, collect_s: float = SSDP_COLLECT_S,
                  clock: Callable[[], float] = time.monotonic) -> Tuple[List[str], Optional[int]]:
    """``(locations_on_gateway, errno)``: LOCATION URLs whose host is ``gateway_ip`` (deduped)."""
    try:
        if socket_factory is not None:
            sock = socket_factory()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    except OSError as exc:
        return [], exc.errno
    found: List[str] = []
    err: Optional[int] = None
    try:
        sock.settimeout(0.5)
        for st in SSDP_TARGETS:
            payload = msearch_payload(st)
            for dest in (SSDP_ADDR, (gateway_ip, 1900)):
                try:
                    sock.sendto(payload, dest)
                except OSError as exc:
                    err = exc.errno if err is None else err
        deadline = clock() + collect_s
        while clock() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                err = exc.errno if err is None else err
                break
            hdr = parse_ssdp_reply(data)
            loc = hdr.get("location")
            if not loc:
                continue
            if _host_of(loc) == gateway_ip and loc not in found:
                found.append(loc)
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return found, err


# ---------------------------------------------------------------------------
# Device description and SOAP
# ---------------------------------------------------------------------------
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_device_xml(xml_text: str, location: str) -> Dict[str, Any]:
    """``{'services': {serviceType: controlURL(abs)}, 'friendly_name', 'model'}`` from a device description."""
    out: Dict[str, Any] = {"services": {}, "friendly_name": None, "model": None, "url_base": None}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    base = location
    for el in root.iter():
        if _local(el.tag) == "URLBase" and (el.text or "").strip():
            base = el.text.strip()
            out["url_base"] = base
            break
    for el in root.iter():
        name = _local(el.tag)
        if name == "friendlyName" and out["friendly_name"] is None:
            out["friendly_name"] = (el.text or "").strip() or None
        elif name == "modelName" and out["model"] is None:
            out["model"] = (el.text or "").strip() or None
        elif name == "service":
            stype = None
            curl = None
            for ch in el:
                ln = _local(ch.tag)
                if ln == "serviceType":
                    stype = (ch.text or "").strip()
                elif ln == "controlURL":
                    curl = (ch.text or "").strip()
            if stype and curl:
                out["services"][stype] = urllib.parse.urljoin(base, curl)
    return out


def soap_envelope(service_type: str, action: str, args: Optional[Dict[str, Any]] = None) -> bytes:
    body = "".join("<%s>%s</%s>" % (k, _xml_escape(str(v)), k) for k, v in (args or {}).items())
    env = ('<?xml version="1.0"?>'
           '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
           's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
           '<u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>' % (action, service_type, body, action))
    return env.encode("utf-8")


def _xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def parse_soap_response(xml_text: str, action: str) -> Dict[str, str]:
    """Child elements of ``<u:<action>Response>`` → dict; raises :class:`SoapFault` on a fault body."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise SoapFault(None, "unparseable SOAP response")
    for el in root.iter():
        if _local(el.tag) == "Fault":
            code = None
            desc = ""
            for sub in el.iter():
                ln = _local(sub.tag)
                if ln == "errorCode":
                    try:
                        code = int((sub.text or "").strip())
                    except ValueError:
                        code = None
                elif ln == "errorDescription":
                    desc = (sub.text or "").strip()
            raise SoapFault(code, desc)
    want = action + "Response"
    for el in root.iter():
        if _local(el.tag) == want:
            return {_local(ch.tag): (ch.text or "").strip() for ch in el}
    # Some stacks answer without the Response wrapper: take the Body's children.
    for el in root.iter():
        if _local(el.tag) == "Body":
            out: Dict[str, str] = {}
            for ch in el.iter():
                if ch is not el and len(ch) == 0:
                    out[_local(ch.tag)] = (ch.text or "").strip()
            return out
    return {}


def soap_call(control_url: str, service_type: str, action: str, args: Optional[Dict[str, Any]] = None,
              urlopen: Optional[Callable[..., Any]] = None, timeout: float = SOAP_TIMEOUT_S) -> Dict[str, str]:
    """POST one SOAP action; returns the response fields or raises ``SoapFault`` / ``OSError``."""
    opener = urlopen or urllib.request.urlopen
    req = urllib.request.Request(control_url, data=soap_envelope(service_type, action, args), method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": '"%s#%s"' % (service_type, action),
        "User-Agent": "LagLens/1.0 UPnP/1.1",
        "Connection": "close",
    })
    try:
        resp = opener(req, timeout=timeout)
        try:
            body = resp.read(256 * 1024)
        finally:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(64 * 1024)
        except Exception:  # noqa: BLE001
            body = b""
        if not body:
            raise SoapFault(None, "HTTP %d" % exc.code)
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    return parse_soap_response(body, action)


def u32_delta(cur: Optional[int], prev: Optional[int]) -> Optional[int]:
    """Counter delta with wrap at 2^32; ``None`` when unknown; a backwards jump beyond a wrap → 0."""
    if cur is None or prev is None:
        return None
    d = (cur - prev) % U32
    if d > U32 // 2:  # went backwards: counter reset
        return 0
    return d


def _to_int(v: Any) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
def rate_limited_upload(n_bytes: int = SELFCHECK_BYTES, rate_bps: int = SELFCHECK_RATE_BPS, host: str = SELFCHECK_HOST,
                        path: str = SELFCHECK_PATH, timeout: float = 15.0) -> int:
    """POST ``n_bytes`` of zeros to ``https://host/path`` at about ``rate_bps``; returns the bytes sent (raises on failure)."""
    chunk = 32 * 1024
    per_chunk_s = chunk * 8.0 / float(max(1, rate_bps))
    conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.putrequest("POST", path)
        conn.putheader("Content-Type", "application/octet-stream")
        conn.putheader("Content-Length", str(n_bytes))
        conn.putheader("User-Agent", "LagLens/1.0 (gateway counter check)")
        conn.endheaders()
        sent = 0
        block = b"\0" * chunk
        t0 = time.monotonic()
        while sent < n_bytes:
            part = block[: min(chunk, n_bytes - sent)]
            conn.send(part)
            sent += len(part)
            ahead = t0 + (sent / float(chunk)) * per_chunk_s - time.monotonic()
            if ahead > 0:
                time.sleep(ahead)
        resp = conn.getresponse()
        resp.read(65536)
        if resp.status >= 400:
            raise OSError("upload endpoint answered HTTP %d" % resp.status)
        return sent
    finally:
        conn.close()


class IgdCollector:
    """``IgdCollector(ctx)``; ``.status()`` is the ``GET /api/igd`` body."""

    name = "igd"

    def __init__(self, ctx: Any, urlopen: Optional[Callable[..., Any]] = None,
                 discover: Optional[Callable[[str], Tuple[List[str], Optional[int]]]] = None,
                 clock: Callable[[], float] = time.time, mono: Callable[[], float] = time.monotonic,
                 uploader: Optional[Callable[[int, int], int]] = None,
                 sleep: Optional[Callable[[float], Any]] = None) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.platform = ctx.platform
        self.cfg = ctx.cfg or {}
        icfg = self.cfg.get("igd") or {}
        self._urlopen = urlopen or urllib.request.urlopen
        self._discover = discover or (lambda gw: ssdp_discover(gw))
        self._clock = clock
        self._mono = mono
        self.counter_interval_s = max(1.0, float(icfg.get("counter_interval_s", 2) or 2))
        self.status_interval_s = max(5.0, float(icfg.get("status_interval_s", 30) or 30))
        self.mappings_interval_s = max(30.0, float(icfg.get("mappings_interval_s", 300) or 300))
        self.verify_upload = bool(icfg.get("verify_upload", True))
        self._uploader = uploader or (lambda n, rate: rate_limited_upload(n, rate))
        self._sleep = sleep or (lambda s: self.state.stop_event.wait(s))
        self.thread = None
        self._lock = threading.Lock()
        self.location: Optional[str] = None
        self.services: Dict[str, str] = {}
        self.device: Dict[str, Any] = {}
        self.ready = False
        self.reason: Optional[str] = None
        self.trusted: Optional[bool] = None  # True only once the upload counter accounted for a known upload
        self.live = False  # the counters move at all
        self.verification: Optional[Dict[str, Any]] = None  # {"method","ratio","bytes","t"} of the last check
        self._host_tx_cum = 0.0
        self._wan_tx_cum = 0.0
        self._vhist: Deque[Tuple[float, float, float, float]] = deque()  # (t, host tx cum, wan tx cum, host Mb/s)
        self._bg: Deque[Tuple[float, float, float]] = deque()  # (t, wan bytes beyond this computer's, s) while quiet
        self._miscounted = False  # a check proved the counter misses uploads: final for this session
        self._ready_mono: Optional[float] = None
        self._selfcheck_next: Optional[float] = None
        self._selfcheck_tries = 0
        self.rx_mbps: Optional[float] = None
        self.tx_mbps: Optional[float] = None
        self.rx_pegged = False  # download counter clamped by the firmware: rx rate unavailable
        self.tx_pegged = False
        self.uptime_s: Optional[int] = None
        self.conn_status: Optional[str] = None
        self.ext_ip: Optional[str] = None
        self.mappings: List[Dict[str, Any]] = []
        self.last_t: Optional[float] = None
        self._prev_sent: Optional[int] = None
        self._prev_recv: Optional[int] = None
        self._prev_counter_t: Optional[float] = None
        self._counter_errors = 0
        self._hist: Deque[Tuple[float, int]] = deque()  # (t, sent+recv modulo-free running total)
        self._running_total = 0
        self._host_bytes = 0.0
        self._started_at: Optional[float] = None
        self._sat_since: Optional[float] = None
        self._sat_noted = False
        self._next_counter: Optional[float] = None
        self._next_status: Optional[float] = None
        self._next_mappings: Optional[float] = None
        self._next_discover: Optional[float] = None
        self._mappings_key: Optional[str] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.state.set_collector(self.name, "ok", trusted=None, reason="discovering")
        self.thread = start_thread(self.name, self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        t = self.thread
        if t is not None:
            t.join(timeout)

    def _loop(self) -> None:
        st = self.state
        self.step()
        while not st.stop_event.wait(0.5):
            self.step()

    def _gateway(self) -> Optional[str]:
        route = getattr(self.ctx, "route", None) or {}
        gw = route.get("gateway") or (self.state.host or {}).get("gateway")
        if not gw:
            try:
                gw = (self.platform.default_route() or {}).get("gateway")
            except Exception:  # noqa: BLE001
                gw = None
        return gw

    # ------------------------------------------------------------- discover
    def discover(self) -> bool:
        """SSDP + device XML; sets ``ready``/``services`` or a disabled reason. Returns ``ready``."""
        gw = self._gateway()
        if not gw:
            self._disable("no default route: is the network up?")
            return False
        try:
            locations, err = self._discover(gw)
        except Exception as exc:  # noqa: BLE001
            self._disable("SSDP failed: %s" % exc)
            return False
        if not locations:
            if err == 65 and self.platform.name == "darwin":
                self._disable(LOCAL_NET_REASON)
            else:
                self._disable(NO_IGD_REASON)
            return False
        for loc in locations:
            try:
                req = urllib.request.Request(loc, headers={"User-Agent": "LagLens/1.0 UPnP/1.1"})
                resp = self._urlopen(req, timeout=SOAP_TIMEOUT_S)
                try:
                    xml_text = resp.read(512 * 1024)
                finally:
                    try:
                        resp.close()
                    except Exception:  # noqa: BLE001
                        pass
            except Exception as exc:  # noqa: BLE001
                log.info("igd: cannot fetch %s: %s", loc, exc)
                continue
            if isinstance(xml_text, bytes):
                xml_text = xml_text.decode("utf-8", "replace")
            dev = parse_device_xml(xml_text, loc)
            svcs = dev.get("services") or {}
            if WANCIC in svcs:
                self.location = loc
                self.device = dev
                self.services = svcs
                self.ready = True
                self.reason = None
                self._started_at = self._clock()
                self.state.set_collector(self.name, "ok", trusted=self.trusted, location=loc, model=dev.get("model"))
                log.info("igd: using %s (%s)", loc, dev.get("friendly_name") or dev.get("model") or "IGD")
                return True
        self._disable(NO_WANCIC_REASON)
        return False

    def _disable(self, reason: str) -> None:
        self.ready = False
        self.reason = reason
        self._next_discover = self._mono() + REDISCOVER_S
        self.state.set_collector(self.name, "disabled", reason=reason, trusted=False)
        log.info("igd: %s (retry in %d s)", reason, int(REDISCOVER_S))

    def _wanip(self) -> Tuple[Optional[str], Optional[str]]:
        for st in (WANIP2, WANIP1):
            if st in self.services:
                return self.services[st], st
        return None, None

    # ----------------------------------------------------------------- step
    def step(self, now: Optional[float] = None) -> None:
        """Run whichever cadence is due (counters / status / mappings / rediscovery)."""
        now = self._clock() if now is None else now
        mono = self._mono()
        if not self.ready:
            if self._next_discover is None or mono >= self._next_discover:
                self._next_discover = mono + REDISCOVER_S
                if not self.discover():
                    return
                self._next_counter = self._next_status = self._next_mappings = None
                self._ready_mono = mono
                self._selfcheck_next = mono + SELFCHECK_DELAY_S
            else:
                return
        if self._next_counter is None or mono >= self._next_counter:
            self._next_counter = mono + self.counter_interval_s
            self.poll_counters(now)
        if self._next_status is None or mono >= self._next_status:
            self._next_status = mono + self.status_interval_s
            self.poll_status(now)
        if self._next_mappings is None or mono >= self._next_mappings:
            self._next_mappings = mono + self.mappings_interval_s
            self.poll_mappings(now)
        # runs after a passive pass too: a passive window can be flattered by other devices' traffic
        if (self.verify_upload and self.trusted is not False and self._selfcheck_next is not None
                and mono >= self._selfcheck_next and self._selfcheck_tries < SELFCHECK_MAX_TRIES):
            self.self_check(now)

    def _call(self, service: str, action: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        url = self.services.get(service)
        if not url:
            raise SoapFault(None, "service %s not offered" % service)
        return soap_call(url, service, action, args, urlopen=self._urlopen)

    def poll_counters(self, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        now = self._clock() if now is None else now
        try:
            sent = _to_int(self._call(WANCIC, "GetTotalBytesSent").get("NewTotalBytesSent"))
            recv = _to_int(self._call(WANCIC, "GetTotalBytesReceived").get("NewTotalBytesReceived"))
        except (SoapFault, OSError, ValueError) as exc:
            self._counter_errors += 1
            if self._counter_errors >= 5:
                self.state.set_collector(self.name, "degraded", reason="IGD counters failing: %s" % exc, trusted=self.trusted)
            if self._counter_errors >= 30:
                self._disable("IGD stopped answering: %s" % exc)
            return None
        self._counter_errors = 0
        d_sent = u32_delta(sent, self._prev_sent)
        d_recv = u32_delta(recv, self._prev_recv)
        dt = (now - self._prev_counter_t) if self._prev_counter_t is not None else None
        self.tx_pegged = sent in PEGGED_VALUES and self._prev_sent == sent
        dt_v = (now - self._prev_counter_t) if self._prev_counter_t is not None else None
        self.rx_pegged = recv in PEGGED_VALUES and self._prev_recv == recv
        if dt and dt > 0 and d_sent is not None and d_recv is not None:
            self.tx_mbps = None if self.tx_pegged else round(d_sent * 8.0 / dt / 1e6, 3)
            self.rx_mbps = None if self.rx_pegged else round(d_recv * 8.0 / dt / 1e6, 3)
            self._running_total += (0 if self.tx_pegged else d_sent) + (0 if self.rx_pegged else d_recv)
            self._hist.append((now, self._running_total))
            iface = self.state.latest("iface") or {}
            for k in ("rx_mbps", "tx_mbps"):
                v = iface.get(k)
                if isinstance(v, (int, float)):
                    self._host_bytes += float(v) * 1e6 / 8.0 * dt
        elif self._prev_counter_t is None:
            # First reading: record the baseline point so the very next delta can prove the
            # counters are live (a window needs two points).
            self._hist.append((now, self._running_total))
        if dt_v and dt_v > 0 and d_sent is not None and not self.tx_pegged:
            iface = self.state.latest("iface") or {}
            host_rate = iface.get("tx_mbps")
            if isinstance(host_rate, (int, float)):
                host_b = float(host_rate) * 1e6 / 8.0 * dt_v
                self._host_tx_cum += host_b
                self._wan_tx_cum += d_sent
                self._vhist.append((now, self._host_tx_cum, self._wan_tx_cum, float(host_rate)))
                if host_rate < VERIFY_QUIET_MBPS:
                    self._bg.append((now, d_sent - host_b, dt_v))
                while self._bg and self._bg[0][0] < now - VERIFY_BG_WINDOW_S:
                    self._bg.popleft()
        self._prev_sent, self._prev_recv, self._prev_counter_t = sent, recv, now
        self._validate_trust(now)
        self._verify_passive(now)
        self._saturation(now)
        self.last_t = now
        self._publish(now)
        return {"sent": sent, "recv": recv, "rx_mbps": self.rx_mbps, "tx_mbps": self.tx_mbps}

    def _validate_trust(self, now: float) -> None:
        cutoff = now - TRUST_WINDOW_S * 5
        while self._hist and self._hist[0][0] < cutoff:
            self._hist.popleft()
        if self.live or self.trusted is not None:
            return
        # Any 60 s window with >= 1 KB of movement proves the counters are live (not that they are right).
        for i in range(len(self._hist)):
            t_i, v_i = self._hist[i]
            for j in range(len(self._hist) - 1, i, -1):
                t_j, v_j = self._hist[j]
                if t_j - t_i > TRUST_WINDOW_S:
                    continue
                if v_j - v_i >= TRUST_MIN_BYTES:
                    self.live = True
                    self.state.set_collector(self.name, "ok", trusted=None, reason=NOT_VERIFIED_CHIP, location=self.location)
                    log.info("igd: counters move; not trusted until they account for a known upload")
                    return
                break
        start = self._started_at if self._started_at is not None else now
        if self.trusted is None and now - start >= TRUST_DEADLINE_S and self._host_bytes >= TRUST_HOST_MIN_BYTES:
            self.trusted = False
            self.state.set_collector(self.name, "ok", trusted=False, reason=NOT_TRUSTED_CHIP, location=self.location)
            log.warning("igd: %s", NOT_TRUSTED_CHIP)

    def _background_bps(self, until: float) -> float:
        """Bytes/s the upload counter adds beyond this computer's own traffic while it is quiet, measured before
        ``until`` (other devices' uploads as this counter sees them); 0 until there is enough quiet time to tell."""
        rows = [r for r in self._bg if r[0] <= until]
        secs = sum(r[2] for r in rows)
        if secs < VERIFY_BG_MIN_S:
            return 0.0
        return max(0.0, sum(r[1] for r in rows) / secs)

    def _apply_verification(self, now: float, counted: float, known: float, method: str,
                            background: float = 0.0) -> Optional[bool]:
        """Judge the counter from ``counted`` WAN bytes against a ``known`` upload of this computer.

        Other devices' traffic can only add to ``counted``, so an undercount is proof, and final for the session.
        A pass must still hold once ``background`` (what the counter adds on its own in as long) is taken off.
        """
        if known <= 0:
            return None
        if self._miscounted:
            log.info("igd: ignoring a %s check (counted %.0f%% of %.1f MB): an earlier check showed this counter "
                     "misses uploads", method, counted / known * 100, known / 1e6)
            return None
        ratio = counted / known
        net = max(0.0, counted - max(0.0, background)) / known
        self.verification = {"method": method, "ratio": round(ratio, 3), "bytes": int(known), "t": round(now, 3)}
        if net >= VERIFY_PASS:
            self.trusted = True
            self.state.set_collector(self.name, "ok", trusted=True, reason=None, location=self.location, verification=self.verification)
            log.info("igd: upload counter verified (%s): counted %.0f%% of %.1f MB", method, ratio * 100, known / 1e6)
        elif ratio < VERIFY_FAIL:
            self.trusted = False
            self._miscounted = True
            reason = MISCOUNT_REASON % (int(round(ratio * 100)), known / 1e6)
            self.state.set_collector(self.name, "ok", trusted=False, reason=reason, location=self.location, verification=self.verification)
            log.warning("igd: %s (%s check)", reason, method)
        else:
            log.info("igd: upload counter check inconclusive (%s): counted %.0f%% of %.1f MB, %.0f%% beyond the "
                     "background", method, ratio * 100, known / 1e6, net * 100)
            return None
        self._publish(now)
        return self.trusted

    def _verify_passive(self, now: float) -> None:
        """This computer uploaded >= 1 MB recently and has gone quiet: did the gateway count it?"""
        while self._vhist and self._vhist[0][0] < now - VERIFY_WINDOW_S:
            self._vhist.popleft()
        if len(self._vhist) < 2 or self._miscounted:
            return
        if any(r[3] >= VERIFY_QUIET_MBPS for r in self._vhist if r[0] >= now - VERIFY_QUIET_S):
            return  # still uploading, or the gateway's counter may not have caught up
        first, last = self._vhist[0], self._vhist[-1]
        host = last[1] - first[1]
        if host < VERIFY_MIN_BYTES:
            return
        background = self._background_bps(first[0]) * (last[0] - first[0])
        self._apply_verification(now, last[2] - first[2], host, "passive", background)
        self._vhist.clear()  # judge each burst once

    def self_check(self, now: Optional[float] = None) -> Optional[bool]:
        """Upload ~1.5 MB at ~3 Mb/s once and see whether the gateway's upload counter moves by as much."""
        now = self._clock() if now is None else now
        mono = self._mono()
        busy = bool(self.state.open_episodes()) or bool((self.state.loadtest or {}).get("running"))
        if busy:
            self._selfcheck_next = mono + 60.0  # never add traffic during an episode or a load test
            return None
        self._selfcheck_tries += 1
        self._selfcheck_next = mono + SELFCHECK_RETRY_S
        try:
            t_a = self._clock()
            a = _to_int(self._call(WANCIC, "GetTotalBytesSent").get("NewTotalBytesSent"))
            n = int(self._uploader(SELFCHECK_BYTES, SELFCHECK_RATE_BPS))
            self._sleep(SELFCHECK_SETTLE_S)
            b = _to_int(self._call(WANCIC, "GetTotalBytesSent").get("NewTotalBytesSent"))
            t_b = self._clock()
        except Exception as exc:  # noqa: BLE001 - offline, endpoint down: try again later
            log.info("igd: upload counter self-check failed (%s); retry in %d min", exc, int(SELFCHECK_RETRY_S // 60))
            return None
        delta = u32_delta(b, a)
        if delta is None or n <= 0:
            return None
        self._vhist.clear()  # the passive check must not judge the same upload again
        background = self._background_bps(t_a) * max(0.0, t_b - t_a)
        result = self._apply_verification(t_b, float(delta), float(n), "self-check", background)
        if result is not None:
            self._selfcheck_next = None
        return result

    def _saturation(self, now: float) -> None:
        up = (self.cfg.get("link") or {}).get("up_mbps")
        try:
            up = float(up)
        except (TypeError, ValueError):
            up = 25.0
        if self.trusted and self.tx_mbps is not None and up > 0 and self.tx_mbps > SATURATION_SHARE * up:
            if self._sat_since is None:
                self._sat_since = now
            elif now - self._sat_since >= SATURATION_HOLD_S and not self._sat_noted:
                self._sat_noted = True
                self.state.raise_note("wan_saturated", t=now, severity=2,
                                      note="WAN upload %.1f Mb/s > %d%% of link.up_mbps %.0f (IGD counters)" % (self.tx_mbps, int(SATURATION_SHARE * 100), up),
                                      tx_mbps=self.tx_mbps, rx_mbps=self.rx_mbps, up_mbps=up)
        else:
            self._sat_since = None
            self._sat_noted = False

    def poll_status(self, now: Optional[float] = None, write: bool = True) -> Optional[Dict[str, Any]]:
        now = self._clock() if now is None else now
        url, st = self._wanip()
        if url is None:
            return None
        try:
            info = self._call(st, "GetStatusInfo")
            self.uptime_s = _to_int(info.get("NewUptime"))
            self.conn_status = info.get("NewConnectionStatus") or None
        except (SoapFault, OSError, ValueError) as exc:
            log.debug("igd: GetStatusInfo failed: %s", exc)
        try:
            ip = self._call(st, "GetExternalIPAddress").get("NewExternalIPAddress") or None
            if ip and ip != "0.0.0.0":
                self.ext_ip = ip
        except (SoapFault, OSError, ValueError) as exc:
            log.debug("igd: GetExternalIPAddress failed: %s", exc)
        self.last_t = now
        self._publish(now)
        row = {"t": round(now, 3), "uptime_s": self.uptime_s, "status": self.conn_status, "ext_ip": self.ext_ip,
               "mappings": list(self.mappings), "rx_mbps": self.rx_mbps, "tx_mbps": self.tx_mbps, "trusted": self.trusted,
               "rx_pegged": self.rx_pegged, "tx_pegged": self.tx_pegged}
        if write:
            try:
                self.store.append_json("igd", row)
            except Exception:  # noqa: BLE001
                log.debug("igd: append_json failed", exc_info=True)
        return row

    def poll_mappings(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        now = self._clock() if now is None else now
        url, st = self._wanip()
        if url is None:
            return []
        out: List[Dict[str, Any]] = []
        for i in range(MAPPINGS_MAX):
            try:
                m = self._call(st, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
            except SoapFault as exc:
                if exc.code in (713, 714, 402):
                    break
                log.debug("igd: mapping %d: %s", i, exc)
                break
            except (OSError, ValueError) as exc:
                log.debug("igd: mapping %d: %s", i, exc)
                break
            if not m:
                break
            out.append({
                "proto": m.get("NewProtocol"),
                "ext": _to_int(m.get("NewExternalPort")),
                "int": "%s:%s" % (m.get("NewInternalClient"), m.get("NewInternalPort")),
                "desc": m.get("NewPortMappingDescription"),
                "enabled": m.get("NewEnabled"),
                "lease_s": _to_int(m.get("NewLeaseDuration")),
            })
        key = repr(sorted((str(x["proto"]), str(x["ext"]), str(x["int"])) for x in out))
        if self._mappings_key is not None and key != self._mappings_key:
            self.state.raise_note("nat_mapping_change", t=now, severity=1,
                                  note="UPnP port mappings changed (%d now)" % len(out), count=len(out))
        self._mappings_key = key
        self.mappings = out
        self._publish(now)
        return out

    # --------------------------------------------------------------- publish
    def _row(self, now: float) -> Dict[str, Any]:
        return {"rx_mbps": self.rx_mbps, "tx_mbps": self.tx_mbps, "trusted": self.trusted, "verification": self.verification,
                "uptime_s": self.uptime_s,
                "rx_pegged": self.rx_pegged, "tx_pegged": self.tx_pegged,
                "ext_ip": self.ext_ip, "status": self.conn_status, "mappings": list(self.mappings),
                "model": (self.device or {}).get("model"), "t": round(now, 3)}

    def _publish(self, now: float) -> None:
        row = self._row(now)
        self.state.set_latest("igd", row)
        with self.state.lock:
            wan = dict(self.state.latest("wan") or {})
            wan.update({"rx_mbps": self.rx_mbps, "tx_mbps": self.tx_mbps, "trusted": self.trusted, "uptime_s": self.uptime_s,
                        "rx_pegged": self.rx_pegged, "tx_pegged": self.tx_pegged})
            wan.setdefault("ext_ip", self.ext_ip)
            if wan.get("ext_ip") is None and self.ext_ip:
                wan["ext_ip"] = self.ext_ip
            self.state.set_latest("wan", wan)

    def status(self) -> Dict[str, Any]:
        """The ``GET /api/igd`` body."""
        coll = self.state.collector(self.name) or {}
        now = self._clock()
        out = self._row(now)
        out.update({
            "status": coll.get("status", "disabled"),
            "connection_status": self.conn_status,
            "reason": self.reason or coll.get("reason"),
            "location": self.location,
            "services": sorted(self.services),
            "device": {"friendly_name": self.device.get("friendly_name"), "model": self.device.get("model")} if self.device else None,
            "last_t": self.last_t,
        })
        return out


__all__ = [
    "IgdCollector", "SoapFault", "ssdp_discover", "parse_ssdp_reply", "msearch_payload", "parse_device_xml",
    "soap_envelope", "parse_soap_response", "soap_call", "u32_delta", "WANCIC", "WANIP1", "WANIP2",
    "NO_IGD_REASON", "NO_WANCIC_REASON", "NOT_TRUSTED_CHIP", "TRUST_DEADLINE_S",
]
