"""macOS platform facts: ``route -n get``, ``netstat -ibn``, ``ifconfig``, ``arp``/``ndp``,
``system_profiler SPAirPortDataType -json``, ``scutil --dns``, ``caffeinate``."""
import json
import re
from typing import Any, Dict, List, Optional

from laglens.platform.base import Platform, empty_stats, to_float, to_int

_KV_LINE = re.compile(r"^\s*([A-Za-z_ ]+?):\s*(.*?)\s*$")
_IFCONFIG_INET = re.compile(r"^\s*inet (\d+\.\d+\.\d+\.\d+) netmask 0x([0-9a-fA-F]{8})", re.M)
_IFCONFIG_MEDIA = re.compile(r"^\s*media:\s*(.+?)\s*$", re.M)
_IFCONFIG_STATUS = re.compile(r"^\s*status:\s*(\S+)", re.M)
_MEDIA_SPEED = re.compile(r"(\d+(?:\.\d+)?)\s*(G|M)?base", re.I)
_ARP_LINE = re.compile(r"^\S+ \((?P<ip>[^)]+)\) at (?P<mac>\S+) on (?P<iface>\S+)")
_SIGNAL_NOISE = re.compile(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm")
_CHANNEL = re.compile(r"^\s*(\d+)")
_NAMESERVER = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)")
_RESOLVER_HDR = re.compile(r"^resolver #(\d+)")
_SPEED_HEADER_NAMES = ("Ipkts", "Ierrs", "Ibytes", "Opkts", "Oerrs", "Obytes", "Coll", "Idrop", "Odrop")

_NDP_STATES = {"R": "REACHABLE", "S": "STALE", "D": "DELAY", "P": "PROBE", "I": "INCOMPLETE", "N": "NOSTATE", "W": "WAITING"}


def netmask_to_prefixlen(hexmask: str) -> Optional[int]:
    try:
        return bin(int(hexmask, 16)).count("1")
    except ValueError:
        return None


def parse_kv_block(text: str) -> Dict[str, str]:
    """``key: value`` lines (``route -n get`` output) → dict of stripped keys."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        m = _KV_LINE.match(line)
        if m:
            out[m.group(1).strip()] = m.group(2)
    return out


def parse_netstat_ibn(text: str, iface: str) -> Dict[str, Optional[int]]:
    """Header-based parse of ``netstat -ibn -I <iface>`` (the ``<Link#N>`` row)."""
    out = empty_stats()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return out
    header = lines[0].split()
    if "Name" not in header:
        return out
    offsets = {}
    for i, h in enumerate(header):
        if h in _SPEED_HEADER_NAMES:
            offsets[h] = len(header) - i  # offset from the right
    for line in lines[1:]:
        toks = line.split()
        if len(toks) < 3 or toks[0] != iface or not toks[2].startswith("<Link#"):
            continue
        vals: Dict[str, Optional[int]] = {}
        for name, off in offsets.items():
            vals[name] = to_int(toks[-off]) if len(toks) >= off else None
        out.update(
            {
                "rx_bytes": vals.get("Ibytes"),
                "tx_bytes": vals.get("Obytes"),
                "rx_packets": vals.get("Ipkts"),
                "tx_packets": vals.get("Opkts"),
                "rx_errors": vals.get("Ierrs"),
                "tx_errors": vals.get("Oerrs"),
                "rx_dropped": vals.get("Idrop"),
                "tx_dropped": vals.get("Odrop"),
                "crc": None,
                "collisions": vals.get("Coll"),
                "multicast": None,
            }
        )
        return out
    return out


def parse_media(media: str) -> Dict[str, Any]:
    """``autoselect (1000baseT <full-duplex>)`` → speed (Mb/s) and duplex."""
    speed = None
    m = _MEDIA_SPEED.search(media)
    if m:
        val = float(m.group(1))
        unit = (m.group(2) or "M").upper()
        speed = int(val * 1000) if unit == "G" else int(val)
    duplex = None
    low = media.lower()
    if "full-duplex" in low:
        duplex = "full"
    elif "half-duplex" in low:
        duplex = "half"
    return {"speed": speed, "duplex": duplex}


class DarwinPlatform(Platform):
    """Parsers for the macOS command set (SPEC_FULL §4, BUILD_PLAN §0)."""

    name = "darwin"

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self._wifi_ports: Optional[Dict[str, str]] = None  # device -> hardware port name

    # -------------------------------------------------------------- routes
    def _route_get(self, *args: str) -> Dict[str, str]:
        txt = self.run(["route", "-n", "get"] + list(args))
        return parse_kv_block(txt) if txt else {}

    def default_route(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {"gateway": None, "iface": None, "gateway6": None, "iface6": None, "lan_ip": None, "prefixlen": None}
        kv = self._route_get("default")
        res["gateway"] = kv.get("gateway") or None
        res["iface"] = kv.get("interface") or None
        if res["gateway"] is None:
            txt = self.run(["netstat", "-rn"])
            if txt:
                for line in txt.splitlines():
                    toks = line.split()
                    if len(toks) >= 4 and toks[0] == "default" and "." in toks[1]:
                        res["gateway"], res["iface"] = toks[1], toks[3]
                        break
        kv6 = self._route_get("-inet6", "default")
        if kv6.get("gateway"):
            gw6 = kv6["gateway"]
            if gw6.startswith("fe80") and "%" not in gw6 and kv6.get("interface"):
                gw6 = "%s%%%s" % (gw6, kv6["interface"])
            res["gateway6"] = gw6
            res["iface6"] = kv6.get("interface") or None
        if res["iface"]:
            txt = self.run(["ifconfig", res["iface"]])
            if txt:
                m = _IFCONFIG_INET.search(txt)
                if m:
                    res["lan_ip"] = m.group(1)
                    res["prefixlen"] = netmask_to_prefixlen(m.group(2))
        if res["lan_ip"] is None and res["gateway"]:
            res["lan_ip"] = self.lan_ip(res["gateway"])
        return res

    def route_to(self, addr: str) -> Dict[str, Any]:
        kv = self._route_get(addr)
        iface = kv.get("interface") or None
        src = None
        if iface:
            txt = self.run(["ifconfig", iface])
            if txt:
                m = _IFCONFIG_INET.search(txt)
                if m:
                    src = m.group(1)
        return {"iface": iface, "src": src}

    # --------------------------------------------------------------- stats
    def iface_stats(self, iface: str) -> Dict[str, Optional[int]]:
        txt = self.run(["netstat", "-ibn", "-I", iface])
        if not txt:
            return empty_stats()
        return parse_netstat_ibn(txt, iface)

    def _wifi_port_map(self) -> Dict[str, str]:
        if self._wifi_ports is not None:
            return self._wifi_ports
        ports: Dict[str, str] = {}
        txt = self.run(["networksetup", "-listallhardwareports"])
        if txt:
            port = None
            for line in txt.splitlines():
                line = line.strip()
                if line.startswith("Hardware Port:"):
                    port = line.split(":", 1)[1].strip()
                elif line.startswith("Device:") and port:
                    ports[line.split(":", 1)[1].strip()] = port
        self._wifi_ports = ports
        return ports

    def is_wireless(self, iface: str) -> bool:
        port = self._wifi_port_map().get(iface, "")
        return "wi-fi" in port.lower() or "airport" in port.lower()

    def link_info(self, iface: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"speed": None, "duplex": None, "carrier": None, "carrier_changes": None, "operstate": None, "wireless": self.is_wireless(iface)}
        txt = self.run(["ifconfig", iface])
        if not txt:
            return info
        m = _IFCONFIG_MEDIA.search(txt)
        if m:
            info.update(parse_media(m.group(1)))
            info["media"] = m.group(1)
        s = _IFCONFIG_STATUS.search(txt)
        if s:
            info["carrier"] = s.group(1) == "active"
            info["operstate"] = "up" if s.group(1) == "active" else "down"
        return info

    # ----------------------------------------------------------- neighbors
    def neighbors(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        txt = self.run(["arp", "-an"])
        if txt:
            for line in txt.splitlines():
                m = _ARP_LINE.match(line.strip())
                if not m:
                    continue
                mac = m.group("mac").lower()
                incomplete = "incomplete" in mac
                out.append({"ip": m.group("ip"), "mac": None if incomplete else mac, "iface": m.group("iface"), "state": "INCOMPLETE" if incomplete else "REACHABLE"})
        txt = self.run(["ndp", "-an"])
        if txt:
            for line in txt.splitlines()[1:]:
                toks = line.split()
                if len(toks) < 5 or ":" not in toks[0]:
                    continue
                mac = toks[1].lower()
                incomplete = "incomplete" in mac or mac == "(incomplete)"
                out.append({"ip": toks[0], "mac": None if incomplete else mac, "iface": toks[2], "state": _NDP_STATES.get(toks[4], toks[4])})
        return out

    # ---------------------------------------------------------------- wifi
    def wifi_info(self, iface: str) -> Optional[Dict[str, Any]]:
        txt = self.run(["system_profiler", "SPAirPortDataType", "-json"], timeout=10.0)
        if txt:
            try:
                data = json.loads(txt)
            except ValueError:
                data = None
            info = self._parse_airport_json(data, iface) if data else None
            if info is not None:
                if info.get("ssid") is None or info.get("bssid") is None:
                    summ = self._ipconfig_summary(iface)
                    info["ssid"] = info.get("ssid") or summ.get("ssid")
                    info["bssid"] = info.get("bssid") or summ.get("bssid")
                return info
        summ = self._ipconfig_summary(iface)
        if summ:
            return {"rssi": None, "noise": None, "chan": None, "bssid": summ.get("bssid"), "ssid": summ.get("ssid"), "rate_mbps": None}
        return None

    @staticmethod
    def _parse_airport_json(data: Any, iface: str) -> Optional[Dict[str, Any]]:
        try:
            sections = data.get("SPAirPortDataType") or []
        except AttributeError:
            return None
        for sec in sections:
            for itf in sec.get("spairport_airport_interfaces") or []:
                if itf.get("_name") != iface:
                    continue
                cur = itf.get("spairport_current_network_information") or {}
                if not cur:
                    return {"rssi": None, "noise": None, "chan": None, "bssid": None, "ssid": None, "rate_mbps": None, "connected": False}
                rssi = noise = None
                m = _SIGNAL_NOISE.search(str(cur.get("spairport_signal_noise", "")))
                if m:
                    rssi, noise = int(m.group(1)), int(m.group(2))
                chan = None
                mc = _CHANNEL.match(str(cur.get("spairport_network_channel", "")))
                if mc:
                    chan = int(mc.group(1))
                return {
                    "rssi": rssi,
                    "noise": noise,
                    "chan": chan,
                    "bssid": (cur.get("spairport_network_bssid") or None),
                    "ssid": cur.get("_name"),
                    "rate_mbps": to_float(cur.get("spairport_network_rate")),
                    "phy": cur.get("spairport_network_phymode"),
                    "connected": True,
                }
        return None

    def _ipconfig_summary(self, iface: str) -> Dict[str, Optional[str]]:
        out: Dict[str, Optional[str]] = {}
        txt = self.run(["ipconfig", "getsummary", iface])
        if not txt:
            return out
        for line in txt.splitlines():
            s = line.strip()
            if s.startswith("SSID :") or s.startswith("SSID:"):
                out["ssid"] = s.split(":", 1)[1].strip() or None
            elif s.startswith("BSSID :") or s.startswith("BSSID:"):
                v = s.split(":", 1)[1].strip().lower()
                out["bssid"] = v if v and "redacted" not in v else None
        return out

    # ----------------------------------------------------------- resolvers
    def resolvers(self) -> List[str]:
        servers: List[str] = []
        txt = self.run(["scutil", "--dns"])
        if txt:
            current = None
            for line in txt.splitlines():
                h = _RESOLVER_HDR.match(line.strip())
                if h:
                    current = int(h.group(1))
                    continue
                if current == 1:
                    m = _NAMESERVER.match(line)
                    if m:
                        servers.append(m.group(1))
        if not servers:
            gw = self.default_route().get("gateway")
            if gw:
                servers.append(gw)
        seen = set()
        out = []
        for s in servers:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out

    # --------------------------------------------------------- misc facts
    def keepawake_cmd(self, pid: int) -> Optional[List[str]]:
        path = self.which("caffeinate") or "/usr/bin/caffeinate"
        return [path, "-i", "-s", "-w", str(pid)]

    def on_battery(self) -> Optional[bool]:
        txt = self.run(["pmset", "-g", "batt"])
        if not txt:
            return None
        if "Battery Power" in txt:
            return True
        if "AC Power" in txt:
            return False
        return None

    def dhcp_lease(self, iface: str) -> Dict[str, Any]:
        txt = self.run(["ipconfig", "getpacket", iface])
        out: Dict[str, Any] = {}
        if not txt:
            return out
        for line in txt.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.split("(")[0].strip()
            v = v.strip()
            if k in ("lease_time", "server_identifier", "router", "yiaddr", "domain_name_server"):
                if v.startswith("0x"):
                    out[k] = to_int(int(v, 16))
                elif v.startswith("{") and v.endswith("}"):
                    out[k] = [x.strip() for x in v[1:-1].split(",") if x.strip()]
                else:
                    out[k] = v
        return out


__all__ = ["DarwinPlatform", "parse_netstat_ibn", "parse_media", "parse_kv_block", "netmask_to_prefixlen"]
