"""Linux (Fedora/Bazzite) platform facts: ``ip -j``, sysfs, ``iw``, resolvectl."""
import json
import re
from typing import Any, Dict, List, Optional

from laglens.platform.base import Platform, empty_stats, to_float, to_int

_SYSFS_STATS = {
    "rx_bytes": "rx_bytes",
    "tx_bytes": "tx_bytes",
    "rx_packets": "rx_packets",
    "tx_packets": "tx_packets",
    "rx_errors": "rx_errors",
    "tx_errors": "tx_errors",
    "rx_dropped": "rx_dropped",
    "tx_dropped": "tx_dropped",
    "crc": "rx_crc_errors",
    "collisions": "collisions",
    "multicast": "multicast",
}

_IW_SIGNAL = re.compile(r"^\s*signal:\s*(-?\d+)\s*dBm", re.M)
_IW_FREQ = re.compile(r"^\s*freq:\s*(\d+)", re.M)
_IW_SSID = re.compile(r"^\s*SSID:\s*(.+?)\s*$", re.M)
_IW_BSSID = re.compile(r"^Connected to\s+([0-9a-fA-F:]{17})", re.M)
_IW_TXRATE = re.compile(r"^\s*tx bitrate:\s*([\d.]+)\s*MBit/s", re.M)
_IW_RXRATE = re.compile(r"^\s*rx bitrate:\s*([\d.]+)\s*MBit/s", re.M)
_PROC_WIRELESS_ROW = re.compile(r"^\s*(\S+):\s*\S+\s+([\d.-]+)\s+([\d.-]+)\s+([\d.-]+)")
_RESOLVECTL_DNS = re.compile(r"^\s*DNS Servers?:\s*(.*)$")
_IP_RE = re.compile(r"^[0-9a-fA-F:.]+(%\w+)?(#\d+)?$")


def freq_to_channel(freq_mhz: Optional[int]) -> Optional[int]:
    """802.11 centre frequency (MHz) → channel number."""
    if not freq_mhz:
        return None
    f = int(freq_mhz)
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5000 <= f <= 5925:
        return (f - 5000) // 5
    if 5925 < f <= 7125:
        return (f - 5950) // 5
    return None


class LinuxPlatform(Platform):
    """Parsers for ``ip -j``, sysfs, ``/proc``, ``iw``, ``resolvectl``, firewalld."""

    name = "linux"

    # ------------------------------------------------------------ helpers
    def _ip_json(self, *args: str) -> Optional[Any]:
        out = self.run(["ip", "-j"] + list(args))
        if out is None:
            return None
        try:
            return json.loads(out)
        except ValueError:
            return None

    def _sysfs(self, iface: str, name: str) -> Optional[str]:
        return self.read_stripped("/sys/class/net/%s/%s" % (iface, name))

    # -------------------------------------------------------------- routes
    def default_route(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {"gateway": None, "iface": None, "gateway6": None, "iface6": None, "lan_ip": None, "prefixlen": None}
        routes = self._ip_json("route", "show", "default")
        best = None
        if isinstance(routes, list):
            for r in routes:
                if not isinstance(r, dict) or not r.get("gateway"):
                    continue
                if best is None or to_int(r.get("metric", 0)) < to_int(best.get("metric", 0)):
                    best = r
        if best is not None:
            res["gateway"] = best.get("gateway")
            res["iface"] = best.get("dev")
        else:
            txt = self.run(["ip", "route", "show", "default"])
            if txt:
                m = re.search(r"default via (\S+) dev (\S+)", txt)
                if m:
                    res["gateway"], res["iface"] = m.group(1), m.group(2)
            if res["gateway"] is None:
                self._proc_net_route(res)
        v6 = self._ip_json("-6", "route", "show", "default")
        if isinstance(v6, list):
            for r in v6:
                if isinstance(r, dict) and r.get("gateway"):
                    gw = r["gateway"]
                    dev = r.get("dev")
                    if gw.startswith("fe80") and dev and "%" not in gw:
                        gw = "%s%%%s" % (gw, dev)
                    res["gateway6"] = gw
                    res["iface6"] = dev
                    res["expires6"] = r.get("expires")
                    break
        if res["iface"]:
            addrs = self._ip_json("addr", "show", "dev", res["iface"])
            if isinstance(addrs, list):
                for entry in addrs:
                    for ai in (entry.get("addr_info") or []) if isinstance(entry, dict) else []:
                        if ai.get("family") == "inet" and ai.get("local"):
                            res["lan_ip"] = ai["local"]
                            res["prefixlen"] = to_int(ai.get("prefixlen"))
                            break
                    if res["lan_ip"]:
                        break
        if res["lan_ip"] is None and res["gateway"]:
            res["lan_ip"] = self.lan_ip(res["gateway"])
        return res

    def _proc_net_route(self, res: Dict[str, Any]) -> None:
        txt = self.read("/proc/net/route")
        if not txt:
            return
        for line in txt.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[1] != "00000000":
                continue
            try:
                flags = int(parts[3], 16)
            except ValueError:
                continue
            if not flags & 2:
                continue
            gw_hex = parts[2]
            try:
                octets = [int(gw_hex[i:i + 2], 16) for i in (6, 4, 2, 0)]
            except ValueError:
                continue
            res["gateway"] = ".".join(str(o) for o in octets)
            res["iface"] = parts[0]
            return

    def route_to(self, addr: str) -> Dict[str, Any]:
        out = self._ip_json("route", "get", addr)
        if isinstance(out, list) and out and isinstance(out[0], dict):
            return {"iface": out[0].get("dev"), "src": out[0].get("prefsrc")}
        txt = self.run(["ip", "route", "get", addr])
        if txt:
            m_dev = re.search(r"\bdev (\S+)", txt)
            m_src = re.search(r"\bsrc (\S+)", txt)
            return {"iface": m_dev.group(1) if m_dev else None, "src": m_src.group(1) if m_src else None}
        return {"iface": None, "src": None}

    # --------------------------------------------------------------- stats
    def iface_stats(self, iface: str) -> Dict[str, Optional[int]]:
        out = empty_stats()
        base = "/sys/class/net/%s/statistics/" % iface
        found = False
        for key, fname in _SYSFS_STATS.items():
            v = to_int(self.read_stripped(base + fname))
            if v is not None:
                found = True
            out[key] = v
        if not found:
            self._proc_net_dev(iface, out)
        return out

    def _proc_net_dev(self, iface: str, out: Dict[str, Optional[int]]) -> None:
        txt = self.read("/proc/net/dev")
        if not txt:
            return
        for line in txt.splitlines():
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            if name.strip() != iface:
                continue
            f = rest.split()
            if len(f) < 16:
                return
            vals = [to_int(x) for x in f]
            out.update(
                {
                    "rx_bytes": vals[0], "rx_packets": vals[1], "rx_errors": vals[2], "rx_dropped": vals[3],
                    "multicast": vals[7], "tx_bytes": vals[8], "tx_packets": vals[9], "tx_errors": vals[10],
                    "tx_dropped": vals[11], "collisions": vals[13], "crc": None,
                }
            )
            return

    def link_info(self, iface: str) -> Dict[str, Any]:
        speed = to_int(self._sysfs(iface, "speed"))
        if speed is not None and speed < 0:
            speed = None
        carrier = to_int(self._sysfs(iface, "carrier"))
        wireless = self.exists("/sys/class/net/%s/wireless" % iface) or self.exists("/sys/class/net/%s/phy80211" % iface)
        duplex = self._sysfs(iface, "duplex")
        if duplex not in ("full", "half"):
            duplex = None
        return {
            "speed": speed,
            "duplex": duplex,
            "carrier": None if carrier is None else bool(carrier),
            "carrier_changes": to_int(self._sysfs(iface, "carrier_changes")),
            "operstate": self._sysfs(iface, "operstate"),
            "wireless": bool(wireless),
        }

    # ----------------------------------------------------------- neighbors
    def neighbors(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for args in (("neigh", "show"), ("-6", "neigh", "show")):
            rows = self._ip_json(*args)
            if not isinstance(rows, list):
                continue
            for r in rows:
                if not isinstance(r, dict) or not r.get("dst"):
                    continue
                st = r.get("state")
                if isinstance(st, list):
                    st = ",".join(st)
                out.append({"ip": r["dst"], "mac": (r.get("lladdr") or "").lower() or None, "iface": r.get("dev"), "state": st})
        if not out:
            txt = self.read("/proc/net/arp")
            if txt:
                for line in txt.splitlines()[1:]:
                    f = line.split()
                    if len(f) >= 6 and f[3] != "00:00:00:00:00:00":
                        out.append({"ip": f[0], "mac": f[3].lower(), "iface": f[5], "state": "REACHABLE" if f[2] == "0x2" else "STALE"})
        return out

    # ---------------------------------------------------------------- wifi
    def wifi_info(self, iface: str) -> Optional[Dict[str, Any]]:
        txt = self.run(["iw", "dev", iface, "link"])
        if txt is not None and "Not connected" not in txt:
            m_sig = _IW_SIGNAL.search(txt)
            if m_sig:
                m_freq = _IW_FREQ.search(txt)
                freq = to_int(m_freq.group(1)) if m_freq else None
                rate = _IW_TXRATE.search(txt) or _IW_RXRATE.search(txt)
                ssid = _IW_SSID.search(txt)
                bssid = _IW_BSSID.search(txt)
                return {
                    "rssi": int(m_sig.group(1)),
                    "noise": None,
                    "chan": freq_to_channel(freq),
                    "freq": freq,
                    "bssid": bssid.group(1).lower() if bssid else None,
                    "ssid": ssid.group(1) if ssid else None,
                    "rate_mbps": to_float(rate.group(1)) if rate else None,
                }
        txt = self.read("/proc/net/wireless")
        if txt:
            for line in txt.splitlines()[2:]:
                m = _PROC_WIRELESS_ROW.match(line)
                if m and m.group(1) == iface:
                    level = to_float(m.group(3).rstrip("."))
                    noise = to_float(m.group(4).rstrip("."))
                    return {
                        "rssi": int(level) if level is not None else None,
                        "noise": int(noise) if noise is not None and noise > -256 else None,
                        "chan": None,
                        "bssid": None,
                        "ssid": None,
                        "rate_mbps": None,
                        "quality": to_float(m.group(2).rstrip(".")),
                    }
        txt = self.run(["nmcli", "-t", "-f", "IN-USE,SIGNAL,CHAN,BSSID", "dev", "wifi"])
        if txt:
            for line in txt.splitlines():
                if not line.startswith("*"):
                    continue
                parts = line.replace("\\:", "\x00").split(":")
                if len(parts) >= 4:
                    return {
                        "rssi": None,
                        "noise": None,
                        "chan": to_int(parts[2]),
                        "bssid": parts[3].replace("\x00", ":").lower() or None,
                        "ssid": None,
                        "rate_mbps": None,
                        "quality": to_float(parts[1]),
                    }
        return None

    # ----------------------------------------------------------- resolvers
    def resolvers(self) -> List[str]:
        servers: List[str] = []
        txt = self.run(["resolvectl", "status"])
        if txt:
            in_list = False
            for line in txt.splitlines():
                m = _RESOLVECTL_DNS.match(line)
                if m:
                    in_list = True
                    servers.extend(t for t in m.group(1).split() if _IP_RE.match(t))
                    continue
                if in_list:
                    toks = line.split()
                    if toks and all(_IP_RE.match(t) for t in toks) and line.startswith(" "):
                        servers.extend(toks)
                        continue
                    in_list = False
        if not servers:
            iface = self.default_route().get("iface")
            if iface:
                txt = self.run(["nmcli", "-t", "-f", "IP4.DNS,IP6.DNS", "dev", "show", iface])
                if txt:
                    for line in txt.splitlines():
                        if ":" in line and line.split(":", 1)[0].startswith(("IP4.DNS", "IP6.DNS")):
                            v = line.split(":", 1)[1].strip()
                            if v:
                                servers.append(v)
        if not servers:
            gw = self.default_route().get("gateway")
            if gw:
                servers.append(gw)
        seen = set()
        out = []
        for s in servers:
            s = s.split("#")[0]
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out

    # ------------------------------------------------------- misc facts
    def keepawake_cmd(self, pid: int) -> Optional[List[str]]:
        if self.which("kde-inhibit"):
            return ["kde-inhibit", "--power", "sleep", "infinity"]
        if self.which("systemd-inhibit"):
            return [
                "systemd-inhibit", "--what=sleep", "--who=Lag Lens", "--why=network monitoring",
                "--mode=block", "sleep", "infinity",
            ]
        return None

    def on_battery(self) -> Optional[bool]:
        for name in ("AC", "ACAD", "AC0", "ADP1", "ADP0"):
            v = self.read_stripped("/sys/class/power_supply/%s/online" % name)
            if v in ("0", "1"):
                return v == "0"
        return None

    def is_game_mode(self) -> bool:
        desk = (self.env("XDG_CURRENT_DESKTOP") + " " + self.env("XDG_SESSION_DESKTOP")).lower()
        if "gamescope" in desk:
            return True
        res = self.run_rc(["pgrep", "-x", "gamescope"])
        return bool(res and res[0] == 0 and res[1].strip())

    def firewall_info(self) -> Dict[str, Any]:
        res = self.run_rc(["firewall-cmd", "--state"])
        if res is None:
            return {}
        info: Dict[str, Any] = {"state": (res[1] or res[2]).strip() or ("running" if res[0] == 0 else "not running")}
        if res[0] != 0:
            return info
        zone = self.run(["firewall-cmd", "--get-default-zone"])
        info["zone"] = zone.strip() if zone else None
        ports = self.run(["firewall-cmd", "--list-ports"])
        info["ports"] = ports.split() if ports else []
        services = self.run(["firewall-cmd", "--list-services"])
        info["services"] = services.split() if services else []
        return info

    def dhcp_lease(self, iface: str) -> Dict[str, Any]:
        txt = self.run(["nmcli", "-t", "-f", "DHCP4.OPTION", "dev", "show", iface])
        out: Dict[str, Any] = {}
        if not txt:
            return out
        for line in txt.splitlines():
            if ":" not in line:
                continue
            kv = line.split(":", 1)[1]
            if "=" in kv:
                k, v = kv.split("=", 1)
                out[k.strip()] = v.strip()
        return out


__all__ = ["LinuxPlatform", "freq_to_channel"]
