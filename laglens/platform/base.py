"""Platform layer base class: the OS-specific facts Lag Lens needs.

Every method **never raises** and returns ``None`` / ``{}`` / ``[]`` on
failure. External commands run through :meth:`Platform.run` with
``subprocess.run(..., timeout=5)``; a ``FileNotFoundError`` is recorded once
in :attr:`Platform.missing` and the command is not retried. File reads go
through :meth:`Platform.read` (``None`` when unreadable).

Tests inject ``runner``, ``reader``, ``exists``, ``env`` and ``which`` fakes.

Return shapes (identical on Linux and macOS):

* ``default_route()`` → ``{'gateway','iface','gateway6','iface6','lan_ip','prefixlen'}``
* ``route_to(addr)`` → ``{'iface','src'}``
* ``iface_stats(iface)`` → counters dict (``rx_bytes, tx_bytes, rx_packets,
  tx_packets, rx_errors, tx_errors, rx_dropped, tx_dropped, crc, collisions,
  multicast``), ``None`` where unavailable
* ``link_info(iface)`` → ``{'speed','duplex','carrier','carrier_changes','operstate','wireless'}``
* ``neighbors()`` → ``[{'ip','mac','iface','state'}]`` (v4 and v6)
* ``wifi_info(iface)`` → ``{'rssi','noise','chan','bssid','ssid','rate_mbps'}`` or ``None``
* ``resolvers()`` → list of DNS server IPs
* ``vpn_routes(addr)`` → ``{'via_tunnel': bool, 'iface'}``
* ``keepawake_cmd(pid)`` → argv list or ``None``
* ``on_battery()`` → bool or ``None``; ``is_game_mode()`` → bool
* ``firewall_info()`` → dict (Linux firewalld, best effort)
* ``terminal_app_name()`` → human name for the macOS Local Network message
* ``load_avg()`` → ``(1, 5, 15)`` or ``None``
"""
import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("laglens.platform")

CMD_TIMEOUT_S = 5.0
TUNNEL_IFACE_RE = re.compile(r"^(tailscale|wg|tun|utun|ppp|tap|nordlynx|proton)")
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

STATS_KEYS = (
    "rx_bytes",
    "tx_bytes",
    "rx_packets",
    "tx_packets",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
    "crc",
    "collisions",
    "multicast",
)

TERMINAL_APP_NAMES = {
    "Apple_Terminal": "Terminal",
    "iTerm.app": "iTerm",
    "ghostty": "Ghostty",
    "WezTerm": "WezTerm",
    "vscode": "Visual Studio Code",
    "Hyper": "Hyper",
    "Alacritty": "Alacritty",
    "kitty": "kitty",
    "tmux": "your terminal app (tmux)",
}

RunResult = Tuple[int, str, str]
Runner = Callable[[Sequence[str], float], RunResult]


def default_runner(argv: Sequence[str], timeout: float = CMD_TIMEOUT_S) -> RunResult:
    """Run ``argv`` and return ``(rc, stdout, stderr)``; raises FileNotFoundError/TimeoutExpired."""
    cp = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    return cp.returncode, cp.stdout, cp.stderr


def default_reader(path: str) -> Optional[str]:
    """Return the file's text or ``None``."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def empty_stats() -> Dict[str, Optional[int]]:
    return {k: None for k in STATS_KEYS}


def to_int(v: Any) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def to_float(v: Any) -> Optional[float]:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def is_private(addr: Optional[str]) -> bool:
    """RFC1918 / link-local / loopback / CGNAT (the token-free source check)."""
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or (ip.version == 4 and ip in CGNAT_NET)


class Platform:
    """Generic platform with injectable I/O; Linux/macOS subclasses parse real output."""

    name = "generic"

    def __init__(
        self,
        runner: Optional[Runner] = None,
        reader: Optional[Callable[[str], Optional[str]]] = None,
        exists: Optional[Callable[[str], bool]] = None,
        env: Optional[Dict[str, str]] = None,
        which: Optional[Callable[[str], Optional[str]]] = None,
    ) -> None:
        self._runner: Runner = runner or default_runner
        self._reader = reader or default_reader
        self._exists = exists or os.path.exists
        self._env: Dict[str, str] = env if env is not None else dict(os.environ)
        self._which = which or shutil.which
        self.missing: set = set()
        self.capabilities: Dict[str, bool] = {}
        self.last_error: Dict[str, str] = {}

    # ------------------------------------------------------------ plumbing
    def run_rc(self, argv: Sequence[str], timeout: float = CMD_TIMEOUT_S) -> Optional[RunResult]:
        """Run a command; ``None`` when the binary is missing or the call failed."""
        if not argv:
            return None
        name = argv[0]
        if name in self.missing:
            return None
        try:
            rc, out, err = self._runner(list(argv), timeout)
            self.capabilities[name] = True
            return rc, out or "", err or ""
        except FileNotFoundError:
            self.missing.add(name)
            self.capabilities[name] = False
            self.last_error[name] = "not found"
            log.info("platform: %s not found; related checks disabled", name)
            return None
        except subprocess.TimeoutExpired:
            self.last_error[name] = "timeout"
            log.warning("platform: %s timed out after %.0fs", " ".join(argv), timeout)
            return None
        except (OSError, ValueError) as exc:
            self.last_error[name] = str(exc)
            log.warning("platform: %s failed: %s", " ".join(argv), exc)
            return None

    def run(self, argv: Sequence[str], timeout: float = CMD_TIMEOUT_S) -> Optional[str]:
        """Stdout of a successful (rc 0) command, else ``None``."""
        res = self.run_rc(argv, timeout)
        if res is None or res[0] != 0:
            return None
        return res[1]

    def read(self, path: str) -> Optional[str]:
        try:
            return self._reader(path)
        except Exception:  # noqa: BLE001
            return None

    def read_stripped(self, path: str) -> Optional[str]:
        v = self.read(path)
        return v.strip() if v is not None else None

    def exists(self, path: str) -> bool:
        try:
            return bool(self._exists(path))
        except Exception:  # noqa: BLE001
            return False

    def which(self, name: str) -> Optional[str]:
        """``shutil.which`` wrapper that never raises."""
        try:
            return self._which(name)
        except Exception:  # noqa: BLE001
            return None

    def env(self, key: str, default: str = "") -> str:
        return self._env.get(key, default)

    # ------------------------------------------------------- shared facts
    def hostname(self) -> str:
        try:
            return socket.gethostname().split(".")[0] or "localhost"
        except OSError:
            return "localhost"

    def lan_ip(self, probe_addr: str = "10.0.0.1") -> Optional[str]:
        """Local address used to reach ``probe_addr`` (UDP connect; no packet is sent)."""
        try:
            fam = socket.AF_INET6 if ":" in probe_addr else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_DGRAM)
            try:
                s.connect((probe_addr, 9))
                return s.getsockname()[0]
            finally:
                s.close()
        except OSError:
            return None

    def load_avg(self) -> Optional[Tuple[float, float, float]]:
        try:
            a, b, c = os.getloadavg()
            return (round(a, 2), round(b, 2), round(c, 2))
        except (OSError, AttributeError):
            return None

    def terminal_app_name(self) -> str:
        """Human name of the terminal app (macOS Local Network privacy message)."""
        tp = self.env("TERM_PROGRAM")
        if tp in TERMINAL_APP_NAMES:
            return TERMINAL_APP_NAMES[tp]
        if tp:
            return tp
        return "your terminal app"

    def os_info(self) -> Dict[str, str]:
        try:
            u = os.uname()
            return {"system": u.sysname, "release": u.release, "machine": u.machine}
        except (AttributeError, OSError):
            return {"system": sys.platform, "release": "", "machine": ""}

    # ----------------------------------------------- overridable interface
    def default_route(self) -> Dict[str, Any]:
        return {"gateway": None, "iface": None, "gateway6": None, "iface6": None, "lan_ip": None, "prefixlen": None}

    def route_to(self, addr: str) -> Dict[str, Any]:
        return {"iface": None, "src": None}

    def iface_stats(self, iface: str) -> Dict[str, Optional[int]]:
        return empty_stats()

    def link_info(self, iface: str) -> Dict[str, Any]:
        return {"speed": None, "duplex": None, "carrier": None, "carrier_changes": None, "operstate": None, "wireless": False}

    def neighbors(self) -> List[Dict[str, Any]]:
        return []

    def wifi_info(self, iface: str) -> Optional[Dict[str, Any]]:
        return None

    def resolvers(self) -> List[str]:
        gw = self.default_route().get("gateway")
        return [gw] if gw else []

    def vpn_routes(self, addr: str = "1.1.1.1") -> Dict[str, Any]:
        r = self.route_to(addr)
        iface = r.get("iface") or ""
        src = r.get("src")
        via = bool(TUNNEL_IFACE_RE.match(iface))
        if not via and src:
            try:
                via = ipaddress.ip_address(src) in CGNAT_NET
            except ValueError:
                via = False
        return {"via_tunnel": via, "iface": iface or None}

    def keepawake_cmd(self, pid: int) -> Optional[List[str]]:
        return None

    def on_battery(self) -> Optional[bool]:
        return None

    def is_game_mode(self) -> bool:
        return False

    def firewall_info(self) -> Dict[str, Any]:
        return {}

    def dhcp_lease(self, iface: str) -> Dict[str, Any]:
        return {}

    def binaries(self, names: Sequence[str]) -> Dict[str, Optional[str]]:
        """Map each binary name to its path or ``None`` (doctor check 19)."""
        return {n: self.which(n) for n in names}


__all__ = [
    "Platform", "default_runner", "default_reader", "empty_stats", "to_int", "to_float", "is_private",
    "STATS_KEYS", "CMD_TIMEOUT_S", "TUNNEL_IFACE_RE", "CGNAT_NET", "TERMINAL_APP_NAMES",
]
