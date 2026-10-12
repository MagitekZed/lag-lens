"""Xbox collector (SPEC_FULL §5.5): find the console, add its target, track AWAKE/ASLEEP.

Address resolution order: ``--xbox IP`` → ``targets.xbox_ip`` → discovery
(when ``targets.xbox_discovery``): rows of ``platform.neighbors()`` whose MAC
prefix is one of the Microsoft OUIs in ``laglens/data/oui_microsoft.txt``,
never the gateway. Exactly one candidate is used; several are offered on the
``/setup`` page (``state.xbox['candidates']``, collector ``degraded``); none
leaves the collector ``disabled`` with a visible reason and discovery is
retried every 600 s.

Once an address is known the ``xbox`` ICMP target is registered (or re-used
on ``--resume``) and the presence state machine runs once per second:

* ``unknown`` at start (and after :meth:`XboxCollector.set_ip`);
* ``awake`` after 10 consecutive ICMP replies on the xbox target or any UDP
  5050 SmartGlass reply (probed every 10 s);
* ``asleep`` after 30 s with zero replies of either kind while the ``gw4``
  target is healthy (loss < 10 % over the last 30 s), so a LAN outage is not
  mistaken for standby;
* if no 5050 reply was ever seen within 60 s while ICMP does reply, presence
  falls back to ICMP only (collector reason "Xbox presence: ICMP only").

The collector never creates events: the ICMP engine reads
``state.xbox['state']`` to flag ``F_XBOX_ASLEEP`` samples and the detector
ignores loss while asleep.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from pathlib import Path
from typing import Tuple, Any, Callable, Dict, Iterable, List, Optional, Set

from laglens.state import Target
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.xbox")

STATE_UNKNOWN = "unknown"
STATE_AWAKE = "awake"
STATE_ASLEEP = "asleep"
SRC_UDP = "udp5050"
SRC_ICMP = "icmp"

AWAKE_ICMP_RUN = 10
# A powered-on console behind a bad cable may never answer 10 in a row: answering at least half of
# the probes over 10 s or more also counts as awake (a console in standby answers a few percent).
AWAKE_MIN_SENT = 40
AWAKE_REPLY_SHARE = 0.5
ASLEEP_SILENCE_S = 30.0
PRESENCE_INTERVAL_S = 10.0
PRESENCE_TIMEOUT_S = 2.0
ICMP_ONLY_AFTER_S = 60.0
REDISCOVER_S = 600.0
# While the console at the known address is asleep, look for it elsewhere this often (its DHCP
# address can change); a console answering the discovery request at another address is followed.
REFIND_EVERY_S = 300.0
GW_WINDOW_S = 30.0
GW_HEALTHY_LOSS_PCT = 10.0
GW_MIN_SAMPLES = 10
REASON_NOT_FOUND = "Xbox not found; set targets.xbox_ip or --xbox"
REASON_MULTIPLE = "multiple candidates; choose on /setup"
REASON_ICMP_ONLY = "Xbox presence: ICMP only"
OUI_FILE = Path(__file__).resolve().parent.parent / "data" / "oui_microsoft.txt"


# ---------------------------------------------------------------------------
# OUI helpers
# ---------------------------------------------------------------------------
def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """``7c:ed:8d:1:2:3`` → ``7C:ED:8D:01:02:03``; ``None`` for anything that is not a MAC."""
    if not mac or not isinstance(mac, str):
        return None
    s = mac.strip().replace("-", ":").replace(".", ":")
    parts = s.split(":")
    if len(parts) == 3 and all(len(p) == 4 for p in parts):  # Cisco style aabb.ccdd.eeff
        parts = [parts[0][:2], parts[0][2:], parts[1][:2], parts[1][2:], parts[2][:2], parts[2][2:]]
    if len(parts) != 6:
        return None
    out = []
    for p in parts:
        if not p or len(p) > 2:
            return None
        try:
            out.append("%02X" % int(p, 16))
        except ValueError:
            return None
    return ":".join(out)


def oui_of(mac: Optional[str]) -> Optional[str]:
    """The upper-case ``XX:XX:XX`` prefix of a MAC, or ``None``."""
    m = normalize_mac(mac)
    return m[:8] if m else None


def load_ouis(path: Optional[Path] = None) -> Set[str]:
    """Parse ``oui_microsoft.txt`` (one ``XX:XX:XX`` per line, ``#`` comments) into a set."""
    p = Path(path) if path is not None else OUI_FILE
    out: Set[str] = set()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("cannot read OUI list %s: %s", p, exc)
        return out
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        norm = normalize_mac(line + ":00:00:00")
        if norm:
            out.add(norm[:8])
    return out


def find_candidates(
    neighbors: Iterable[Dict[str, Any]],
    ouis: Set[str],
    exclude_ips: Iterable[str] = (),
    exclude_macs: Iterable[str] = (),
) -> List[Dict[str, Any]]:
    """IPv4 neighbour rows whose MAC has a Microsoft OUI, minus the gateway; one per IP."""
    skip_ips = {str(ip) for ip in exclude_ips if ip}
    skip_macs = {normalize_mac(m) for m in exclude_macs if m}
    skip_macs.discard(None)
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for row in neighbors or []:
        if not isinstance(row, dict):
            continue
        ip = row.get("ip")
        mac = normalize_mac(row.get("mac"))
        if not ip or not mac or ip in skip_ips or mac in skip_macs or ip in seen:
            continue
        try:
            addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
        except ValueError:
            continue
        if addr.version != 4 or addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            continue
        prefix = mac[:8]
        if prefix not in ouis:
            continue
        seen.add(ip)
        out.append({"ip": str(ip), "mac": mac.lower(), "oui_match": prefix})
    out.sort(key=lambda c: tuple(int(x) for x in c["ip"].split(".")))
    return out


def _valid_ip(ip: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except (ValueError, TypeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
class XboxCollector:
    """Locate the Xbox, keep its ICMP target registered and track its presence state.

    Injectable for tests: ``clock`` (monotonic), ``wall`` (unix time),
    ``presence_probe(ip, timeout)``, ``neighbors()`` and ``oui_path``.
    """

    def __init__(
        self,
        ctx: Any,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        presence_probe: Optional[Callable[..., bool]] = None,
        neighbors: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        oui_path: Optional[Path] = None,
        sweep: Optional[Callable[..., List[str]]] = None,
        save_config: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.cfg = getattr(ctx, "cfg", None) or {}
        self.clock = clock
        self.wall = wall
        if presence_probe is None:
            from laglens.probes import xbox_presence

            presence_probe = xbox_presence.probe
        self.presence_probe = presence_probe
        if sweep is None:
            from laglens.probes import xbox_presence as _xp

            sweep = _xp.sweep
        self.sweep_fn = sweep
        self._save_config_fn = save_config
        self._last_refind: Optional[float] = None
        self.since_wall: Optional[float] = None
        self._neighbors_fn = neighbors
        self.ouis = load_ouis(oui_path)
        self.lock = threading.RLock()
        self.ip: Optional[str] = None
        self.mac: Optional[str] = None
        self.ip_source: Optional[str] = None  # 'args' | 'config' | 'discovery' | 'setup' | 'resume' | 'rediscovered'
        self.candidates: List[Dict[str, Any]] = []
        self.xbox_state = STATE_UNKNOWN
        self.src: Optional[str] = None  # evidence behind the current state
        self.presence_source: Optional[str] = None  # 'udp5050' once a reply was seen, 'icmp' after fallback
        self._known_since: Optional[float] = None
        self._last_presence: Optional[float] = None
        self._last_udp_reply: Optional[float] = None
        self._last_discovery: Optional[float] = None
        self._last_neigh_refresh: Optional[float] = None
        self.thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.thread = start_thread("xbox", self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        if self.thread is not None:
            self.thread.join(timeout)

    def _loop(self) -> None:
        stop = self.state.stop_event
        self.initialize()
        while not stop.wait(1.0):
            self.step()

    # ------------------------------------------------------------- address
    def initialize(self) -> Optional[str]:
        """Pick the address from ``--xbox``, config, a resumed target or discovery."""
        args = getattr(self.ctx, "args", None)
        ip = _valid_ip(getattr(args, "xbox", None)) if args is not None else None
        if ip:
            self.apply_ip(ip, "args")
            return ip
        ip = _valid_ip((self.cfg.get("targets", {}) or {}).get("xbox_ip"))
        if ip:
            self.apply_ip(ip, "config")
            return ip
        existing = self.state.target("xbox")
        if existing is not None and existing.addr:
            self.apply_ip(existing.addr, "resume")
            return existing.addr
        if (self.cfg.get("targets", {}) or {}).get("xbox_discovery", True):
            return self.discover()
        self._set_collector("disabled", REASON_NOT_FOUND)
        self._publish()
        return None

    def _neighbors(self) -> List[Dict[str, Any]]:
        try:
            if self._neighbors_fn is not None:
                return list(self._neighbors_fn() or [])
            plat = getattr(self.ctx, "platform", None)
            return list(plat.neighbors() or []) if plat is not None else []
        except Exception:  # noqa: BLE001
            log.exception("neighbors() failed")
            return []

    def _gateway(self) -> Optional[str]:
        route = getattr(self.ctx, "route", None) or {}
        gw = route.get("gateway") if isinstance(route, dict) else None
        if not gw:
            plat = getattr(self.ctx, "platform", None)
            try:
                gw = (plat.default_route() or {}).get("gateway") if plat is not None else None
            except Exception:  # noqa: BLE001
                gw = None
        return gw

    def _sweep_targets(self, rows: List[Dict[str, Any]], gw: Optional[str]) -> Tuple[List[str], List[str]]:
        """IPv4 neighbours (minus gateway and this host) and the broadcast addresses to sweep."""
        route = getattr(self.ctx, "route", None) or {}
        me = route.get("lan_ip") if isinstance(route, dict) else None
        if not me or not gw:
            return [], []  # no LAN address or gateway: nothing to sweep (and never broadcast blindly)
        ips = []
        for r in rows:
            ip = r.get("ip") if isinstance(r, dict) else None
            if not ip or ":" in ip or ip in (gw, me) or ip.startswith(("224.", "239.", "255.", "169.254.")) or ip.endswith(".255"):
                continue
            ips.append(ip)
        bcast = ["255.255.255.255"]
        try:
            prefix = int(route.get("prefixlen")) if isinstance(route, dict) and route.get("prefixlen") is not None else None
            if me and prefix is not None:
                import ipaddress

                bcast.append(str(ipaddress.ip_network("%s/%d" % (me, prefix), strict=False).broadcast_address))
        except (TypeError, ValueError):
            pass
        return ips, bcast

    def _sweep(self, rows: List[Dict[str, Any]], gw: Optional[str]) -> List[str]:
        ips, bcast = self._sweep_targets(rows, gw)
        if not ips and not bcast:
            return []
        try:
            return [ip for ip in (self.sweep_fn(ips, broadcast=bcast) or []) if ip != gw]
        except Exception:  # noqa: BLE001
            log.exception("xbox sweep failed")
            return []

    def discover(self) -> Optional[str]:
        """Run one discovery round; returns the chosen address (``None`` when 0 or >1 candidates).

        Consoles that answer the discovery request win (any vendor prefix); the Microsoft-prefix list is
        the fallback for consoles with network features turned off.
        """
        self._last_discovery = self.clock()
        rows = self._neighbors()
        gw = self._gateway()
        answering = self._sweep(rows, gw)
        if len(answering) == 1:
            ip = answering[0]
            log.info("xbox discovered at %s (answered the console discovery request)", ip)
            with self.lock:
                self.candidates = [{"ip": ip, "mac": self._lookup_mac(ip), "oui_match": None, "answers_5050": True}]
            self.mac = self._lookup_mac(ip)
            self.apply_ip(ip, "discovery")
            return ip
        if len(answering) > 1:
            with self.lock:
                self.candidates = [{"ip": ip, "mac": self._lookup_mac(ip), "oui_match": None, "answers_5050": True} for ip in answering]
            log.info("xbox discovery: %d consoles answered: %s", len(answering), ", ".join(answering))
            self._set_collector("degraded", REASON_MULTIPLE, candidates=len(answering))
            self._publish()
            return None
        gw_macs = [r.get("mac") for r in rows if isinstance(r, dict) and gw and r.get("ip") == gw]
        cands = find_candidates(rows, self.ouis, exclude_ips=[gw] if gw else [], exclude_macs=gw_macs)
        with self.lock:
            self.candidates = cands
        if len(cands) == 1:
            log.info("xbox discovered at %s (%s, OUI %s)", cands[0]["ip"], cands[0]["mac"], cands[0]["oui_match"])
            self.mac = cands[0]["mac"]
            self.apply_ip(cands[0]["ip"], "discovery")
            return cands[0]["ip"]
        if len(cands) > 1:
            log.info("xbox discovery: %d Microsoft devices on the LAN: %s", len(cands), ", ".join(c["ip"] for c in cands))
            self._set_collector("degraded", REASON_MULTIPLE, candidates=len(cands))
        else:
            log.info("xbox discovery: no Microsoft OUI among %d neighbours", len(rows))
            self._set_collector("disabled", REASON_NOT_FOUND)
        self._publish()
        return None

    def apply_ip(self, ip: str, source: str) -> None:
        """Use ``ip``: register/switch the xbox target and reset the state machine.

        Re-applying the address already in use (e.g. saving it again on /setup) only updates its source.
        """
        existing_t = self.state.target("xbox")
        if self.ip == ip and existing_t is not None and existing_t.addr == ip and existing_t.enabled:
            with self.lock:
                self.ip_source = source
            self._set_collector("ok", None, ip=ip, source=source)
            self._publish()
            return
        label = "Xbox %s" % ip
        rate = 4.0
        try:
            rate = float(self.cfg.get("rate_hz", 4) or 4)
        except (TypeError, ValueError):
            pass
        existing = self.state.target("xbox")
        if existing is None:
            t = Target(id=-1, key="xbox", role="xbox", addr=ip, family=4, kind="icmp", label=label, rate_hz=rate)
            self.state.add_target(t)
            self._save_targets()
            log.info("xbox target added: %s (id %d)", ip, t.id)
        elif existing.addr != ip or not existing.enabled:
            self.state.set_target_state("xbox", addr=ip, enabled=True, reason=None, label=label)
            self._save_targets()
            log.info("xbox target switched to %s", ip)
        with self.lock:
            if self.ip != ip:
                self.mac = self.mac if source == "discovery" else self._lookup_mac(ip)
            self.ip = ip
            self.ip_source = source
            self.since_wall = self.wall()  # samples sent before this belong to the previous address
            self.xbox_state = STATE_UNKNOWN
            self.src = None
            self.presence_source = None
            now = self.clock()
            self._known_since = now
            self._last_presence = None
            self._last_udp_reply = None
            self._last_neigh_refresh = now
        self._set_collector("ok", None, ip=ip, source=source)
        self._publish()

    def set_ip(self, ip: str) -> bool:
        """Switch to ``ip`` (from ``POST /api/xbox`` on the ``/setup`` page); ``False`` if invalid."""
        v = _valid_ip(ip)
        if v is None:
            return False
        try:
            self.cfg.setdefault("targets", {})["xbox_ip"] = v  # in-memory only; config.json is not ours
        except Exception:  # noqa: BLE001
            pass
        self.mac = None
        self.apply_ip(v, "setup")
        return True

    def _lookup_mac(self, ip: str) -> Optional[str]:
        for row in self._neighbors():
            if isinstance(row, dict) and row.get("ip") == ip:
                m = normalize_mac(row.get("mac"))
                return m.lower() if m else None
        return None

    def _save_targets(self) -> None:
        try:
            from laglens.targets import save_targets

            save_targets(self.state, self.store)
        except Exception:  # noqa: BLE001
            log.exception("save_targets failed")

    # ---------------------------------------------------------------- step
    def step(self) -> None:
        """One second of work: discovery retry, presence probe, state evaluation."""
        now = self.clock()
        if self.ip is None:
            if self._last_discovery is None or now - self._last_discovery >= REDISCOVER_S:
                if (self.cfg.get("targets", {}) or {}).get("xbox_discovery", True):
                    self.discover()
            return
        if self._last_presence is None or now - self._last_presence >= PRESENCE_INTERVAL_S:
            self._last_presence = now
            if self._probe_presence():
                self._last_udp_reply = self.clock()
        self.evaluate(self.clock())
        self._maybe_refind(now)
        if self._last_neigh_refresh is None or now - self._last_neigh_refresh >= REDISCOVER_S:
            self._last_neigh_refresh = now
            mac = self._lookup_mac(self.ip)
            if mac and mac != self.mac:
                self.mac = mac
                self._publish()

    def _maybe_refind(self, now: float) -> Optional[str]:
        """While the known console is asleep, sweep for it; follow it if it answers at another address."""
        if self.xbox_state != STATE_ASLEEP or self.ip is None:
            return None
        if self._last_refind is not None and now - self._last_refind < REFIND_EVERY_S:
            return None
        if not (self.cfg.get("targets", {}) or {}).get("xbox_discovery", True):
            return None
        self._last_refind = now
        rows = self._neighbors()
        answering = [ip for ip in self._sweep(rows, self._gateway())]
        if self.ip in answering or len(answering) != 1:
            if len(answering) > 1:
                log.info("xbox: known address %s is silent; %d consoles answer elsewhere (%s): choose on /setup",
                         self.ip, len(answering), ", ".join(answering))
            return None
        new_ip, old_ip, old_source = answering[0], self.ip, self.ip_source
        if old_source == "args":
            log.warning("xbox: %s (from --xbox) is silent but a console answers at %s; restart with --xbox %s",
                        old_ip, new_ip, new_ip)
            return None
        log.info("xbox: console moved from %s to %s (answered the discovery request); following it", old_ip, new_ip)
        self.mac = self._lookup_mac(new_ip)
        self.apply_ip(new_ip, "rediscovered")
        if old_source in ("config", "setup"):
            try:
                self.cfg.setdefault("targets", {})["xbox_ip"] = new_ip
            except Exception:  # noqa: BLE001
                pass
            self._persist_ip(new_ip)
        return new_ip

    def _persist_ip(self, ip: str) -> bool:
        """Keep a followed address in config.json (it was configured there or chosen on /setup)."""
        try:
            if self._save_config_fn is not None:
                return bool(self._save_config_fn({"targets.xbox_ip": ip}))
            path = getattr(self.ctx, "config_file", None)
            if not path:
                return False
            from laglens.config import save_values

            return bool(save_values(path, {"targets.xbox_ip": ip}))
        except Exception:  # noqa: BLE001
            log.exception("could not save the new Xbox address")
            return False

    def _probe_presence(self) -> bool:
        try:
            return bool(self.presence_probe(self.ip, timeout=PRESENCE_TIMEOUT_S))
        except TypeError:
            try:
                return bool(self.presence_probe(self.ip))
            except Exception:  # noqa: BLE001
                return False
        except Exception:  # noqa: BLE001
            log.exception("presence probe failed")
            return False

    def _icmp_summary(self, now_wall: float) -> Dict[str, Any]:
        """``{'run': trailing consecutive replies, 'replies': any reply in 30 s, 'sent': samples in 30 s}``."""
        t = self.state.target("xbox")
        if t is None:
            return {"run": 0, "replies": False, "sent": 0, "received": 0}
        samples = self.state.raw_window(t.id, now_wall - ASLEEP_SILENCE_S, now_wall + 1.0)
        run = 0
        for s in reversed(samples):
            if s.late:
                continue
            if s.received:
                run += 1
            else:
                break
        replies = any(s.received or s.late for s in samples)
        received = sum(1 for s in samples if s.received)
        return {"run": run, "replies": replies, "sent": sum(1 for s in samples if not s.late), "received": received}

    def _gateway_healthy(self, now_wall: float) -> bool:
        gw = self.state.target("gw4")
        if gw is None:
            return False
        samples = [s for s in self.state.raw_window(gw.id, now_wall - GW_WINDOW_S, now_wall + 1.0) if not s.late]
        if len(samples) < GW_MIN_SAMPLES:
            return False
        lost = sum(1 for s in samples if s.lost)
        return lost * 100.0 / len(samples) < GW_HEALTHY_LOSS_PCT

    def evaluate(self, now: float) -> str:
        """Apply the state machine rules once; returns the (possibly new) state."""
        now_wall = self.wall()
        icmp = self._icmp_summary(now_wall)
        udp_recent = self._last_udp_reply is not None and now - self._last_udp_reply < ASLEEP_SILENCE_S
        udp_fresh = self._last_udp_reply is not None and now - self._last_udp_reply < PRESENCE_INTERVAL_S
        presence_before = self.presence_source
        if self._last_udp_reply is not None and self.presence_source != SRC_UDP:
            if self.presence_source == SRC_ICMP:
                log.info("xbox: UDP 5050 presence replies again")
            self.presence_source = SRC_UDP
            self._set_collector("ok", None, ip=self.ip, source=self.ip_source)
        elif (self.presence_source is None and self._known_since is not None
              and now - self._known_since >= ICMP_ONLY_AFTER_S and icmp["replies"]):
            self.presence_source = SRC_ICMP
            log.info("xbox: no UDP 5050 reply in %ds while ICMP answers; presence is ICMP only", int(ICMP_ONLY_AFTER_S))
            self._set_collector("ok", REASON_ICMP_ONLY, ip=self.ip, source=self.ip_source)

        presence_changed = self.presence_source != presence_before
        new_state = self.xbox_state
        src = self.src
        if udp_fresh:
            new_state, src = STATE_AWAKE, SRC_UDP
        elif icmp["run"] >= AWAKE_ICMP_RUN:
            new_state, src = STATE_AWAKE, SRC_ICMP
        elif icmp["sent"] >= AWAKE_MIN_SENT and icmp.get("received", 0) >= AWAKE_REPLY_SHARE * icmp["sent"]:
            new_state, src = STATE_AWAKE, SRC_ICMP
        elif (not icmp["replies"] and not udp_recent and icmp["sent"] > 0
              and self._known_since is not None and now - self._known_since >= ASLEEP_SILENCE_S
              and self._gateway_healthy(now_wall)):
            new_state, src = STATE_ASLEEP, (SRC_UDP if self.presence_source == SRC_UDP else SRC_ICMP)
        if new_state != self.xbox_state or src != self.src or presence_changed:
            if new_state != self.xbox_state:
                log.info("xbox %s: %s -> %s (%s)", self.ip, self.xbox_state, new_state, src)
            with self.lock:
                self.xbox_state = new_state
                self.src = src
            self._publish()
        return self.xbox_state

    # --------------------------------------------------------------- publish
    def _publish(self) -> None:
        with self.lock:
            row = {
                "ip": self.ip,
                "mac": self.mac,
                "state": self.xbox_state,
                "source": self.src,
                "presence": self.presence_source,
                "ip_source": self.ip_source,
                "since": self.since_wall,
                "link_mbps": None,
                "candidates": [dict(c) for c in self.candidates],
            }
        try:
            self.state.xbox = row
        except Exception:  # noqa: BLE001
            log.exception("cannot update state.xbox")
        try:
            self.state.set_latest("xbox", {"state": row["state"], "src": row["source"] or row["presence"] or SRC_ICMP,
                                           "t": self.wall()})
        except Exception:  # noqa: BLE001
            log.exception("set_latest failed")

    def _set_collector(self, status: str, reason: Optional[str], **kv: Any) -> None:
        try:
            self.state.set_collector("xbox", status, reason=reason, **kv)
        except Exception:  # noqa: BLE001
            log.exception("set_collector failed")

    def status(self) -> dict:
        """A copy of the published ``state.xbox`` row."""
        self._publish()
        return dict(self.state.xbox)


__all__ = [
    "XboxCollector", "normalize_mac", "oui_of", "load_ouis", "find_candidates",
    "STATE_UNKNOWN", "STATE_AWAKE", "STATE_ASLEEP", "SRC_UDP", "SRC_ICMP",
    "AWAKE_ICMP_RUN", "AWAKE_MIN_SENT", "AWAKE_REPLY_SHARE", "ASLEEP_SILENCE_S", "PRESENCE_INTERVAL_S", "ICMP_ONLY_AFTER_S", "REDISCOVER_S",
    "REASON_NOT_FOUND", "REASON_MULTIPLE", "REASON_ICMP_ONLY", "OUI_FILE",
]
