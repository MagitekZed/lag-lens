"""Target table: the static probe destinations and ``targets.json``.

:func:`build_targets` creates the targets that are known at start (gateway,
internet anycast, DNS, TCP, NTP, CDN) with ids assigned in a **stable order**
and writes ``targets.json``. Targets discovered later (``xbox``, ``isp_hop4``,
``mid_hop4``, ``isp_hop6``) are added by their modules through
``state.add_target`` followed by :func:`save_targets`.

On ``--resume`` the ids from the existing ``targets.json`` are kept so
``samples.bin`` stays consistent; addresses are refreshed. A malformed entry
(id not an int in 0..255, missing key) never aborts the resume: the entry is
skipped or given a fresh id with a warning.
"""
import ipaddress
import logging
import re
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from laglens.state import MAX_TARGET_ID, State, Target

log = logging.getLogger("laglens.targets")

RESOLVE_TIMEOUT_S = 5.0
CF_NTP_LITERAL = "162.159.200.1"
KNOWN_ANYCAST = {
    "1.1.1.1": "Cloudflare",
    "8.8.8.8": "Google",
    "2606:4700:4700::1111": "Cloudflare",
    "2001:4860:4860::8888": "Google",
}
TCP_NAME_KEYS = {
    "xsts.auth.xboxlive.com": "tcp_xbl_auth",
    "profile.xboxlive.com": "tcp_xbl_profile",
    "login.live.com": "tcp_live",
}
NTP_NAME_KEYS = {"time.cloudflare.com": "ntp_cf", "time.google.com": "ntp_g"}
RATE_DNS = 1 / 3.0
RATE_TCP = 0.5
RATE_NTP = 0.2
RATE_CDN = 1 / 60.0

Resolver = Callable[[str, int], Optional[str]]


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def is_ipv4_mapped(addr: Optional[str]) -> bool:
    """``::ffff:40.90.8.102`` style answers: an A record dressed up as AAAA (macOS ``getaddrinfo``)."""
    if not addr or ":" not in addr:
        return False
    try:
        return ipaddress.ip_address(addr.split("%")[0]).ipv4_mapped is not None
    except ValueError:
        return False


def default_resolver(name: str, family: int) -> Optional[str]:
    """First address of ``name`` for family 4/6 via ``getaddrinfo``; ``None`` on failure.

    IPv4-mapped "AAAA" answers (``::ffff:a.b.c.d``, what macOS returns for a
    name without AAAA records) are rejected for family 6 so a ``tcp_*6``
    target stays unresolved (and disabled with a reason) instead of silently
    probing IPv4 through an IPv6 socket.
    """
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return None
    for info in infos:
        addr = info[4][0]
        if not addr:
            continue
        if family == 6 and is_ipv4_mapped(addr):
            continue
        return addr
    return None


def lan_resolver(resolvers: List[str], route: Optional[dict]) -> Optional[str]:
    """The first IPv4 resolver that is the gateway or inside the LAN prefix; ``None`` otherwise.

    A VPN/MagicDNS resolver such as Tailscale's ``100.100.100.100`` is often
    first in the system list; the ``dns_gw`` target must time the home
    gateway, not that.
    """
    route = route or {}
    gw = route.get("gateway")
    net = None
    lan_ip = route.get("lan_ip")
    plen = route.get("prefixlen")
    if lan_ip and plen:
        try:
            net = ipaddress.ip_network("%s/%s" % (lan_ip, plen), strict=False)
        except ValueError:
            net = None
    for r in resolvers:
        if not isinstance(r, str) or ":" in r:
            continue
        if gw and r == gw:
            return r
        if net is not None:
            try:
                if ipaddress.ip_address(r) in net:
                    return r
            except ValueError:
                continue
    return None


def resolve_many(
    items: List[Tuple[str, int]], resolver: Optional[Resolver] = None, timeout: float = RESOLVE_TIMEOUT_S
) -> Dict[Tuple[str, int], Optional[str]]:
    """Resolve ``(name, family)`` pairs concurrently; unresolved → ``None``."""
    resolver = resolver or default_resolver
    results: Dict[Tuple[str, int], Optional[str]] = {k: None for k in items}
    if not items:
        return results
    lock = threading.Lock()

    def worker(key: Tuple[str, int]) -> None:
        try:
            v = resolver(key[0], key[1])
        except Exception:  # noqa: BLE001 - resolvers must not kill startup
            v = None
        with lock:
            results[key] = v

    threads = [threading.Thread(target=worker, args=(k,), name="resolve", daemon=True) for k in items]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    return results


def _anycast_label(addr: str) -> str:
    who = KNOWN_ANYCAST.get(addr)
    return "%s (%s)" % (addr, who) if who else addr


def static_targets(
    cfg: dict, platform: Any, resolver: Optional[Resolver] = None, route: Optional[dict] = None
) -> List[Target]:
    """The static target list in id order (ids are provisional, -1)."""
    tcfg = cfg.get("targets", {})
    rate = float(cfg.get("rate_hz", 4))
    route = route if route is not None else (platform.default_route() if platform is not None else {})
    gw4 = route.get("gateway")
    gw6 = route.get("gateway6")
    out: List[Target] = []

    def add(key: str, role: str, addr: Optional[str], family: int, kind: str, label: str, **kw: Any) -> Target:
        t = Target(id=-1, key=key, role=role, addr=addr, family=family, kind=kind, label=label, **kw)
        if addr is None and t.enabled:
            t.enabled = False
            t.reason = t.reason or "cannot resolve"
        out.append(t)
        return t

    add("gw4", "gateway", gw4, 4, "icmp", "Gateway %s" % gw4 if gw4 else "Gateway", rate_hz=rate,
        reason=None if gw4 else "no default route: is the network up?")
    add("gw6", "gateway", gw6, 6, "icmp", "IPv6 gateway", rate_hz=rate, reason=None if gw6 else "no IPv6 default route")

    v4 = [a for a in tcfg.get("v4", []) if isinstance(a, str)]
    v6 = [a for a in tcfg.get("v6", []) if isinstance(a, str)]
    for i, addr in enumerate(v4):
        key = "inet4_cf" if i == 0 else ("inet4_g" if i == 1 else "inet4_%d" % i)
        add(key, "anycast", addr, 4, "icmp", _anycast_label(addr), rate_hz=rate)
    for i, addr in enumerate(v6):
        key = "inet6_cf" if i == 0 else ("inet6_g" if i == 1 else "inet6_%d" % i)
        add(key, "anycast", addr, 6, "icmp", _anycast_label(addr), rate_hz=rate)

    resolvers = []
    try:
        resolvers = [r for r in (platform.resolvers() if platform is not None else []) if isinstance(r, str)]
    except Exception:  # noqa: BLE001
        resolvers = []
    # Prefer a resolver that *is* the gateway or sits inside the LAN prefix, then the gateway
    # itself; a foreign first resolver (Tailscale MagicDNS, a VPN) is only the last resort.
    dns_gw = lan_resolver(resolvers, route) or gw4
    dns_label = "Gateway DNS %s" % dns_gw if dns_gw else "Gateway DNS"
    if dns_gw is None:
        dns_gw = next((r for r in resolvers if ":" not in r), None)
        if dns_gw:
            dns_label = "System DNS %s" % dns_gw
    add("dns_gw", "dns", dns_gw, 4, "dns", dns_label, rate_hz=RATE_DNS, port=53,
        reason=None if dns_gw else "no resolver found")
    cf4 = v4[0] if v4 else "1.1.1.1"
    add("dns_cf4", "dns", cf4, 4, "dns", "%s DNS" % cf4, rate_hz=RATE_DNS, port=53)

    add("tcp_cf4", "tcp", cf4, 4, "tcp", "%s:443" % cf4, rate_hz=RATE_TCP, port=443)
    cf6 = v6[0] if v6 else "2606:4700:4700::1111"
    add("tcp_cf6", "tcp", cf6, 6, "tcp", "[%s]:443" % cf6, rate_hz=RATE_TCP, port=443)
    add("tcp_gw", "tcp", gw4, 4, "tcp", "Gateway web UI :80", rate_hz=RATE_TCP, port=80,
        reason=None if gw4 else "no default route")

    names = [n for n in tcfg.get("tcp_names", []) if isinstance(n, str)]
    ntp_names = [n for n in tcfg.get("ntp", []) if isinstance(n, str)]
    lookups: List[Tuple[str, int]] = []
    for n in names:
        lookups.append((n, 4))
        lookups.append((n, 6))
    for n in ntp_names:
        lookups.append((n, 4))
    resolved = resolve_many(lookups, resolver)

    for n in names:
        base = TCP_NAME_KEYS.get(n, "tcp_xbl_" + _slug(n))
        for fam in (4, 6):
            addr = resolved.get((n, fam))
            add("%s%d" % (base, fam), "tcp_xbl", addr, fam, "tcp", "%s (v%d)" % (n, fam), rate_hz=RATE_TCP, port=443,
                extra={"name": n})

    for i, ep in enumerate(tcfg.get("game_endpoints", []) or []):
        host, port = _split_hostport(str(ep))
        fam = 6 if ":" in host else 4
        add("tcp_game_%d" % i, "tcp_game", host or None, fam, "tcp", "Game server %s" % ep, rate_hz=RATE_TCP, port=port or 0,
            extra={"endpoint": ep})

    for n in ntp_names:
        key = NTP_NAME_KEYS.get(n, "ntp_" + _slug(n))
        addr = resolved.get((n, 4))
        reason = None
        if addr is None and n == "time.cloudflare.com":
            addr = CF_NTP_LITERAL
            reason = "using literal fallback"
        add(key, "ntp", addr, 4, "ntp", "NTP %s" % n, rate_hz=RATE_NTP, port=123, extra={"name": n}, reason=reason)

    cdn = cfg.get("cdn", {})
    if cdn.get("enabled", True):
        for i, url in enumerate(cdn.get("urls", []) or []):
            host = _url_host(url)
            add("cdn_%d" % i, "cdn", host, 4, "cdn", "CDN %s" % (host or url), rate_hz=1.0 / float(cdn.get("interval_s", 60) or 60),
                port=443, extra={"url": url})
    return out


def _split_hostport(ep: str) -> Tuple[str, Optional[int]]:
    ep = ep.strip()
    if ep.startswith("["):
        host, _, rest = ep[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else None
    if ep.count(":") == 1:
        host, port = ep.split(":")
        return host, int(port) if port.isdigit() else None
    return ep, None


def _url_host(url: str) -> Optional[str]:
    m = re.match(r"^[a-z]+://([^/:?#]+)", url, re.I)
    return m.group(1) if m else None


def build_targets(
    cfg: dict,
    platform: Any,
    state: State,
    store: Optional[Any] = None,
    resume_targets: Optional[List[dict]] = None,
    resolver: Optional[Resolver] = None,
    route: Optional[dict] = None,
) -> List[Target]:
    """Register the static targets in ``state`` (stable ids) and write ``targets.json``.

    ``resume_targets`` (the list from an existing ``targets.json``) pins ids;
    new keys get the next free id. ``resolver`` and ``route`` are injectable
    for offline tests. Returns the registered targets in id order.
    """
    if resume_targets:
        for d in resume_targets:
            if not isinstance(d, dict):
                log.warning("targets.json: ignoring non-object entry %r", d)
                continue
            try:
                t = Target.from_dict(d)
            except TypeError as exc:
                log.warning("targets.json: ignoring malformed entry %r (%s)", d.get("key"), exc)
                continue
            if not isinstance(t.key, str) or not t.key:
                log.warning("targets.json: ignoring entry without a key: %r", d)
                continue
            tid = t.id
            if isinstance(tid, bool) or not isinstance(tid, int) or tid < 0 or tid > MAX_TARGET_ID:
                log.warning("targets.json: target %r has invalid id %r; assigning a fresh one", t.key, tid)
                t.id = -1
            try:
                state.add_target(t)
            except ValueError as exc:
                log.warning("targets.json: cannot keep target %r: %s", t.key, exc)
    fresh = static_targets(cfg, platform, resolver=resolver, route=route)
    for t in fresh:
        existing = state.target(t.key)
        if existing is not None:
            state.set_target_state(
                t.key, enabled=t.enabled, reason=t.reason, addr=t.addr, label=t.label, rate_hz=t.rate_hz, port=t.port,
                extra=t.extra,
            )
        else:
            state.add_target(t)
    if store is not None:
        save_targets(state, store)
    return state.targets_list()


def targets_document(state: State) -> dict:
    """The ``targets.json`` object (SPEC_FULL §6.2)."""
    created = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    return {"targets": [t.to_dict() for t in state.targets_list()], "created": created}


def save_targets(state: State, store: Any) -> None:
    """Atomically rewrite ``targets.json`` from ``state`` (call after ``add_target``)."""
    try:
        store.write_json_atomic("targets.json", targets_document(state))
    except Exception:  # noqa: BLE001
        log.exception("cannot write targets.json")


__all__ = [
    "build_targets", "static_targets", "save_targets", "targets_document", "resolve_many", "default_resolver",
    "lan_resolver", "is_ipv4_mapped",
    "RATE_DNS", "RATE_TCP", "RATE_NTP", "RATE_CDN", "TCP_NAME_KEYS", "NTP_NAME_KEYS",
]
