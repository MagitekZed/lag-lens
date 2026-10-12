"""WAN identity and IPv6 health collector (SPEC_FULL §3.2 ``wan`` thread, S5/S6).

Every 300 s it fetches ``https://1.1.1.1/cdn-cgi/trace`` and
``https://[2606:4700:4700::1111]/cdn-cgi/trace`` (5 s timeout each, plain
``urllib``) and reads the ``ip=`` line: the public IPv4 address and the
public IPv6 address, from which the delegated ``/64`` prefix is derived.
Changes raise ``wan_ip_change`` / ``v6_prefix_change`` notes (never on the
first reading).

Every 30 s it checks IPv6 health through the platform layer: the presence of
the IPv6 default route (``v6_route_expired`` when it disappears) and the
neighbour-cache state of the IPv6 gateway (``v6_gw_stale`` when it has been
``STALE``/``FAILED``/``INCOMPLETE`` for more than 60 s).

The ``wan`` latest row is shared with the IGD collector: this module owns
``ext_ip``/``ext_ip6``/``prefix6``/``t`` and merges them into whatever
``rx_mbps``/``tx_mbps``/``trusted``/``uptime_s`` the IGD collector put there.
"""
from __future__ import annotations

import ipaddress
import logging
import time
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

from laglens.supervisor import start_thread

log = logging.getLogger("laglens.wan")

TRACE_V4 = "https://1.1.1.1/cdn-cgi/trace"
TRACE_V6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
TRACE_TIMEOUT_S = 5.0
TRACE_INTERVAL_S = 300.0
V6_INTERVAL_S = 30.0
V6_STALE_S = 60.0
STALE_STATES = ("STALE", "FAILED", "INCOMPLETE")
USER_AGENT = "LagLens/1.0 (+https://github.com/MagitekZed/lag-lens)"


def parse_trace(text: str) -> Dict[str, str]:
    """``key=value`` lines of ``/cdn-cgi/trace`` → dict."""
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def prefix64(addr: Optional[str]) -> Optional[str]:
    """The ``/64`` prefix of a global IPv6 address, e.g. ``2601:abcd:1234:5678::/64``."""
    if not addr:
        return None
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    if ip.version != 6:
        return None
    return str(ipaddress.ip_network((ip, 64), strict=False))


def _strip_zone(addr: Optional[str]) -> str:
    return (addr or "").split("%")[0].lower()


class WanCollector:
    """WAN IP (v4/v6 + prefix) every 300 s, IPv6 route/neighbour health every 30 s."""

    name = "wan"

    def __init__(self, ctx: Any, urlopen: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.time, mono: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.platform = ctx.platform
        self.cfg = ctx.cfg or {}
        self._urlopen = urlopen or urllib.request.urlopen
        self._clock = clock
        self._mono = mono
        self.thread = None
        self.ext_ip: Optional[str] = None
        self.ext_ip6: Optional[str] = None
        self.prefix6: Optional[str] = None
        self.last_trace_t: Optional[float] = None
        self._trace_at: Optional[float] = None
        self._v6_at: Optional[float] = None
        self._had_gw6: Optional[bool] = None
        self._stale_since: Optional[float] = None
        self._stale_noted = False
        self.v6: Dict[str, Any] = {"route": None, "gateway6": None, "neigh_state": None}

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.state.set_collector(self.name, "ok")
        self.thread = start_thread(self.name, self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        t = self.thread
        if t is not None:
            t.join(timeout)

    def _loop(self) -> None:
        st = self.state
        self.step()
        while not st.stop_event.wait(1.0):
            self.step()

    def step(self, now: Optional[float] = None) -> None:
        """Run whichever of the two cadences is due (tests call this with a fake clock)."""
        now = self._clock() if now is None else now
        mono = self._mono()
        if self._trace_at is None or mono - self._trace_at >= TRACE_INTERVAL_S:
            self._trace_at = mono
            self.poll_trace(now)
        if self._v6_at is None or mono - self._v6_at >= V6_INTERVAL_S:
            self._v6_at = mono
            self.check_v6(now)

    # ----------------------------------------------------------------- trace
    def _fetch(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """``(ip, error)`` from one trace URL."""
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            resp = self._urlopen(req, timeout=TRACE_TIMEOUT_S)
            try:
                body = resp.read(65536)
            finally:
                try:
                    resp.close()
                except Exception:  # noqa: BLE001
                    pass
            if isinstance(body, bytes):
                body = body.decode("utf-8", "replace")
            ip = parse_trace(body).get("ip")
            if not ip:
                return None, "no ip= line"
            return ip, None
        except Exception as exc:  # noqa: BLE001 - network errors are expected (no v6, captive portal...)
            return None, "%s: %s" % (type(exc).__name__, str(exc)[:120])

    def poll_trace(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Fetch both trace endpoints, publish the ``wan`` row and raise change notes."""
        now = self._clock() if now is None else now
        ip4, err4 = self._fetch(TRACE_V4)
        ip6, err6 = self._fetch(TRACE_V6)
        if ip4 is not None:
            if self.ext_ip is not None and ip4 != self.ext_ip:
                self.state.raise_note("wan_ip_change", t=now, severity=2, note="WAN IPv4 %s -> %s" % (self.ext_ip, ip4),
                                      old=self.ext_ip, new=ip4)
            self.ext_ip = ip4
        if ip6 is not None:
            p6 = prefix64(ip6)
            if self.prefix6 is not None and p6 != self.prefix6:
                self.state.raise_note("v6_prefix_change", t=now, severity=2, note="IPv6 prefix %s -> %s" % (self.prefix6, p6),
                                      old=self.prefix6, new=p6)
            self.ext_ip6 = ip6
            self.prefix6 = p6
            with self.state.lock:
                host = dict(self.state.host or {})
                host["v6_prefix"] = p6
                self.state.host = host
        if ip4 is None and ip6 is None:
            self.state.set_collector(self.name, "degraded", reason="cdn-cgi/trace unreachable: %s" % (err4 or err6))
        else:
            self.state.set_collector(self.name, "ok", v6=bool(ip6))
            self.last_trace_t = now
        self._publish(now)
        return {"ext_ip": self.ext_ip, "ext_ip6": self.ext_ip6, "prefix6": self.prefix6, "err4": err4, "err6": err6}

    def _publish(self, now: float) -> None:
        with self.state.lock:
            row = dict(self.state.latest("wan") or {})
            row.update({"ext_ip": self.ext_ip, "ext_ip6": self.ext_ip6, "prefix6": self.prefix6, "t": round(now, 3)})
            row.setdefault("rx_mbps", None)
            row.setdefault("tx_mbps", None)
            row.setdefault("trusted", None)
            row.setdefault("uptime_s", None)
            self.state.set_latest("wan", row)

    # ------------------------------------------------------------------- v6
    def check_v6(self, now: Optional[float] = None) -> Dict[str, Any]:
        """IPv6 default route presence and gateway neighbour state."""
        now = self._clock() if now is None else now
        try:
            route = self.platform.default_route() or {}
        except Exception:  # noqa: BLE001
            route = {}
        gw6 = route.get("gateway6")
        has = bool(gw6)
        if self._had_gw6 and not has:
            self.state.raise_note("v6_route_expired", t=now, severity=2, note="IPv6 default route disappeared",
                                  gateway6=self.v6.get("gateway6"))
        self._had_gw6 = has
        neigh_state = None
        if has:
            want = _strip_zone(gw6)
            try:
                for n in self.platform.neighbors() or []:
                    if _strip_zone(n.get("ip")) == want:
                        neigh_state = (n.get("state") or "").upper() or None
                        break
            except Exception:  # noqa: BLE001
                neigh_state = None
            stale = bool(neigh_state) and any(s in neigh_state for s in STALE_STATES)
            if stale:
                if self._stale_since is None:
                    self._stale_since = now
                elif now - self._stale_since > V6_STALE_S and not self._stale_noted:
                    self._stale_noted = True
                    self.state.raise_note("v6_gw_stale", t=now, severity=1,
                                          note="IPv6 gateway %s neighbour %s for %.0f s" % (gw6, neigh_state, now - self._stale_since),
                                          state=neigh_state, gateway6=gw6)
            else:
                self._stale_since = None
                self._stale_noted = False
        else:
            self._stale_since = None
            self._stale_noted = False
        self.v6 = {"route": has, "gateway6": gw6, "neigh_state": neigh_state, "expires6": route.get("expires6")}
        return self.v6


__all__ = ["WanCollector", "parse_trace", "prefix64", "TRACE_V4", "TRACE_V6", "TRACE_INTERVAL_S", "V6_INTERVAL_S", "V6_STALE_S"]
