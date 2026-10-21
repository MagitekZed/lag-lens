"""Host collector: NIC counters/rates, link state, load, clock jumps, VPN route, DHCP lease.

Runs at 1 Hz (SPEC_FULL §4.2–4.3, §4.14, §7.2 host rows). Every reading
comes from :class:`laglens.platform.Platform` so this module never touches
``subprocess`` or ``/sys`` directly. Each second it

* reads the interface counters and turns the deltas into ``rx_mbps`` /
  ``tx_mbps``, error / drop / CRC / collision deltas and a multicast pps
  (``None`` where the OS has no per-interface multicast counter);
* every 10 s refreshes the link info (speed, duplex, carrier changes) and
  raises ``link_flap`` on a carrier change;
* raises ``iface_errors`` (rate-limited to once a minute) when an
  error/drop/CRC delta is positive;
* samples ``time.time() - time.monotonic()`` and raises ``clock_jump`` when
  the offset shifts by more than 2 s ("system slept?");
* reads the engine's lateness statistics (``ctx.component('engine').stats()``)
  when the engine is present;
* every 300 s re-checks whether 1.1.1.1 is routed through a tunnel
  (``vpn_route``) and the DHCP lease (``dhcp_renew`` on change);
* raises ``self_load`` when this host's transmit rate stays above 60 % of
  ``link.up_mbps`` for 3 s.

Published rows: ``state.set_latest('iface', ...)`` and
``state.set_latest('host', ...)`` (SPEC_FULL §6.3; copied into
``rollups.jsonl`` every 5 s by the ticker) and one full-rate row per second
in ``host.jsonl`` (``{"t", "iface": {...}, "host": {...}}``).

Tests drive :meth:`HostCollector.step` directly with a fake clock; the
thread body only calls it once a second.
"""
from __future__ import annotations

import logging
import shutil
import time
from typing import Any, Callable, Dict, Optional

from laglens.supervisor import start_thread

log = logging.getLogger("laglens.host")

LINK_INTERVAL_S = 10.0
VPN_INTERVAL_S = 300.0
DHCP_INTERVAL_S = 300.0
DISK_INTERVAL_S = 30.0
CLOCK_JUMP_S = 2.0
IFACE_ERRORS_RATE_LIMIT_S = 60.0
SELF_LOAD_SHARE = 0.60
SELF_LOAD_HOLD_S = 3.0
STALL_LATE_MS = 50.0
STALL_GAP_MS = 200.0

_COUNTER_KEYS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors",
                 "rx_dropped", "tx_dropped", "crc", "collisions", "multicast")


def _delta(cur: Optional[int], prev: Optional[int]) -> Optional[int]:
    """Counter delta; ``None`` when either side is unknown; negative (reset) → 0."""
    if cur is None or prev is None:
        return None
    d = cur - prev
    return d if d >= 0 else 0


def _mbps(delta_bytes: Optional[int], dt: float) -> Optional[float]:
    if delta_bytes is None or dt <= 0:
        return None
    return round(delta_bytes * 8.0 / dt / 1e6, 3)


def _num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class HostCollector:
    """1 Hz host facts; ``Cls(ctx)`` with ``start()`` / ``stop(timeout)``."""

    name = "host"

    def __init__(self, ctx: Any, clock: Callable[[], float] = time.time,
                 mono: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.platform = ctx.platform
        self.cfg = ctx.cfg or {}
        self._clock = clock
        self._mono = mono
        self.thread = None
        self.iface: Optional[str] = None
        self._prev_stats: Optional[Dict[str, Optional[int]]] = None
        self._prev_t: Optional[float] = None
        self._link: Dict[str, Any] = {}
        self._link_at: Optional[float] = None
        self._prev_carrier: Optional[bool] = None
        self._prev_carrier_changes: Optional[int] = None
        self._prev_media: Optional[str] = None
        self._counter_reset_logged = False
        self._last_iface_errors_note: Optional[float] = None
        self._offset0: Optional[float] = None
        self._prev_offset: Optional[float] = None
        self._vpn_at: Optional[float] = None
        self._vpn_route: Optional[bool] = None
        self._dhcp_at: Optional[float] = None
        self._dhcp_prev: Optional[str] = None
        self._disk_at: Optional[float] = None
        self._free_mb: Optional[float] = None
        self._self_load_since: Optional[float] = None
        self._self_load_noted = False
        self._route_at: Optional[float] = None
        self.last_iface_row: Dict[str, Any] = {}
        self.last_host_row: Dict[str, Any] = {}

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Fill the static host facts and start the 1 Hz thread."""
        try:
            self.refresh_static()
        except Exception:  # noqa: BLE001 - static facts are best effort
            log.exception("host: static facts failed")
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

    # ---------------------------------------------------------- static facts
    def _route(self) -> dict:
        route = getattr(self.ctx, "route", None) or {}
        if not route.get("iface"):
            try:
                route = self.platform.default_route() or {}
            except Exception:  # noqa: BLE001
                route = {}
            try:
                self.ctx.route = route
            except Exception:  # noqa: BLE001
                pass
        return route

    def refresh_static(self) -> dict:
        """Merge the static facts (os, hostname, iface, speed, gateway, ...) into ``state.host``."""
        plat = self.platform
        route = self._route()
        iface = route.get("iface")
        self.iface = iface
        link = plat.link_info(iface) if iface else {}
        vpn = plat.vpn_routes("1.1.1.1") if iface else {"via_tunnel": False, "iface": None}
        self._vpn_route = bool(vpn.get("via_tunnel"))
        self._vpn_at = self._mono()
        facts = {
            "os": plat.name,
            "hostname": plat.hostname(),
            "iface": iface,
            "wifi": bool(link.get("wireless")),
            "speed": link.get("speed"),
            "duplex": link.get("duplex"),
            "lan_ip": route.get("lan_ip"),
            "gateway": route.get("gateway"),
            "gw6": route.get("gateway6"),
            "v6": bool(route.get("gateway6")),
            "vpn_route": self._vpn_route,
            "link_up_mbps": (self.cfg.get("link") or {}).get("up_mbps"),
        }
        with self.state.lock:
            host = dict(self.state.host or {})
            host.update(facts)
            self.state.host = host
        self._link = link or {}
        self._link_at = self._mono()
        self._prev_carrier = link.get("carrier") if link else None
        self._prev_carrier_changes = link.get("carrier_changes") if link else None
        self._prev_media = link.get("media") if link else None
        if not iface:
            self.state.set_collector(self.name, "degraded", reason="no default route: is the network up?")
        else:
            self.state.set_collector(self.name, "ok")
        return facts

    # ------------------------------------------------------------------ step
    def step(self, now: Optional[float] = None) -> Dict[str, Any]:
        """One 1 Hz iteration; returns the ``host.jsonl`` row that was written."""
        now = self._clock() if now is None else now
        mono = self._mono()
        if not self.iface and (self._route_at is None or mono - self._route_at >= LINK_INTERVAL_S):
            self._route_at = mono
            self.refresh_static()
        iface_row = self._iface_step(now, mono)
        host_row = self._host_step(now, mono, iface_row)
        self.last_iface_row = iface_row
        self.last_host_row = host_row
        self.state.set_latest("iface", iface_row)
        self.state.set_latest("host", host_row)
        row = {"t": round(now, 3), "iface": iface_row, "host": host_row}
        try:
            self.store.append_json("host", row)
        except Exception:  # noqa: BLE001 - storage problems are reported by the store itself
            log.debug("host: append_json failed", exc_info=True)
        return row

    # ---------------------------------------------------------------- iface
    def _iface_step(self, now: float, mono: float) -> Dict[str, Any]:
        iface = self.iface
        row: Dict[str, Any] = {
            "rx_mbps": None, "tx_mbps": None, "rx_err": None, "tx_err": None, "rx_drop": None, "tx_drop": None,
            "crc": None, "collisions": None, "mcast_pps": None, "carrier_changes": None, "speed": None,
            "duplex": None, "operstate": None,
        }
        if not iface:
            return row
        stats = self.platform.iface_stats(iface) or {}
        have = any(stats.get(k) is not None for k in _COUNTER_KEYS)
        if not have:
            reason = "netstat unavailable" if self.platform.name == "darwin" else "sysfs unreadable for %s" % iface
            self.state.set_collector(self.name, "degraded", reason=reason)
        elif (self.state.collector(self.name) or {}).get("status") == "degraded":
            self.state.set_collector(self.name, "ok")
        prev = self._prev_stats
        dt = (now - self._prev_t) if (self._prev_t is not None) else 0.0
        if prev is not None and have and dt > 0:
            reset = any(
                stats.get(k) is not None and prev.get(k) is not None and stats[k] < prev[k]
                for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
            )
            if reset and not self._counter_reset_logged:
                self._counter_reset_logged = True
                log.info("host: interface counters of %s went backwards (reset); rates zeroed for this second", iface)
            row["rx_mbps"] = _mbps(_delta(stats.get("rx_bytes"), prev.get("rx_bytes")), dt)
            row["tx_mbps"] = _mbps(_delta(stats.get("tx_bytes"), prev.get("tx_bytes")), dt)
            row["rx_err"] = _delta(stats.get("rx_errors"), prev.get("rx_errors"))
            row["tx_err"] = _delta(stats.get("tx_errors"), prev.get("tx_errors"))
            row["rx_drop"] = _delta(stats.get("rx_dropped"), prev.get("rx_dropped"))
            row["tx_drop"] = _delta(stats.get("tx_dropped"), prev.get("tx_dropped"))
            row["crc"] = _delta(stats.get("crc"), prev.get("crc"))
            row["collisions"] = _delta(stats.get("collisions"), prev.get("collisions"))
            mc = _delta(stats.get("multicast"), prev.get("multicast"))
            row["mcast_pps"] = round(mc / dt, 1) if mc is not None else None
            bad = sum(v for v in (row["rx_err"], row["tx_err"], row["rx_drop"], row["tx_drop"], row["crc"]) if v)
            if bad > 0 and (self._last_iface_errors_note is None or now - self._last_iface_errors_note >= IFACE_ERRORS_RATE_LIMIT_S):
                self._last_iface_errors_note = now
                self.state.raise_note(
                    "iface_errors", t=now, severity=2,
                    note="%s: %d error/drop/crc counter increments" % (iface, bad),
                    rx_err=row["rx_err"], tx_err=row["tx_err"], rx_drop=row["rx_drop"], tx_drop=row["tx_drop"], crc=row["crc"],
                )
            self._self_load(now, row["tx_mbps"])
        if have:
            self._prev_stats = stats
            self._prev_t = now

        if self._link_at is None or mono - self._link_at >= LINK_INTERVAL_S:
            self._link_at = mono
            self._link_step(now, iface)
        link = self._link or {}
        row["carrier_changes"] = link.get("carrier_changes")
        row["speed"] = link.get("speed")
        row["duplex"] = link.get("duplex")
        row["operstate"] = link.get("operstate")
        row["carrier"] = link.get("carrier")
        return row

    def _link_step(self, now: float, iface: str) -> None:
        link = self.platform.link_info(iface) or {}
        self._link = link
        flapped = False
        detail = ""
        cc = link.get("carrier_changes")
        if cc is not None and self._prev_carrier_changes is not None and cc > self._prev_carrier_changes:
            flapped = True
            detail = "carrier_changes %d -> %d" % (self._prev_carrier_changes, cc)
        carrier = link.get("carrier")
        if carrier is not None and self._prev_carrier is not None and carrier != self._prev_carrier:
            flapped = True
            detail = detail or ("link %s" % ("up" if carrier else "down"))
        media = link.get("media")
        if media is not None and self._prev_media is not None and media != self._prev_media:
            flapped = True
            detail = detail or ("media %s -> %s" % (self._prev_media, media))
        if flapped:
            self.state.raise_note("link_flap", t=now, severity=3, note="%s: %s" % (iface, detail),
                                  carrier=carrier, carrier_changes=cc, speed=link.get("speed"), duplex=link.get("duplex"))
            with self.state.lock:
                host = dict(self.state.host or {})
                host["speed"] = link.get("speed")
                host["duplex"] = link.get("duplex")
                self.state.host = host
        self._prev_carrier = carrier if carrier is not None else self._prev_carrier
        self._prev_carrier_changes = cc if cc is not None else self._prev_carrier_changes
        self._prev_media = media if media is not None else self._prev_media

    def _self_load(self, now: float, tx_mbps: Optional[float]) -> None:
        up = _num((self.cfg.get("link") or {}).get("up_mbps")) or 25.0
        if tx_mbps is not None and up > 0 and tx_mbps > SELF_LOAD_SHARE * up:
            if self._self_load_since is None:
                self._self_load_since = now
            elif now - self._self_load_since >= SELF_LOAD_HOLD_S and not self._self_load_noted:
                self._self_load_noted = True
                self.state.raise_note("self_load", t=now, severity=2,
                                      note="this host sends %.1f Mb/s (> %d%% of link.up_mbps %.0f)" % (tx_mbps, int(SELF_LOAD_SHARE * 100), up),
                                      tx_mbps=tx_mbps, up_mbps=up)
        else:
            self._self_load_since = None
            self._self_load_noted = False

    # ----------------------------------------------------------------- host
    def _host_step(self, now: float, mono: float, iface_row: Dict[str, Any]) -> Dict[str, Any]:
        offset = now - mono
        drift_ms = 0.0
        if self._offset0 is None:
            self._offset0 = offset
        if self._prev_offset is not None and abs(offset - self._prev_offset) > CLOCK_JUMP_S:
            shift = offset - self._prev_offset
            self.state.raise_note("clock_jump", t=now, severity=1, note="clock jumped %+.1f s (system slept?)" % shift, shift_s=round(shift, 3))
            self._offset0 = offset  # drift is measured from the new baseline
        self._prev_offset = offset
        drift_ms = round((offset - self._offset0) * 1000.0, 1)

        late_ms_max, loop_gap_ms = self._engine_lateness()
        load = self.platform.load_avg()
        load1 = load[0] if load else None

        if self._vpn_at is None or mono - self._vpn_at >= VPN_INTERVAL_S:
            self._vpn_at = mono
            self._vpn_step(now)
        if self.iface and (self._dhcp_at is None or mono - self._dhcp_at >= DHCP_INTERVAL_S):
            self._dhcp_at = mono
            self._dhcp_step(now)
        if self._disk_at is None or mono - self._disk_at >= DISK_INTERVAL_S:
            self._disk_at = mono
            self._free_mb = self._disk_free_mb()

        stall = bool((late_ms_max is not None and late_ms_max > STALL_LATE_MS) or (loop_gap_ms is not None and loop_gap_ms > STALL_GAP_MS))
        return {
            "late_ms_max": late_ms_max,
            "loop_gap_ms": loop_gap_ms,
            "drift_ms": drift_ms,
            "load1": load1,
            "free_mb": self._free_mb,
            "vpn_route": bool(self._vpn_route),
            "stall": stall,
        }

    def _engine_lateness(self):
        eng = None
        try:
            eng = self.ctx.component("engine")
        except Exception:  # noqa: BLE001
            eng = None
        if eng is None or not hasattr(eng, "stats"):
            return None, None
        try:
            s = eng.stats() or {}
        except Exception:  # noqa: BLE001
            log.debug("host: engine.stats() failed", exc_info=True)
            return None, None
        late = None
        gap = None
        for k in ("late_ms_max", "lateness_ms_max", "lateness_ms", "late_ms", "max_late_ms"):
            if s.get(k) is not None:
                late = _num(s.get(k))
                break
        for k in ("loop_gap_ms", "gap_ms", "max_gap_ms", "loop_gap_ms_max"):
            if s.get(k) is not None:
                gap = _num(s.get(k))
                break
        return late, gap

    def _vpn_step(self, now: float) -> None:
        try:
            vpn = self.platform.vpn_routes("1.1.1.1") or {}
        except Exception:  # noqa: BLE001
            return
        via = bool(vpn.get("via_tunnel"))
        if via and not self._vpn_route:
            self.state.raise_note("vpn_route", t=now, severity=2,
                                  note="probes would go through the VPN (%s), not your gateway" % (vpn.get("iface") or "tunnel"),
                                  iface=vpn.get("iface"))
        if via != bool(self._vpn_route):
            with self.state.lock:
                host = dict(self.state.host or {})
                host["vpn_route"] = via
                self.state.host = host
        self._vpn_route = via

    def _dhcp_step(self, now: float) -> None:
        try:
            lease = self.platform.dhcp_lease(self.iface) or {}
        except Exception:  # noqa: BLE001
            return
        if not lease:
            return
        key = repr(sorted((str(k), str(v)) for k, v in lease.items()))
        if self._dhcp_prev is not None and key != self._dhcp_prev:
            self.state.raise_note("dhcp_renew", t=now, severity=1, note="DHCP lease changed on %s" % self.iface,
                                  lease={k: lease[k] for k in sorted(lease)})
        self._dhcp_prev = key

    def _disk_free_mb(self) -> Optional[float]:
        disk = getattr(self.state, "disk", None) or {}
        v = disk.get("free_mb")
        if v is not None:
            return v
        try:
            path = str(getattr(self.store, "dir", None) or ".")
            return round(shutil.disk_usage(path).free / (1024 * 1024), 1)
        except OSError:
            return None


__all__ = ["HostCollector", "LINK_INTERVAL_S", "VPN_INTERVAL_S", "CLOCK_JUMP_S", "SELF_LOAD_SHARE"]
