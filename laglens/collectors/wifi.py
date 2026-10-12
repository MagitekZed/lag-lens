"""Wi-Fi link quality collector (SPEC_FULL §4.5, best effort).

Runs only when the probe host's default interface is wireless (otherwise
the registry entry is ``disabled`` with reason ``wired interface``, which is
the normal state on a wired host). Readings come from
``platform.wifi_info(iface)``:

* Linux: every ``wifi.interval_s`` (5 s) via ``iw`` / ``/proc/net/wireless`` / ``nmcli``;
* macOS: every 15 s via ``system_profiler`` (slow); the cadence backs off to
  30 s when a call takes longer than 2 s.

Publishes ``state.set_latest('wifi', {rssi, noise, chan, bssid, rate_mbps,
ssid})`` and raises ``wifi_drop`` when the RSSI falls by 10 dB or more within
10 s and ``wifi_roam`` when the BSSID changes.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional, Tuple

from laglens.supervisor import start_thread

log = logging.getLogger("laglens.wifi")

MAC_INTERVAL_S = 15.0
MAC_SLOW_INTERVAL_S = 30.0
SLOW_CALL_S = 2.0
DROP_DB = 10
DROP_WINDOW_S = 10.0
DROP_RATE_LIMIT_S = 10.0


class WifiCollector:
    """Wi-Fi quality sampler; ``Cls(ctx)`` with ``start()`` / ``stop(timeout)``."""

    name = "wifi"

    def __init__(self, ctx: Any, clock: Callable[[], float] = time.time,
                 mono: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.platform = ctx.platform
        self.cfg = ctx.cfg or {}
        self._clock = clock
        self._mono = mono
        self.thread = None
        self.iface: Optional[str] = None
        self.enabled = False
        self.interval_s = self._base_interval()
        self._rssi_hist: Deque[Tuple[float, int]] = deque()
        self._last_drop_note: Optional[float] = None
        self._prev_bssid: Optional[str] = None
        self.last_row: Optional[Dict[str, Any]] = None

    def _base_interval(self) -> float:
        if self.platform.name == "darwin":
            return MAC_INTERVAL_S
        try:
            return max(1.0, float((self.cfg.get("wifi") or {}).get("interval_s", 5)))
        except (TypeError, ValueError):
            return 5.0

    # ------------------------------------------------------------ lifecycle
    def _is_wireless(self) -> bool:
        route = getattr(self.ctx, "route", None) or {}
        iface = route.get("iface") or (self.state.host or {}).get("iface")
        if not iface:
            try:
                iface = (self.platform.default_route() or {}).get("iface")
            except Exception:  # noqa: BLE001
                iface = None
        self.iface = iface
        if not iface:
            return False
        host_wifi = (self.state.host or {}).get("wifi")
        if host_wifi is not None:
            return bool(host_wifi)
        try:
            return bool((self.platform.link_info(iface) or {}).get("wireless"))
        except Exception:  # noqa: BLE001
            return False

    def start(self) -> None:
        forced = (self.cfg.get("wifi") or {}).get("enabled", "auto") is True
        wireless = self._is_wireless()
        if not self.iface:
            self.state.set_collector(self.name, "disabled", reason="no default route: is the network up?")
            return
        if not wireless and not forced:
            self.state.set_collector(self.name, "disabled", reason="wired interface")
            return
        self.enabled = True
        self.state.set_collector(self.name, "ok", iface=self.iface, interval_s=self.interval_s)
        self.thread = start_thread(self.name, self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        t = self.thread
        if t is not None:
            t.join(timeout)

    def _loop(self) -> None:
        st = self.state
        self.step()
        while not st.stop_event.wait(self.interval_s):
            self.step()

    # ------------------------------------------------------------------ step
    def step(self, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Take one reading, publish it and raise drop/roam notes. Returns the row."""
        now = self._clock() if now is None else now
        t0 = self._mono()
        try:
            info = self.platform.wifi_info(self.iface) if self.iface else None
        except Exception:  # noqa: BLE001
            log.debug("wifi: wifi_info failed", exc_info=True)
            info = None
        took = self._mono() - t0
        if self.platform.name == "darwin":
            if took > SLOW_CALL_S and self.interval_s < MAC_SLOW_INTERVAL_S:
                self.interval_s = MAC_SLOW_INTERVAL_S
                log.info("wifi: system_profiler took %.1f s; sampling every %.0f s", took, self.interval_s)
        if not info:
            reason = "system_profiler failed" if self.platform.name == "darwin" else "iw and /proc/net/wireless unavailable"
            self.state.set_collector(self.name, "degraded", reason=reason, iface=self.iface)
            return None
        row = {
            "rssi": info.get("rssi"),
            "noise": info.get("noise"),
            "chan": info.get("chan"),
            "bssid": info.get("bssid"),
            "rate_mbps": info.get("rate_mbps"),
            "ssid": info.get("ssid"),
        }
        if (self.state.collector(self.name) or {}).get("status") != "ok":
            self.state.set_collector(self.name, "ok", iface=self.iface, interval_s=self.interval_s)
        self._detect(now, row)
        self.last_row = row
        self.state.set_latest("wifi", row)
        return row

    def _detect(self, now: float, row: Dict[str, Any]) -> None:
        rssi = row.get("rssi")
        if isinstance(rssi, (int, float)):
            rssi = int(rssi)
            cutoff = now - DROP_WINDOW_S
            while self._rssi_hist and self._rssi_hist[0][0] < cutoff:
                self._rssi_hist.popleft()
            if self._rssi_hist:
                peak = max(v for _, v in self._rssi_hist)
                if peak - rssi >= DROP_DB and (self._last_drop_note is None or now - self._last_drop_note >= DROP_RATE_LIMIT_S):
                    self._last_drop_note = now
                    self.state.raise_note("wifi_drop", t=now, severity=2,
                                          note="RSSI fell %d dB (%d -> %d dBm) within %.0f s" % (peak - rssi, peak, rssi, DROP_WINDOW_S),
                                          rssi=rssi, peak=peak, noise=row.get("noise"))
            self._rssi_hist.append((now, rssi))
        bssid = row.get("bssid")
        if bssid and self._prev_bssid and bssid != self._prev_bssid:
            self.state.raise_note("wifi_roam", t=now, severity=2,
                                  note="roamed %s -> %s" % (self._prev_bssid, bssid), old=self._prev_bssid, new=bssid,
                                  chan=row.get("chan"))
        if bssid:
            self._prev_bssid = bssid


__all__ = ["WifiCollector", "DROP_DB", "DROP_WINDOW_S", "MAC_INTERVAL_S", "MAC_SLOW_INTERVAL_S"]
