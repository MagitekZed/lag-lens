"""CDN fetch probe (SPEC_FULL §5.10): a small HTTPS download per URL every 60 s.

For every target of kind ``cdn`` (``Target.extra['url']``) the prober opens
``http.client.HTTPSConnection(host, timeout=10)``, measures

* ``connect_ms`` — TCP (+TLS) connect time,
* ``ttfb_ms`` — from the start of the connect until the response headers arrived,
* ``throughput_mbps`` — over the first 256 KB of the body, read in 64 KB
  chunks (``None`` when the body is shorter than one chunk, e.g. a 204),

and closes the connection. Two samples per URL are emitted:
``KIND_CDN_CONNECT`` (value ``connect_us``) and ``KIND_CDN_TTFB`` (value
``ttfb_us``). A timeout marks the samples ``F_LOST``; any other failure marks
them ``F_ERROR`` with the errno (0 when there is none) as the value; the
connect sample stays a normal reading when the failure happened after the
connect. ``state.latest('cdn')`` carries one row per URL key and a
``cdn_slow`` note (severity 2) is raised when TTFB exceeds 1000 ms or the
throughput is below 5 Mb/s twice in a row for the same URL.
"""
from __future__ import annotations

import http.client
import logging
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from laglens.state import F_ERROR, F_LOADTEST, F_LOST, KIND_CDN_CONNECT, KIND_CDN_TTFB, Sample, Target
from laglens.supervisor import start_thread

log = logging.getLogger("laglens.cdn")

DEFAULT_INTERVAL_S = 60.0
HTTP_TIMEOUT_S = 10.0
MAX_BYTES = 256 * 1024
CHUNK = 64 * 1024
SLOW_TTFB_MS = 1000.0
SLOW_MBPS = 5.0
SLOW_IN_A_ROW = 2
USER_AGENT = "laglens/1 (+https://github.com/MagitekZed)"


class _TargetState:
    __slots__ = ("seq", "slow_run", "last")

    def __init__(self) -> None:
        self.seq = 0
        self.slow_run = 0
        self.last: Optional[dict] = None


class CdnProber:
    """Fetch every ``cdn`` URL once per ``cfg['cdn']['interval_s']`` and time it.

    Injectable for tests: ``https_factory(host, port, timeout=...)`` and
    ``http_factory`` (objects with ``connect``, ``request``, ``getresponse``,
    ``close``), ``clock`` (monotonic) and ``wall`` (unix time).
    """

    def __init__(
        self,
        ctx: Any,
        https_factory: Callable[..., Any] = http.client.HTTPSConnection,
        http_factory: Callable[..., Any] = http.client.HTTPConnection,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.https_factory = https_factory
        self.http_factory = http_factory
        self.clock = clock
        self.wall = wall
        cfg = getattr(ctx, "cfg", None) or {}
        cdn = cfg.get("cdn", {}) or {}
        try:
            self.interval_s = float(cdn.get("interval_s", DEFAULT_INTERVAL_S) or DEFAULT_INTERVAL_S)
        except (TypeError, ValueError):
            self.interval_s = DEFAULT_INTERVAL_S
        self.interval_s = max(5.0, self.interval_s)
        self.timeout_s = HTTP_TIMEOUT_S
        self.max_bytes = MAX_BYTES
        self.chunk = CHUNK
        self._targets: Dict[str, _TargetState] = {}
        self.thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.thread = start_thread("cdn", self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        if self.thread is not None:
            self.thread.join(timeout)

    def _loop(self) -> None:
        stop = self.state.stop_event
        # a short head start so the ICMP engine and targets are settled first
        if stop.wait(2.0):
            return
        while not stop.is_set():
            started = self.clock()
            self.run_cycle()
            elapsed = self.clock() - started
            if stop.wait(max(1.0, self.interval_s - elapsed)):
                break

    # --------------------------------------------------------------- targets
    def _cdn_targets(self) -> List[Target]:
        try:
            return [t for t in self.state.targets_list() if t.kind == "cdn"]
        except Exception:  # noqa: BLE001
            log.exception("cannot list targets")
            return []

    def run_cycle(self) -> List[dict]:
        """Fetch every enabled CDN URL once; returns the per-URL result dicts."""
        out: List[dict] = []
        for t in self._cdn_targets():
            if self.state.stop_event.is_set():
                break
            url = (t.extra or {}).get("url") if isinstance(t.extra, dict) else None
            if not t.enabled or not url:
                continue
            try:
                out.append(self.probe_target(t))
            except Exception:  # noqa: BLE001 - one bad URL must not stop the cycle
                log.exception("cdn %s failed", t.key)
        return out

    # ----------------------------------------------------------------- fetch
    def fetch(self, url: str) -> dict:
        """Time one fetch of ``url``.

        Returns ``{'connect_ms','ttfb_ms','throughput_mbps','status','bytes',
        'error','errno','phase'}``; ``phase`` is ``'ok'``, ``'connect'`` (the
        connect failed), ``'request'`` (headers never arrived) or ``'body'``;
        ``error`` is ``'timeout'`` for a timeout, otherwise the exception text.
        """
        parts = urlsplit(url)
        host = parts.hostname or ""
        scheme = (parts.scheme or "https").lower()
        port = parts.port or (80 if scheme == "http" else 443)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        res: Dict[str, Any] = {
            "connect_ms": None, "ttfb_ms": None, "throughput_mbps": None, "status": None, "bytes": 0,
            "error": None, "errno": 0, "phase": "connect",
        }
        factory = self.http_factory if scheme == "http" else self.https_factory
        conn = None
        try:
            conn = factory(host, port, timeout=self.timeout_s)
            t0 = self.clock()
            conn.connect()
            t_conn = self.clock()
            res["connect_ms"] = round((t_conn - t0) * 1000.0, 3)
            res["phase"] = "request"
            conn.request("GET", path, headers={
                "Host": parts.netloc or host,
                "User-Agent": USER_AGENT,
                "Accept-Encoding": "identity",
                "Cache-Control": "no-cache",
                "Connection": "close",
            })
            resp = conn.getresponse()
            t_hdr = self.clock()
            res["ttfb_ms"] = round((t_hdr - t0) * 1000.0, 3)
            res["status"] = int(getattr(resp, "status", 0) or 0)
            res["phase"] = "body"
            total = 0
            while total < self.max_bytes:
                chunk = resp.read(min(self.chunk, self.max_bytes - total))
                if not chunk:
                    break
                total += len(chunk)
            t_end = self.clock()
            res["bytes"] = total
            if total >= self.chunk and t_end > t_hdr:
                res["throughput_mbps"] = round(total * 8.0 / (t_end - t_hdr) / 1e6, 3)
            res["phase"] = "ok"
        except socket.timeout as exc:  # also TimeoutError on 3.10+
            res["error"] = "timeout"
            res["errno"] = getattr(exc, "errno", None) or 0
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            res["error"] = "%s: %s" % (type(exc).__name__, exc)
            res["errno"] = getattr(exc, "errno", None) or 0
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
        return res

    def probe_target(self, t: Target) -> dict:
        """Fetch a target's URL, emit its two samples, update the latest row and notes."""
        ts = self._targets.get(t.key)
        if ts is None:
            ts = _TargetState()
            self._targets[t.key] = ts
        ts.seq += 1
        base = F_LOADTEST if self._loadtest_running() else 0
        ts_ms = int(self.wall() * 1000)
        url = t.extra.get("url")
        res = self.fetch(url)
        fail_flag = 0
        if res["error"] is not None:
            fail_flag = F_LOST if res["error"] == "timeout" else F_ERROR
        err_value = -1 if fail_flag == F_LOST else int(res["errno"] or 0)
        if res["connect_ms"] is not None:
            self._emit(Sample(ts_ms, t.id, KIND_CDN_CONNECT, base, ts.seq, int(round(res["connect_ms"] * 1000))))
        else:
            self._emit(Sample(ts_ms, t.id, KIND_CDN_CONNECT, base | fail_flag, ts.seq, err_value))
        if res["ttfb_ms"] is not None:
            self._emit(Sample(ts_ms, t.id, KIND_CDN_TTFB, base, ts.seq, int(round(res["ttfb_ms"] * 1000))))
        else:
            self._emit(Sample(ts_ms, t.id, KIND_CDN_TTFB, base | fail_flag, ts.seq, err_value))
        if res["error"] is not None:
            log.info("cdn %s: %s (%s)", t.key, res["error"], url)
        row = {
            "connect_ms": res["connect_ms"],
            "ttfb_ms": res["ttfb_ms"],
            "throughput_mbps": res["throughput_mbps"],
            "status": res["status"],
            "bytes": res["bytes"],
            "error": res["error"],
            "t": ts_ms / 1000.0,
        }
        ts.last = row
        self._publish_latest()
        self._check_slow(t, ts, res)
        return res

    # ------------------------------------------------------------- analysis
    def _check_slow(self, t: Target, ts: _TargetState, res: dict) -> None:
        slow = False
        if res["ttfb_ms"] is not None and res["ttfb_ms"] > SLOW_TTFB_MS:
            slow = True
        if res["throughput_mbps"] is not None and res["throughput_mbps"] < SLOW_MBPS:
            slow = True
        if res["error"] is not None:
            slow = True  # an unreachable CDN is at least as bad as a slow one
        ts.slow_run = ts.slow_run + 1 if slow else 0
        if ts.slow_run >= SLOW_IN_A_ROW:
            try:
                self.state.raise_note(
                    "cdn_slow", target=t.id, severity=2,
                    note="%s slow %d times in a row (ttfb %s ms, %s Mb/s)" % (
                        t.label, ts.slow_run, res["ttfb_ms"], res["throughput_mbps"]),
                    ttfb_ms=res["ttfb_ms"], throughput_mbps=res["throughput_mbps"], url=t.extra.get("url"),
                    error=res["error"],
                )
            except Exception:  # noqa: BLE001
                log.exception("raise_note failed")

    def _publish_latest(self) -> None:
        row: Dict[str, Any] = {}
        for key, ts in self._targets.items():
            if ts.last is not None:
                row[key] = dict(ts.last)
        try:
            self.state.set_latest("cdn", row)
        except Exception:  # noqa: BLE001
            log.exception("set_latest failed")

    # --------------------------------------------------------------- helpers
    def _loadtest_running(self) -> bool:
        try:
            return bool(self.state.loadtest.get("running"))
        except Exception:  # noqa: BLE001
            return False

    def _emit(self, s: Sample) -> None:
        try:
            self.state.add_sample(s)
        except Exception:  # noqa: BLE001
            log.exception("add_sample failed")
        try:
            self.store.append_sample(s)
        except Exception:  # noqa: BLE001
            log.exception("append_sample failed")


__all__ = ["CdnProber", "DEFAULT_INTERVAL_S", "HTTP_TIMEOUT_S", "MAX_BYTES", "CHUNK", "SLOW_TTFB_MS", "SLOW_MBPS",
           "SLOW_IN_A_ROW"]
