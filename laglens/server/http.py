"""The Lag Lens HTTP server: pages, static files, JSON API, SSE, report and export.

``serve(ctx)`` binds a ``ThreadingHTTPServer`` (daemon request threads) to
``cfg['bind']:cfg['port']`` — trying up to ten higher ports when the
configured one is busy — records the port in ``state.port`` / ``ctx.port``,
runs ``serve_forever`` under :func:`laglens.supervisor.start_thread` and
returns an :class:`HttpServer` with ``.stop(timeout)``.

Routes are those of BUILD_PLAN §3.4 / SPEC_FULL §10. Rules shared by every
handler:

* JSON replies are ``application/json; charset=utf-8`` with
  ``Cache-Control: no-store``; errors are ``{"error": ..., "code": ...}``;
* every POST and ``GET /mark`` must carry the session token
  (``X-LagLens-Token`` header or ``token=`` query) **and** come from a
  private source address (:func:`laglens.platform.is_private`), else 403;
* a feature whose component is not loaded answers
  ``503 {"error": "<name> not available", "code": "unavailable"}``;
* any exception inside a handler becomes a 500 JSON error — the server
  never dies because of one request — and requests are logged at ``DEBUG``
  only.

Pages come from ``laglens/web`` with ``{{TOKEN}}`` / ``{{VERSION}}`` /
``{{ACTIVITIES}}`` (the configured activity slugs, comma-separated) replaced; ``/static/<file>`` serves the same directory (plus the vendored
uPlot as ``uplot.js`` / ``uplot.css``) with ``Cache-Control: max-age=3600``.
"""
from __future__ import annotations

import hmac
import importlib
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from laglens.platform import is_private
from laglens.state import Mark
from laglens.supervisor import start_thread
from laglens.version import __version__

from laglens.server.series import build_series
from laglens.server.sse import Broadcaster

log = logging.getLogger("laglens.server.http")

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
VENDOR_DIR = WEB_DIR / "vendor"
PORT_TRIES = 11  # the configured port and up to +10
MAX_BODY = 1 << 20
MAX_SAMPLE_ROWS = 50_000
MAX_SAMPLE_SPAN_S = 600.0
RAW_RING_SAFE_S = 840.0  # inside this the RAM ring is complete (ring is 900 s)
REPORT_MAX_AGE_S = 30.0
STATIC_MAX_AGE_S = 3600
SESSION_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}(-[0-9]+)?$")
ACTIVITY_RE = re.compile(r"^[a-z0-9_\-]{1,40}$")
MARK_ID_RE = re.compile(r"^mk-[0-9]{1,9}$")
EPISODE_ID_RE = re.compile(r"^ep-[0-9]{1,9}$")
UPDATE_CMD = "bash start.sh --update"

PAGES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/phone": "phone.html",
    "/sessions": "sessions.html",
    "/setup": "setup.html",
}
STATIC_FILES = {
    "app.js": ("app.js", "application/javascript; charset=utf-8"),
    "phone.js": ("phone.js", "application/javascript; charset=utf-8"),
    "common.js": ("common.js", "application/javascript; charset=utf-8"),
    "qr.js": ("qr.js", "application/javascript; charset=utf-8"),
    "style.css": ("style.css", "text/css; charset=utf-8"),
    "uplot.js": ("vendor/uPlot.iife.min.js", "application/javascript; charset=utf-8"),
    "uplot.css": ("vendor/uPlot.min.css", "text/css; charset=utf-8"),
}
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#111827"/>'
    '<polyline points="8,40 20,40 26,20 34,52 40,32 46,40 56,40" fill="none" stroke="#f43f5e" stroke-width="6" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)

#: Components the server may construct itself when ``app`` did not (they are
#: not in ``app.COMPONENTS``): name → (module, class).
LAZY_COMPONENTS = {
    "marks": ("laglens.engine.marks", "MarkService"),
    "loadtest": ("laglens.loadtest", "LoadTest"),
}

JSON_CT = "application/json; charset=utf-8"
TEXT_CT = "text/plain; charset=utf-8"
HTML_CT = "text/html; charset=utf-8"


class ApiError(Exception):
    """Raised by handlers to produce a JSON error reply."""

    def __init__(self, status: int, message: str, code: str = "error") -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


def _json_default(o: Any) -> Any:
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    return str(o)


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=_json_default).encode("utf-8")


def _import(modname: str) -> Optional[Any]:
    """Import a feature module; ``None`` (logged at debug) when it is missing or broken."""
    try:
        return importlib.import_module(modname)
    except Exception:  # noqa: BLE001 - a broken optional module must not break the server
        log.debug("optional module %s not importable", modname, exc_info=True)
        return None


def _first(q: Dict[str, List[str]], key: str, default: Optional[str] = None) -> Optional[str]:
    v = q.get(key)
    return v[0] if v else default


def _float(v: Any, default: Optional[float] = None, name: str = "value") -> Optional[float]:
    if v is None or v == "":
        return default
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ApiError(400, "%s must be a number" % name, "bad_request")
    if f != f or f in (float("inf"), float("-inf")):
        raise ApiError(400, "%s must be finite" % name, "bad_request")
    return f


def _int(v: Any, default: Optional[int] = None, name: str = "value", lo: Optional[int] = None,
         hi: Optional[int] = None) -> Optional[int]:
    if v is None or v == "":
        return default
    try:
        i = int(float(v))
    except (TypeError, ValueError):
        raise ApiError(400, "%s must be an integer" % name, "bad_request")
    if lo is not None and i < lo:
        i = lo
    if hi is not None and i > hi:
        i = hi
    return i


def _id_list(v: Optional[str], name: str = "targets") -> Optional[List[int]]:
    if v is None or v.strip() == "":
        return None
    out: List[int] = []
    for part in v.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except ValueError:
            raise ApiError(400, "%s must be a comma-separated list of integers" % name, "bad_request")
    return out


def _bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _seg(m: Any, i: int = 1) -> str:
    """A captured, percent-decoded path segment."""
    return unquote(m.group(i) or "")


def client_ip(addr: Any) -> str:
    """The textual source address of a request (IPv4-mapped IPv6 unwrapped)."""
    ip = addr[0] if isinstance(addr, (tuple, list)) and addr else str(addr)
    ip = str(ip).split("%")[0]
    if ip.lower().startswith("::ffff:") and ip.count(".") == 3:
        ip = ip[7:]
    return ip


def source_is_private(addr: Any) -> bool:
    return is_private(client_ip(addr))


# ---------------------------------------------------------------------------
# Server context shared by request threads
# ---------------------------------------------------------------------------
class ServerContext:
    """What every request handler needs: the app context, the broadcaster and caches."""

    def __init__(self, ctx: Any, broadcaster: Broadcaster, web_dir: Path = WEB_DIR) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.cfg = ctx.cfg or {}
        self.broadcaster = broadcaster
        self.web_dir = Path(web_dir)
        self.started = time.time()
        self._lazy: Dict[str, Any] = {}
        self._lazy_lock = threading.Lock()
        self._report_lock = threading.Lock()

    @property
    def token(self) -> str:
        try:
            return str(self.ctx.token or "")
        except Exception:  # noqa: BLE001
            return ""

    def component(self, name: str) -> Optional[Any]:
        """``ctx.component(name)``, constructing :data:`LAZY_COMPONENTS` on first use."""
        obj = None
        try:
            obj = self.ctx.component(name)
        except Exception:  # noqa: BLE001
            obj = None
        if obj is not None or name not in LAZY_COMPONENTS:
            return obj
        with self._lazy_lock:
            if name in self._lazy:
                return self._lazy[name]
            modname, attr = LAZY_COMPONENTS[name]
            mod = _import(modname)
            inst = None
            if mod is not None and hasattr(mod, attr):
                try:
                    inst = getattr(mod, attr)(self.ctx)
                    if hasattr(inst, "start"):
                        try:
                            inst.start()
                        except Exception:  # noqa: BLE001
                            log.debug("%s.start() failed", name, exc_info=True)
                except Exception:  # noqa: BLE001
                    log.debug("cannot construct %s", name, exc_info=True)
                    inst = None
            self._lazy[name] = inst
            if inst is not None:
                try:
                    self.ctx.components.setdefault(name, inst)
                except Exception:  # noqa: BLE001
                    pass
            return inst

    def require(self, name: str) -> Any:
        obj = self.component(name)
        if obj is None:
            raise ApiError(503, "%s not available" % name, "unavailable")
        return obj

    def page(self, name: str) -> Optional[bytes]:
        p = self.web_dir / name
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            return None
        text = text.replace("{{TOKEN}}", self.token).replace("{{VERSION}}", __version__)
        text = text.replace("{{ACTIVITIES}}", self.activities_csv())
        return text.encode("utf-8")

    def activities_csv(self) -> str:
        """``cfg['activities']`` as a comma-separated slug list for the page meta tag."""
        acts = self.cfg.get("activities") if isinstance(self.cfg, dict) else None
        if not isinstance(acts, (list, tuple)) or not acts:
            acts = ["idle", "bf6", "rocket_league", "hbo_max", "other"]
        out = []
        for a in acts:
            a = str(a).strip().lower()
            if ACTIVITY_RE.match(a) and a not in out:
                out.append(a)
        return ",".join(out)


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
Response = Tuple[int, bytes, str, Dict[str, str]]


class LagLensHandler(BaseHTTPRequestHandler):
    """One request. Routing is table driven (:attr:`ROUTES`)."""

    server_version = "LagLens/%s" % __version__
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    # (method, regex, handler name)
    ROUTES: List[Tuple[str, Any, str]] = []

    # ----------------------------------------------------------- plumbing
    @property
    def sc(self) -> ServerContext:
        return self.server.ll  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401 - BaseHTTPRequestHandler API
        log.debug("%s %s", client_ip(self.client_address), fmt % args)

    def log_error(self, fmt: str, *args: Any) -> None:
        log.debug("%s %s", client_ip(self.client_address), fmt % args)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._dispatch("GET", head=True)

    def _dispatch(self, method: str, head: bool = False) -> None:
        parts = urlsplit(self.path)
        # Routes match the RAW path so an encoded slash (``%2F``) stays inside one
        # segment; handlers decode the segments they capture with :func:`_seg`.
        # ``..%2F..%2Ftoken`` therefore reaches the session-id validator (400)
        # instead of being re-routed as ``../../token``.
        path = parts.path or "/"
        self.query = parse_qs(parts.query, keep_blank_values=True)
        self.url_path = unquote(path)
        self.head_only = head
        self._body_cache: Optional[dict] = None
        try:
            for m, rx, name in self.ROUTES:
                if m != method:
                    continue
                match = rx.match(path)
                if match is None:
                    continue
                handler = getattr(self, name)
                resp = handler(match)
                if resp is not None:
                    self._send(*resp)
                return
            if any(rx.match(path) for _, rx, _ in self.ROUTES):
                raise ApiError(405, "method not allowed", "method")
            raise ApiError(404, "not found", "not_found")
        except ApiError as exc:
            self._send_error_json(exc.status, exc.message, exc.code)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            log.debug("client went away")
        except Exception as exc:  # noqa: BLE001 - never kill the server
            log.debug("handler failed for %s %s", method, path, exc_info=True)
            try:
                self._send_error_json(500, "internal error: %s" % exc, "internal")
            except Exception:  # noqa: BLE001
                pass

    # ---------------------------------------------------------- responses
    def _send(self, status: int, body: bytes, ctype: str, headers: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        hdrs = dict(headers or {})
        if "Cache-Control" not in hdrs:
            hdrs["Cache-Control"] = "no-store"
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.end_headers()
        if not getattr(self, "head_only", False):
            self.wfile.write(body)

    def _send_error_json(self, status: int, message: str, code: str) -> None:
        self._send(status, dumps({"error": message, "code": code}), JSON_CT)

    @staticmethod
    def _json(obj: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
        return status, dumps(obj), JSON_CT, dict(headers or {})

    @staticmethod
    def _text(text: str, status: int = 200) -> Response:
        return status, text.encode("utf-8"), TEXT_CT, {}

    # -------------------------------------------------------------- input
    def body(self) -> dict:
        """The JSON object of a POST body (``{}`` when empty); 400 when malformed."""
        if self._body_cache is not None:
            return self._body_cache
        length = _int(self.headers.get("Content-Length"), 0, "Content-Length", lo=0) or 0
        if length > MAX_BODY:
            raise ApiError(413, "body too large", "too_large")
        raw = self.rfile.read(length) if length else b""
        if not raw.strip():
            self._body_cache = {}
            return self._body_cache
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "body must be a JSON object", "bad_json")
        if not isinstance(obj, dict):
            raise ApiError(400, "body must be a JSON object", "bad_json")
        self._body_cache = obj
        return obj

    def q(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return _first(self.query, key, default)

    def wants_text(self) -> bool:
        return "text/plain" in (self.headers.get("Accept") or "")

    def require_auth(self) -> None:
        """Token (header or ``token=`` query) + private source, else 403."""
        token = self.headers.get("X-LagLens-Token") or self.q("token") or ""
        expected = self.sc.token
        ok = bool(expected) and hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))
        if not ok:
            raise ApiError(403, "missing or wrong token", "forbidden")
        if not source_is_private(self.client_address):
            raise ApiError(403, "requests are only accepted from the local network", "forbidden")

    # --------------------------------------------------------------- pages
    def h_page(self, m: Any) -> Response:
        name = PAGES[m.group(0)]
        if name == "index.html" and _bool(self.q("phone")):
            name = "phone.html"
        body = self.sc.page(name)
        if body is None:
            raise ApiError(404, "page not found", "not_found")
        return 200, body, HTML_CT, {}

    def h_static(self, m: Any) -> Response:
        name = _seg(m)
        entry = STATIC_FILES.get(name)
        if entry is None:
            raise ApiError(404, "no such static file", "not_found")
        rel, ctype = entry
        p = self.sc.web_dir / rel
        try:
            data = p.read_bytes()
        except OSError:
            raise ApiError(404, "static file missing", "not_found")
        return 200, data, ctype, {"Cache-Control": "max-age=%d" % STATIC_MAX_AGE_S}

    def h_favicon(self, m: Any) -> Response:
        return 200, FAVICON_SVG.encode("utf-8"), "image/svg+xml", {"Cache-Control": "max-age=%d" % STATIC_MAX_AGE_S}

    def h_report(self, m: Any) -> Response:
        sc = self.sc
        path = sc.store.path("report.html")
        builder = sc.component("report")
        if builder is not None and hasattr(builder, "build"):
            try:
                age = time.time() - path.stat().st_mtime
            except OSError:
                age = float("inf")
            if age > REPORT_MAX_AGE_S:
                with sc._report_lock:
                    try:
                        builder.build(final=False)
                    except Exception:  # noqa: BLE001
                        log.debug("report build failed", exc_info=True)
        try:
            data = path.read_bytes()
        except OSError:
            raise ApiError(503, "report not available yet", "unavailable")
        return 200, data, HTML_CT, {}

    def _session_dir(self, sid: str) -> Path:
        if not SESSION_ID_RE.match(sid or ""):
            raise ApiError(400, "bad session id", "bad_request")
        d = Path(self.sc.ctx.sessions_root) / sid
        if not d.is_dir():
            raise ApiError(404, "no such session", "not_found")
        return d

    def h_session_report(self, m: Any) -> Response:
        d = self._session_dir(_seg(m))
        try:
            data = (d / "report.html").read_bytes()
        except OSError:
            raise ApiError(404, "that session has no report.html", "not_found")
        return 200, data, HTML_CT, {}

    def _export(self, session_dir: Path, sid: str) -> Optional[Response]:
        mod = _import("laglens.report.export")
        if mod is None or not hasattr(mod, "build_zip"):
            raise ApiError(503, "export not available", "unavailable")
        pack = self.q("pack", "full") or "full"
        if pack not in ("full", "comcast"):
            raise ApiError(400, "pack must be full or comcast", "bad_request")
        raw = _bool(self.q("raw", "1"), True)
        # the live context only for *this* session (fresh Tell-Comcast text); past sessions get none.
        # `ctx` is an optional extra of report.export.build_zip beyond the §10.2 signature.
        live_ctx = self.sc.ctx if str(session_dir) == str(self.sc.store.dir) else None
        try:
            data = mod.build_zip(session_dir, pack=pack, raw=raw, cfg=self.sc.cfg, ctx=live_ctx)
        except TypeError:
            data = mod.build_zip(session_dir, pack=pack, raw=raw, cfg=self.sc.cfg)
        if not isinstance(data, (bytes, bytearray)):
            raise ApiError(500, "export produced no data", "internal")
        fname = "laglens-%s%s.zip" % (sid, "" if pack == "full" else "-" + pack)
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % fname)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not self.head_only:
            view = memoryview(data)
            for off in range(0, len(view), 1 << 16):
                self.wfile.write(view[off:off + (1 << 16)])
            self.wfile.flush()
        return None

    def h_export(self, m: Any) -> Optional[Response]:
        store = self.sc.store
        return self._export(Path(store.dir), store.id)

    def h_session_export(self, m: Any) -> Optional[Response]:
        sid = _seg(m)
        return self._export(self._session_dir(sid), sid)

    # ----------------------------------------------------------------- SSE
    def h_events(self, m: Any) -> Optional[Response]:
        sc = self.sc
        since = _float(self.q("since"), None, "since")
        client = sc.broadcaster.add_client(since)
        if client is None:
            raise ApiError(503, "too many SSE clients (max %d)" % sc.broadcaster.max_clients, "busy")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True
        if self.head_only:
            sc.broadcaster.remove_client(client)
            return None
        sc.broadcaster.stream(self.wfile, client, sc.state.stop_event)
        return None

    # ---------------------------------------------------------------- state
    def h_state(self, m: Any) -> Response:
        return self._json(self.sc.state.snapshot())

    def h_series(self, m: Any) -> Response:
        st = self.sc.state
        now = st.now()
        t_to = _float(self.q("to"), now, "to")
        t_from = _float(self.q("from"), t_to - 600.0, "from")
        span = t_to - t_from
        res = _int(self.q("res"), 1 if span <= 7200 else 5, "res")
        ids = _id_list(self.q("targets"))
        try:
            body = build_series(st, self.sc.store, t_from, t_to, res, ids)
        except ValueError as exc:
            raise ApiError(400, str(exc), "bad_request")
        return self._json(body)

    def h_samples(self, m: Any) -> Response:
        sc = self.sc
        st = sc.state
        now = st.now()
        t_to = _float(self.q("to"), now, "to")
        t_from = _float(self.q("from"), t_to - 60.0, "from")
        if t_to < t_from:
            raise ApiError(400, "'to' must not be before 'from'", "bad_request")
        if t_to - t_from > MAX_SAMPLE_SPAN_S:
            raise ApiError(400, "range too large (max 10 min)", "range")
        ids = _id_list(self.q("targets"))
        kinds = _id_list(self.q("kinds"), "kinds")
        kind_set = set(kinds) if kinds is not None else None
        rows: Dict[Tuple[int, int, int, int, int], list] = {}
        for s in st.raw_all(t_from, t_to, ids):
            if kind_set is not None and s.kind not in kind_set:
                continue
            rows[(s.ts_ms, s.target_id, s.kind, s.flags, s.seq)] = s.to_row()
        truncated = False
        if t_from < now - RAW_RING_SAFE_S and sc.store is not None:
            file_rows = sc.store.read_samples(int(t_from * 1000), int(t_to * 1000), ids, max_rows=MAX_SAMPLE_ROWS)
            truncated = bool(getattr(sc.store, "last_read_truncated", False))
            for ts, tid, kind, flags, seq, value in file_rows:
                if kind_set is not None and kind not in kind_set:
                    continue
                rows.setdefault((ts, tid, kind, flags, seq), [ts, tid, kind, flags, value])
        out = [rows[k] for k in sorted(rows)]
        if len(out) > MAX_SAMPLE_ROWS:
            out = out[:MAX_SAMPLE_ROWS]
            truncated = True
        return self._json({
            "from": t_from, "to": t_to, "count": len(out), "truncated": truncated,
            "columns": ["ts_ms", "id", "kind", "flags", "value_us"], "rows": out,
        })

    def h_events_list(self, m: Any) -> Response:
        st = self.sc.state
        since = _float(self.q("since"), 0.0, "since") or 0.0
        limit = _int(self.q("limit"), 200, "limit", lo=1, hi=5000) or 200
        with st.lock:
            evs = [e.to_dict() for e in st.events if (e.t1 or e.t0) >= since]
        return self._json({"events": evs[-limit:]})

    def h_episodes(self, m: Any) -> Response:
        st = self.sc.state
        since = _float(self.q("since"), 0.0, "since") or 0.0
        limit = _int(self.q("limit"), 100, "limit", lo=1, hi=5000) or 100
        cls = self.q("class")
        with st.lock:
            eps = [e for e in st.episodes if (e.t1 or e.t0) >= since or e.t1 is None]
            if cls:
                eps = [e for e in eps if e.cls == cls]
            out = [e.to_dict(brief=True) for e in eps[-limit:]]
        return self._json({"episodes": out})

    def h_episode(self, m: Any) -> Response:
        ep = self.sc.state.episode(_seg(m))
        if ep is None:
            raise ApiError(404, "no such episode", "not_found")
        return self._json(ep.to_dict())

    # ---------------------------------------------------------------- marks
    def _create_mark(self, params: dict, default_source: str) -> dict:
        sc = self.sc
        st = sc.state
        offset = _float(params.get("offset_s"), 0.0, "offset_s") or 0.0
        offset = min(max(offset, 0.0), 3600.0)
        activity = params.get("activity")
        activity = str(activity)[:40] if activity not in (None, "") else None
        note = str(params.get("note") or "")[:500]
        source = str(params.get("source") or default_source)[:40]
        replay = _bool(params.get("replay"))
        t_pressed = _float(params.get("t_pressed"), None, "t_pressed") if replay else None
        svc = sc.component("marks")
        mark: Any = None
        if svc is not None and hasattr(svc, "create"):
            mark = svc.create(offset_s=offset, activity=activity, note=note, source=source,
                              t_pressed=t_pressed, replay=replay)
        else:
            mark = self._fallback_mark(offset, activity, note, source, t_pressed)
        d = mark.to_dict() if hasattr(mark, "to_dict") else dict(mark)
        ep = st.episode(d.get("episode")) if d.get("episode") else None
        return {
            "id": d.get("id"),
            "t_est": d.get("t_est"),
            "assessment": d.get("assessment"),
            "episode": d.get("episode"),
            "episode_class": ep.cls if ep is not None else None,
            "snapshot_at": (d.get("t_pressed") or st.now()) + 30.0,
            "activity": d.get("activity"),
            "replay": replay,
        }

    def _fallback_mark(self, offset: float, activity: Optional[str], note: str, source: str,
                       t_pressed: Optional[float]) -> Mark:
        """Record a press without ``engine.marks`` (no assessment, nearest-episode link only)."""
        sc = self.sc
        st = sc.state
        now = st.now()
        pressed = t_pressed if t_pressed else now
        t_est = pressed - offset
        linked = None
        with st.lock:
            for ep in reversed(st.episodes):
                t1 = ep.t1 if ep.t1 is not None else now
                if ep.t0 - 10.0 <= t_est + 2.0 and t1 >= t_est - 10.0:
                    linked = ep.id
                    break
            current = st.activity.get("current", "idle")
        m = Mark(id=st.next_mark_id(), t_pressed=pressed, offset_s=offset, t_est=t_est,
                 activity=activity or current, note=note, source=source, episode=linked,
                 assessment="Press recorded; the instant assessment is not available (mark service not loaded).")
        st.add_mark(m)
        try:
            sc.store.append_json("marks", m.to_dict())
        except Exception:  # noqa: BLE001
            log.debug("cannot append mark", exc_info=True)
        if linked:
            ep = st.episode(linked)
            if ep is not None and m.id not in ep.marks:
                ep.marks.append(m.id)
        return m

    def h_mark_post(self, m: Any) -> Response:
        self.require_auth()
        return self._json(self._create_mark(self.body(), "dashboard"))

    def h_mark_get(self, m: Any) -> Response:
        self.require_auth()
        params = {k: v[0] for k, v in self.query.items() if v}
        if "source" not in params and params.get("src"):
            params["source"] = params["src"]
        resp = self._create_mark(params, "shortcut")
        if self.wants_text():
            lines = ["Saved %s" % resp["id"], str(resp.get("assessment") or "")]
            lines.append("Linked to episode %s" % resp["episode"] if resp.get("episode") else "No nearby event")
            return self._text("\n".join(lines) + "\n")
        return self._json(resp)

    def h_marks(self, m: Any) -> Response:
        st = self.sc.state
        with st.lock:
            marks = [mk.to_dict() for mk in st.marks]
        return self._json({"marks": marks})

    def h_mark_snapshot(self, m: Any) -> Response:
        mid = _seg(m)
        if not MARK_ID_RE.match(mid):
            raise ApiError(400, "bad mark id", "bad_request")
        sc = self.sc
        svc = sc.component("marks")
        snap = None
        if svc is not None and hasattr(svc, "snapshot"):
            try:
                snap = svc.snapshot(mid)
            except Exception:  # noqa: BLE001
                log.debug("snapshot() failed", exc_info=True)
        if snap is None:
            snap = sc.store.read_file_json("marks/%s.json" % mid)
        if snap is None:
            raise ApiError(404, "no snapshot for that mark (yet)", "not_found")
        return self._json(snap)

    # ------------------------------------------------------------- activity
    def h_activity(self, m: Any) -> Response:
        self.require_auth()
        sc = self.sc
        body = self.body()
        activity = str(body.get("activity") or "").strip().lower()
        if not ACTIVITY_RE.match(activity):
            raise ApiError(400, "activity must be a short slug", "bad_request")
        label = body.get("label")
        label = str(label)[:120] if label else None
        source = str(body.get("source") or "dashboard")[:40]
        snap = sc.state.set_activity(activity, source=source, label=label)
        try:
            with sc.state.lock:
                tag = dict(sc.state.tags[-1]) if sc.state.tags else {"t0": snap["since"], "t1": None, "activity": activity, "source": source}
            sc.store.append_json("tags", tag)
        except Exception:  # noqa: BLE001
            log.debug("cannot append tag", exc_info=True)
        return self._json({"ok": True, "since": snap.get("since"), "activity": activity})

    # ------------------------------------------------------------- loadtest
    def h_loadtest_start(self, m: Any) -> Response:
        self.require_auth()
        lt = self.sc.require("loadtest")
        force = _bool(self.body().get("force"))
        try:
            result = lt.start(force=force)
        except Exception as exc:  # noqa: BLE001 - map the module's own exceptions by name
            name = type(exc).__name__
            if name == "EpisodeOpen":
                raise ApiError(409, "episode open", "episode_open")
            if name == "LoadTestBusy":
                raise ApiError(409, "load test already running", "busy")
            raise
        out = {"ok": True}
        if isinstance(result, dict):
            out.update(result)
        return self._json(out)

    def h_loadtest_stop(self, m: Any) -> Response:
        self.require_auth()
        lt = self.sc.require("loadtest")
        lt.stop()
        return self._json({"ok": True})

    def h_loadtest(self, m: Any) -> Response:
        lt = self.sc.component("loadtest")
        if lt is not None and hasattr(lt, "status"):
            return self._json(lt.status())
        return self._json(dict(self.sc.state.loadtest))

    # ----------------------------------------------------------------- path
    def h_path_rediscover(self, m: Any) -> Response:
        self.require_auth()
        tracer = self.sc.require("tracer")
        started = bool(tracer.rediscover())
        return self._json({"ok": True, "running": not started}, 200 if started else 202)

    def h_path(self, m: Any) -> Response:
        sc = self.sc
        tracer = sc.component("tracer")
        if tracer is not None and hasattr(tracer, "current"):
            return self._json(tracer.current())
        body = dict(sc.state.path)
        try:
            body.setdefault("history", sc.store.read_json("path")[-50:])
        except Exception:  # noqa: BLE001
            body.setdefault("history", [])
        return self._json(body)

    # --------------------------------------------------------------- docsis
    def h_docsis_refresh(self, m: Any) -> Response:
        self.require_auth()
        col = self.sc.require("docsis")
        if not col.refresh():
            raise ApiError(409, "DOCSIS refresh not possible right now", "disabled")
        return self._json({"ok": True})

    def h_docsis(self, m: Any) -> Response:
        col = self.sc.component("docsis")
        if col is None or not hasattr(col, "recent"):
            entry = self.sc.state.collector("docsis") or {}
            raise ApiError(503, "docsis not available%s" % (": " + entry["reason"] if entry.get("reason") else ""), "unavailable")
        n = _int(self.q("last"), 20, "last", lo=1, hi=500) or 20
        return self._json(col.recent(n))

    # ----------------------------------------------------------------- plex
    def h_plex(self, m: Any) -> Response:
        col = self.sc.component("plex")
        if col is None or not hasattr(col, "status"):
            pcfg = (self.sc.ctx.cfg or {}).get("plex") or {}
            entry = self.sc.state.collector("plex") or {}
            return self._json({"enabled": False, "reason": entry.get("reason") or "Plex mode is off",
                               "server": pcfg.get("server"), "players": list(pcfg.get("players") or []),
                               "token_set": bool(pcfg.get("token"))})
        return self._json(col.status())

    def h_plex_set(self, m: Any) -> Response:
        """Setup page: server, players and the token (write-only: never sent back). Plex mode follows the activity."""
        self.require_auth()
        body = self.body()
        ctx = self.sc.ctx
        pcfg = ctx.cfg.setdefault("plex", {}) if isinstance(ctx.cfg, dict) else {}
        values: Dict[str, Any] = {}
        if "server" in body:
            srv = str(body.get("server") or "").strip()
            host = srv.rsplit(":", 1)[0] if srv.count(":") == 1 else srv
            if srv:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    raise ApiError(400, "server must be an IP address, optionally with :port", "bad_request")
            values["plex.server"] = srv or None
        if "players" in body:
            raw = body.get("players")
            items = raw if isinstance(raw, list) else str(raw or "").replace(",", " ").split()
            players = []
            for it in items[:8]:
                ip, _, name = str(it).strip().partition("=")
                try:
                    ipaddress.ip_address(ip.strip())
                except ValueError:
                    raise ApiError(400, "players must be IP addresses (optionally ip=name)", "bad_request")
                players.append(ip.strip() + ("=" + name.strip()[:40] if name.strip() else ""))
            values["plex.players"] = players
        if body.get("clear_token"):
            values["plex.token"] = None
        elif isinstance(body.get("token"), str) and body["token"].strip():
            tok = body["token"].strip()
            if len(tok) > 200 or any(c.isspace() for c in tok):
                raise ApiError(400, "that does not look like a Plex token", "bad_request")
            values["plex.token"] = tok
        for dotted, v in values.items():
            pcfg[dotted.split(".", 1)[1]] = v
        saved = self._persist_config(values) if values else False
        col = ctx.component("plex")
        return self._json({"ok": True, "saved": saved, "token_set": bool(pcfg.get("token")),
                           "enabled": bool(getattr(col, "active", False))})

    def h_igd(self, m: Any) -> Response:
        col = self.sc.component("igd")
        if col is None or not hasattr(col, "status"):
            entry = self.sc.state.collector("igd") or {}
            raise ApiError(503, "igd not available%s" % (": " + entry["reason"] if entry.get("reason") else ""), "unavailable")
        return self._json(col.status())

    # ---------------------------------------------------------------- stats
    def h_stats(self, m: Any) -> Response:
        window = self.q("window", "session") or "session"
        if window not in ("session", "1h", "5m"):
            raise ApiError(400, "window must be session, 1h or 5m", "bad_request")
        activity = self.q("activity", "all") or "all"
        from laglens.engine.rollup import stats

        return self._json(stats(self.sc.state, window, activity))

    def h_verdict(self, m: Any) -> Response:
        return self._json(dict(self.sc.state.verdict))

    def h_comcast(self, m: Any) -> Response:
        mod = _import("laglens.engine.verdict")
        text = None
        if mod is not None and hasattr(mod, "comcast_text"):
            try:
                text = mod.comcast_text(self.sc.ctx)
            except Exception:  # noqa: BLE001
                log.debug("comcast_text failed", exc_info=True)
        if not text:
            text = str(self.sc.state.verdict.get("comcast") or "")
        return self._text(text)

    # --------------------------------------------------------------- doctor
    def _doctor_ran_at(self) -> Optional[float]:
        try:
            return self.sc.store.path("doctor.json").stat().st_mtime
        except OSError:
            return None

    def h_doctor(self, m: Any) -> Response:
        return self._json({"ran_at": self._doctor_ran_at(), "checks": list(self.sc.state.doctor)})

    def h_doctor_run(self, m: Any) -> Response:
        self.require_auth()
        mod = _import("laglens.doctor")
        if mod is None or not hasattr(mod, "fast"):
            raise ApiError(503, "doctor not available", "unavailable")
        checks = mod.fast(self.sc.ctx)
        if checks is None:
            checks = list(self.sc.state.doctor)
        return self._json({"ran_at": self._doctor_ran_at() or time.time(), "checks": checks})

    # ------------------------------------------------------------- sessions
    def h_sessions(self, m: Any) -> Response:
        mod = _import("laglens.report.sessions")
        if mod is None or not hasattr(mod, "list_sessions"):
            raise ApiError(503, "sessions not available", "unavailable")
        return self._json({"sessions": mod.list_sessions(self.sc.ctx.sessions_root)})

    def h_session_summary(self, m: Any) -> Response:
        d = self._session_dir(_seg(m))
        try:
            with open(d / "session.json", "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            raise ApiError(404, "that session has no session.json", "not_found")
        return self._json(doc)

    def h_label(self, m: Any) -> Response:
        self.require_auth()
        sc = self.sc
        label = str(self.body().get("label") or "").strip()[:120] or None
        with sc.state.lock:
            sc.state.label = label
        try:
            sc.cfg["label"] = label
        except Exception:  # noqa: BLE001
            pass
        app = _import("laglens.app")
        if app is not None and hasattr(app, "write_session_json"):
            try:
                app.write_session_json(sc.ctx)
            except Exception:  # noqa: BLE001
                log.debug("session.json rewrite failed", exc_info=True)
        return self._json({"ok": True, "label": label})

    def h_notify_test(self, m: Any) -> Response:
        self.require_auth()
        notifier = self.sc.require("notify")
        ok, detail = notifier.test()
        if not ok:
            return self._json({"error": str(detail or "notification failed"), "code": "notify_failed"}, 502)
        return self._json({"ok": True, "detail": detail})

    def h_stop(self, m: Any) -> Response:
        self.require_auth()
        self.sc.state.request_stop("api")
        return self._json({"ok": True, "report": "/report.html"})

    def h_version(self, m: Any) -> Response:
        upd = dict(self.sc.state.update or {})
        return self._json({"version": __version__, "latest": upd.get("latest"), "available": bool(upd.get("available")),
                           "update_cmd": UPDATE_CMD, "update": upd})

    # ----------------------------------------------------------------- xbox
    def h_xbox_set(self, m: Any) -> Response:
        self.require_auth()
        ip = str(self.body().get("ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ApiError(400, "ip must be an IPv4/IPv6 address", "bad_request")
        col = self.sc.require("xbox")
        if col.set_ip(ip) is False:
            raise ApiError(400, "the Xbox collector rejected that address", "bad_request")
        # the collector only changes cfg in memory; the choice must survive a restart (config.json)
        saved = self._persist_config({"targets.xbox_ip": ip})
        return self._json({"ok": True, "ip": ip, "saved": saved})

    def _persist_config(self, values: Dict[str, Any]) -> bool:
        """Write ``values`` into the app's ``config.json`` through ``laglens.config.save_values``."""
        path = getattr(self.sc.ctx, "config_file", None)
        if not path:
            return False
        cfgmod = _import("laglens.config")
        if cfgmod is None or not hasattr(cfgmod, "save_values"):
            return False
        try:
            return bool(cfgmod.save_values(path, values))
        except Exception:  # noqa: BLE001
            log.exception("cannot persist %s to %s", list(values), path)
            return False

    def h_xbox(self, m: Any) -> Response:
        return self._json(dict(self.sc.state.xbox))


def _route(method: str, pattern: str, name: str) -> Tuple[str, Any, str]:
    return method, re.compile(pattern), name


LagLensHandler.ROUTES = [
    _route("GET", r"^/(?:index\.html)?$", "h_page"),
    _route("GET", r"^/phone$", "h_page"),
    _route("GET", r"^/sessions$", "h_page"),
    _route("GET", r"^/setup$", "h_page"),
    _route("GET", r"^/static/([A-Za-z0-9_.\-]+)$", "h_static"),
    _route("GET", r"^/favicon\.ico$", "h_favicon"),
    _route("GET", r"^/report\.html$", "h_report"),
    _route("GET", r"^/sessions/([^/]+)/report\.html$", "h_session_report"),
    _route("GET", r"^/export\.zip$", "h_export"),
    _route("GET", r"^/sessions/([^/]+)/export\.zip$", "h_session_export"),
    _route("GET", r"^/events$", "h_events"),
    _route("GET", r"^/mark$", "h_mark_get"),
    _route("GET", r"^/api/state$", "h_state"),
    _route("GET", r"^/api/series$", "h_series"),
    _route("GET", r"^/api/samples$", "h_samples"),
    _route("GET", r"^/api/events$", "h_events_list"),
    _route("GET", r"^/api/episodes$", "h_episodes"),
    _route("GET", r"^/api/episodes/([^/]+)$", "h_episode"),
    _route("POST", r"^/api/mark$", "h_mark_post"),
    _route("GET", r"^/api/marks$", "h_marks"),
    _route("GET", r"^/api/marks/([^/]+)/snapshot$", "h_mark_snapshot"),
    _route("POST", r"^/api/activity$", "h_activity"),
    _route("POST", r"^/api/loadtest/start$", "h_loadtest_start"),
    _route("POST", r"^/api/loadtest/stop$", "h_loadtest_stop"),
    _route("GET", r"^/api/loadtest$", "h_loadtest"),
    _route("POST", r"^/api/path/rediscover$", "h_path_rediscover"),
    _route("GET", r"^/api/path$", "h_path"),
    _route("POST", r"^/api/docsis/refresh$", "h_docsis_refresh"),
    _route("GET", r"^/api/docsis$", "h_docsis"),
    _route("GET", r"^/api/igd$", "h_igd"),
    _route("GET", r"^/api/plex$", "h_plex"),
    _route("POST", r"^/api/plex$", "h_plex_set"),
    _route("GET", r"^/api/stats$", "h_stats"),
    _route("GET", r"^/api/verdict$", "h_verdict"),
    _route("GET", r"^/api/comcast\.txt$", "h_comcast"),
    _route("GET", r"^/api/doctor$", "h_doctor"),
    _route("POST", r"^/api/doctor/run$", "h_doctor_run"),
    _route("GET", r"^/api/sessions$", "h_sessions"),
    _route("GET", r"^/api/sessions/([^/]+)/summary$", "h_session_summary"),
    _route("POST", r"^/api/session/label$", "h_label"),
    _route("POST", r"^/api/notify/test$", "h_notify_test"),
    _route("POST", r"^/api/stop$", "h_stop"),
    _route("GET", r"^/api/version$", "h_version"),
    _route("POST", r"^/api/xbox$", "h_xbox_set"),
    _route("GET", r"^/api/xbox$", "h_xbox"),
]


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, addr: Tuple[str, int], family: int) -> None:
        self.address_family = family
        self.ll: Optional[ServerContext] = None
        super().__init__(addr, LagLensHandler)

    def handle_error(self, request: Any, client_address: Any) -> None:  # noqa: D401
        log.debug("request from %s failed", client_ip(client_address), exc_info=True)


def bind_server(bind: str, port: int, tries: int = PORT_TRIES) -> _Server:
    """Bind ``bind:port`` or the first free port up to ``port + tries - 1`` (``port`` 0: any free port)."""
    family = socket.AF_INET6 if ":" in (bind or "") else socket.AF_INET
    last: Optional[Exception] = None
    candidates = [0] if int(port) == 0 else range(int(port), int(port) + max(1, tries))
    for p in candidates:
        try:
            return _Server((bind or "0.0.0.0", p), family)
        except OSError as exc:
            last = exc
            log.debug("port %d busy: %s", p, exc)
    raise OSError("no free port in %d..%d (%s)" % (port, port + tries - 1, last))


class HttpServer:
    """The running server: ``.port``, ``.url``, ``.broadcaster`` and ``.stop(timeout)``."""

    def __init__(self, ctx: Any, server: _Server, broadcaster: Broadcaster) -> None:
        self.ctx = ctx
        self.server = server
        self.broadcaster = broadcaster
        self.port: int = int(server.server_address[1])
        self.url = "http://127.0.0.1:%d" % self.port
        self.thread: Optional[threading.Thread] = None
        self._stopped = False

    def _run(self) -> None:
        self.server.serve_forever(poll_interval=0.5)

    def start(self) -> None:
        if self.thread is None:
            self.thread = start_thread("http", self._run, self.ctx.state)

    def stop(self, timeout: float = 2.0) -> None:
        if self._stopped:
            return
        self._stopped = True
        self.broadcaster.close()
        t = threading.Thread(target=self.server.shutdown, name="http-shutdown", daemon=True)
        t.start()
        t.join(max(0.2, float(timeout)))
        try:
            self.server.server_close()
        except OSError:
            pass
        if self.thread is not None:
            self.thread.join(max(0.2, float(timeout)))


def serve(ctx: Any, heartbeat_s: float = 15.0, max_clients: int = 8, web_dir: Optional[Path] = None) -> HttpServer:
    """Start the HTTP server for ``ctx`` (BUILD_PLAN §3.4) and return it.

    Raises ``OSError`` when no port in ``port..port+10`` can be bound; the app
    then records the component as failed with that reason.
    """
    cfg = ctx.cfg or {}
    # ``ctx.port`` wins, then ``cfg['port']``, then 8787; an explicit 0 means "any free port"
    # (the OS picks one; used by tests and handy for a second instance).
    port = getattr(ctx, "port", None)
    if port is None or port == "":
        port = cfg.get("port")
    if port is None or port == "":
        port = 8787
    port = int(port)
    bind = str(cfg.get("bind") or "0.0.0.0")
    state = ctx.state
    try:
        srv = bind_server(bind, port)
    except OSError as exc:
        try:
            state.set_collector("http", "disabled", reason=str(exc))
        except Exception:  # noqa: BLE001
            pass
        raise
    broadcaster = Broadcaster(state, max_clients=max_clients, heartbeat_s=heartbeat_s)
    srv.ll = ServerContext(ctx, broadcaster, web_dir or WEB_DIR)
    http = HttpServer(ctx, srv, broadcaster)
    try:
        state.port = http.port
        ctx.port = http.port
    except Exception:  # noqa: BLE001
        pass
    if http.port != port:
        log.info("port %d busy; listening on %d", port, http.port)
    http.start()
    try:
        state.set_collector("http", "ok", port=http.port)
    except Exception:  # noqa: BLE001
        pass
    return http


__all__ = ["serve", "HttpServer", "LagLensHandler", "ServerContext", "ApiError", "bind_server", "client_ip",
           "source_is_private", "WEB_DIR", "STATIC_FILES", "PAGES", "MAX_SAMPLE_ROWS", "MAX_SAMPLE_SPAN_S"]
