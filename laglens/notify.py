"""Notifications (SPEC_FULL S8): ntfy.sh topic and/or a generic JSON webhook.

Off unless ``notify.ntfy_topic`` or ``notify.webhook_url`` is set. The
notifier subscribes to ``episode_open`` / ``episode_close`` / ``verdict``
on :class:`laglens.state.State`, filters by ``notify.min_confidence``
(``low`` < ``medium`` < ``high``; an episode's numeric confidence maps to
``high`` ≥ 0.75, ``medium`` ≥ 0.5, else ``low``), batches for
``notify.batch_s`` seconds and then sends one message per channel:

* ntfy: ``POST https://ntfy.sh/<topic>`` (a topic that starts with ``http``
  is used as the full URL) with the text body and a ``Title`` header;
* webhook: ``POST`` of ``{"title", "text", "events": [...]}`` as JSON.

Both use a 10 s timeout. Blips (episodes shorter than 1.5 s) are never
notified. ``test()`` sends a test message synchronously and returns
``(ok, message)``.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from laglens.supervisor import start_thread

log = logging.getLogger("laglens.notify")

NTFY_BASE = "https://ntfy.sh/"
HTTP_TIMEOUT_S = 10.0
MIN_EPISODE_S = 1.5
#: Episode classes that never trigger a notification: the load test's own symptoms (rule 3) and the
#: informational classes (``INFO_CLASSES`` in ``laglens.engine.classify``).
SILENT_CLASSES = frozenset({"loadtest", "xb7_cpu", "hop_rate_limit"})
LEVELS = {"low": 0, "medium": 1, "high": 2}
USER_AGENT = "LagLens/1.0"


def confidence_level(value: Any) -> str:
    """Numeric episode confidence → ``low`` / ``medium`` / ``high``."""
    if isinstance(value, str):
        return value if value in LEVELS else "low"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "low"
    if v >= 0.75:
        return "high"
    if v >= 0.5:
        return "medium"
    return "low"


def _fmt_time(t: Any) -> str:
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(t)))
    except (TypeError, ValueError, OverflowError):
        return "?"


class Notifier:
    """``Notifier(ctx)``; ``start()`` subscribes, ``stop()`` flushes what is queued."""

    name = "notify"

    def __init__(self, ctx: Any, urlopen: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.time, mono: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.cfg = (ctx.cfg or {}).get("notify") or {}
        self._urlopen = urlopen or urllib.request.urlopen
        self._clock = clock
        self._mono = mono
        self.topic: Optional[str] = (self.cfg.get("ntfy_topic") or None)
        self.webhook: Optional[str] = (self.cfg.get("webhook_url") or None)
        self.min_level = LEVELS.get(str(self.cfg.get("min_confidence", "medium")).lower(), 1)
        try:
            self.batch_s = max(0.0, float(self.cfg.get("batch_s", 120)))
        except (TypeError, ValueError):
            self.batch_s = 120.0
        self._lock = threading.Lock()
        self._queue: List[Dict[str, Any]] = []
        self._first_queued_at: Optional[float] = None
        self._wake = threading.Event()
        self._unsub: Optional[Callable[[], None]] = None
        self.thread = None
        self.sent = 0
        self.failed = 0
        self.last_error: Optional[str] = None
        self._last_verdict_text: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.topic or self.webhook)

    def channels(self) -> List[str]:
        out = []
        if self.topic:
            out.append("ntfy")
        if self.webhook:
            out.append("webhook")
        return out

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if not self.configured:
            self.state.set_collector(self.name, "disabled", reason="not configured")
            return
        self._unsub = self.state.subscribe(self.on_event)
        self.state.set_collector(self.name, "ok", channels=self.channels(), batch_s=self.batch_s)
        self.thread = start_thread(self.name, self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        if self._unsub is not None:
            try:
                self._unsub()
            except Exception:  # noqa: BLE001
                pass
            self._unsub = None
        self._wake.set()
        t = self.thread
        if t is not None:
            t.join(timeout)
        if self.configured and self._queue:
            try:
                self.flush()
            except Exception:  # noqa: BLE001
                log.debug("notify: final flush failed", exc_info=True)

    def _loop(self) -> None:
        st = self.state
        while not st.stop_event.is_set():
            self._wake.wait(1.0)
            self._wake.clear()
            if st.stop_event.is_set():
                break
            if self.due():
                self.flush()

    # ---------------------------------------------------------------- events
    def on_event(self, name: str, obj: Any) -> None:
        """State subscriber: queue episode/verdict events that pass the filters."""
        if name not in ("episode_open", "episode_close", "verdict"):
            return
        item = self._item(name, obj)
        if item is None:
            return
        with self._lock:
            self._queue.append(item)
            if self._first_queued_at is None:
                self._first_queued_at = self._mono()
        self._wake.set()

    def _item(self, name: str, obj: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(obj, dict):
            return None
        if name == "verdict":
            text = str(obj.get("text") or "").strip()
            if not text or text == self._last_verdict_text:
                return None
            if LEVELS.get(confidence_level(obj.get("confidence")), 0) < self.min_level:
                return None
            self._last_verdict_text = text
            return {"kind": "verdict", "t": self._clock(), "text": "Verdict: %s" % text, "confidence": obj.get("confidence")}
        if LEVELS.get(confidence_level(obj.get("confidence")), 0) < self.min_level:
            return None
        dur = obj.get("dur_s")
        if name == "episode_close" and dur is not None and float(dur) < MIN_EPISODE_S:
            return None
        cls = obj.get("class") or obj.get("cls") or "unknown"
        if cls in SILENT_CLASSES:
            # a load test's own symptoms and the informational classes are not trouble worth a page
            return None
        t0 = obj.get("t0")
        if name == "episode_open":
            text = "Trouble started %s (%s)" % (_fmt_time(t0), cls)
        else:
            text = "Episode %s: %s for %s s from %s, confidence %s" % (
                obj.get("id"), cls, ("%.1f" % float(dur)) if dur is not None else "?", _fmt_time(t0),
                confidence_level(obj.get("confidence")))
            ev = obj.get("evidence") or []
            if ev:
                text += " — " + "; ".join(str(e) for e in ev[:2])
        return {"kind": name, "t": self._clock(), "text": text, "id": obj.get("id"), "class": cls,
                "confidence": obj.get("confidence")}

    def due(self) -> bool:
        with self._lock:
            if not self._queue or self._first_queued_at is None:
                return False
            return self._mono() - self._first_queued_at >= self.batch_s

    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    # ------------------------------------------------------------------ send
    def flush(self) -> Tuple[bool, str]:
        """Send everything queued as one batched message per channel."""
        with self._lock:
            items = list(self._queue)
            self._queue = []
            self._first_queued_at = None
        if not items:
            return True, "nothing to send"
        title = "Lag Lens: %d event%s" % (len(items), "" if len(items) == 1 else "s")
        if len(items) == 1:
            title = "Lag Lens: " + (items[0].get("kind") or "event").replace("_", " ")
        text = "\n".join(i["text"] for i in items)
        return self.send(title, text, items)

    def send(self, title: str, text: str, items: Optional[List[Dict[str, Any]]] = None) -> Tuple[bool, str]:
        results: List[str] = []
        ok_all = True
        if self.topic:
            ok, msg = self._post_ntfy(title, text)
            ok_all = ok_all and ok
            results.append("ntfy: " + msg)
        if self.webhook:
            ok, msg = self._post_webhook(title, text, items or [])
            ok_all = ok_all and ok
            results.append("webhook: " + msg)
        if not results:
            return False, "not configured"
        if ok_all:
            self.sent += 1
            self.last_error = None
            if self.state.collector(self.name) is not None:
                self.state.set_collector(self.name, "ok", channels=self.channels(), sent=self.sent, batch_s=self.batch_s)
        else:
            self.failed += 1
            self.last_error = "; ".join(results)
            if self.state.collector(self.name) is not None:
                self.state.set_collector(self.name, "degraded", reason=self.last_error[:200], channels=self.channels(),
                                         sent=self.sent, failed=self.failed)
        return ok_all, "; ".join(results)

    def _post(self, url: str, data: bytes, headers: Dict[str, str]) -> Tuple[bool, str]:
        req = urllib.request.Request(url, data=data, headers=dict(headers, **{"User-Agent": USER_AGENT}), method="POST")
        try:
            resp = self._urlopen(req, timeout=HTTP_TIMEOUT_S)
            try:
                code = getattr(resp, "status", None) or resp.getcode()
                resp.read(4096)
            finally:
                try:
                    resp.close()
                except Exception:  # noqa: BLE001
                    pass
            if 200 <= int(code) < 300:
                return True, "HTTP %s" % code
            return False, "HTTP %s" % code
        except urllib.error.HTTPError as exc:
            return False, "HTTP %s" % exc.code
        except Exception as exc:  # noqa: BLE001
            return False, "%s: %s" % (type(exc).__name__, str(exc)[:120])

    def _ntfy_url(self) -> str:
        t = self.topic or ""
        if t.startswith("http://") or t.startswith("https://"):
            return t
        return NTFY_BASE + t.strip("/")

    def _post_ntfy(self, title: str, text: str) -> Tuple[bool, str]:
        headers = {"Title": title.encode("ascii", "replace").decode("ascii"), "Content-Type": "text/plain; charset=utf-8",
                   "Tags": "satellite"}
        return self._post(self._ntfy_url(), text.encode("utf-8"), headers)

    def _post_webhook(self, title: str, text: str, items: List[Dict[str, Any]]) -> Tuple[bool, str]:
        body = json.dumps({"title": title, "text": text, "events": items, "source": "laglens",
                           "session": getattr(self.state, "session_id", "")}).encode("utf-8")
        return self._post(self.webhook or "", body, {"Content-Type": "application/json"})

    def test(self) -> Tuple[bool, str]:
        """Send a test notification now; ``(ok, message)`` (the ``POST /api/notify/test`` body)."""
        if not self.configured:
            return False, "notify not configured (set notify.ntfy_topic or notify.webhook_url)"
        return self.send("Lag Lens test", "Test notification from Lag Lens (session %s)" % getattr(self.state, "session_id", ""),
                         [{"kind": "test", "t": self._clock(), "text": "test"}])


__all__ = ["Notifier", "confidence_level", "NTFY_BASE", "HTTP_TIMEOUT_S", "MIN_EPISODE_S", "SILENT_CLASSES", "LEVELS"]
