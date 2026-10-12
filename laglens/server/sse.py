"""Server-sent events: fan ``state.publish`` out to dashboard clients.

:class:`Broadcaster` subscribes once to :meth:`laglens.state.State.subscribe`
and keeps one bounded ``queue.Queue`` per connected client. A request
thread serving ``GET /events`` calls :meth:`Broadcaster.add_client` (``None``
when :data:`MAX_CLIENTS` are already connected → the HTTP layer answers 503)
and then :meth:`Broadcaster.stream` which blocks, writing frames
``event: <name>\\ndata: <json>\\n\\n`` and a ``: hb\\n\\n`` comment every
:data:`HEARTBEAT_S`, until the client goes away, the queue overflows, or
``state.stop_event`` is set. ``state.sse_clients`` always equals the number
of connected clients.

Only the event names of SPEC_FULL §10.3 are forwarded (:data:`EVENT_NAMES`);
``?since=<t>`` replays stored events, episodes and marks newer than ``t``
before live traffic.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("laglens.server.sse")

MAX_CLIENTS = 8
HEARTBEAT_S = 15.0
QUEUE_SIZE = 1000
EVENT_NAMES = frozenset({
    "tick", "rollup5", "event", "episode_open", "episode_update", "episode_close", "mark", "activity",
    "collector", "loadtest", "verdict", "docsis", "stopping",
})
_CLOSE = ("__close__", None)


def _json_default(o: Any) -> Any:
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    return str(o)


def format_frame(name: str, obj: Any) -> bytes:
    """One SSE frame (``event:`` + single-line ``data:``) as bytes."""
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=_json_default)
    data = data.replace("\r", "\\r").replace("\n", "\\n")
    return ("event: %s\ndata: %s\n\n" % (name, data)).encode("utf-8")


HEARTBEAT_FRAME = b": hb\n\n"


class Client:
    """One connected SSE consumer: a bounded queue plus a replay backlog."""

    def __init__(self, replay: List[Tuple[str, Any]], maxsize: int = QUEUE_SIZE) -> None:
        self.q: "queue.Queue[Tuple[str, Any]]" = queue.Queue(maxsize=maxsize)
        self.replay = list(replay)
        self.alive = True
        self.dropped = 0
        self.connected_at = time.time()

    def push(self, name: str, obj: Any) -> bool:
        """Queue a frame; ``False`` (and ``alive=False``) when the queue is full."""
        if not self.alive:
            return False
        try:
            self.q.put_nowait((name, obj))
            return True
        except queue.Full:
            self.dropped += 1
            self.alive = False
            return False


class Broadcaster:
    """Fan ``state.publish`` events out to up to ``max_clients`` SSE streams."""

    def __init__(self, state: Any, max_clients: int = MAX_CLIENTS, heartbeat_s: float = HEARTBEAT_S,
                 queue_size: int = QUEUE_SIZE, clock: Callable[[], float] = time.monotonic,
                 poll_s: float = 1.0) -> None:
        self.state = state
        self.max_clients = int(max_clients)
        self.heartbeat_s = float(heartbeat_s)
        self.queue_size = int(queue_size)
        self.clock = clock
        #: Longest a stream blocks on its queue before re-checking stop/heartbeat.
        self.poll_s = float(poll_s)
        self._lock = threading.Lock()
        self._clients: List[Client] = []
        self._closed = False
        self._unsubscribe: Optional[Callable[[], None]] = None
        if hasattr(state, "subscribe"):
            self._unsubscribe = state.subscribe(self.on_publish)

    # ----------------------------------------------------------- registry
    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def _sync_count(self) -> None:
        try:
            self.state.sse_clients = len(self._clients)
        except Exception:  # noqa: BLE001
            pass

    def add_client(self, since: Optional[float] = None) -> Optional[Client]:
        """Register a client (``None`` when full or closed); builds the ``since`` replay."""
        replay = self.replay_for(since) if since is not None else []
        with self._lock:
            if self._closed or len(self._clients) >= self.max_clients:
                return None
            c = Client(replay, self.queue_size)
            self._clients.append(c)
            self._sync_count()
            return c

    def remove_client(self, c: Client) -> None:
        with self._lock:
            c.alive = False
            try:
                self._clients.remove(c)
            except ValueError:
                return
            self._sync_count()

    def close(self) -> None:
        """Unsubscribe and wake every stream so it returns."""
        with self._lock:
            self._closed = True
            clients = list(self._clients)
        if self._unsubscribe is not None:
            try:
                self._unsubscribe()
            except Exception:  # noqa: BLE001
                pass
        for c in clients:
            c.alive = False
            try:
                c.q.put_nowait(_CLOSE)
            except queue.Full:
                pass

    # ------------------------------------------------------------ replay
    def replay_for(self, since: float) -> List[Tuple[str, Any]]:
        """Events, episodes and marks newer than ``since`` (oldest first)."""
        st = self.state
        out: List[Tuple[str, Any]] = []
        try:
            with st.lock:
                events = [e for e in st.events if (e.t1 or e.t0) > since]
                episodes = [e for e in st.episodes if (e.t1 or e.t0) > since or e.t1 is None]
                marks = [m for m in st.marks if m.t_pressed > since]
        except Exception:  # noqa: BLE001
            return out
        for e in events[-500:]:
            out.append(("event", e.to_dict()))
        for ep in episodes[-200:]:
            out.append(("episode_open" if ep.t1 is None else "episode_close", ep.to_dict(brief=True)))
        for m in marks[-200:]:
            out.append(("mark", m.to_dict()))
        return out

    # ------------------------------------------------------------ publish
    def on_publish(self, name: str, obj: Any) -> None:
        """``state.subscribe`` callback: enqueue for every client; drop overflowing ones."""
        if name not in EVENT_NAMES:
            return
        with self._lock:
            clients = list(self._clients)
        dead = [c for c in clients if not c.push(name, obj)]
        for c in dead:
            log.debug("sse client dropped: queue full")
            self.remove_client(c)

    # ------------------------------------------------------------- stream
    def stream(self, wfile: Any, client: Client, stop_event: Optional[threading.Event] = None,
               max_frames: Optional[int] = None) -> int:
        """Write frames to ``wfile`` until the client dies or stop is requested; returns frames written.

        ``max_frames`` bounds the loop for tests. The replay backlog goes
        first, then live frames; a heartbeat comment is written whenever
        ``heartbeat_s`` passed without any frame.
        """
        written = 0
        last_write = self.clock()
        sent_stopping = False
        try:
            try:
                wfile.write(b": connected\n\n")
                wfile.flush()
            except (OSError, ValueError):
                return 0
            while client.replay:
                name, obj = client.replay.pop(0)
                wfile.write(format_frame(name, obj))
                written += 1
            if written:
                wfile.flush()
                last_write = self.clock()
            while client.alive and not (stop_event is not None and stop_event.is_set()):
                if max_frames is not None and written >= max_frames:
                    break
                wait = max(0.01, self.heartbeat_s - (self.clock() - last_write))
                try:
                    name, obj = client.q.get(timeout=min(wait, self.poll_s))
                except queue.Empty:
                    if self.clock() - last_write >= self.heartbeat_s:
                        wfile.write(HEARTBEAT_FRAME)
                        wfile.flush()
                        last_write = self.clock()
                        written += 1
                    continue
                if name == "__close__":
                    break
                wfile.write(format_frame(name, obj))
                wfile.flush()
                written += 1
                last_write = self.clock()
                if name == "stopping":
                    sent_stopping = True
                    break
            if not sent_stopping and client.alive and stop_event is not None and stop_event.is_set():
                # ``State.request_stop`` sets the event *before* it publishes ``stopping``, so the loop
                # above can end with the frame still queued (or not yet published). The client must
                # hear it (SPEC §10.3: ``stopping`` closes the stream), so deliver it here.
                obj = None
                while True:
                    try:
                        name, pending = client.q.get_nowait()
                    except queue.Empty:
                        break
                    if name == "stopping":
                        obj = pending
                        break
                if obj is None:
                    obj = {"reason": getattr(self.state, "stop_reason", None) or "stop"}
                wfile.write(format_frame("stopping", obj))
                wfile.flush()
                written += 1
        except (OSError, ValueError, BrokenPipeError, ConnectionError):
            log.debug("sse client went away")
        except Exception:  # noqa: BLE001 - never let a stream kill the request thread
            log.debug("sse stream error", exc_info=True)
        finally:
            self.remove_client(client)
        return written

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"clients": len(self._clients), "max": self.max_clients,
                    "dropped": sum(c.dropped for c in self._clients)}


__all__ = ["Broadcaster", "Client", "format_frame", "EVENT_NAMES", "MAX_CLIENTS", "HEARTBEAT_S", "QUEUE_SIZE",
           "HEARTBEAT_FRAME"]
