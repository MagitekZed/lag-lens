"""Plex mode: the Plex Media Server and its players on the home network (``--plex`` / ``plex.enabled``).

Lag Lens normally looks outward (gateway → Comcast → internet). A Plex stream between two devices at
home never passes this computer, so this collector watches both ends instead and asks the server what
it is doing:

* **Server:** found by GDM (the LAN broadcast Plex apps use, UDP 32414) unless ``plex.server`` names it.
  A TCP target ``plex_srv`` (port 32400, 2 Hz) watches it; Windows' firewall drops pings by default, so
  the server is never probed with ICMP. ``/identity`` (no token) says whether it answers at all.
* **Players:** ``plex.players`` plus the address of every player in a session, when it answers a ping
  (``plex_player_N`` ICMP targets at the probe rate). A player that stops answering for a minute while
  it is not playing is taken as asleep (target disabled) and comes back when it answers again.
* **Server status** (needs ``plex.token``, the X-Plex-Token, kept in ``config.json`` only and sent as a
  header, never in a URL or a log line): ``/status/sessions`` (Direct Play / Direct Stream / Transcode,
  transcoder speed and throttling, bitrate, player state, local or remote), ``/statistics/resources``
  (host and server CPU) and ``/activities`` (background tasks such as scans and thumbnail generation).

Notes raised (``state.raise_note``): ``plex_buffering`` (a player went into buffering),
``plex_transcode_slow`` (the transcoder fell under real time without being throttled),
``plex_cpu_high``, ``plex_activity`` (a background task started), ``plex_remote`` (a session left the
LAN or was relayed), ``plex_offline`` / ``plex_online``. ``GET /api/plex`` is :meth:`PlexCollector.status`.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Tuple

from laglens.state import Target

log = logging.getLogger("laglens.plex")

GDM_PORT = 32414
GDM_ADDRS = ("255.255.255.255", "239.0.0.250")
GDM_QUERY = b"M-SEARCH * HTTP/1.1\r\n\r\n"
DEFAULT_PORT = 32400
HTTP_TIMEOUT_S = 4.0
DISCOVER_RETRY_S = 60.0
OFFLINE_AFTER_S = 30.0
SERVER_RATE_HZ = 2.0
MAX_PLAYERS = 4
PLAYER_ASLEEP_S = 60.0
PLAYER_RECHECK_S = 60.0
SLOW_SPEED = 1.0
SLOW_POLLS = 2
CPU_HIGH_PCT = 90.0
CPU_OK_PCT = 80.0
CPU_POLLS = 2
STORE_IDLE_S = 60.0
CLIENT_ID = "laglens"
TOKEN_REJECTED = "Plex rejected the token (check plex.token on the Setup page)"
NO_TOKEN = "no Plex token: server status (transcoding, CPU, buffering) is off; probes still run"


class PlexError(Exception):
    """An HTTP or parse failure talking to the server; ``code`` is the HTTP status when there is one."""

    def __init__(self, msg: str, code: Optional[int] = None) -> None:
        super().__init__(msg)
        self.code = code


# ---------------------------------------------------------------------------
# Parsing (pure)
# ---------------------------------------------------------------------------
def parse_gdm_reply(data: bytes) -> Dict[str, str]:
    """``{"Name": ..., "Port": ..., "Version": ..., "Content-Type": ...}`` of a GDM answer."""
    out: Dict[str, str] = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def gdm_discover(timeout: float = 2.0, sock_factory: Optional[Callable[[], Any]] = None) -> List[Dict[str, Any]]:
    """Plex Media Servers on the LAN: ``[{"ip", "port", "name", "version"}]`` (servers only, first answer wins)."""
    sock = sock_factory() if sock_factory else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found: Dict[str, Dict[str, Any]] = {}
    try:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        sock.settimeout(0.3)
        for addr in GDM_ADDRS:
            try:
                sock.sendto(GDM_QUERY, (addr, GDM_PORT))
            except OSError as exc:
                log.debug("plex: GDM send to %s failed: %s", addr, exc)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            info = parse_gdm_reply(data)
            if "media-server" not in info.get("Content-Type", "plex/media-server"):
                continue
            ip = peer[0]
            if ip not in found:
                try:
                    port = int(info.get("Port") or DEFAULT_PORT)
                except ValueError:
                    port = DEFAULT_PORT
                found[ip] = {"ip": ip, "port": port, "name": info.get("Name") or ip, "version": info.get("Version")}
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return list(found.values())


def _xml(text: str) -> ET.Element:
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise PlexError("unreadable reply from the server: %s" % exc)


def _num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def decision_of(video: Dict[str, Any]) -> str:
    """``direct play`` (no transcoder), ``direct stream`` (video copied, container/audio converted) or ``transcode``."""
    tc = video.get("transcode")
    if not tc:
        return "direct play"
    if tc.get("video_decision") == "transcode":
        return "transcode"
    return "direct stream"


def parse_sessions(text: str) -> List[Dict[str, Any]]:
    """Video sessions of ``/status/sessions``: title, player, state, decision, transcoder, bitrate, location."""
    root = _xml(text)
    out: List[Dict[str, Any]] = []
    for v in root:
        if v.tag != "Video":
            continue
        title = v.get("title") or "?"
        if v.get("grandparentTitle"):
            title = "%s — %s" % (v.get("grandparentTitle"), title)
        media = v.find("Media")
        player = v.find("Player")
        sess = v.find("Session")
        tc = v.find("TranscodeSession")
        item: Dict[str, Any] = {
            "key": v.get("sessionKey") or (sess.get("id") if sess is not None else None) or title,
            "title": title,
            "type": v.get("type"),
            "state": (player.get("state") if player is not None else None) or "unknown",
            "player": (player.get("title") or player.get("product")) if player is not None else None,
            "product": player.get("product") if player is not None else None,
            "platform": player.get("platform") if player is not None else None,
            "address": player.get("address") if player is not None else None,
            "local": (player.get("local") == "1") if player is not None and player.get("local") is not None else None,
            "relayed": (player.get("relayed") == "1") if player is not None and player.get("relayed") is not None else None,
            "location": sess.get("location") if sess is not None else None,
            "bandwidth_kbps": _num(sess.get("bandwidth")) if sess is not None else None,
            "bitrate_kbps": _num(media.get("bitrate")) if media is not None else None,
            "resolution": media.get("videoResolution") if media is not None else None,
            "video_codec": media.get("videoCodec") if media is not None else None,
            "transcode": None,
        }
        if tc is not None:
            item["transcode"] = {
                "video_decision": tc.get("videoDecision"),
                "audio_decision": tc.get("audioDecision"),
                "subtitle_decision": tc.get("subtitleDecision"),
                "speed": _num(tc.get("speed")),
                "throttled": tc.get("throttled") == "1",
                "complete": tc.get("complete") == "1",
                "hw": (tc.get("transcodeHwRequested") == "1") or bool(tc.get("transcodeHwDecoding") or tc.get("transcodeHwEncoding")),
                "source_codec": tc.get("sourceVideoCodec"),
                "target_codec": tc.get("videoCodec"),
            }
        item["decision"] = decision_of(item)
        out.append(item)
    return out


def parse_resources(text: str) -> Optional[Dict[str, Any]]:
    """The newest ``/statistics/resources`` sample: ``{"host_cpu", "plex_cpu", "host_mem", "at"}`` (percent)."""
    root = _xml(text)
    best = None
    for r in root.iter("StatisticsResources"):
        at = _num(r.get("at")) or 0.0
        if best is None or at >= best[0]:
            best = (at, r)
    if best is None:
        return None
    r = best[1]
    return {"at": best[0], "host_cpu": _num(r.get("hostCpuUtilization")), "plex_cpu": _num(r.get("processCpuUtilization")),
            "host_mem": _num(r.get("hostMemoryUtilization"))}


def parse_activities(text: str) -> List[Dict[str, Any]]:
    """Running background tasks of ``/activities``: ``[{"id", "type", "title", "subtitle", "progress"}]``."""
    root = _xml(text)
    out = []
    for a in root.iter("Activity"):
        out.append({"id": a.get("uuid") or a.get("title"), "type": a.get("type"), "title": a.get("title") or a.get("type") or "task",
                    "subtitle": a.get("subtitle"), "progress": _num(a.get("progress"))})
    return out


def _private_v4(ip: Optional[str]) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return a.version == 4 and a.is_private and not a.is_loopback


def default_pinger(platform: Any) -> Callable[[str], bool]:
    """``pinger(ip) -> answered`` through the platform's ping binary (two tries)."""
    def ping(ip: str) -> bool:
        if platform is None:
            return False
        argv = ["ping", "-n", "-c", "1", "-t", "1", ip] if platform.name == "darwin" else ["ping", "-n", "-c", "1", "-W", "1", ip]
        for _ in range(2):
            try:
                out = platform.run(argv, timeout=3.0)
            except Exception:  # noqa: BLE001
                out = None
            if out and "time=" in out:
                return True
        return False
    return ping


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
class PlexCollector:
    """``PlexCollector(ctx)``; ``.status()`` is the ``GET /api/plex`` body."""

    name = "plex"

    def __init__(self, ctx: Any, urlopen: Optional[Callable[..., Any]] = None,
                 discover: Optional[Callable[[], List[Dict[str, Any]]]] = None,
                 pinger: Optional[Callable[[str], bool]] = None,
                 clock: Callable[[], float] = time.time, mono: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = getattr(ctx, "store", None)
        self.cfg = ctx.cfg if getattr(ctx, "cfg", None) is not None else {}
        self._urlopen = urlopen or urllib.request.urlopen
        self._discover = discover or (lambda: gdm_discover())
        self._ping = pinger or default_pinger(getattr(ctx, "platform", None))
        self._clock = clock
        self._mono = mono
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.server: Optional[Dict[str, Any]] = None  # {"ip", "port", "name", "version", "source"}
        self.reachable: Optional[bool] = None
        self.reason: Optional[str] = None
        self.last_error: Optional[str] = None
        self.sessions: List[Dict[str, Any]] = []
        self.resources: Optional[Dict[str, Any]] = None
        self.activities: List[Dict[str, Any]] = []
        self.players: Dict[str, Dict[str, Any]] = {}  # ip -> {"ip", "name", "key", "pingable", "asleep", "checked"}
        self.counts = {"buffering": 0, "transcode_slow": 0, "cpu_high": 0, "activity": 0, "remote": 0, "offline": 0}
        self._last_ok: Optional[float] = None
        self._offline_noted = False
        self._next_discover: Optional[float] = None
        self._next_poll: Optional[float] = None
        self._token_rejected: Optional[str] = None  # the token Plex refused (retried only once it changes)
        self._prev_states: Dict[str, str] = {}
        self._slow_polls: Dict[str, int] = {}
        self._slow_noted: Dict[str, bool] = {}
        self._remote_noted: Dict[str, bool] = {}
        self._cpu_polls = 0
        self._cpu_noted = False
        self._seen_activities: Dict[str, bool] = {}
        self._last_store: Optional[float] = None

    # --------------------------------------------------------------- config
    def _pcfg(self) -> Dict[str, Any]:
        p = self.cfg.get("plex")
        return p if isinstance(p, dict) else {}

    def _token(self) -> Optional[str]:
        tok = self._pcfg().get("token")
        tok = str(tok).strip() if tok else ""
        return tok or None

    def _interval(self) -> float:
        try:
            return max(2.0, float(self._pcfg().get("interval_s", 5) or 5))
        except (TypeError, ValueError):
            return 5.0

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.state.set_collector(self.name, "ok", reason="looking for the Plex server")
        th = threading.Thread(target=self._loop, name=self.name, daemon=True)
        self.thread = th
        th.start()

    def stop(self, timeout: float = 2.0) -> None:
        t = self.thread
        if t is not None:
            t.join(timeout)

    def _loop(self) -> None:
        st = self.state
        while not st.stop_event.is_set():
            try:
                self.step()
            except Exception:  # noqa: BLE001 - one bad poll must not end the collector
                log.exception("plex: step failed")
            st.stop_event.wait(1.0)

    # ----------------------------------------------------------------- HTTP
    def _get(self, path: str, token: Optional[str]) -> str:
        srv = self.server or {}
        url = "http://%s:%d%s" % (srv.get("ip"), int(srv.get("port") or DEFAULT_PORT), path)
        headers = {"Accept": "application/xml", "X-Plex-Client-Identifier": CLIENT_ID, "X-Plex-Product": "Lag Lens"}
        if token:
            headers["X-Plex-Token"] = token
        req = urllib.request.Request(url, headers=headers)
        try:
            resp = self._urlopen(req, timeout=HTTP_TIMEOUT_S)
            try:
                body = resp.read(2 * 1024 * 1024)
            finally:
                try:
                    resp.close()
                except Exception:  # noqa: BLE001
                    pass
        except urllib.error.HTTPError as exc:
            try:
                exc.close()
            except Exception:  # noqa: BLE001
                pass
            raise PlexError("%s answered HTTP %d" % (path, exc.code), exc.code)
        except (OSError, ValueError) as exc:
            raise PlexError("%s: %s" % (path, type(exc).__name__ if not str(exc) else exc))
        return body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)

    # ------------------------------------------------------------- discover
    def _configured_server(self) -> Optional[Dict[str, Any]]:
        raw = str(self._pcfg().get("server") or "").strip()
        if not raw:
            return None
        host, _, port = raw.rpartition(":") if raw.count(":") == 1 else (raw, "", "")
        try:
            p = int(port) if port else DEFAULT_PORT
        except ValueError:
            p = DEFAULT_PORT
        return {"ip": host or raw, "port": p, "name": host or raw, "version": None, "source": "config"}

    def discover(self) -> bool:
        srv = self._configured_server()
        if srv is None:
            try:
                found = self._discover()
            except Exception as exc:  # noqa: BLE001
                found = []
                self.last_error = "GDM discovery failed: %s" % exc
            if not found:
                self.reason = "no Plex server answered on the LAN (set plex.server on the Setup page)"
                self.state.set_collector(self.name, "degraded", reason=self.reason)
                return False
            srv = dict(found[0], source="discovery")
        with self.lock:
            self.server = srv
            self.reason = None
        self._ensure_server_target()
        log.info("plex: server %s at %s:%s (%s)", srv.get("name"), srv.get("ip"), srv.get("port"), srv.get("source"))
        return True

    def _rate(self) -> float:
        try:
            return float(self.cfg.get("rate_hz", 4) or 4)
        except (TypeError, ValueError):
            return 4.0

    def _ensure_server_target(self) -> None:
        srv = self.server or {}
        label = "Plex server %s :%d" % (srv.get("name") or srv.get("ip"), int(srv.get("port") or DEFAULT_PORT))
        t = self.state.target("plex_srv")
        if t is None:
            self.state.add_target(Target(id=-1, key="plex_srv", role="plex_server", addr=srv.get("ip"), family=4, kind="tcp",
                                         label=label, rate_hz=SERVER_RATE_HZ, port=int(srv.get("port") or DEFAULT_PORT)))
            self._save_targets()
        elif t.addr != srv.get("ip") or not t.enabled:
            self.state.set_target_state("plex_srv", addr=srv.get("ip"), enabled=True, reason=None, label=label,
                                        port=int(srv.get("port") or DEFAULT_PORT))
            self._save_targets()

    def _save_targets(self) -> None:
        if self.store is None:
            return
        try:
            from laglens.targets import save_targets

            save_targets(self.state, self.store)
        except Exception:  # noqa: BLE001
            log.debug("plex: cannot save targets", exc_info=True)

    # ------------------------------------------------------------------ step
    def step(self, now: Optional[float] = None) -> None:
        now = self._clock() if now is None else now
        mono = self._mono()
        if self.server is None:
            if self._next_discover is not None and mono < self._next_discover:
                return
            self._next_discover = mono + DISCOVER_RETRY_S
            if not self.discover():
                return
        if self._next_poll is not None and mono < self._next_poll:
            return
        self._next_poll = mono + self._interval()
        self.poll(now)

    def poll(self, now: Optional[float] = None) -> None:
        now = self._clock() if now is None else now
        try:
            self._get("/identity", None)
            ok = True
        except PlexError as exc:
            ok = False
            self.last_error = str(exc)
        self._reachability(ok, now)
        token = self._token()
        if ok and token and token != self._token_rejected:
            self._poll_status(token, now)
        elif ok and token and token == self._token_rejected:
            self.state.set_collector(self.name, "degraded", reason=TOKEN_REJECTED)
        elif ok:
            self.sessions, self.resources, self.activities = [], None, []
            self.state.set_collector(self.name, "ok", reason=NO_TOKEN)
        self._configured_players(now)
        self._check_players(now)
        self._publish(now)

    def _reachability(self, ok: bool, now: float) -> None:
        if ok:
            if self._offline_noted:
                self.state.raise_note("plex_online", t=now, severity=1, note="Plex server answers again")
                self._offline_noted = False
                if self.state.target("plex_srv") is not None:
                    self.state.set_target_state("plex_srv", enabled=True, reason=None)
            self._last_ok = now
            self.reachable = True
            return
        since = self._last_ok if self._last_ok is not None else now
        if self._last_ok is None and self.reachable is None:
            self._last_ok = now  # never reached yet: give it the same grace period
            since = now
        if now - since >= OFFLINE_AFTER_S and not self._offline_noted:
            self._offline_noted = True
            self.counts["offline"] += 1
            self.reachable = False
            self.state.raise_note("plex_offline", t=now, severity=2, note="Plex server stopped answering for %d s" % int(now - since))
            if self.state.target("plex_srv") is not None:
                # one episode for the drop-out; then the probe pauses until the server is back
                self.state.set_target_state("plex_srv", enabled=False, reason="Plex server not answering")
            self.state.set_collector(self.name, "degraded", reason="Plex server not answering")

    def _poll_status(self, token: str, now: float) -> None:
        try:
            sessions = parse_sessions(self._get("/status/sessions", token))
        except PlexError as exc:
            if exc.code == 401:
                self._token_rejected = token
                self.state.set_collector(self.name, "degraded", reason=TOKEN_REJECTED)
                log.warning("plex: %s", TOKEN_REJECTED)
            else:
                self.last_error = str(exc)
                self.state.set_collector(self.name, "degraded", reason="Plex status failed: %s" % exc)
            return
        self._token_rejected = None
        try:
            resources = parse_resources(self._get("/statistics/resources?timespan=6", token))
        except PlexError as exc:
            resources = None
            log.debug("plex: resources: %s", exc)
        try:
            activities = parse_activities(self._get("/activities", token))
        except PlexError as exc:
            activities = []
            log.debug("plex: activities: %s", exc)
        with self.lock:
            self.sessions, self.resources, self.activities = sessions, resources, activities
        self.state.set_collector(self.name, "ok", reason=None)
        self._derive(now)

    # -------------------------------------------------------------- derive
    def _derive(self, now: float) -> None:
        st = self.state
        live_keys = set()
        for s in self.sessions:
            k = str(s.get("key"))
            live_keys.add(k)
            state = str(s.get("state") or "")
            prev = self._prev_states.get(k)
            if state == "buffering" and prev != "buffering":
                self.counts["buffering"] += 1
                st.raise_note("plex_buffering", t=now, severity=2, note="%s is buffering %s" % (s.get("player") or "a player", s.get("title")),
                              player=s.get("player"), address=s.get("address"), decision=s.get("decision"),
                              speed=(s.get("transcode") or {}).get("speed"))
            self._prev_states[k] = state
            tc = s.get("transcode") or {}
            speed = tc.get("speed")
            slow = (state in ("playing", "buffering") and isinstance(speed, float) and speed < SLOW_SPEED
                    and not tc.get("throttled") and not tc.get("complete"))
            self._slow_polls[k] = self._slow_polls.get(k, 0) + 1 if slow else 0
            if self._slow_polls[k] >= SLOW_POLLS and not self._slow_noted.get(k):
                self._slow_noted[k] = True
                self.counts["transcode_slow"] += 1
                st.raise_note("plex_transcode_slow", t=now, severity=2,
                              note="the server transcodes %s at %.1f× real time (needs 1.0×)" % (s.get("title"), speed),
                              speed=speed, decision=s.get("decision"), hw=tc.get("hw"))
            elif not slow and self._slow_polls[k] == 0:
                self._slow_noted[k] = False
            remote = s.get("location") == "wan" or bool(s.get("relayed")) or s.get("local") is False
            if remote and not self._remote_noted.get(k):
                self._remote_noted[k] = True
                self.counts["remote"] += 1
                st.raise_note("plex_remote", t=now, severity=1,
                              note="%s streams %s (not over the home network directly)" % (
                                  s.get("player") or "a player", "through Plex Relay" if s.get("relayed") else "as a remote client"),
                              location=s.get("location"), relayed=s.get("relayed"))
            if _private_v4(s.get("address")):
                self._add_player(str(s.get("address")), s.get("player") or s.get("product"), now, in_session=True)
        for k in list(self._prev_states):
            if k not in live_keys:
                for d in (self._prev_states, self._slow_polls, self._slow_noted, self._remote_noted):
                    d.pop(k, None)
        cpu = (self.resources or {}).get("host_cpu")
        if isinstance(cpu, float):
            if cpu >= CPU_HIGH_PCT:
                self._cpu_polls += 1
                if self._cpu_polls >= CPU_POLLS and not self._cpu_noted:
                    self._cpu_noted = True
                    self.counts["cpu_high"] += 1
                    st.raise_note("plex_cpu_high", t=now, severity=2, note="Plex server CPU at %d%%" % int(round(cpu)), cpu=cpu)
            elif cpu < CPU_OK_PCT:
                self._cpu_polls = 0
                self._cpu_noted = False
        live_acts = set()
        for a in self.activities:
            aid = str(a.get("id"))
            live_acts.add(aid)
            if aid not in self._seen_activities:
                self._seen_activities[aid] = True
                self.counts["activity"] += 1
                st.raise_note("plex_activity", t=now, severity=1, note="Plex background task: %s" % a.get("title"),
                              task=a.get("title"), task_type=a.get("type"))
        for aid in list(self._seen_activities):
            if aid not in live_acts:
                self._seen_activities.pop(aid, None)

    # -------------------------------------------------------------- players
    def _configured_players(self, now: float) -> None:
        for p in self._pcfg().get("players") or []:
            ip, _, name = str(p).partition("=")
            ip = ip.strip()
            if _private_v4(ip):
                self._add_player(ip, name.strip() or None, now, in_session=False)

    def _add_player(self, ip: str, name: Optional[str], now: float, in_session: bool) -> None:
        with self.lock:
            known = self.players.get(ip)
            if known is not None:
                if name and not known.get("name"):
                    known["name"] = name
                known["in_session"] = in_session or known.get("in_session", False)
                return
            if len(self.players) >= MAX_PLAYERS or (self.server and ip == self.server.get("ip")):
                return
            idx = len(self.players)
            self.players[ip] = {"ip": ip, "name": name, "key": "plex_player_%d" % idx, "pingable": None, "asleep": False,
                                "checked": None, "in_session": in_session}
        self._probe_player(ip, now)

    def _probe_player(self, ip: str, now: float) -> None:
        p = self.players[ip]
        answered = bool(self._ping(ip))
        p["checked"] = now
        p["pingable"] = answered
        label = "Plex player %s" % ("%s (%s)" % (p["name"], ip) if p.get("name") else ip)
        t = self.state.target(p["key"])
        if not answered:
            if t is not None and t.enabled:
                self.state.set_target_state(p["key"], enabled=False, reason="does not answer ping")
            return
        p["asleep"] = False
        if t is None:
            self.state.add_target(Target(id=-1, key=p["key"], role="plex_player", addr=ip, family=4, kind="icmp", label=label,
                                         rate_hz=self._rate()))
            self._save_targets()
            log.info("plex: watching player %s", label)
        elif not t.enabled or t.addr != ip:
            self.state.set_target_state(p["key"], addr=ip, enabled=True, reason=None, label=label)

    def _check_players(self, now: float) -> None:
        """A player silent for a minute and not playing is asleep (target off); re-checked every minute."""
        playing = {str(s.get("address")) for s in self.sessions if s.get("state") in ("playing", "buffering")}
        for ip, p in list(self.players.items()):
            t = self.state.target(p["key"])
            if t is not None and t.enabled:
                window = self.state.raw_window(t.id, now - PLAYER_ASLEEP_S, now)
                if len(window) >= 20 and not any(s.received for s in window) and ip not in playing:
                    p["asleep"] = True
                    self.state.set_target_state(p["key"], enabled=False, reason="not answering (asleep or off)")
                    log.info("plex: player %s asleep", ip)
            elif p.get("checked") is None or now - p["checked"] >= PLAYER_RECHECK_S:
                self._probe_player(ip, now)

    # -------------------------------------------------------------- publish
    def _row(self, now: float) -> Dict[str, Any]:
        srv = dict(self.server) if self.server else None
        return {
            "t": round(now, 3),
            "server": srv,
            "reachable": self.reachable,
            "token_set": bool(self._token()),  # never the token itself
            "sessions": [dict(s) for s in self.sessions],
            "resources": dict(self.resources) if self.resources else None,
            "activities": [dict(a) for a in self.activities],
            "players": [{k: v for k, v in p.items()} for p in self.players.values()],
            "counts": dict(self.counts),
        }

    def _publish(self, now: float) -> None:
        row = self._row(now)
        self.state.set_latest("plex", row)
        busy = bool(self.sessions or self.activities)
        if self.store is not None and (busy or self._last_store is None or now - self._last_store >= STORE_IDLE_S):
            self._last_store = now
            try:
                self.store.append_json("plex", {"t": row["t"], "reachable": row["reachable"], "sessions": [
                    {k: s.get(k) for k in ("title", "player", "address", "state", "decision", "bitrate_kbps", "location")}
                    | {"speed": (s.get("transcode") or {}).get("speed"), "throttled": (s.get("transcode") or {}).get("throttled")}
                    for s in self.sessions], "cpu": (row["resources"] or {}).get("host_cpu"),
                    "activities": [a.get("title") for a in self.activities]})
            except Exception:  # noqa: BLE001
                log.debug("plex: append_json failed", exc_info=True)

    def status(self) -> Dict[str, Any]:
        row = self._row(self._clock())
        row.update({"enabled": True, "reason": self.reason, "last_error": self.last_error,
                    "token_rejected": self._token_rejected is not None and self._token_rejected == self._token()})
        return row


__all__ = ["PlexCollector", "PlexError", "gdm_discover", "parse_gdm_reply", "parse_sessions", "parse_resources",
           "parse_activities", "decision_of"]
