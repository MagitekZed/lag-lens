"""Tests for laglens.server.http / laglens.server.sse against a fake AppContext.

A real State + Store live in a temp dir; the components the server talks to
(INTERFACES §10.2) are small fakes. Requests go over a loopback socket to a
real ThreadingHTTPServer bound to an ephemeral port.
"""
import http.client
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.platform import get_platform  # noqa: E402
from laglens.server import http as httpmod  # noqa: E402
from laglens.server import sse as ssemod  # noqa: E402
from laglens.server.http import serve  # noqa: E402
from laglens.server.sse import Broadcaster, format_frame  # noqa: E402
from laglens.state import F_LOST, KIND_ICMP, Episode, Event, Mark, Rollup, Sample, State, Target  # noqa: E402
from laglens.store import Store  # noqa: E402

T0 = 1_760_000_000.0
WEB_DIR = Path(__file__).resolve().parent.parent / "laglens" / "web"


class FakeUsage:
    def __init__(self, free_mb=50_000):
        self.free = int(free_mb * 1024 * 1024)
        self.total = self.free * 2
        self.used = self.free


# ---------------------------------------------------------------- fakes
class FakeMarks:
    def __init__(self, state, store):
        self.state = state
        self.store = store
        self.calls = []

    def create(self, offset_s=0.0, activity=None, note="", source="dashboard", t_pressed=None, replay=False):
        self.calls.append(dict(offset_s=offset_s, activity=activity, note=note, source=source, t_pressed=t_pressed, replay=replay))
        pressed = t_pressed if (replay and t_pressed) else self.state.now()
        m = Mark(id=self.state.next_mark_id(), t_pressed=pressed, offset_s=offset_s, t_est=pressed - offset_s,
                 activity=activity or "idle", note=note, source=source, episode="ep-000001" if self.state.episodes else None,
                 assessment="Nothing abnormal in the last 10 s on any target.")
        self.state.add_mark(m)
        return m

    def snapshot(self, mark_id):
        return {"id": mark_id, "rows": []} if mark_id == "mk-1" else None


class LoadTestBusy(Exception):
    pass


class EpisodeOpen(Exception):
    pass


class FakeLoadTest:
    def __init__(self):
        self.running = False
        self.raise_busy = False
        self.raise_episode = False

    def start(self, force=False):
        if self.raise_episode and not force:
            raise EpisodeOpen()
        if self.raise_busy:
            raise LoadTestBusy()
        self.running = True
        return {"id": "lt-1", "phases": ["idle", "down", "up", "both", "recover"], "eta_s": 95}

    def stop(self):
        self.running = False

    def status(self):
        return {"running": self.running, "phase": "down" if self.running else None, "elapsed_s": 0, "live": None, "last": None}


class FakeTracer:
    def __init__(self):
        self.busy = False

    def rediscover(self):
        return not self.busy

    def current(self):
        return {"v4": [{"ttl": 1, "ip": "10.0.0.1", "role": "gateway"}], "v6": [], "roles": {}, "discovered_at": T0,
                "changes": 0, "history": [], "method": "native"}


class FakeDocsis:
    def __init__(self):
        self.ok = True

    def refresh(self):
        return self.ok

    def recent(self, n=20):
        return {"status": "ok", "polls": [{"t": T0, "ok": True}][:n], "log": []}


class FakeIgd:
    def status(self):
        return {"status": "ok", "trusted": True, "uptime_s": 100, "ext_ip": "73.1.2.3", "mappings": []}


class FakeNotify:
    def __init__(self, ok=True):
        self.ok = ok

    def test(self):
        return (True, "sent") if self.ok else (False, "ntfy 404")


class FakeXbox:
    def __init__(self):
        self.ip = None

    def set_ip(self, ip):
        self.ip = ip


class FakeReport:
    def __init__(self, store):
        self.store = store
        self.builds = 0

    def build(self, final=False):
        self.builds += 1
        return self.store.write_atomic("report.html", "<html>report %d</html>" % self.builds)


class FakeCtx:
    """Just enough of laglens.app.AppContext for the server."""

    def __init__(self, tmp, cfg=None, components=None):
        self.cfg = {"port": 0, "bind": "127.0.0.1", "activities": ["idle", "bf6", "other"], "disk": {}}
        self.cfg.update(cfg or {})
        self.args = Namespace()
        self.sessions_root = Path(tmp) / "sessions"
        self.root = Path(tmp)
        self.store = Store(self.sessions_root / "20261011-190000", self.cfg, disk_usage=lambda p: FakeUsage())
        self.state = State(T0, self.store.id, self.cfg)
        self.store.state = self.state
        self.store.ensure_token()
        self.platform = get_platform("generic", runner=lambda a, t: (1, "", ""), reader=lambda p: None,
                                     exists=lambda p: False, env={}, which=lambda n: None)
        self.port = 0
        self.components = dict(components or {})
        self.started_at = time.time()
        self.route = {}
        self.urls = []
        self.log = None

    @property
    def token(self):
        return self.store.token

    def component(self, name):
        return self.components.get(name)

    def wants(self, name):
        return True


def add_target(state, key, tid=-1, **kw):
    d = dict(id=tid, key=key, role="anycast", addr="1.1.1.1", family=4, kind="icmp", label=key)
    d.update(kw)
    return state.add_target(Target(**d))


# ------------------------------------------------------------ base class
class ServerBase(unittest.TestCase):
    components = None  # overridden per test when needed

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-server-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ctx = FakeCtx(self.tmp)
        self.state = self.ctx.state
        self.store = self.ctx.store
        self.addCleanup(self.store.stop)
        add_target(self.state, "gw4", role="gateway", addr="10.0.0.1")
        add_target(self.state, "inet4_cf")
        self.comps = {
            "marks": FakeMarks(self.state, self.store),
            "loadtest": FakeLoadTest(),
            "tracer": FakeTracer(),
            "docsis": FakeDocsis(),
            "igd": FakeIgd(),
            "notify": FakeNotify(),
            "xbox": FakeXbox(),
            "report": FakeReport(self.store),
        }
        self.ctx.components = dict(self.comps)
        self.http = serve(self.ctx, heartbeat_s=0.3)
        self.addCleanup(self.http.stop, 2.0)
        self.port = self.http.port

    # helpers
    def conn(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(c.close)
        return c

    def get(self, path, headers=None):
        c = self.conn()
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        return r, body

    def post(self, path, obj=None, token=True, headers=None):
        c = self.conn()
        h = {"Content-Type": "application/json"}
        if token:
            h["X-LagLens-Token"] = self.ctx.token
        h.update(headers or {})
        c.request("POST", path, body=json.dumps(obj or {}), headers=h)
        r = c.getresponse()
        body = r.read()
        return r, body

    def jget(self, path, status=200, headers=None):
        r, body = self.get(path, headers)
        self.assertEqual(r.status, status, body[:300])
        self.assertTrue(r.getheader("Content-Type").startswith("application/json"), r.getheader("Content-Type"))
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        return json.loads(body.decode("utf-8"))

    def jpost(self, path, obj=None, status=200, token=True, headers=None):
        r, body = self.post(path, obj, token=token, headers=headers)
        self.assertEqual(r.status, status, body[:300])
        return json.loads(body.decode("utf-8"))


# ---------------------------------------------------------------- tests
class PagesAndStaticTests(ServerBase):
    def test_pages_carry_token_meta(self):
        for path in ("/", "/phone", "/sessions", "/setup", "/?phone=1"):
            r, body = self.get(path)
            self.assertEqual(r.status, 200, path)
            self.assertTrue(r.getheader("Content-Type").startswith("text/html"))
            text = body.decode("utf-8")
            self.assertIn('<meta name="laglens-token" content="%s">' % self.ctx.token, text, path)
            self.assertNotIn("{{TOKEN}}", text)
            self.assertNotIn("{{VERSION}}", text)
            self.assertNotIn("{{ACTIVITIES}}", text)
            self.assertIn('<meta name="laglens-activities" content="idle,bf6,other">', text, path)

    def test_pages_are_phone_friendly_and_reference_only_local_static(self):
        import re

        for path in ("/", "/phone", "/sessions", "/setup"):
            text = self.get(path)[1].decode("utf-8")
            self.assertIn('name="viewport"', text, path)
            for src in re.findall(r'(?:src|href)="([^"]+)"', text):
                self.assertFalse(src.startswith(("http:", "https:", "//")), (path, src))

    def test_phone_query_serves_phone_page(self):
        _, a = self.get("/?phone=1")
        _, b = self.get("/phone")
        self.assertEqual(a, b)

    def test_static_files_and_cache_header(self):
        for name in ("app.js", "phone.js", "common.js", "qr.js", "style.css", "uplot.js", "uplot.css"):
            r, body = self.get("/static/%s?v=1.0.0" % name)
            self.assertEqual(r.status, 200, name)
            self.assertEqual(r.getheader("Cache-Control"), "max-age=3600")
            self.assertTrue(len(body) > 100, name)
        r, _ = self.get("/static/uplot.js")
        self.assertIn("javascript", r.getheader("Content-Type"))
        r, _ = self.get("/static/style.css")
        self.assertIn("text/css", r.getheader("Content-Type"))

    def test_unknown_static_and_traversal_404(self):
        self.jget("/static/nope.js", 404)
        r, _ = self.get("/static/../store.py")
        self.assertIn(r.status, (400, 404))
        r, _ = self.get("/sessions/../../token/report.html")
        self.assertIn(r.status, (400, 404))

    def test_404_and_405_are_json(self):
        body = self.jget("/nope", 404)
        self.assertEqual(body["code"], "not_found")
        r, body = self.post("/api/state")
        self.assertEqual(r.status, 405)
        self.assertEqual(json.loads(body)["code"], "method")

    def test_favicon(self):
        r, body = self.get("/favicon.ico")
        self.assertEqual(r.status, 200)
        self.assertIn(b"<svg", body)

    def test_head_request(self):
        c = self.conn()
        c.request("HEAD", "/api/state")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 200)


class ReportAndExportTests(ServerBase):
    def test_report_is_built_when_stale_and_served(self):
        r, body = self.get("/report.html")
        self.assertEqual(r.status, 200)
        self.assertEqual(body, b"<html>report 1</html>")
        r, body = self.get("/report.html")  # fresh (< 30 s): not rebuilt
        self.assertEqual(body, b"<html>report 1</html>")
        self.assertEqual(self.comps["report"].builds, 1)

    def test_report_503_without_builder(self):
        self.ctx.components.pop("report")
        self.jget("/report.html", 503)

    def test_past_session_report(self):
        d = self.ctx.sessions_root / "20261010-080000"
        d.mkdir(parents=True)
        (d / "report.html").write_text("<html>old</html>")
        r, body = self.get("/sessions/20261010-080000/report.html")
        self.assertEqual(body, b"<html>old</html>")
        self.jget("/sessions/20261010-090000/report.html", 404)
        self.jget("/sessions/bad_id/report.html", 400)
        self.jget("/sessions/..%2F..%2Ftoken/report.html", 400)

    def test_export_zip_uses_report_export(self):
        import types

        calls = []
        mod = types.ModuleType("laglens.report.export")

        def build_zip(session_dir, pack="full", raw=True, cfg=None, ctx=None):
            calls.append((Path(session_dir).name, pack, raw))
            # the live context is handed over for the running session only
            self.assertIs(ctx, self.ctx if Path(session_dir).name == "20261011-190000" else None)
            return b"PK\x03\x04fake"

        mod.build_zip = build_zip
        saved = {k: sys.modules.get(k) for k in ("laglens.report", "laglens.report.export")}
        pkg = types.ModuleType("laglens.report")
        pkg.__path__ = []
        sys.modules["laglens.report"] = pkg
        sys.modules["laglens.report.export"] = mod
        try:
            r, body = self.get("/export.zip?pack=comcast&raw=0")
            self.assertEqual(r.status, 200)
            self.assertEqual(body, b"PK\x03\x04fake")
            self.assertEqual(r.getheader("Content-Type"), "application/zip")
            self.assertIn('attachment; filename="laglens-20261011-190000-comcast.zip"', r.getheader("Content-Disposition"))
            self.assertEqual(calls[-1], ("20261011-190000", "comcast", False))
            d = self.ctx.sessions_root / "20261010-080000"
            d.mkdir(parents=True)
            r, body = self.get("/sessions/20261010-080000/export.zip")
            self.assertEqual(r.status, 200)
            self.assertEqual(calls[-1], ("20261010-080000", "full", True))
            self.jget("/export.zip?pack=weird", 400)
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def test_export_503_without_module(self):
        saved = sys.modules.get("laglens.report.export")
        sys.modules["laglens.report.export"] = None  # import -> ImportError
        try:
            self.jget("/export.zip", 503)
        finally:
            if saved is None:
                sys.modules.pop("laglens.report.export", None)
            else:
                sys.modules["laglens.report.export"] = saved


class StateSeriesSamplesTests(ServerBase):
    def test_state_snapshot_shape(self):
        body = self.jget("/api/state")
        for key in ("version", "session", "state", "pill", "headline", "health", "host", "targets", "xbox", "collectors",
                    "path", "activity", "episodes_open", "episodes_recent", "marks_recent", "verdict", "loadtest",
                    "doctor", "disk", "update", "token_required", "sse_clients", "now"):
            self.assertIn(key, body, key)
        self.assertEqual(body["session"]["id"], "20261011-190000")
        self.assertEqual(len(body["targets"]), 2)
        self.assertIn("http", body["collectors"])
        self.assertEqual(body["collectors"]["http"]["status"], "ok")
        self.assertEqual(self.state.port, self.port)
        self.assertEqual(self.ctx.port, self.port)

    def test_series_shape_and_400(self):
        now = self.state.now()
        self.state.add_rollup(1, Rollup(t=int(now) - 2, id=0, n=4, lost=0, late=0, err=0, min=1, p50=1.0, p95=1.5, max=2, jit=0.1, stall=0))
        body = self.jget("/api/series?from=%s&to=%s&res=1" % (now - 10, now))
        for key in ("res", "from", "to", "t", "targets", "iface", "wan", "wifi", "docsis", "ntp", "segments", "slots_lost",
                    "xbox_state", "stall"):
            self.assertIn(key, body, key)
        self.assertEqual(body["res"], 1)
        self.assertIn("0", body["targets"])
        self.assertIn(1.0, body["targets"]["0"]["p50"])
        err = self.jget("/api/series?from=%s&to=%s&res=1" % (now - 8000, now), 400)
        self.assertEqual(err["code"], "bad_request")
        self.jget("/api/series?from=x", 400)
        self.jget("/api/series?res=3", 400)

    def test_series_default_resolution(self):
        now = self.state.now()
        self.assertEqual(self.jget("/api/series?from=%s&to=%s" % (now - 60, now))["res"], 1)
        self.assertEqual(self.jget("/api/series?from=%s&to=%s" % (now - 8000, now))["res"], 5)

    def test_samples_ring_plus_file_and_limits(self):
        now = self.state.now()
        base = int(now * 1000) - 5000
        for i in range(8):
            s = Sample(ts_ms=base + i * 250, target_id=0, kind=KIND_ICMP, flags=F_LOST if i == 3 else 0, seq=i,
                       value=-1 if i == 3 else 1000 + i)
            self.state.add_sample(s)
            self.store.append_sample(s)
        self.store.start()
        self.store.flush()
        body = self.jget("/api/samples?from=%s&to=%s" % (now - 10, now))
        self.assertEqual(body["columns"], ["ts_ms", "id", "kind", "flags", "value_us"])
        self.assertEqual(body["count"], 8)
        self.assertFalse(body["truncated"])
        self.assertEqual(body["rows"][3], [base + 750, 0, 0, F_LOST, -1])
        # targets / kinds filters
        self.assertEqual(self.jget("/api/samples?from=%s&to=%s&targets=1" % (now - 10, now))["count"], 0)
        self.assertEqual(self.jget("/api/samples?from=%s&to=%s&kinds=7" % (now - 10, now))["count"], 0)
        # a window older than the ring's safe span reads the file; rows present in both are not duplicated
        old = int(now * 1000) - 950_000
        for i in range(6):
            s = Sample(ts_ms=old + i * 250, target_id=1, kind=KIND_ICMP, flags=0, seq=100 + i, value=2000 + i)
            self.store.append_sample(s)
            if i < 3:
                self.state.add_sample(s)  # the ring also holds the first three (same key -> deduped)
        self.store.flush()
        body = self.jget("/api/samples?from=%s&to=%s" % (now - 1000, now - 500))
        self.assertEqual(body["count"], 6)
        self.assertEqual([r[0] for r in body["rows"]], [old + i * 250 for i in range(6)])
        # limits
        err = self.jget("/api/samples?from=%s&to=%s" % (now - 601, now), 400)
        self.assertEqual(err["code"], "range")
        self.jget("/api/samples?from=%s&to=%s" % (now, now - 1), 400)

    def test_samples_truncation_flag(self):
        saved = httpmod.MAX_SAMPLE_ROWS
        httpmod.MAX_SAMPLE_ROWS = 5
        try:
            now = self.state.now()
            base = int(now * 1000) - 5000
            for i in range(8):
                self.state.add_sample(Sample(ts_ms=base + i * 250, target_id=0, kind=KIND_ICMP, flags=0, seq=i, value=1000))
            body = self.jget("/api/samples?from=%s&to=%s" % (now - 10, now))
            self.assertTrue(body["truncated"])
            self.assertEqual(body["count"], 5)
        finally:
            httpmod.MAX_SAMPLE_ROWS = saved

    def test_events_and_episodes(self):
        now = self.state.now()
        self.state.add_event(Event(id="ev-000001", t0=now - 100, t1=now - 98, type="loss_burst", target=1, severity=2))
        self.state.add_event(Event(id="ev-000002", t0=now - 5, t1=None, type="latency_spike", target=1, severity=2))
        ep = Episode(id="ep-000001", t0=now - 100, t1=now - 90, dur_s=10, targets=[1], events=["ev-000001"], cls="docsis_access",
                     sweep={"dst": "1.1.1.1"}, docsis={"pre_uncorr": {}})
        self.state.add_episode(ep)
        self.state.add_episode(Episode(id="ep-000002", t0=now - 3, targets=[1], cls="unknown"))
        self.assertEqual(len(self.jget("/api/events")["events"]), 2)
        self.assertEqual(len(self.jget("/api/events?since=%s" % (now - 10))["events"]), 1)
        self.assertEqual(len(self.jget("/api/events?limit=1")["events"]), 1)
        eps = self.jget("/api/episodes")["episodes"]
        self.assertEqual(len(eps), 2)
        self.assertNotIn("sweep", eps[0])
        self.assertEqual(eps[0]["class"], "docsis_access")
        self.assertEqual(len(self.jget("/api/episodes?class=unknown")["episodes"]), 1)
        full = self.jget("/api/episodes/ep-000001")
        self.assertEqual(full["sweep"], {"dst": "1.1.1.1"})
        self.jget("/api/episodes/ep-000099", 404)

    def test_stats_verdict_version_path_igd_docsis(self):
        body = self.jget("/api/stats?window=5m")
        self.assertIn("targets", body)
        self.assertIn("0", body["targets"])
        self.assertIn("health", body)
        self.assertIn("matrix", body)
        self.jget("/api/stats?window=2d", 400)
        self.assertIn("confidence", self.jget("/api/verdict"))
        v = self.jget("/api/version")
        self.assertEqual(v["version"], self.state.version)
        self.assertEqual(v["update_cmd"], "bash start.sh --update")
        self.assertIn("latest", v)
        self.assertEqual(self.jget("/api/path")["v4"][0]["ip"], "10.0.0.1")
        self.assertEqual(self.jget("/api/igd")["trusted"], True)
        self.assertEqual(self.jget("/api/docsis?last=5")["status"], "ok")
        self.assertIn("checks", self.jget("/api/doctor"))
        lt = self.jget("/api/loadtest")
        self.assertFalse(lt["running"])

    def test_comcast_text_prefers_verdict_module(self):
        # engine.verdict.comcast_text is importable in the tree: the endpoint returns its text
        self.state.verdict["comcast"] = "Dear Comcast"
        r, body = self.get("/api/comcast.txt")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/plain"))
        text = body.decode()
        self.assertIn("Comcast", text)
        self.assertIn(self.store.id, text)
        self.assertNotEqual(text, "Dear Comcast")

    def test_comcast_text_falls_back_to_verdict(self):
        # without the verdict module the endpoint serves state.verdict["comcast"]
        self.state.verdict["comcast"] = "Dear Comcast"
        saved = sys.modules.get("laglens.engine.verdict")
        sys.modules["laglens.engine.verdict"] = None  # import -> ImportError
        try:
            r, body = self.get("/api/comcast.txt")
        finally:
            if saved is None:
                sys.modules.pop("laglens.engine.verdict", None)
            else:
                sys.modules["laglens.engine.verdict"] = saved
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/plain"))
        self.assertEqual(body.decode(), "Dear Comcast")

    def test_path_without_tracer_uses_state(self):
        self.ctx.components.pop("tracer")
        self.state.path = {"v4": [], "v6": [], "discovered_at": None, "changes": 0}
        body = self.jget("/api/path")
        self.assertEqual(body["history"], [])

    def test_xbox_get(self):
        self.assertIn("state", self.jget("/api/xbox"))


class AuthTests(ServerBase):
    def test_post_without_token_403(self):
        body = self.jpost("/api/activity", {"activity": "bf6"}, status=403, token=False)
        self.assertEqual(body["code"], "forbidden")
        self.jpost("/api/activity", {"activity": "bf6"}, status=403, token=False, headers={"X-LagLens-Token": "nope"})
        self.jpost("/api/stop", status=403, token=False)
        self.assertFalse(self.state.stop_event.is_set())

    def test_get_mark_requires_token(self):
        self.jget("/mark?src=shortcut", 403)
        body = self.jget("/mark?src=shortcut&token=%s&offset_s=30&activity=bf6" % self.ctx.token)
        self.assertEqual(body["id"], "mk-1")
        self.assertEqual(self.comps["marks"].calls[-1]["source"], "shortcut")
        self.assertEqual(self.comps["marks"].calls[-1]["offset_s"], 30.0)
        self.assertEqual(self.comps["marks"].calls[-1]["activity"], "bf6")

    def test_token_query_accepted_for_post(self):
        self.jpost("/api/activity?token=%s" % self.ctx.token, {"activity": "bf6"}, token=False)
        self.assertEqual(self.state.activity["current"], "bf6")

    def test_non_private_source_rejected(self):
        saved = httpmod.is_private
        httpmod.is_private = lambda ip: False
        try:
            body = self.jpost("/api/activity", {"activity": "bf6"}, status=403)
            self.assertIn("local network", body["error"])
        finally:
            httpmod.is_private = saved

    def test_client_ip_helpers(self):
        self.assertEqual(httpmod.client_ip(("::ffff:10.0.0.5", 1234)), "10.0.0.5")
        self.assertEqual(httpmod.client_ip(("fe80::1%en0", 1)), "fe80::1")
        self.assertTrue(httpmod.source_is_private(("10.0.0.7", 1)))
        self.assertTrue(httpmod.source_is_private(("100.64.3.4", 1)))
        self.assertTrue(httpmod.source_is_private(("::ffff:192.168.1.2", 1)))
        self.assertFalse(httpmod.source_is_private(("8.8.8.8", 1)))
        self.assertFalse(httpmod.source_is_private(("::ffff:8.8.8.8", 1)))


class MutatingEndpointTests(ServerBase):
    def test_mark_post_shape(self):
        body = self.jpost("/api/mark", {"offset_s": 30, "activity": "bf6", "note": "teleport", "source": "phone"})
        for key in ("id", "t_est", "assessment", "episode", "episode_class", "snapshot_at"):
            self.assertIn(key, body, key)
        self.assertEqual(body["id"], "mk-1")
        self.assertIsNone(body["episode"])
        call = self.comps["marks"].calls[-1]
        self.assertEqual(call["note"], "teleport")
        self.assertIsNone(call["t_pressed"])
        self.assertFalse(call["replay"])

    def test_mark_replay_passes_t_pressed(self):
        self.jpost("/api/mark", {"offset_s": 0, "t_pressed": T0 + 5, "replay": True})
        call = self.comps["marks"].calls[-1]
        self.assertTrue(call["replay"])
        self.assertEqual(call["t_pressed"], T0 + 5)
        self.jpost("/api/mark", {"offset_s": 0, "t_pressed": T0 + 5})  # not a replay: server clock
        self.assertIsNone(self.comps["marks"].calls[-1]["t_pressed"])

    def test_mark_links_episode_class(self):
        now = self.state.now()
        self.state.add_episode(Episode(id="ep-000001", t0=now - 3, targets=[1], cls="docsis_access"))
        body = self.jpost("/api/mark", {})
        self.assertEqual(body["episode"], "ep-000001")
        self.assertEqual(body["episode_class"], "docsis_access")

    def test_mark_text_plain(self):
        r, body = self.get("/mark?src=shortcut&token=%s" % self.ctx.token, headers={"Accept": "text/plain"})
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/plain"))
        text = body.decode()
        self.assertIn("Saved mk-1", text)
        self.assertIn("Nothing abnormal", text)

    def test_mark_fallback_without_service(self):
        self.ctx.components.pop("marks")
        sys.modules["laglens.engine.marks"] = None  # make the lazy import fail
        try:
            body = self.jpost("/api/mark", {"offset_s": 10, "note": "x"})
            self.assertEqual(body["id"], "mk-1")
            self.assertIn("not available", body["assessment"])
            self.assertEqual(len(self.state.marks), 1)
            self.assertEqual(self.jget("/api/marks")["marks"][0]["offset_s"], 10.0)
        finally:
            sys.modules.pop("laglens.engine.marks", None)

    def test_marks_list_and_snapshot(self):
        self.jpost("/api/mark", {})
        self.assertEqual(len(self.jget("/api/marks")["marks"]), 1)
        self.assertEqual(self.jget("/api/marks/mk-1/snapshot")["id"], "mk-1")
        self.jget("/api/marks/mk-2/snapshot", 404)
        self.jget("/api/marks/evil/snapshot", 400)

    def test_activity_sets_state_and_tags_file(self):
        body = self.jpost("/api/activity", {"activity": "bf6", "label": "port 2"})
        self.assertTrue(body["ok"])
        self.assertIn("since", body)
        self.assertEqual(self.state.activity["current"], "bf6")
        self.store.start()
        self.store.flush()
        rows = self.store.read_json("tags")
        self.assertEqual(rows[-1]["activity"], "bf6")
        self.assertEqual(rows[-1]["label"], "port 2")
        self.jpost("/api/activity", {"activity": "Not A Slug!"}, status=400)
        self.jpost("/api/activity", {}, status=400)

    def test_loadtest_start_stop_and_409s(self):
        body = self.jpost("/api/loadtest/start", {})
        self.assertTrue(body["ok"])
        self.assertEqual(body["id"], "lt-1")
        self.assertEqual(body["phases"][0], "idle")
        self.assertTrue(self.jget("/api/loadtest")["running"])
        self.jpost("/api/loadtest/stop")
        self.assertFalse(self.comps["loadtest"].running)
        self.comps["loadtest"].raise_episode = True
        self.assertEqual(self.jpost("/api/loadtest/start", {}, status=409)["code"], "episode_open")
        self.jpost("/api/loadtest/start", {"force": True})
        self.comps["loadtest"].raise_busy = True
        self.assertEqual(self.jpost("/api/loadtest/start", {"force": True}, status=409)["code"], "busy")

    def test_path_rediscover_202_when_running(self):
        self.assertTrue(self.jpost("/api/path/rediscover")["ok"])
        self.comps["tracer"].busy = True
        body = self.jpost("/api/path/rediscover", status=202)
        self.assertTrue(body["running"])

    def test_docsis_refresh(self):
        self.jpost("/api/docsis/refresh")
        self.comps["docsis"].ok = False
        self.assertEqual(self.jpost("/api/docsis/refresh", status=409)["code"], "disabled")

    def test_label_and_session_summary(self):
        self.jpost("/api/session/label", {"label": "xbox on port 2"})
        self.assertEqual(self.state.label, "xbox on port 2")
        self.store.write_json_atomic("session.json", {"id": self.store.id, "label": "xbox on port 2"})
        self.assertEqual(self.jget("/api/sessions/%s/summary" % self.store.id)["label"], "xbox on port 2")
        self.jget("/api/sessions/20200101-000000/summary", 404)

    def test_notify_test(self):
        self.assertTrue(self.jpost("/api/notify/test")["ok"])
        self.comps["notify"].ok = False
        self.assertEqual(self.jpost("/api/notify/test", status=502)["code"], "notify_failed")

    def test_doctor_run_without_module_503(self):
        sys.modules["laglens.doctor"] = None
        try:
            self.assertEqual(self.jpost("/api/doctor/run", status=503)["code"], "unavailable")
        finally:
            sys.modules.pop("laglens.doctor", None)

    def test_sessions_without_module_503(self):
        sys.modules["laglens.report.sessions"] = None
        try:
            self.assertEqual(self.jget("/api/sessions", 503)["error"], "sessions not available")
        finally:
            sys.modules.pop("laglens.report.sessions", None)

    def test_xbox_set_ip(self):
        body = self.jpost("/api/xbox", {"ip": "10.0.0.23"})
        self.assertEqual(self.comps["xbox"].ip, "10.0.0.23")
        self.assertFalse(body["saved"])  # this FakeCtx has no config file to persist into
        self.jpost("/api/xbox", {"ip": "not-an-ip"}, status=400)
        self.comps["xbox"].set_ip = lambda ip: False  # the collector may reject an address
        self.assertEqual(self.jpost("/api/xbox", {"ip": "10.0.0.24"}, status=400)["code"], "bad_request")

    def test_xbox_set_ip_persists_into_config_json(self):
        cfg_file = self.tmp / "config.json"
        cfg_file.write_text(json.dumps({"port": 8787, "targets": {"xbox_ip": None, "v4": ["1.1.1.1"]}}))
        self.ctx.config_file = cfg_file
        body = self.jpost("/api/xbox", {"ip": "10.0.0.23"})
        self.assertTrue(body["saved"])
        data = json.loads(cfg_file.read_text())
        self.assertEqual(data["targets"]["xbox_ip"], "10.0.0.23")
        self.assertEqual(data["targets"]["v4"], ["1.1.1.1"])
        self.assertEqual(data["port"], 8787)
        # a rejected address is never written
        self.comps["xbox"].set_ip = lambda ip: False
        self.jpost("/api/xbox", {"ip": "10.0.0.24"}, status=400)
        self.assertEqual(json.loads(cfg_file.read_text())["targets"]["xbox_ip"], "10.0.0.23")

    def test_plex_settings_keep_the_token_write_only(self):
        cfg_file = self.tmp / "config.json"
        cfg_file.write_text(json.dumps({"port": 8787}))
        self.ctx.config_file = cfg_file
        tok = "fake-plex-token-123"  # made up
        self.assertEqual(self.jget("/api/plex")["enabled"], False)  # Plex mode off: a status, not an error
        body = self.jpost("/api/plex", {"enabled": False, "server": "192.168.0.125", "players": "192.168.0.20=HTPC 192.168.0.30",
                                        "token": tok})
        self.assertTrue(body["saved"] and body["token_set"])
        self.assertNotIn(tok, json.dumps(body))
        data = json.loads(cfg_file.read_text())
        self.assertEqual(data["plex"], {"enabled": False, "server": "192.168.0.125", "players": ["192.168.0.20=HTPC", "192.168.0.30"],
                                        "token": tok})
        self.assertNotIn(tok, json.dumps(self.jget("/api/plex")))
        self.assertNotIn(tok, json.dumps(self.jget("/api/state")))
        self.jpost("/api/plex", {"server": "192.168.0.126"})  # no token in the body: the saved one stays
        self.assertEqual(json.loads(cfg_file.read_text())["plex"]["token"], tok)
        self.jpost("/api/plex", {"server": "not an ip"}, status=400)
        self.jpost("/api/plex", {"players": "192.168.0.20 nonsense"}, status=400)
        self.jpost("/api/plex", {"token": "has spaces in it"}, status=400)
        self.post("/api/plex", {"token": "x" * 30}, token=False)  # without the session token: refused
        self.assertEqual(json.loads(cfg_file.read_text())["plex"]["token"], tok)
        self.assertFalse(self.jpost("/api/plex", {"clear_token": True})["token_set"])
        self.assertIsNone(json.loads(cfg_file.read_text())["plex"]["token"])

    def test_version_carries_the_update_check_result(self):
        self.state.update = {"available": True, "latest": "9.9.9", "url": "u", "sha256": None, "checked_at": 1.0, "error": None}
        body = self.jget("/api/version")
        self.assertEqual((body["latest"], body["available"]), ("9.9.9", True))
        self.assertEqual(body["update"]["url"], "u")
        self.assertIn("update_cmd", body)

    def test_encoded_path_segments_are_decoded_once(self):
        now = self.state.now()
        self.state.add_episode(Episode(id="ep-000001", t0=now - 3, targets=[1], cls="unknown"))
        self.assertEqual(self.jget("/api/episodes/ep%2D000001")["id"], "ep-000001")
        self.jget("/api/marks/mk%2F1/snapshot", 400)

    def test_stop_requests_shutdown(self):
        seen = []
        self.state.subscribe(lambda n, o: seen.append(n))
        body = self.jpost("/api/stop")
        self.assertEqual(body, {"ok": True, "report": "/report.html"})
        self.assertTrue(self.state.stop_event.is_set())
        self.assertEqual(self.state.stop_reason, "api")
        self.assertIn("stopping", seen)

    def test_bad_json_body_400(self):
        c = self.conn()
        c.request("POST", "/api/activity", body="{not json", headers={"X-LagLens-Token": self.ctx.token, "Content-Type": "application/json"})
        r = c.getresponse()
        self.assertEqual(r.status, 400)
        self.assertEqual(json.loads(r.read())["code"], "bad_json")

    def test_handler_exception_is_500_json_and_server_survives(self):
        self.comps["igd"].status = lambda: 1 / 0
        body = self.jget("/api/igd", 500)
        self.assertEqual(body["code"], "internal")
        self.assertIn("state", self.jget("/api/state"))


class MissingComponentTests(ServerBase):
    def test_503_for_every_component_endpoint(self):
        self.ctx.components = {}
        sys.modules["laglens.loadtest"] = None
        sys.modules["laglens.engine.marks"] = None
        try:
            cases = [
                ("POST", "/api/loadtest/start", "loadtest"),
                ("POST", "/api/loadtest/stop", "loadtest"),
                ("POST", "/api/path/rediscover", "tracer"),
                ("POST", "/api/docsis/refresh", "docsis"),
                ("GET", "/api/docsis", "docsis"),
                ("GET", "/api/igd", "igd"),
                ("POST", "/api/notify/test", "notify"),
                ("POST", "/api/xbox", "xbox"),
            ]
            for method, path, name in cases:
                if method == "POST":
                    body = self.jpost(path, {"ip": "10.0.0.1"}, status=503)
                else:
                    body = self.jget(path, 503)
                self.assertEqual(body["code"], "unavailable", path)
                self.assertTrue(body["error"].startswith("%s not available" % name), (path, body))
        finally:
            sys.modules.pop("laglens.loadtest", None)
            sys.modules.pop("laglens.engine.marks", None)

    def test_docsis_503_carries_collector_reason(self):
        self.ctx.components = {}
        self.state.set_collector("docsis", "disabled", reason="docsis.password not set")
        body = self.jget("/api/docsis", 503)
        self.assertIn("docsis.password not set", body["error"])


class SseTests(ServerBase):
    def open_sse(self, path="/events"):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(s.close)
        s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n" % path).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        return s, head.decode("latin-1"), rest

    def read_until(self, s, needle, buf=b"", timeout=5.0):
        deadline = time.time() + timeout
        while needle not in buf and time.time() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def test_framing_heartbeat_and_replay(self):
        now = self.state.now()
        self.state.add_event(Event(id="ev-000001", t0=now - 50, t1=now - 48, type="loss_burst", target=1, severity=2))
        s, head, rest = self.open_sse("/events?since=%s" % (now - 100))
        self.assertIn("200", head.split("\r\n")[0])
        self.assertIn("text/event-stream", head)
        buf = self.read_until(s, b"event: event\n", rest)
        self.assertIn(b"event: event\ndata: {", buf)
        self.assertIn(b'"id":"ev-000001"', buf)
        # live publish
        self.state.publish("tick", {"t": now, "state": "OK"})
        buf = self.read_until(s, b"event: tick\n", buf)
        self.assertIn(b'event: tick\ndata: {"t":', buf)
        self.assertTrue(buf.endswith(b"\n\n") or b"\n\n" in buf)
        # unknown names are not forwarded; marks are
        self.state.publish("target", {"id": 1})
        self.state.add_mark(Mark(id="mk-9", t_pressed=now, offset_s=0, t_est=now))
        buf = self.read_until(s, b"event: mark\n", buf)
        self.assertNotIn(b"event: target", buf)
        self.assertIn(b"event: mark\n", buf)
        # heartbeat (heartbeat_s is 0.3 in this fixture)
        buf = self.read_until(s, b": hb\n\n", buf, timeout=3.0)
        self.assertIn(b": hb\n\n", buf)
        self.assertEqual(self.state.sse_clients, 1)

    def test_ninth_client_gets_503_and_disconnect_frees_slot(self):
        socks = []
        for _ in range(8):
            s, head, _ = self.open_sse()
            self.assertIn("200", head.split("\r\n")[0])
            socks.append(s)
        deadline = time.time() + 3
        while self.state.sse_clients < 8 and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.state.sse_clients, 8)
        s9, head, rest = self.open_sse()
        self.assertIn("503", head.split("\r\n")[0])
        body = self.read_until(s9, b"}", rest)
        self.assertIn(b'"code":"busy"', body)
        socks[0].close()
        self.state.publish("tick", {"t": 1})  # the write to the closed socket drops that client
        deadline = time.time() + 3
        while self.state.sse_clients > 7 and time.time() < deadline:
            self.state.publish("tick", {"t": 2})
            time.sleep(0.05)
        self.assertEqual(self.state.sse_clients, 7)

    def test_stopping_ends_stream(self):
        s, head, rest = self.open_sse()
        self.state.request_stop("api")
        buf = self.read_until(s, b"event: stopping\n", rest)
        self.assertIn(b"event: stopping\n", buf)
        s.settimeout(3)
        tail = self.read_until(s, b"\x00", b"", timeout=3.0)  # connection closes after 'stopping'
        self.assertNotIn(b"\x00", tail)
        deadline = time.time() + 3
        while self.state.sse_clients and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.state.sse_clients, 0)


class BroadcasterUnitTests(unittest.TestCase):
    def test_format_frame_escapes_newlines(self):
        frame = format_frame("event", {"note": "a\nb"})
        self.assertEqual(frame, b'event: event\ndata: {"note":"a\\nb"}\n\n')

    def test_queue_overflow_drops_client(self):
        st = State(T0, "s")
        b = Broadcaster(st, max_clients=2, heartbeat_s=15, queue_size=3)
        c = b.add_client()
        for i in range(4):
            st.publish("tick", {"i": i})
        self.assertFalse(c.alive)
        self.assertEqual(b.client_count, 0)
        self.assertEqual(st.sse_clients, 0)

    def test_max_clients(self):
        st = State(T0, "s")
        b = Broadcaster(st, max_clients=2)
        self.assertIsNotNone(b.add_client())
        self.assertIsNotNone(b.add_client())
        self.assertIsNone(b.add_client())
        self.assertEqual(st.sse_clients, 2)

    def test_stream_writes_heartbeat_with_fake_clock(self):
        st = State(T0, "s")
        clock = {"t": 0.0}

        def fake_clock():
            clock["t"] += 10.0  # every look at the clock "takes" 10 s
            return clock["t"]

        b = Broadcaster(st, heartbeat_s=15.0, clock=fake_clock, poll_s=0.01)
        c = b.add_client()
        out = io.BytesIO()

        class W:
            def write(self, data):
                out.write(data)

            def flush(self):
                pass

        n = b.stream(W(), c, max_frames=2)
        self.assertEqual(n, 2)
        self.assertEqual(out.getvalue().count(b": hb\n\n"), 2)
        self.assertEqual(b.client_count, 0)

    def test_stream_stops_on_write_error(self):
        st = State(T0, "s")
        b = Broadcaster(st)
        c = b.add_client()

        class W:
            def write(self, data):
                raise BrokenPipeError()

            def flush(self):
                pass

        self.assertEqual(b.stream(W(), c), 0)
        self.assertEqual(st.sse_clients, 0)

    def test_close_unsubscribes(self):
        st = State(T0, "s")
        b = Broadcaster(st)
        c = b.add_client()
        b.close()
        st.publish("tick", {})
        self.assertIsNone(b.add_client())
        self.assertFalse(c.alive)


class PortTests(unittest.TestCase):
    def test_port_auto_increments_when_busy(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-port-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        busy = blocker.getsockname()[1]
        ctx = FakeCtx(tmp, cfg={"port": busy})
        self.addCleanup(ctx.store.stop)
        ctx.port = busy
        srv = serve(ctx)
        self.addCleanup(srv.stop, 2.0)
        self.assertNotEqual(srv.port, busy)
        self.assertTrue(busy < srv.port <= busy + 10, srv.port)
        self.assertEqual(ctx.state.port, srv.port)
        self.assertEqual(ctx.port, srv.port)
        self.assertEqual(ctx.state.collector("http")["status"], "ok")

    def test_no_free_port_is_visible(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-port-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        ctx = FakeCtx(tmp, cfg={"port": 1})
        self.addCleanup(ctx.store.stop)
        ctx.port = 1
        saved = httpmod.bind_server

        def failing(bind, port, tries=11):
            raise OSError("no free port in 1..11 (test)")

        httpmod.bind_server = failing
        try:
            with self.assertRaises(OSError):
                serve(ctx)
        finally:
            httpmod.bind_server = saved
        self.assertEqual(ctx.state.collector("http")["status"], "disabled")
        self.assertIn("no free port", ctx.state.collector("http")["reason"])

    def test_port_zero_means_any_free_port(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-port-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        ctx = FakeCtx(tmp, cfg={"port": 0})
        self.addCleanup(ctx.store.stop)
        ctx.port = 0
        srv = serve(ctx)
        self.addCleanup(srv.stop, 2.0)
        self.assertGreater(srv.port, 1024)
        self.assertNotEqual(srv.port, 8787)
        self.assertEqual(ctx.state.port, srv.port)
        # ctx.port None and cfg.port missing -> the documented default range starts at 8787
        ctx2 = FakeCtx(tmp, cfg={})
        self.addCleanup(ctx2.store.stop)
        ctx2.port = None
        del ctx2.cfg["port"]
        srv2 = serve(ctx2)
        self.addCleanup(srv2.stop, 2.0)
        self.assertTrue(8787 <= srv2.port <= 8797, srv2.port)

    def test_stop_is_idempotent_and_quick(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-port-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        ctx = FakeCtx(tmp)
        self.addCleanup(ctx.store.stop)
        srv = serve(ctx)
        t = time.time()
        srv.stop(2.0)
        srv.stop(2.0)
        self.assertLess(time.time() - t, 4.0)
        with self.assertRaises((ConnectionRefusedError, OSError)):
            socket.create_connection(("127.0.0.1", srv.port), timeout=1).close()


if __name__ == "__main__":
    unittest.main()
