"""Plex mode: GDM discovery, server status parsing, the collector's notes/targets/token handling, the
classification of LAN episodes, lag-press context and the verdict sentence. No network: every HTTP call
goes to a fake server and every ping to a fake pinger."""
import io
import logging
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import helpers_detection as hd  # noqa: E402
from helpers_detection import T0, Session, make_cfg, run_episode  # noqa: E402
from laglens.collectors import plex as px  # noqa: E402
from laglens.engine import marks as mk  # noqa: E402
from laglens.engine import verdict as vm  # noqa: E402
from laglens.engine.detector import Detector  # noqa: E402
from laglens.state import State, Target  # noqa: E402

TOKEN = "fake-plex-token-xyz"  # made up; the real one lives only in config.json

SESSIONS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<MediaContainer size="2">
  <Video sessionKey="7" type="episode" title="Pilot" grandparentTitle="Some Show">
    <Media bitrate="8500" videoResolution="1080" videoCodec="hevc"/>
    <Player address="192.168.0.20" title="HTPC" product="Plex HTPC" platform="Linux" state="{state}" local="1" relayed="0"/>
    <Session id="abc" bandwidth="9000" location="lan"/>
    <TranscodeSession key="t1" throttled="{throttled}" complete="0" speed="{speed}" videoDecision="transcode"
        audioDecision="copy" transcodeHwRequested="0" sourceVideoCodec="hevc" videoCodec="h264"/>
  </Video>
  <Video sessionKey="9" type="movie" title="A Movie">
    <Media bitrate="20000" videoResolution="4k" videoCodec="hevc"/>
    <Player address="192.168.0.30" title="PS5" product="Plex for PlayStation" state="playing" local="1"/>
    <Session id="def" bandwidth="21000" location="lan"/>
  </Video>
</MediaContainer>"""
RESOURCES_XML = """<MediaContainer>
  <StatisticsResources timespan="6" at="100" hostCpuUtilization="20.0" processCpuUtilization="5.0" hostMemoryUtilization="40"/>
  <StatisticsResources timespan="6" at="200" hostCpuUtilization="{cpu}" processCpuUtilization="80.5" hostMemoryUtilization="41"/>
</MediaContainer>"""
ACTIVITIES_XML = """<MediaContainer>{acts}</MediaContainer>"""
ACT = '<Activity uuid="{uuid}" type="media.generate.bif" title="Generating video preview thumbnails" progress="12"/>'


class FakeResp(io.BytesIO):
    def close(self):
        pass


class FakePlex:
    """A Plex server: answers by path; records headers; ``fail`` makes everything time out."""

    def __init__(self):
        self.state, self.throttled, self.speed, self.cpu, self.acts = "playing", "0", "1.5", "30", ""
        self.fail = False
        self.reject = False
        self.calls = []

    def __call__(self, req, timeout=None):
        url = req.full_url
        headers = {k.lower(): v for k, v in req.header_items()}
        self.calls.append((url, headers))
        if self.fail:
            raise urllib.error.URLError("timed out")
        path = url.split(":32400", 1)[1]
        if path.startswith("/identity"):
            return FakeResp(b'<MediaContainer machineIdentifier="x" version="1.43"/>')
        if self.reject:
            raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)
        if path.startswith("/status/sessions"):
            return FakeResp(SESSIONS_XML.format(state=self.state, throttled=self.throttled, speed=self.speed).encode())
        if path.startswith("/statistics/resources"):
            return FakeResp(RESOURCES_XML.format(cpu=self.cpu).encode())
        if path.startswith("/activities"):
            return FakeResp(ACTIVITIES_XML.format(acts=self.acts).encode())
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


class Store:
    def __init__(self):
        self.rows = []

    def append_json(self, name, obj):
        self.rows.append((name, obj))


class Ctx:
    def __init__(self, token=TOKEN, players=None):
        self.cfg = {"rate_hz": 4, "plex": {"enabled": True, "server": "192.168.0.125", "token": token,
                                           "players": players or [], "interval_s": 5}}
        self.state = State(cfg=self.cfg)
        self.store = Store()
        self.platform = None


class Clock:
    def __init__(self):
        self.t = T0
        self.m = 1000.0

    def tick(self, s):
        self.t += s
        self.m += s


def make(token=TOKEN, pingable=("192.168.0.20",), players=None):
    ctx, clk, srv = Ctx(token, players), Clock(), FakePlex()
    col = px.PlexCollector(ctx, urlopen=srv, discover=lambda: [], pinger=lambda ip: ip in pingable,
                           clock=lambda: clk.t, mono=lambda: clk.m)
    return ctx, clk, srv, col


def notes(ctx, kind):
    return [n for n in ctx.state.drain_notes() if n["type"] == kind] if kind else ctx.state.drain_notes()


class ParseTests(unittest.TestCase):
    def test_gdm_reply_and_discovery(self):
        reply = b"HTTP/1.0 200 OK\r\nContent-Type: plex/media-server\r\nName: Den PC\r\nPort: 32400\r\nVersion: 1.43.4\r\n"
        self.assertEqual(px.parse_gdm_reply(reply)["Name"], "Den PC")

        class Sock:
            def __init__(self):
                self.sent, self.replies = [], [(reply, ("192.168.0.125", 32414)), (reply, ("192.168.0.125", 32414))]

            def setsockopt(self, *a):
                pass

            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                self.sent.append(addr)

            def recvfrom(self, n):
                if self.replies:
                    return self.replies.pop(0)
                raise OSError("done")

            def close(self):
                pass

        sock = Sock()
        found = px.gdm_discover(timeout=0.5, sock_factory=lambda: sock)
        self.assertEqual(found, [{"ip": "192.168.0.125", "port": 32400, "name": "Den PC", "version": "1.43.4"}])
        self.assertIn(("255.255.255.255", 32414), sock.sent)

    def test_sessions_resources_activities(self):
        ss = px.parse_sessions(SESSIONS_XML.format(state="buffering", throttled="0", speed="0.7"))
        self.assertEqual([s["decision"] for s in ss], ["transcode", "direct play"])
        a = ss[0]
        self.assertEqual((a["title"], a["player"], a["address"], a["state"], a["location"]),
                         ("Some Show — Pilot", "HTPC", "192.168.0.20", "buffering", "lan"))
        self.assertEqual((a["transcode"]["speed"], a["transcode"]["throttled"], a["bitrate_kbps"]), (0.7, False, 8500.0))
        self.assertIsNone(ss[1]["transcode"])
        res = px.parse_resources(RESOURCES_XML.format(cpu="95.5"))
        self.assertEqual((res["host_cpu"], res["plex_cpu"], res["at"]), (95.5, 80.5, 200.0))  # the newest sample
        acts = px.parse_activities(ACTIVITIES_XML.format(acts=ACT.format(uuid="u1")))
        self.assertEqual(acts[0]["title"], "Generating video preview thumbnails")
        self.assertEqual(px.decision_of({"transcode": {"video_decision": "copy"}}), "direct stream")
        with self.assertRaises(px.PlexError):
            px.parse_sessions("<not xml")


class CollectorTests(unittest.TestCase):
    def test_targets_token_header_and_no_token_leak(self):
        ctx, clk, srv, col = make()
        handler_records = []

        class H(logging.Handler):
            def emit(self, record):
                handler_records.append(self.format(record))

        h = H(level=logging.DEBUG)
        logging.getLogger("laglens").addHandler(h)
        self.addCleanup(logging.getLogger("laglens").removeHandler, h)
        col.step()
        t = ctx.state.target("plex_srv")
        self.assertEqual((t.kind, t.role, t.addr, t.port, t.rate_hz), ("tcp", "plex_server", "192.168.0.125", 32400, 2.0))
        ident = [hdrs for url, hdrs in srv.calls if url.endswith("/identity")]
        status = [(url, hdrs) for url, hdrs in srv.calls if "/status/sessions" in url]
        self.assertNotIn("x-plex-token", ident[0])  # /identity needs none
        self.assertEqual(status[0][1]["x-plex-token"], TOKEN)
        self.assertTrue(all(TOKEN not in url for url, _ in srv.calls))  # never in a URL
        self.assertNotIn(TOKEN, repr(col.status()))
        self.assertNotIn(TOKEN, repr(ctx.state.latest("plex")))
        self.assertTrue(col.status()["token_set"])
        self.assertTrue(all(TOKEN not in r for r in handler_records))
        # the session's player answered a ping, so it is watched; the PS5 did not, so it is not
        self.assertEqual(ctx.state.target("plex_player_0").addr, "192.168.0.20")
        self.assertIsNone(ctx.state.target("plex_player_1"))
        self.assertEqual({p["ip"]: p["pingable"] for p in col.status()["players"]}, {"192.168.0.20": True, "192.168.0.30": False})
        self.assertEqual(ctx.store.rows[-1][0], "plex")

    def test_notes_buffering_slow_transcode_cpu_tasks(self):
        ctx, clk, srv, col = make()
        col.step()
        notes(ctx, None)
        srv.state, srv.speed = "buffering", "0.6"
        clk.tick(5)
        col.step()
        self.assertEqual(len(notes(ctx, "plex_buffering")), 1)
        clk.tick(5)
        col.step()  # still buffering: no second note; slow for the second poll in a row: noted
        got = ctx.state.drain_notes()
        self.assertEqual([n["type"] for n in got].count("plex_buffering"), 0)
        slow = [n for n in got if n["type"] == "plex_transcode_slow"]
        self.assertEqual(len(slow), 1)
        self.assertEqual(slow[0]["peak"]["speed"], 0.6)
        # a throttled transcoder is ahead of playback: never "slow"
        ctx2, clk2, srv2, col2 = make()
        srv2.speed, srv2.throttled = "0.4", "1"
        for _ in range(3):
            col2.step()
            clk2.tick(5)
        self.assertEqual(notes(ctx2, "plex_transcode_slow"), [])
        # CPU over 90 % for two polls, and a background task, each noted once
        srv.state, srv.speed, srv.cpu, srv.acts = "playing", "1.5", "97", ACT.format(uuid="u1")
        for _ in range(3):
            clk.tick(5)
            col.step()
        got = [n["type"] for n in ctx.state.drain_notes()]
        self.assertEqual((got.count("plex_cpu_high"), got.count("plex_activity")), (1, 1))
        self.assertEqual(col.status()["counts"]["buffering"], 1)

    def test_token_rejected_is_not_retried_until_it_changes(self):
        ctx, clk, srv, col = make()
        srv.reject = True
        col.step()
        self.assertIn("rejected the token", ctx.state.collector("plex")["reason"])
        n = len([u for u, _ in srv.calls if "/status/sessions" in u])
        clk.tick(5)
        col.step()
        self.assertEqual(len([u for u, _ in srv.calls if "/status/sessions" in u]), n)
        self.assertTrue(col.status()["token_rejected"])
        ctx.cfg["plex"]["token"] = "another-fake-token"
        srv.reject = False
        clk.tick(5)
        col.step()
        self.assertEqual(len([u for u, _ in srv.calls if "/status/sessions" in u]), n + 1)
        self.assertIsNone(ctx.state.collector("plex")["reason"])

    def test_without_a_token_only_the_probes_run(self):
        ctx, clk, srv, col = make(token=None, players=["192.168.0.20=HTPC"])
        col.step()
        self.assertFalse(any("/status" in u for u, _ in srv.calls))
        self.assertIn("no Plex token", ctx.state.collector("plex")["reason"])
        self.assertIsNotNone(ctx.state.target("plex_srv"))
        self.assertEqual(ctx.state.target("plex_player_0").label, "Plex player HTPC (192.168.0.20)")

    def test_rows_reach_the_real_store_and_this_computer_is_no_player(self):
        sess = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(sess.close)
        sess.store.append_json("plex", {"t": T0, "sessions": []})  # a known file name (no ValueError)
        ctx, clk, srv, col = make(pingable=("192.168.0.20", "192.168.0.30"))
        ctx.state.host = {"lan_ip": "192.168.0.30"}  # Plex Web open on the probe host itself
        col.step()
        self.assertEqual([p["ip"] for p in col.status()["players"]], ["192.168.0.20"])

    def test_server_offline_then_back(self):
        ctx, clk, srv, col = make()
        col.step()
        notes(ctx, None)
        srv.fail = True
        for _ in range(7):
            clk.tick(5)
            col.step()
        self.assertEqual(len(notes(ctx, "plex_offline")), 1)
        self.assertFalse(ctx.state.target("plex_srv").enabled)
        self.assertFalse(col.status()["reachable"])
        srv.fail = False
        clk.tick(5)
        col.step()
        self.assertEqual(len(notes(ctx, "plex_online")), 1)
        self.assertTrue(ctx.state.target("plex_srv").enabled)


def add_lan_target(s, key, role, addr, p50=1.5):
    t = s.state.add_target(Target(id=-1, key=key, role=role, addr=addr, family=4, kind="icmp", label="%s %s" % (role, addr),
                                  rate_hz=4.0))
    s.ids[key], s.seq[key] = t.id, 0
    hd.P50[key] = p50
    return t


class ClassifyTests(unittest.TestCase):
    def session(self):
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        add_lan_target(s, "plex_srv", "plex_server", "192.168.0.125")
        add_lan_target(s, "plex_player_0", "plex_player", "192.168.0.20")
        return s

    def test_plex_server_player_and_both(self):
        cases = ((["plex_srv"], "plex_server", "only the Plex server was affected"),
                 (["plex_player_0"], "plex_player", "only the player was affected"),
                 (["plex_srv", "plex_player_0"], "home_lan", "suffered together"))
        for lost, cls, phrase in cases:
            s = self.session()
            eps = run_episode(s, Detector(s.ctx).step, baseline_s=40, lost_keys=lost, fault_s=4)
            self.assertEqual(eps[0].cls, cls, lost)
            self.assertIn(phrase, " ".join(eps[0].evidence))
            self.assertIn(cls, vm.HOME_CLASSES)

    def test_plex_rules_stay_out_without_plex_targets(self):
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        eps = run_episode(s, Detector(s.ctx).step, baseline_s=40, lost_keys=["xbox"], fault_s=4)
        self.assertEqual(eps[0].cls, "xbox_lan")
        self.assertNotIn(eps[0].alt["class"], ("plex_server", "plex_player", "home_lan"))


class PressAndVerdictTests(unittest.TestCase):
    def test_press_carries_plex_context_and_verdict_sentence(self):
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        st = s.state
        st.set_latest("plex", {"token_set": True, "sessions": [
            {"player": "HTPC", "state": "playing", "decision": "transcode", "transcode": {"speed": 0.7}}],
            "resources": {"host_cpu": 96.0}, "activities": [{"title": "Scanning Movies"}]})
        s.stream(T0, T0 + 30)
        text, _ = mk.assess_window(st, T0 + 25)
        self.assertTrue(text.startswith(mk.NULL_NETWORK), text)
        self.assertIn("Plex: HTPC transcode at 0.7x; server CPU 96%; background task: Scanning Movies.", text)
        from laglens.state import Event
        st.events.append(Event(id="ev-1", t0=T0 + 10, t1=T0 + 10, type="plex_buffering", target=None, severity=2,
                               note="HTPC is buffering Pilot"))
        st.events.append(Event(id="ev-2", t0=T0 + 12, t1=T0 + 12, type="plex_transcode_slow", target=None, severity=2,
                               note="slow", peak={"speed": 0.6}))
        sentence = vm.plex_finding(st, st.latest("plex"))
        self.assertIn("1 buffering moment reported by the server", sentence)
        self.assertIn("the server fell behind transcoding 1 time (slowest 0.6x real time)", sentence)
        self.assertIn("now playing as transcode", sentence)
        self.assertIn("no Plex token", vm.plex_finding(st, {"token_set": False}))
        # without Plex mode a quiet press keeps the classic wording
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        s2.stream(T0, T0 + 30)
        self.assertEqual(mk.assess_window(s2.state, T0 + 25)[0], mk.NULL_ASSESSMENT)

    def test_activities_offer_plex_while_the_mode_runs(self):
        st = State(cfg={"activities": ["idle", "bf6", "other"]})
        self.assertNotIn("plex", st._activities())
        st.set_latest("plex", {"token_set": False})
        self.assertEqual(st._activities(), ["idle", "bf6", "plex", "other"])


if __name__ == "__main__":
    unittest.main()
