"""Shared fixture for the report/export/sessions tests: a realistic session built through the real Store/State.

Not a test module itself (no TestCase). ``make_session`` writes
``<root>/sessions/<id>/`` with samples (a loss burst and a latency spike),
5 s rollups through ``engine.rollup``, events/episodes/marks/tags, path,
XB7 polls (with a MAC address and a T3 log line), IGD rows, a load test,
``doctor.json``, ``session.json`` (via ``app.session_document``) and a token,
plus a ``log.txt`` that leaks the XB7 password so the exporter's scrubbing
is exercised. It also makes a minimal web template tree the builder can
inline (``laglens/web/`` under a temp root, never under the real package).
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import config as configmod  # noqa: E402
from laglens.app import AppContext, session_document  # noqa: E402
from laglens.engine import rollup as rollupmod  # noqa: E402
from laglens.state import (  # noqa: E402
    F_LOST, KIND_DNS, KIND_ICMP, KIND_NTP, KIND_TCP, Episode, Event, Mark, Sample, State, Target,
)
from laglens.store import Store  # noqa: E402
from laglens.targets import save_targets  # noqa: E402

PASSWORD = "hunter2-xb7-S3cret"
MAC = "aa:bb:cc:dd:ee:ff"
MAC2 = "01:23:45:67:89:AB"
XSS = "</script><script>alert('x')</script>"
SESSION_ID = "20261011-190000"
LABEL = "xbox on port 2"

TARGET_SPECS = [
    # key, role, addr, family, kind, label, rate
    ("gw4", "gateway", "10.0.0.1", 4, "icmp", "XB7 gateway", 4.0),
    ("inet4_cf", "anycast", "1.1.1.1", 4, "icmp", "1.1.1.1 (Cloudflare)", 4.0),
    ("inet4_g", "anycast", "8.8.8.8", 4, "icmp", "8.8.8.8 (Google)", 4.0),
    ("inet6_cf", "anycast", "2606:4700:4700::1111", 6, "icmp", "2606:4700:4700::1111 (Cloudflare)", 4.0),
    ("dns_cf4", "dns", "1.1.1.1", 4, "dns", "1.1.1.1 DNS", 1 / 3.0),
    ("tcp_cf4", "tcp", "1.1.1.1", 4, "tcp", "1.1.1.1:443", 0.5),
    ("ntp_cf", "ntp", "162.159.200.1", 4, "ntp", "time.cloudflare.com", 0.2),
    ("isp_hop4", "isp_hop", "10.60.12.1", 4, "icmp", "Comcast hop 10.60.12.1", 2.0),
    ("mid_hop4", "mid_hop", "11.0.5.33", 4, "icmp", "Mid-path 11.0.5.33", 2.0),
]
BASE_RTT_MS = {"gw4": 1.0, "inet4_cf": 14.0, "inet4_g": 16.0, "inet6_cf": 15.0, "isp_hop4": 11.0, "mid_hop4": 13.0,
               "dns_cf4": 18.0, "tcp_cf4": 20.0, "ntp_cf": 15.0}
KIND_OF = {"icmp": KIND_ICMP, "dns": KIND_DNS, "tcp": KIND_TCP, "ntp": KIND_NTP}
LOSS_BURST = (300.0, 309.5)  # seconds after t0; hop + internet targets lose packets, gateway stays clean
SPIKE = (450.0, 458.0)
STALL = (468, 478)  # host stall seconds (host_stall row in the 5 s rollups)


class StubPlatform:
    name = "darwin"

    def hostname(self):
        return "mac-studio"

    def link_info(self, iface):
        return {"speed": 1000, "duplex": "full", "wireless": False}

    def vpn_routes(self, addr="1.1.1.1"):
        return {"via_tunnel": False}

    def lan_ip(self, probe_addr="10.0.0.1"):
        return "10.0.0.50"

    def default_route(self):
        return {"gateway": "10.0.0.1", "iface": "en0", "gateway6": "fe80::1", "lan_ip": "10.0.0.50"}

    def resolvers(self):
        return ["10.0.0.1"]


def make_cfg(password: Optional[str] = PASSWORD, label: str = LABEL) -> dict:
    cfg = configmod.load_config(None)
    cfg["docsis"]["password"] = password
    cfg["label"] = label
    cfg["disk"]["min_free_mb"] = 0
    return cfg


def make_web_tree(root: Path) -> Path:
    """A minimal ``laglens/web`` under ``root`` with sentinel contents in every asset."""
    web = root / "laglens" / "web"
    (web / "vendor").mkdir(parents=True, exist_ok=True)
    (web / "report_template.html").write_text(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{{TITLE}}</title>"
        "<style>{{STYLE}}</style><style>{{UPLOT_CSS}}</style></head><body><div id=\"app\">TEMPLATE-SENTINEL</div>"
        "<script id=\"laglens-data\" type=\"application/json\">{{DATA_JSON}}</script>"
        "<script>{{UPLOT_JS}}</script><script>{{COMMON_JS}}</script><script>{{APP_JS}}</script></body></html>\n",
        encoding="utf-8")
    (web / "style.css").write_text("body{background:#0f1115}/*STYLE-SENTINEL*/\n", encoding="utf-8")
    (web / "common.js").write_text("window.COMMON_SENTINEL=1; var s='</script>'; // common\n", encoding="utf-8")
    (web / "app.js").write_text("window.APP_SENTINEL=document.getElementById('laglens-data')?'static':'live';\n",
                                encoding="utf-8")
    (web / "vendor" / "uPlot.min.css").write_text(".uplot{/*UPLOT-CSS-SENTINEL*/}\n", encoding="utf-8")
    (web / "vendor" / "uPlot.iife.min.js").write_text("var uPlot=function(){/*UPLOT-JS-SENTINEL*/};\n", encoding="utf-8")
    return root


class Fixture:
    """What ``make_session`` returns: handles the tests use."""

    def __init__(self) -> None:
        self.root: Path = Path(".")
        self.sessions_root: Path = Path(".")
        self.dir: Path = Path(".")
        self.cfg: dict = {}
        self.state: Optional[State] = None
        self.store: Optional[Store] = None
        self.ctx: Optional[AppContext] = None
        self.token: str = ""
        self.t0: float = 0.0
        self.t_end: float = 0.0
        self.ids: Dict[str, int] = {}
        self.sample_count: int = 0
        self.rollup_rows: int = 0


def _rtt_us(key: str, sec: float, sub: int) -> int:
    base = BASE_RTT_MS.get(key, 10.0)
    wobble = ((int(sec * 7) + sub * 3) % 10) / 10.0  # deterministic 0..0.9 ms
    v = base + wobble
    if key != "gw4" and SPIKE[0] <= sec < SPIKE[1]:
        v += 180.0
    return int(v * 1000)


def _lost(key: str, sec: float, sub: int) -> bool:
    if key == "gw4":
        return False
    if LOSS_BURST[0] <= sec < LOSS_BURST[1]:
        return (int(sec * 4) + sub) % 3 != 0  # ~2/3 of the probes lost
    return False


def make_session(root: Path, duration_s: int = 600, t0: Optional[float] = None, close: bool = False,
                 password: Optional[str] = PASSWORD, with_web: bool = True) -> Fixture:
    """Build the fixture session under ``root/sessions``.

    ``close`` mirrors a clean shutdown: the final ``report.html`` /
    ``comcast_evidence.txt`` are built, ``session.json`` gets ``stopped`` and
    the store is stopped (gzips ``samples.bin``). Without it the session looks
    like one still running (or crashed): no report, no ``stopped``.
    """
    root = Path(root)
    if with_web:
        make_web_tree(root)
    fx = Fixture()
    fx.root = root
    fx.sessions_root = root / "sessions"
    fx.cfg = make_cfg(password)
    if t0 is None:
        t0 = time.time() - duration_s - 60.0
    fx.t0 = float(t0)
    fx.dir = fx.sessions_root / SESSION_ID
    state = State(t0=fx.t0, session_id=SESSION_ID, cfg=fx.cfg)
    state.label = LABEL
    store = Store(fx.dir, fx.cfg, resume=False, state=state, disk_usage=lambda p: _Usage())
    store.ensure_token()
    fx.token = store.token
    store.start()
    fx.state = state
    fx.store = store
    ctx = AppContext(fx.cfg, argparse.Namespace(), state, store, StubPlatform(), root=root, sessions_root=fx.sessions_root)
    ctx.route = StubPlatform().default_route()
    fx.ctx = ctx
    state.host = {"os": "darwin", "hostname": "mac-studio", "iface": "en0", "wifi": False, "speed": 1000,
                  "duplex": "full", "lan_ip": "10.0.0.50", "gateway": "10.0.0.1", "gw6": "fe80::1", "v6": True,
                  "vpn_route": False, "link_up_mbps": 25}

    for key, role, addr, fam, kind, label, rate in TARGET_SPECS:
        t = state.add_target(Target(id=-1, key=key, role=role, addr=addr, family=fam, kind=kind, label=label, rate_hz=rate))
        fx.ids[key] = t.id
    save_targets(state, store)

    # activity tags: idle, then bf6 from +200 s
    state.tags = [{"t0": fx.t0, "t1": fx.t0 + 200.0, "activity": "idle", "source": "dashboard"},
                  {"t0": fx.t0 + 200.0, "t1": None, "activity": "bf6", "source": "phone"}]
    state.activity = {"current": "bf6", "since": fx.t0 + 200.0}
    for tag in state.tags:
        store.append_json("tags", tag)

    # samples + rollups like the ticker would do them
    t0i = int(fx.t0)
    seq: Dict[int, int] = {}
    next_w5 = (t0i // 5) * 5 + 5
    last_close = None
    for sec_i in range(duration_s):
        sec_abs = t0i + sec_i
        for key, role, addr, fam, kind, label, rate in TARGET_SPECS:
            tid = fx.ids[key]
            if kind == "icmp":
                subs = range(4) if rate >= 4 else range(0, 4, 2)
            elif kind == "dns":
                subs = [0] if sec_i % 3 == 0 else []
            elif kind == "tcp":
                subs = [1] if sec_i % 2 == 0 else []
            else:
                subs = [2] if sec_i % 5 == 0 else []
            for sub in subs:
                ts = sec_abs * 1000 + sub * 250 + 3
                seq[tid] = seq.get(tid, 0) + 1
                lost = _lost(key, float(sec_i), sub) and kind == "icmp"
                s = Sample(ts_ms=ts, target_id=tid, kind=KIND_OF[kind], flags=F_LOST if lost else 0, seq=seq[tid],
                           value=-1 if lost else _rtt_us(key, float(sec_i), sub))
                state.add_sample(s)
                store.append_sample(s)
                fx.sample_count += 1
        _set_latest(state, sec_i, fx.t0)
        close_to = sec_abs - 3
        if last_close is None or close_to > last_close:
            rollupmod.close_second(state, close_to)
            last_close = close_to
        while next_w5 + 5 + rollupmod.WINDOW5_LAG_S <= sec_abs:
            for row in rollupmod.close_window5(state, next_w5):
                store.append_json("rollups", row)
                fx.rollup_rows += 1
            next_w5 += 5
        if sec_i % 2 == 0:
            store.append_json("host", {"t": sec_abs, "iface": state.latest("iface"), "host": state.latest("host")})
    fx.t_end = fx.t0 + duration_s
    rollupmod.close_second(state, t0i + duration_s + 1)
    while next_w5 + 5 <= t0i + duration_s:
        for row in rollupmod.close_window5(state, next_w5):
            store.append_json("rollups", row)
            fx.rollup_rows += 1
        next_w5 += 5

    # events / episodes / marks
    hop, cf, g, v6 = fx.ids["isp_hop4"], fx.ids["inet4_cf"], fx.ids["inet4_g"], fx.ids["inet6_cf"]
    ev1 = Event(id=state.next_event_id(), t0=fx.t0 + 300.25, t1=fx.t0 + 309.5, type="loss_burst", target=hop, severity=3,
                peak={"loss_pct": 66, "lost": 12, "n": 18}, episode="ep-000001")
    ev2 = Event(id=state.next_event_id(), t0=fx.t0 + 300.5, t1=fx.t0 + 309.5, type="loss_burst", target=cf, severity=3,
                peak={"loss_pct": 60, "lost": 22, "n": 36}, episode="ep-000001")
    ev3 = Event(id=state.next_event_id(), t0=fx.t0 + 450.0, t1=fx.t0 + 458.0, type="latency_spike", target=cf, severity=2,
                peak={"rtt_max_ms": 195.0}, episode="ep-000002")
    ev4 = Event(id=state.next_event_id(), t0=fx.t0 + 120.0, t1=fx.t0 + 120.0, type="route_change", target=None, severity=1,
                peak={"hop": 2, "old": "10.60.12.1", "new": "10.60.12.1"}, note="rediscovery, no change")
    for ev in (ev1, ev2, ev3, ev4):
        state.add_event(ev)
        store.append_json("events", ev.to_dict())
    ep1 = Episode(id=state.next_episode_id(), t0=fx.t0 + 300.25, targets=[hop, cf, g, v6], events=[ev1.id, ev2.id])
    state.add_episode(ep1)
    store.append_json("episodes", ep1.to_dict())  # open row
    ep1.t1 = fx.t0 + 309.5
    ep1.dur_s = 9.25
    ep1.cls = "docsis_access"
    ep1.subclass = "t3_signature"
    ep1.confidence = 0.86
    ep1.evidence = ["gateway 10.0.0.1: 0% loss, +1 ms", "Comcast hop 10.60.12.1: 66% loss", "1.1.1.1: 60% loss",
                    "XB7 log: T3 time-out at +2 s (CM-MAC=%s)" % MAC, "note: " + XSS]
    ep1.alt = {"class": "upload_saturation", "why_rejected": "no uniform RTT inflation; WAN tx 0.3 Mbps"}
    ep1.locus = {"shallowest": "isp_hop4", "cond": {"isp_hop4|inet4_cf": 0.91, "gw4|inet4_cf": 0.02}}
    ep1.direction = "upstream"
    ep1.xbox_state = "awake"
    ep1.activity = "bf6"
    ep1.sweep = {"dst": "1.1.1.1", "hops": [{"ttl": 1, "ip": "10.0.0.1", "rtt": [1.1, 1.0, 1.2], "loss": 0},
                                            {"ttl": 2, "ip": "10.60.12.1", "rtt": [14.2, None, None], "loss": 67}]}
    ep1.docsis = {"pre_uncorr": {"18": 120443}, "post_uncorr": {"18": 121255},
                  "log_lines": ["2026-10-11 21:14:03 T3 time-out CM-MAC=%s" % MAC]}
    ep1.marks = ["mk-1"]
    ep1.onset_order = ["isp_hop4", "inet4_cf", "inet6_cf"]
    ep1.wan = {"tx_mbps_max": 0.3, "rx_mbps_max": 2.1, "trusted": True}
    store.append_json("episodes", ep1.to_dict())  # close row
    ep2 = Episode(id=state.next_episode_id(), t0=fx.t0 + 450.0, t1=fx.t0 + 458.0, dur_s=8.0, targets=[cf, g, v6],
                  events=[ev3.id], cls="upload_saturation", confidence=0.55, evidence=["uniform +180 ms on every target"],
                  direction="upstream", xbox_state="awake", activity="bf6", host_tags=["self_load"], comcast_relevant=False)
    state.add_episode(ep2)
    store.append_json("episodes", ep2.to_dict())
    mk1 = Mark(id=state.next_mark_id(), t_pressed=fx.t0 + 335.1, offset_s=30, t_est=fx.t0 + 305.1, activity="bf6",
               note="teleport " + XSS, source="phone", episode=ep1.id,
               assessment="Comcast hop and internet lost packets for 9 s; XB7 answered normally.", snapshot="marks/mk-1.json")
    mk2 = Mark(id=state.next_mark_id(), t_pressed=fx.t0 + 500.0, offset_s=0, t_est=fx.t0 + 500.0, activity="bf6",
               note="", source="dashboard", episode=None, assessment="Nothing abnormal in the last 10 s on any target.")
    for m in (mk1, mk2):
        state.add_mark(m)
        store.append_json("marks", m.to_dict())
    store.write_json_atomic("marks/mk-1.json", {"id": "mk-1", "from_ms": int((fx.t0 + 185) * 1000),
                                                "rows": [[int((fx.t0 + 300) * 1000), hop, 0, 1, -1]]})

    # path / xb7 / igd / loadtests / doctor / log
    state.path = {"v4": [{"ttl": 1, "ip": "10.0.0.1", "rdns": None, "role": "gateway"},
                         {"ttl": 2, "ip": "10.60.12.1", "rdns": None, "role": "isp_hop", "mode": "direct", "rate_hz": 2},
                         {"ttl": 3, "ip": "11.0.5.33", "rdns": "be-1-cr.comcast.net", "role": "mid_hop"}],
                  "v6": [{"ttl": 1, "ip": "fe80::1", "rdns": None, "role": "gateway"}],
                  "discovered_at": fx.t0 + 5.0, "changes": 0}
    for dst, hops in (("1.1.1.1", state.path["v4"]), ("2606:4700:4700::1111", state.path["v6"])):
        store.append_json("path", {"t": fx.t0 + 5.0, "dst": dst, "hops": hops,
                                   "roles": {"isp_hop": "10.60.12.1", "mid_hop": "11.0.5.33"}, "changed": False,
                                   "method": "ttl_probe"})
    for i in range(3):
        store.append_json("xb7", {
            "t": fx.t0 + 60 * (i + 1), "ok": True, "uptime_s": 123456 + 60 * i, "fw": "CGM4331COM_5.3p7s1",
            "mac": MAC2,
            "ds": [{"ch": c, "freq_hz": 507000000 + c * 6000000, "snr_db": 36.4 - c * 0.1, "pwr_dbmv": 1.2, "mod": "QAM256",
                    "lock": True, "unerr": 987654 + c, "corr": 123, "uncorr": 812 if (c == 4 and i == 2) else 0}
                   for c in range(1, 5)],
            "us": [{"ch": c, "freq_hz": 35600000 + c * 6400000, "pwr_dbmv": 44.0, "type": "ATDMA", "lock": True}
                   for c in range(1, 3)],
            "log_new": [{"ts": "2026-10-11 21:14:03", "text": "T3 time-out CM-MAC=%s;CMTS-MAC=%s" % (MAC, MAC2),
                         "class": "t3"}] if i == 2 else [],
            "flags": ["us_power_high"] if i == 2 else [], "log_clock_offset_s": -3,
        })
    (fx.dir / "xb7_raw").mkdir(exist_ok=True)
    (fx.dir / "xb7_raw" / "hardware.html").write_text(
        "<html><body><td>CM MAC Address</td><td>%s</td><td>Serial</td><td>XYZ</td></body></html>" % MAC2, encoding="utf-8")
    for i in range(3):
        store.append_json("igd", {"t": fx.t0 + 30 * (i + 1), "status": "Connected", "trusted": True, "uptime_s": 5000 + 30 * i,
                                  "ext_ip": "73.1.2.3", "mappings": [{"proto": "UDP", "ext": 3074, "int": "10.0.0.23:3074",
                                                                      "desc": "Xbox"}]})
    store.append_json("loadtests", {"t0": fx.t0 + 100, "phases": {"idle": {"p50": 12, "p95": 15},
                                                                   "down": {"mbps": 912, "p50": 14, "p95": 22},
                                                                   "up": {"mbps": 24.1, "p50": 60, "p95": 210}},
                                    "grade": "D", "added_ms": {"down": 7, "up": 195}})
    doctor = [{"check": "icmp_v4_socket", "status": "ok", "detail": "DGRAM ICMP works", "fallback": None},
              {"check": "local_network", "status": "ok", "detail": "10.0.0.1 answers", "fallback": None}]
    state.doctor = doctor
    store.write_json_atomic("doctor.json", doctor)
    state.verdict = {
        "text": "Over 10 m your connection dropped packets in 1 burst totalling 9 s. Your XB7 kept answering but "
                "everything past it went silent, and the modem logged a T3 timeout, which points at the cable line. "
                "1 of your 2 presses lines up with it.",
        "confidence": "medium",
        "top": [{"class": "docsis_access", "share": 0.71, "episodes": 1, "seconds": 9.25},
                {"class": "upload_saturation", "share": 0.29, "episodes": 1, "seconds": 8.0}],
        "comcast": "Tell Comcast: 1 episode of upstream loss past the XB7 (10.0.0.1) at hop 10.60.12.1 with a T3 time-out.",
        "next": [{"try": "Call Comcast with the attached evidence", "confirm_if": "T3 count grows",
                  "refute_if": "clean 24 h after a modem swap"}],
        "marks": {"total": 2, "linked": 1},
    }
    state.health = {"now": 88, "session": 83}
    state.set_collector("engine", "ok")
    state.set_collector("docsis", "ok", polls=3)
    state.set_collector("wifi", "disabled", reason="wired interface")
    state.set_collector("notify", "disabled", reason="not configured")
    state.set_status("OK", "All clear")
    (fx.dir / "log.txt").write_text("2026-10-11 19:00:00 INFO laglens.collectors.docsis: login POST password=%s ok\n"
                                    "2026-10-11 19:00:01 INFO laglens.app: started\n" % (password or "none"), encoding="utf-8")
    store.flush()
    if close:
        # Mirror app.shutdown: the final report (and comcast_evidence.txt) is written before
        # the writer closes, so a cleanly closed session always carries report.html.
        from laglens.report.build import ReportBuilder

        ReportBuilder(ctx).build(final=True)
    store.write_json_atomic("session.json", session_document(ctx, stopped=fx.t_end if close else None))
    if close:
        store.stop()
    return fx


def _set_latest(state: State, sec_i: int, t0: float) -> None:
    state.set_latest("iface", {"rx_mbps": 0.4 + (sec_i % 5) * 0.1, "tx_mbps": 0.1, "rx_err": 0, "tx_err": 0,
                               "rx_drop": 0, "tx_drop": 0, "crc": 0, "mcast_pps": 12, "carrier_changes": 0,
                               "speed": 1000, "duplex": "full", "operstate": "up"})
    # The 5 s window close only copies the *latest* host row, so a stall must span a whole
    # window (whatever t0 % 5 is) to be visible in the series: 468..477 s.
    state.set_latest("host", {"late_ms_max": 3, "loop_gap_ms": 12, "drift_ms": 0, "load1": 0.8, "free_mb": 52000,
                              "vpn_route": False, "stall": STALL[0] <= sec_i < STALL[1]})
    state.set_latest("wifi", {"rssi": -58, "noise": -92, "chan": 36, "bssid": MAC, "ssid": "home", "rate_mbps": 866})
    state.set_latest("wan", {"rx_mbps": 2.3, "tx_mbps": 0.3, "trusted": True, "uptime_s": 5000 + sec_i, "ext_ip": "73.1.2.3"})
    state.set_latest("ntp", {"cf": {"rtt": 14.1, "offset": -0.9 - (sec_i // 100) * 0.1}, "g": {"rtt": 15.0, "offset": -1.1}})
    state.set_latest("docsis", {"ds_snr_min": 36.1, "ds_pwr_min": -1.2, "ds_pwr_max": 3.4, "us_pwr_max": 44.0,
                                "uncorr_delta": 812 if sec_i == 305 else 0, "corr_delta": 12, "uptime_s": 123456,
                                "flags": []})
    state.set_latest("xbox", {"state": "awake", "src": "udp5050"})


class _Usage:
    free = 50_000 * 1024 * 1024
    total = free * 2
    used = free


def data_blob(html: str) -> dict:
    """Parse the embedded JSON back out of a rendered report."""
    start_tag = '<script id="laglens-data" type="application/json">'
    i = html.index(start_tag) + len(start_tag)
    j = html.index("</script>", i)
    raw = html[i:j]
    assert "</" not in raw, "unescaped </ inside the data block"
    return json.loads(raw.replace("<\\/", "</"))


BLOB_KEYS = [
    "version", "generated_at", "static", "session", "targets", "state", "stats", "stats_1h", "series", "events",
    "episodes", "marks", "tags", "raw_slices", "path", "docsis", "igd", "loadtests", "doctor", "collectors", "config",
    "verdict", "comcast_text", "activity_stats", "hour_heatmap", "methodology",
]
