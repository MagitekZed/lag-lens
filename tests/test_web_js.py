"""Browser-side JavaScript checks run through node (skipped when node is missing).

* ``node --check`` on every file in ``laglens/web`` (syntax only);
* a smoke test of the pure-JS QR encoder (``qr.js``): the phone URL encodes to a
  symbol whose size matches its version and whose three finder patterns are present;
* ``common.js`` + ``app.js`` + ``phone.js`` evaluated against a minimal fake
  ``window``/``document`` so top-level code never throws, the dashboard boots
  against an unreachable backend, and the static report renders all 13 sections.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "laglens" / "web"
def _nvm_nodes():
    """node binaries installed with nvm (newest first), for shells where nvm is not on PATH."""
    base = Path(os.path.expanduser("~")) / ".nvm" / "versions" / "node"
    try:
        return [str(p / "bin" / "node") for p in sorted(base.iterdir(), reverse=True)]
    except OSError:
        return []


NODE_CANDIDATES = [os.environ.get("LAGLENS_NODE") or "", shutil.which("node") or ""] + _nvm_nodes() + [
    "/opt/homebrew/bin/node",
    "/usr/local/bin/node",
]
NODE = next((p for p in NODE_CANDIDATES if p and os.access(p, os.X_OK)), None)
JS_FILES = ["common.js", "app.js", "phone.js", "qr.js"]

# A tiny DOM: enough for h()/clear()/appendChild/classList/style/querySelector and
# the id lookups the pages use. Every unknown id resolves to a fresh element so the
# page scripts can bind their buttons.
HARNESS = r"""
'use strict';
const fs = require('fs');
const [webDir, mode, blobPath] = process.argv.slice(2);
process.on('unhandledRejection', (e) => { console.error('UNHANDLED', e && e.stack || e); process.exit(3); });

class ClassList {
  constructor() { this.set = new Set(); }
  add(...c) { c.forEach((x) => x && this.set.add(x)); }
  remove(...c) { c.forEach((x) => this.set.delete(x)); }
  contains(c) { return this.set.has(c); }
  toggle(c, force) { const on = force === undefined ? !this.set.has(c) : !!force; on ? this.set.add(c) : this.set.delete(c); return on; }
}
class Style { setProperty(k, v) { this[k] = v; } getPropertyValue(k) { return this[k] || ''; } }
let seq = 0;
class El {
  constructor(tag) {
    this.tagName = String(tag || 'div').toUpperCase(); this.childNodes = []; this.attrs = {}; this.dataset = {}; this.style = new Style();
    this.classList = new ClassList(); this.listeners = {}; this.parentNode = null; this.textContent = ''; this._html = '';
    this.value = ''; this.disabled = false; this.checked = false; this.options = []; this.title = ''; this.id = ''; this.width = 0; this.height = 0;
    this.clientWidth = 600; this.clientHeight = 34; this.ownerDocument = null; this.uid = ++seq;
  }
  get className() { return Array.from(this.classList.set).join(' '); }
  set className(v) { this.classList = new ClassList(); String(v || '').split(/\s+/).forEach((c) => c && this.classList.add(c)); }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = String(v); this.childNodes = []; }
  get firstChild() { return this.childNodes[0] || null; }
  get children() { return this.childNodes.filter((c) => c instanceof El); }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.childNodes.push(c); if (this.tagName === 'SELECT' && c.tagName === 'OPTION') this.options.push(c); return c; }
  insertBefore(c, ref) { const i = this.childNodes.indexOf(ref); if (i < 0) return this.appendChild(c); c.parentNode = this; this.childNodes.splice(i, 0, c); return c; }
  removeChild(c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); c.parentNode = null; if (this.tagName === 'SELECT') this.options = this.options.filter((o) => o !== c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); if (k === 'class') this.className = v; }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(n, f) { (this.listeners[n] = this.listeners[n] || []).push(f); }
  removeEventListener() {}
  dispatch(n, ev) { (this.listeners[n] || []).forEach((f) => f(ev || { target: this, preventDefault() {} })); }
  querySelector(sel) { return this.all().find((e) => matches(e, sel)) || null; }
  querySelectorAll(sel) { return this.all().filter((e) => matches(e, sel)); }
  all() { const out = []; const walk = (e) => { e.childNodes.forEach((c) => { if (c instanceof El) { out.push(c); walk(c); } }); }; walk(this); return out; }
  getContext() { return new Proxy({ fillStyle: '#000000', canvas: this }, { get: (t, k) => (k in t ? t[k] : () => {}), set: (t, k, v) => { t[k] = v; return true; } }); }
  captureStream() { return { id: 'fake-stream' }; }
  play() { return Promise.resolve(); }
  pause() {}
  select() {}
  focus() {}
  getBoundingClientRect() { return { left: 0, top: 0, width: 600, height: 100 }; }
}
function matches(e, sel) {
  if (sel.startsWith('#')) return e.id === sel.slice(1);
  if (sel.startsWith('.')) return e.classList.contains(sel.slice(1));
  const m = /^([a-z]+)?\[name="([^"]+)"\]$/i.exec(sel);
  if (m) return (!m[1] || e.tagName === m[1].toUpperCase()) && e.getAttribute('name') === m[2];
  return e.tagName === sel.toUpperCase();
}
class Text { constructor(t) { this.textContent = String(t); this.parentNode = null; } }

const metas = { 'laglens-token': 'tok123', 'laglens-version': '9.9.9', 'laglens-activities': 'idle,bf6,other' };
const byId = {};
const document = {
  readyState: 'complete', hidden: false, title: '', documentElement: new El('html'), body: new El('body'), head: new El('head'),
  createElement(t) { const e = new El(t); e.ownerDocument = document; return e; },
  createTextNode(t) { return new Text(t); },
  getElementById(id) {
    if (id === 'laglens-data') return mode === 'report' ? { textContent: fs.readFileSync(blobPath, 'utf8') } : null;
    if (mode === 'none' && id !== 'report') return null;
    if (!byId[id]) { byId[id] = document.createElement(id === 'activity-sel' || id === 'ep-class' || id === 'ep-conf' ? 'select' : 'div'); byId[id].id = id; }
    return byId[id];
  },
  querySelector(sel) { const m = /meta\[name="([^"]+)"\]/.exec(sel); if (m) return metas[m[1]] != null ? { getAttribute: () => metas[m[1]] } : null; return null; },
  querySelectorAll() { return []; },
  addEventListener(n, f) { (document.listeners = document.listeners || {})[n] = f; },
  execCommand() { return true; },
};
const storage = {}; const localStorage = { getItem: (k) => (k in storage ? storage[k] : null), setItem: (k, v) => { storage[k] = String(v); }, removeItem: (k) => { delete storage[k]; } };
const fetchCalls = [];
const window = {
  document, localStorage, location: { hostname: '10.0.0.35', port: '8787', search: '', origin: 'http://10.0.0.35:8787', replace() {} },
  navigator: { vibrate: () => true, clipboard: null }, devicePixelRatio: 1,
  addEventListener() {}, getComputedStyle: () => ({ getPropertyValue: () => '' }),
  setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
  prompt: () => null, confirm: () => false, alert() {},
  fetch(url) { fetchCalls.push(String(url)); return Promise.resolve({ ok: false, status: 503, text: () => Promise.resolve('{"error":"down","code":"unavailable"}') }); },
};
window.window = window;
// Timers must not keep the process alive (setInterval is stubbed), but promise callbacks still run.
const sandbox = { window, document, localStorage, navigator: window.navigator, location: window.location, fetch: window.fetch,
  setTimeout: window.setTimeout, clearTimeout: window.clearTimeout, setInterval: window.setInterval, clearInterval: window.clearInterval,
  console, Promise, JSON, Math, Date, Object, Array, Number, String, Error, Infinity, NaN, isNaN, parseInt, parseFloat, encodeURIComponent, decodeURIComponent, Set, Map, RegExp, undefined: undefined };
const vm = require('vm');
const ctx = vm.createContext(sandbox);
function load(name) { vm.runInContext(fs.readFileSync(webDir + '/' + name, 'utf8'), ctx, { filename: name }); }
load('qr.js'); load('common.js');
const LL = sandbox.window.LL;
if (!LL || typeof LL.h !== 'function') throw new Error('common.js did not export LL');
if (LL.token !== 'tok123' || LL.version !== '9.9.9') throw new Error('meta tags not read: ' + LL.token + ' ' + LL.version);
if (LL.activities.join(',') !== 'idle,bf6,other') throw new Error('activities meta not read: ' + LL.activities);
if (LL.isStatic !== (mode === 'report')) throw new Error('isStatic wrong for mode ' + mode);
load('app.js'); load('phone.js');
const out = { mode, fetchCalls: 0, sections: [], dashboard: false, phone: false, title: '' };
setImmediate(() => setImmediate(() => {   // let the first promise chain settle
  out.fetchCalls = fetchCalls.length;
  out.dashboard = !!sandbox.window.LagLensDashboard;
  out.phone = !!sandbox.window.LagLensPhone;
  if (mode === 'report') {
    const rep = document.getElementById('report');
    out.sections = rep.all().filter((e) => e.tagName === 'SECTION').map((s) => s.id);
    out.title = document.title;
    const failed = rep.all().find((e) => e.tagName === 'PRE' && /Report render failed/.test(e.childNodes.map((c) => c.textContent || '').join('')));
    if (failed) { console.error(failed.childNodes.map((c) => c.textContent).join('')); process.exit(4); }
  }
  if (mode === 'dashboard') {
    const dash = sandbox.window.LagLensDashboard;
    out.pill = document.getElementById('pill').textContent;
    out.lagBtn = document.getElementById('btn-lag').textContent;
    // the Lag-happened press while offline queues the mark in localStorage with replay:true
    dash.lagPressed(); const sheet = document.body.childNodes[document.body.childNodes.length - 1];
    sheet.querySelector('.save').dispatch('click');
    out.queue = JSON.parse(storage['laglens.queue'] || '[]');
  }
  if (mode === 'phone') {
    const ph = sandbox.window.LagLensPhone;
    ph.setOnline(false);
    ph.pressed(); const sheet = document.body.childNodes[document.body.childNodes.length - 1];
    sheet.querySelector('.save').dispatch('click');
    out.queue = JSON.parse(storage['laglens.queue'] || '[]');
    out.bignums = document.getElementById('bignums').childNodes.length;
    out.interacted = ph.interacted;
  }
  console.log(JSON.stringify(out));
}));
"""


def report_blob():
    t0 = 1_760_000_000
    targets = [
        {"id": 0, "key": "gw4", "role": "gateway", "addr": "10.0.0.1", "family": 4, "kind": "icmp", "label": "XB7", "enabled": True},
        {"id": 1, "key": "isp_hop4", "role": "isp_hop", "addr": "10.60.1.1", "family": 4, "kind": "icmp", "label": "hop", "enabled": True},
        {"id": 2, "key": "inet4_cf", "role": "anycast", "addr": "1.1.1.1", "family": 4, "kind": "icmp", "label": "CF", "enabled": True},
        {"id": 3, "key": "dns_cf4", "role": "dns", "addr": "1.1.1.1", "family": 4, "kind": "dns", "label": "DNS CF", "enabled": True},
    ]
    n = 24
    ts = [t0 + 5 * i for i in range(n)]
    series = {"res": 5, "from": t0, "to": t0 + 5 * n, "t": ts, "targets": {}, "iface": {"rx_mbps": [1.0] * n, "tx_mbps": [0.5] * n, "err": [0] * n, "drop": [0] * n, "carrier_changes": [0] * n, "mcast_pps": [1] * n},
              "wan": {"rx_mbps": [None] * n, "tx_mbps": [None] * n}, "wifi": {"rssi": [None] * n, "noise": [None] * n}, "docsis": {"ds_snr_min": [38.0] * n, "us_pwr_max": [44.0] * n, "uncorr_delta": [0] * n},
              "ntp": {"offset_shift": [0.1] * n}, "segments": {"lan": [1.0] * n, "docsis": [8.0] * n, "comcast": [3.0] * n, "internet": [5.0] * n},
              "slots_lost": [[0, 0, 0, 0]] * n, "xbox_state": ["awake"] * 12 + ["asleep"] * 12, "stall": [0] * n}
    for t in targets:
        series["targets"][str(t["id"])] = {"p50": [2.0 + t["id"]] * n, "p95": [3.0 + t["id"]] * n, "max": [5.0] * n, "lost": [0] * 10 + [2, 3] + [0] * 12, "late": [0] * n, "n": [20] * n, "jit": [0.3] * n}
    ep = {"id": "ep-000001", "t0": t0 + 50, "t1": t0 + 62, "dur_s": 12, "targets": [1, 2], "events": ["ev-000001"], "class": "docsis_access", "subclass": None, "confidence": 0.8,
          "evidence": ["Comcast hop 10.60.1.1 and 1.1.1.1 lost 30% of probes for 12 s", "gateway 0% loss"], "alt": {"class": "internet", "why_rejected": "hop lost first"},
          "locus": {"shallowest": "isp_hop4", "cond": {"isp_hop4|inet4_cf": 0.91}}, "direction": "upstream", "xbox_state": "awake", "activity": "bf6", "host_tags": [], "comcast_relevant": True,
          "sweep": {"dst": "1.1.1.1", "hops": [{"ttl": 1, "ip": "10.0.0.1", "rtt": [1.0, 1.1, 0.9], "loss": 0}]}, "docsis": {"pre_uncorr": {"1": 10}, "post_uncorr": {"1": 14}, "log_lines": ["T3 time-out"]},
          "marks": ["mk-1"], "onset_order": ["isp_hop4", "inet4_cf"], "size_loss_ratio": {}, "wan": None, "xb7_cpu_only": False}
    mark = {"id": "mk-1", "t_pressed": t0 + 60, "offset_s": 0, "t_est": t0 + 60, "activity": "bf6", "note": "teleport", "source": "phone", "episode": "ep-000001", "assessment": "Comcast hop and internet lost packets.", "snapshot": "marks/mk-1.json"}
    state = {"version": "9.9.9", "session": {"id": "20261011-190000", "started": t0, "label": "port 2"}, "state": "OK", "pill": "All clear", "headline": {"answer": "yes", "text": "Probably yes — Comcast side", "action": "Call them"},
             "health": {"now": 90, "session": 85}, "host": {"os": "darwin", "hostname": "mac", "iface": "en0", "wifi": True, "lan_ip": "10.0.0.35", "gateway": "10.0.0.1", "v6": True, "vpn_route": False, "link_up_mbps": 25},
             "targets": targets, "xbox": {"ip": None, "state": "unknown"}, "collectors": {"engine": {"status": "ok"}, "docsis": {"status": "disabled", "reason": "docsis.password not set"}},
             "path": {"v4": [{"ttl": 1, "ip": "10.0.0.1", "role": "gateway"}, {"ttl": 2, "ip": "10.60.1.1", "role": "isp_hop", "rate_hz": 2}], "v6": [], "changes": 0}, "activity": {"current": "bf6"},
             "episodes_open": [], "episodes_recent": [ep], "marks_recent": [mark], "verdict": {"text": "Three sentences.", "confidence": "medium", "top": [{"class": "docsis_access", "share": 0.7, "episodes": 1, "seconds": 12}], "comcast": "Dear Comcast", "next": [{"try": "swap cable", "confirm_if": "gone", "refute_if": "same"}], "marks": {"total": 1, "linked": 1}},
             "loadtest": {"running": False, "last": None}, "doctor": [{"check": "icmp_v4_socket", "status": "ok", "detail": "fine", "fallback": None}], "disk": {"free_mb": 1000, "writing": True}, "update": {"available": False}, "token_required": True, "sse_clients": 0, "now": t0 + 120}
    stats = {"targets": {str(t["id"]): {"sent": 400, "lost": 4, "loss_pct": 1.0, "late_pct": 0.0, "min": 1.0, "p50": 2.0, "p95": 3.0, "p99": 4.0, "max": 5.0, "jitter": 0.3, "longest_outage_s": 1.5, "episodes": 1, "big_loss_ratio": None} for t in targets}, "health": 85, "matrix": {"pairs": {}, "locus_counts": {}}}
    return {"version": "9.9.9", "generated_at": t0 + 120, "static": True, "session": {"id": "20261011-190000", "started": t0, "stopped": t0 + 120, "label": "port 2", "os": "darwin", "resumed_count": 0},
            "targets": targets, "state": state, "stats": stats, "stats_1h": stats, "series": series, "events": [{"id": "ev-000001", "t0": t0 + 50, "t1": t0 + 62, "type": "loss_burst", "target": 1, "severity": 2}],
            "episodes": [ep], "marks": [mark], "tags": [{"t0": t0, "t1": None, "activity": "bf6", "source": "phone"}],
            "raw_slices": {"ep-000001": {"from_ms": (t0 + 40) * 1000, "to_ms": (t0 + 70) * 1000, "rows": [[(t0 + 50) * 1000 + 250 * i, 1, 0, 1 if i % 4 == 0 else 0, -1 if i % 4 == 0 else 2000 + i] for i in range(40)]}},
            "path": state["path"], "docsis": {"status": "ok", "polls": [{"t": t0, "uptime_s": 1000, "fw": "x", "ds": [{"ch": 1, "freq_hz": 500e6, "snr_db": 38.1, "pwr_dbmv": 1.0, "mod": "QAM256", "corr": 1, "uncorr": 0}], "us": [{"ch": 1, "freq_hz": 30e6, "pwr_dbmv": 44.0, "type": "ATDMA", "lock": True}], "flags": [], "log_new": [{"ts": "1", "class": "t3", "text": "T3 time-out"}]}], "log": []},
            "igd": {"status": "ok", "trusted": True, "uptime_s": 5000, "ext_ip": "73.1.2.3", "mappings": [{"proto": "UDP", "ext": 3074, "int": "10.0.0.23:3074", "desc": "Xbox"}]},
            "loadtests": [{"t0": t0, "grade": "B", "phases": {"idle": {"p50": 10, "p95": 12}, "down": {"p50": 15, "p95": 40, "mbps": 900}, "up": {"p50": 30, "p95": 90, "mbps": 23.5}}, "added_ms": {"down": 5, "up": 20}}],
            "doctor": state["doctor"], "collectors": state["collectors"], "config": {"port": 8787, "docsis": {"password": "***"}}, "verdict": state["verdict"], "comcast_text": "Dear Comcast, evidence attached.",
            "activity_stats": {"bf6": stats}, "hour_heatmap": [{"hour": hh, "loss_pct": 0.5 if hh == 21 else 0.0, "p95": 3.0, "episodes": 1 if hh == 21 else 0} for hh in range(24)],
            "methodology": ["Rule one.", "Rule two."]}


@unittest.skipIf(NODE is None, "node is not installed")
class WebJsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="laglens-js-"))
        cls.harness = cls.tmp / "harness.js"
        cls.harness.write_text(HARNESS, encoding="utf-8")
        cls.blob = cls.tmp / "blob.json"
        cls.blob.write_text(json.dumps(report_blob()), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def node(self, *args, timeout=60):
        p = subprocess.run([NODE] + list(args), cwd=str(self.tmp), capture_output=True, text=True, timeout=timeout)
        return p

    def run_mode(self, mode):
        p = self.node(str(self.harness), str(WEB), mode, str(self.blob))
        self.assertEqual(p.returncode, 0, "mode %s: %s\n%s" % (mode, p.stderr[-2000:], p.stdout[-2000:]))
        lines = [ln for ln in p.stdout.strip().splitlines() if ln.startswith("{")]
        self.assertTrue(lines, p.stdout)
        return json.loads(lines[-1])

    def test_every_js_file_parses(self):
        for name in JS_FILES:
            p = self.node("--check", str(WEB / name))
            self.assertEqual(p.returncode, 0, "%s: %s" % (name, p.stderr))
        # the vendored uPlot too
        p = self.node("--check", str(WEB / "vendor" / "uPlot.iife.min.js"))
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_qr_encoder_smoke(self):
        script = (
            "const QR=require(process.argv[1]);"
            "const q=QR.encode('http://10.0.0.35:8787/phone');"
            "const m=q.modules; const f=(x,y)=>m[y][x]; const s=q.size;"
            "const finder=(cx,cy)=>{for(let dy=-3;dy<=3;dy++)for(let dx=-3;dx<=3;dx++){const r=Math.max(Math.abs(dx),Math.abs(dy));"
            "const want=(r===3||r<=1); if(f(cx+dx,cy+dy)!==want) return false;} return true;};"
            "const ok={version:q.version,size:s,sizeOk:s===17+4*q.version,tl:finder(3,3),tr:finder(s-4,3),bl:finder(3,s-4),"
            "rows:m.length,cols:m.every(r=>r.length===s),dark:m.flat().filter(Boolean).length,"
            "lower:QR.encode('http://10.0.0.35:8787/phone',{ecl:'L'}).version,"
            "big:QR.encode('x'.repeat(200)).version};"
            "console.log(JSON.stringify(ok));"
        )
        p = self.node("-e", script, str(WEB / "qr.js"))
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertTrue(r["sizeOk"], r)
        self.assertEqual(r["size"], 17 + 4 * r["version"])
        self.assertIn(r["version"], (2, 3), r)  # 27 bytes: v3 at EC M, v2 at EC L
        self.assertTrue(r["tl"] and r["tr"] and r["bl"], r)
        self.assertEqual(r["rows"], r["size"])
        self.assertTrue(r["cols"])
        self.assertTrue(0.3 < r["dark"] / float(r["size"] ** 2) < 0.7, r)
        self.assertLessEqual(r["lower"], r["version"])
        self.assertGreater(r["big"], r["version"])

    def test_top_level_evaluation_without_dom_ids(self):
        r = self.run_mode("none")
        self.assertFalse(r["dashboard"])
        self.assertFalse(r["phone"])
        self.assertEqual(r["fetchCalls"], 0)

    def test_dashboard_boots_offline_and_queues_presses(self):
        r = self.run_mode("dashboard")
        self.assertTrue(r["dashboard"])
        self.assertGreaterEqual(r["fetchCalls"], 1)
        self.assertEqual(r["pill"], "UNREACHABLE")
        self.assertIn("reconnected", r["lagBtn"])
        self.assertEqual(len(r["queue"]), 1)
        self.assertTrue(r["queue"][0]["replay"])
        self.assertEqual(r["queue"][0]["source"], "dashboard")
        self.assertIn("t_pressed", r["queue"][0])

    def test_phone_boots_offline_and_queues_presses(self):
        r = self.run_mode("phone")
        self.assertTrue(r["phone"])
        self.assertEqual(len(r["queue"]), 1)
        self.assertTrue(r["queue"][0]["replay"])
        self.assertEqual(r["queue"][0]["source"], "phone")
        self.assertTrue(r["interacted"])

    def test_static_report_renders_all_sections(self):
        r = self.run_mode("report")
        expect = ["sec-verdict", "sec-comcast", "sec-stats", "sec-episodes", "sec-marks", "sec-timelines", "sec-activity", "sec-hours",
                  "sec-path", "sec-docsis", "sec-loadtests", "sec-facts", "sec-methodology"]
        self.assertEqual(r["sections"], expect)
        self.assertIn("20261011-190000", r["title"])
        self.assertIn("port 2", r["title"])


class PagesTests(unittest.TestCase):
    """Static checks on the HTML shells (no node needed)."""

    PAGES = ["index.html", "phone.html", "sessions.html", "setup.html"]

    def test_pages_have_meta_and_local_assets_only(self):
        import re

        for name in self.PAGES:
            text = (WEB / name).read_text(encoding="utf-8")
            self.assertIn('<meta name="laglens-token" content="{{TOKEN}}">', text, name)
            self.assertIn('<meta name="laglens-version" content="{{VERSION}}">', text, name)
            self.assertIn('<meta name="laglens-activities" content="{{ACTIVITIES}}">', text, name)
            self.assertIn('name="viewport"', text, name)
            for src in re.findall(r'(?:src|href)="([^"]+)"', text):
                self.assertFalse(src.startswith(("http:", "https:", "//")), (name, src))
            self.assertIn('/static/common.js', text, name)

    def test_dashboard_has_every_id_app_js_binds(self):
        import re

        html = (WEB / "index.html").read_text(encoding="utf-8")
        ids = set(re.findall(r'id="([^"]+)"', html))
        app = (WEB / "app.js").read_text(encoding="utf-8")
        # ids app.js fetches with $('...') in live mode (static-mode ids are created by the renderer)
        used = set(re.findall(r"\$\('([a-z0-9\-]+)'\)", app)) - {"report"}
        missing = sorted(u for u in used if u not in ids)
        self.assertEqual(missing, [], "index.html lacks ids used by app.js: %s" % missing)

    def test_phone_has_every_id_phone_js_binds(self):
        import re

        html = (WEB / "phone.html").read_text(encoding="utf-8")
        ids = set(re.findall(r'id="([^"]+)"', html))
        js = (WEB / "phone.js").read_text(encoding="utf-8")
        used = set(re.findall(r"\$\('([a-z0-9\-]+)'\)", js))
        missing = sorted(u for u in used if u not in ids)
        self.assertEqual(missing, [], "phone.html lacks ids used by phone.js: %s" % missing)
        for meta in ("apple-mobile-web-app-capable", "mobile-web-app-capable", "apple-mobile-web-app-title"):
            self.assertIn(meta, html)
        self.assertIn('<video id="keep-awake"', html)

    def test_report_template_placeholders(self):
        text = (WEB / "report_template.html").read_text(encoding="utf-8")
        for key in ("TITLE", "STYLE", "UPLOT_CSS", "UPLOT_JS", "COMMON_JS", "APP_JS"):
            self.assertEqual(text.count("{{%s}}" % key), 1, key)
        self.assertIn('<script id="laglens-data" type="application/json">{{DATA_JSON}}</script>', text)
        self.assertIn('id="report"', text)
        self.assertNotIn("{{TOKEN}}", text)
        self.assertNotIn("src=", text)  # everything is inlined
        # order: data blob before the scripts that read it, uPlot before common/app
        self.assertLess(text.index("{{DATA_JSON}}"), text.index("{{UPLOT_JS}}"))
        self.assertLess(text.index("{{UPLOT_JS}}"), text.index("{{COMMON_JS}}"))
        self.assertLess(text.index("{{COMMON_JS}}"), text.index("{{APP_JS}}"))


if __name__ == "__main__":
    unittest.main()
