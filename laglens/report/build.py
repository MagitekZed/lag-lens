"""``report.html``: the self-contained session report (SPEC_FULL §9.1, INTERFACES §10.3).

Two entry points:

* :class:`ReportBuilder` — the live component (``Cls(ctx)`` with ``start``/
  ``stop``/``build``). Its thread rebuilds ``report.html`` every
  :data:`REPORT_INTERVAL_S` while the store is writing, on ``episode_close``
  (debounced :data:`EPISODE_DEBOUNCE_S`) and :meth:`ReportBuilder.build`
  ``(final=True)`` is called by ``app.shutdown`` after the writer drained.
* :func:`rebuild` — the offline reconstruction used by ``--report DIR`` and by
  ``GET /sessions/<id>/report.html`` when the file is missing: a fresh
  :class:`~laglens.state.State` is filled from ``targets.json`` and the
  JSONL files, ``samples.bin[.gz]`` is replayed into 1 s / 5 s rollups with
  :mod:`laglens.engine.rollup` (no live detection is re-run) and the same
  blob is rendered.

The blob is the one documented in INTERFACES §10.3 and is embedded as
``<script id="laglens-data" type="application/json">`` with ``</`` escaped
as ``<\\/``; ``app.js`` renders it in *static mode*. Size control: the series
is at 5 s resolution and folded to every 3rd window (15 s) once the session is
longer than :data:`THIN_AFTER_S`; raw ±90 s slices are only embedded around
the newest :data:`RAW_MAX_SLICES` episodes/marks within a row budget.

Nothing in the blob may carry the XB7 password, the session token or a MAC
address: :func:`scrub` masks them before serialisation (the config comes from
:func:`laglens.config.public`).
"""
import gzip
import importlib
import json
import logging
import math
import os
import re
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from laglens import config as configmod
from laglens.engine import rollup as rollupmod
from laglens.state import (
    STATUS_STOPPED,
    Episode,
    Event,
    Mark,
    Sample,
    State,
    Target,
)
from laglens.store import SAMPLE_SIZE, SAMPLE_STRUCT, Store
from laglens.supervisor import start_thread
from laglens.version import __version__

log = logging.getLogger("laglens.report")

REPORT_INTERVAL_S = 30.0
EPISODE_DEBOUNCE_S = 10.0
#: SPEC_FULL §9.1: size target < 8 MB at 12 h.
SIZE_LIMIT_BYTES = 8 * 1024 * 1024
#: Sessions longer than this get the series folded to every THIN_FACTOR-th window.
THIN_AFTER_S = 6 * 3600
THIN_FACTOR = 3
SERIES_RES_S = 5
RAW_SLICE_PAD_S = 90
#: A slice never covers more than this (long episodes keep their onset).
RAW_SLICE_MAX_S = 600
RAW_MAX_SLICES = 60
RAW_ROWS_BUDGET = 120_000
RAW_ROWS_PER_SLICE = 20_000
#: How many slices per live build may be fetched from samples.bin (each is a file scan).
RAW_FILE_READS_PER_BUILD = 4
#: A slice is complete once its end is this far in the past (late window).
RAW_SETTLE_S = 12
REFERENCE_KEYS = ("inet4_cf", "inet4_g", "inet6_cf", "inet6_g", "isp_hop4")
DOCSIS_RECENT_POLLS = 20
PATH_HISTORY_MAX = 50
PLACEHOLDERS = ("TITLE", "STYLE", "UPLOT_CSS", "UPLOT_JS", "COMMON_JS", "APP_JS", "DATA_JSON")
DATA_SCRIPT_ID = "laglens-data"
REPORT_FILE = "report.html"
COMCAST_FILE = "comcast_evidence.txt"
WEB_SUBDIR = ("laglens", "web")
ASSET_FILES = {
    "STYLE": "style.css",
    "UPLOT_CSS": "vendor/uPlot.min.css",
    "UPLOT_JS": "vendor/uPlot.iife.min.js",
    "COMMON_JS": "common.js",
    "APP_JS": "app.js",
}
TEMPLATE_FILE = "report_template.html"
GZ_CHUNK = 256 * 1024

METHODOLOGY: List[str] = [
    "Probes: ICMP echo at 4 Hz on a shared 250 ms slot grid to the gateway (the XB7, or your own router), the first Comcast hop, "
    "a mid-path hop and Cloudflare/Google anycast over IPv4 and IPv6; plus NTP, DNS, TCP connect and CDN fetch "
    "probes at lower rates. A probe is 'lost' after timeout_ms (2 s) and 'late' if the reply arrives within "
    "late_window_ms (10 s) after that; late replies never count as lost.",
    "Baselines: per-target rolling 10 min median (p50) and MAD, recomputed every 5 s, after a 60 s warm-up "
    "(loss events after 15 s).",
    "latency_spike: at least 3 consecutive received replies above max(p50 + 5*MAD, 2*p50, p50 + floor); the floor "
    "is max(10 ms, 5*MAD) for the gateway and Xbox, 25 ms for hops and 30 ms for internet targets.",
    "loss_burst: at least 2 lost of 8 consecutive probes or 3 in a row (gateway/Xbox: at least 3 of 8).",
    "Episodes open on a severity >= 2 symptom on a non-hop target (a hop symptom needs a deeper target symptom in "
    "the same or next slot), merge while symptoms are < 5 s apart, close after 10 s quiet, and are discarded as "
    "blips when shorter than 1.5 s.",
    "Loss locus: over the 250 ms slot matrix on the ladder gateway -> Xbox/Comcast hop -> mid-path -> internet, the "
    "locus is the shallowest target lost in at least 70% of the slots where any deeper target was lost. "
    "Hop loss alone is not evidence: a router may deprioritise ICMP to itself; a hop only counts when deeper "
    "targets suffered at the same time.",
    "Classification rules run in a fixed order (first match wins) and attach a confidence; the rejected "
    "alternative is kept with the reason. Episodes overlapping host_stall / monitor_gap / wifi_drop / "
    "iface_errors / link_flap / self_load / vpn_route / clock_jump are tagged and excluded from the Comcast tally.",
    "ICMP to the gateway is answered by its CPU, not by its forwarding path: a slow or lost gateway reply with clean "
    "deeper targets is reported as xb7_cpu_only, not as a LAN fault.",
    "The parallel witness (NTP direction, IGD WAN counters, DOCSIS log) cannot see the Xbox's own packets; "
    "the Xbox LAN probe only shows whether the console answers on the LAN, not whether its game traffic made it "
    "through.",
    "DOCSIS: T3/T4 timeouts, ranging, partial service and uncorrectable codeword growth are read from the XB7 "
    "status pages every 60 s; the modem log clock offset is measured against the probe host and applied before "
    "correlation (within +/-60 s of an episode).",
    "Health score: 100 - min(40, 20*loss%) - min(25, max(0, p95-p50-10)/4) - min(15, jitter/2) - "
    "min(20, episode_minutes/6) - min(20, 40*xbox_loss% while awake) over the reference targets, excluding "
    "host-stall seconds and load-test windows.",
    "Session verdict: per class the sum of duration x confidence over episodes >= 1.5 s; a class with >= 60% share "
    "is the headline, otherwise 'mixed'. Marks: a 'Lag happened' press links to an episode within its window; "
    "fewer than 50% linked marks adds a warning that the probe could not see most presses.",
    "Limitations: unprivileged ICMP sockets; a single vantage point behind the gateway; no view of the Xbox's own "
    "game flows; loss on anycast targets can be the anycast site, not the path; report series beyond 6 h are "
    "folded to 15 s windows and raw samples are only embedded around the newest 60 episodes/marks.",
]

_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
)
_MAC_KEYS = frozenset({"mac", "bssid", "hwaddr", "mac_address", "cm_mac", "cpe_mac"})
_SECRET_KEYS = frozenset({"password", "token", "secret", "passwd"})
#: Delegated IPv6 prefixes are cut to their first three groups (SPEC §6.7 / §9.1 privacy checklist).
_PREFIX_KEYS = frozenset({"v6_prefix", "prefix6"})
_MAC_MASK = "xx:xx:xx:xx:xx:xx"
#: The EUI-64 interface identifier of an IPv6 address (``211:22ff:fe33:4455``) *is* the MAC of the device
#: (the XB7's global address shows up as hop 1 of the v6 path); masked like a MAC.
_EUI64_RE = re.compile(r"(?<=:)[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,2}[fF][fF]:[fF][eE][0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])")
_EUI64_MASK = "xxxx:xxff:fexx:xxxx"


def truncate_v6_prefix(prefix: Any) -> Any:
    """``2601:abcd:1234:5678::/64`` → ``2601:abcd:1234::/64 (truncated)`` (anything else unchanged)."""
    if not isinstance(prefix, str) or ":" not in prefix or "(truncated)" in prefix:
        return prefix
    addr = prefix.split("/")[0]
    groups = [g for g in addr.split("::")[0].split(":") if g]
    if len(groups) <= 3:
        return prefix
    return "%s::/64 (truncated)" % ":".join(groups[:3])

_FALLBACK_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--text:#e6e8ee;--muted:#8b93a7;--accent:#4f8cff;--good:#3ddc84;--warn:#ffb454;--bad:#ff5c5c}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1,h2{font-weight:600}h1{font-size:28px;margin:0 0 4px}h2{font-size:20px;margin:28px 0 10px}
.muted{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:500}
pre{white-space:pre-wrap;word-break:break-word;background:#0b0d11;border:1px solid var(--line);border-radius:8px;padding:12px}
.bad{color:var(--bad)}.good{color:var(--good)}.warn{color:var(--warn)}
{{STYLE}}
{{UPLOT_CSS}}
</style></head>
<body><main>
<h1>Lag Lens report</h1>
<div id="subtitle" class="muted"></div>
<div class="panel"><h2 style="margin-top:0">Verdict</h2><div id="verdict"></div></div>
<div class="panel"><h2 style="margin-top:0">Tell Comcast</h2><pre id="comcast"></pre></div>
<h2>Per-target stats (session)</h2><div class="panel"><table id="stats"></table></div>
<h2>Episodes</h2><div class="panel"><table id="episodes"></table></div>
<h2>Marks</h2><div class="panel"><table id="marks"></table></div>
<h2>Methodology</h2><div class="panel"><ul id="methodology"></ul></div>
<p class="muted">The full interactive template (laglens/web/report_template.html) was not available when this report was built; this is the built-in fallback view of the same data.</p>
</main>
<script id="laglens-data" type="application/json">{{DATA_JSON}}</script>
<script>{{UPLOT_JS}}</script>
<script>{{COMMON_JS}}</script>
<script>{{APP_JS}}</script>
<script>
(function(){
  var el=document.getElementById('laglens-data'); if(!el) return;
  var d; try{ d=JSON.parse(el.textContent); }catch(e){ return; }
  function esc(s){ return String(s==null?'':s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];}); }
  function fmt(t){ return t?new Date(t*1000).toLocaleString():''; }
  var s=d.session||{};
  document.getElementById('subtitle').textContent='Session '+(s.id||'')+(s.label?' - '+s.label:'')+' - started '+fmt(s.started)+(s.stopped?' - stopped '+fmt(s.stopped):'')+' - v'+(d.version||'');
  var v=d.verdict||{}; var h=(d.state||{}).headline||{};
  document.getElementById('verdict').innerHTML='<p><strong>'+esc(h.text||'')+'</strong> <span class="muted">'+esc(h.action||'')+'</span></p><p>'+esc(v.text||'No verdict yet.')+'</p><p class="muted">confidence: '+esc(v.confidence||'')+'</p>';
  document.getElementById('comcast').textContent=d.comcast_text||'(no Comcast-relevant episodes)';
  var tg={}; (d.targets||[]).forEach(function(t){tg[t.id]=t;});
  var st=((d.stats||{}).targets)||{}; var rows='<tr><th>target</th><th>sent</th><th>loss%</th><th>late%</th><th>p50</th><th>p95</th><th>max</th><th>jitter</th><th>outage s</th><th>episodes</th></tr>';
  Object.keys(st).forEach(function(id){var x=st[id]; var t=tg[id]||{}; rows+='<tr><td>'+esc(t.label||t.key||id)+'</td><td>'+esc(x.sent)+'</td><td>'+esc(x.loss_pct)+'</td><td>'+esc(x.late_pct)+'</td><td>'+esc(x.p50)+'</td><td>'+esc(x.p95)+'</td><td>'+esc(x.max)+'</td><td>'+esc(x.jitter)+'</td><td>'+esc(x.longest_outage_s)+'</td><td>'+esc(x.episodes)+'</td></tr>';});
  document.getElementById('stats').innerHTML=rows;
  var er='<tr><th>start</th><th>dur s</th><th>class</th><th>conf</th><th>direction</th><th>activity</th><th>evidence</th></tr>';
  (d.episodes||[]).forEach(function(e){er+='<tr><td>'+esc(fmt(e.t0))+'</td><td>'+esc(e.dur_s)+'</td><td>'+esc(e['class'])+(e.subclass?' / '+esc(e.subclass):'')+'</td><td>'+esc(e.confidence)+'</td><td>'+esc(e.direction)+'</td><td>'+esc(e.activity)+'</td><td>'+esc((e.evidence||[]).join('; '))+'</td></tr>';});
  document.getElementById('episodes').innerHTML=er;
  var mr='<tr><th>pressed</th><th>t_est</th><th>activity</th><th>note</th><th>episode</th><th>assessment</th></tr>';
  (d.marks||[]).forEach(function(m){mr+='<tr><td>'+esc(fmt(m.t_pressed))+'</td><td>'+esc(fmt(m.t_est))+'</td><td>'+esc(m.activity)+'</td><td>'+esc(m.note)+'</td><td>'+esc(m.episode||'none')+'</td><td>'+esc(m.assessment||'')+'</td></tr>';});
  document.getElementById('marks').innerHTML=mr;
  document.getElementById('methodology').innerHTML=(d.methodology||[]).map(function(x){return '<li>'+esc(x)+'</li>';}).join('');
})();
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _json_default(o: Any) -> Any:
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    return str(o)


def _finite(v: float) -> Optional[float]:
    return v if math.isfinite(v) else None


def scrub(obj: Any, secrets: Sequence[str] = ()) -> Any:
    """Return a copy of ``obj`` safe to embed: MACs masked, secrets removed, NaN → null.

    * values of keys named ``mac``/``bssid``/… become ``"xx:xx:xx:xx:xx:xx"``;
    * values of keys named ``password``/``token``/``secret`` become ``"***"``
      (``None``/empty stay as they are so a report can show "not configured");
    * values of keys named ``v6_prefix``/``prefix6`` are truncated to three groups;
    * every string has MAC addresses masked and every literal secret in
      ``secrets`` replaced by ``***``;
    * non-finite floats become ``None`` (``json.dumps`` would emit ``NaN``,
      which ``JSON.parse`` rejects).
    """
    secrets = [s for s in secrets if s]

    def fix_str(s: str) -> str:
        for sec in secrets:
            if sec in s:
                s = s.replace(sec, "***")
        if ":" in s or "-" in s:
            s = _MAC_RE.sub(_MAC_MASK, s)
            if "ff:fe" in s.lower():
                s = _EUI64_RE.sub(_EUI64_MASK, s)
        return s

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return fix_str(v)
        if isinstance(v, bool) or v is None or isinstance(v, int):
            return v
        if isinstance(v, float):
            return _finite(v)
        if isinstance(v, dict):
            out: Dict[str, Any] = {}
            for k, x in v.items():
                ks = str(k)
                lk = ks.lower()
                if lk in _MAC_KEYS and isinstance(x, str) and x:
                    out[ks] = _MAC_MASK
                elif lk in _PREFIX_KEYS and isinstance(x, str):
                    out[ks] = truncate_v6_prefix(x)
                elif isinstance(x, str) and x and any(sk in lk for sk in _SECRET_KEYS):
                    out[ks] = "***"
                else:
                    out[ks] = walk(x)
            return out
        if isinstance(v, (list, tuple)):
            return [walk(x) for x in v]
        if hasattr(v, "to_dict"):
            return walk(v.to_dict())
        return v

    return walk(obj)


def escape_json_for_html(s: str) -> str:
    """Make a JSON text safe inside ``<script type="application/json">``: ``</`` → ``<\\/``."""
    return s.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _escape_js(s: str) -> str:
    """Keep inlined JS/CSS from closing the surrounding tag (``</script`` → ``<\\/script``)."""
    return re.sub(r"</(script|style)", lambda m: "<\\/" + m.group(1), s, flags=re.IGNORECASE)


def write_atomic_file(path: Path, data: str) -> Path:
    """tmp + ``os.replace`` write (used by :func:`rebuild`, which has no live store)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp-%d" % os.getpid())
    with open(tmp, "wb") as fh:
        fh.write(data.encode("utf-8"))
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    os.replace(tmp, path)
    return path


def _local(t: Optional[float]) -> str:
    if not t:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(t)))
    except (ValueError, OverflowError, OSError):
        return str(t)


def _local_hour(t: float) -> int:
    try:
        return time.localtime(float(t)).tm_hour
    except (ValueError, OverflowError, OSError):
        return 0


def _get(d: Any, *keys: str, default: Any = None) -> Any:
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return default if cur is None else cur


# ---------------------------------------------------------------------------
# Assets / template
# ---------------------------------------------------------------------------
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def load_assets(root: Optional[Path]) -> Dict[str, str]:
    """Template + inlined assets from ``<root>/laglens/web``; missing files degrade.

    Returns a dict with the keys of :data:`PLACEHOLDERS` (minus ``TITLE`` and
    ``DATA_JSON``) plus ``template`` and ``missing`` (a list of names).
    """
    web = Path(root or repo_root()).joinpath(*WEB_SUBDIR)
    out: Dict[str, Any] = {"missing": []}
    tpl = web / TEMPLATE_FILE
    try:
        out["template"] = tpl.read_text(encoding="utf-8")
    except OSError:
        out["template"] = _FALLBACK_TEMPLATE
        out["missing"].append(TEMPLATE_FILE)
    for key, rel in ASSET_FILES.items():
        try:
            out[key] = (web / rel).read_text(encoding="utf-8")
        except OSError:
            out[key] = ""
            out["missing"].append(rel)
    return out


def render_html(blob: dict, assets: Dict[str, Any], title: Optional[str] = None) -> str:
    """Fill the template placeholders; the blob is serialised with ``</`` escaped."""
    data = json.dumps(blob, separators=(",", ":"), ensure_ascii=False, default=_json_default, allow_nan=False)
    data = escape_json_for_html(data)
    html = assets.get("template") or _FALLBACK_TEMPLATE
    sess = blob.get("session") or {}
    if title is None:
        title = "Lag Lens report %s" % (sess.get("id") or "")
        if sess.get("label"):
            title += " - %s" % sess["label"]
    repl = {
        "TITLE": _html_text(title),
        "STYLE": _escape_js(assets.get("STYLE", "")),
        "UPLOT_CSS": _escape_js(assets.get("UPLOT_CSS", "")),
        "UPLOT_JS": _escape_js(assets.get("UPLOT_JS", "")),
        "COMMON_JS": _escape_js(assets.get("COMMON_JS", "")),
        "APP_JS": _escape_js(assets.get("APP_JS", "")),
        "DATA_JSON": data,
    }
    # Replace the data last so nothing inside it is ever treated as a placeholder.
    for key in ("TITLE", "STYLE", "UPLOT_CSS", "UPLOT_JS", "COMMON_JS", "APP_JS"):
        html = html.replace("{{%s}}" % key, repl[key])
    html = html.replace("{{DATA_JSON}}", repl["DATA_JSON"])
    for key in PLACEHOLDERS:
        if ("{{%s}}" % key) in html:
            log.warning("report template still contains {{%s}} after rendering", key)
    return html


def _html_text(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------------------------------------------------------------------------
# Series (GET /api/series shape) — local builder used when server.series is absent
# ---------------------------------------------------------------------------
_TARGET_ARRAYS = ("p50", "p95", "max", "lost", "late", "n", "jit")
_COLLECTOR_ARRAYS: Dict[str, Tuple[str, ...]] = {
    "iface": ("rx_mbps", "tx_mbps", "err", "drop", "carrier_changes", "mcast_pps"),
    "wan": ("rx_mbps", "tx_mbps"),
    "wifi": ("rssi", "noise"),
    "docsis": ("ds_snr_min", "us_pwr_max", "uncorr_delta"),
    "ntp": ("offset_shift",),
}


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return _finite(float(v)) if isinstance(v, float) else v
    return None


def _sum_opt(*vals: Any) -> Optional[float]:
    nums = [v for v in (_num(x) for x in vals) if v is not None]
    return sum(nums) if nums else None


def build_series_local(
    state: State,
    store: Optional[Store],
    t_from: float,
    t_to: float,
    res: int = SERIES_RES_S,
    target_ids: Optional[Iterable[int]] = None,
    file_rows: Optional[Iterable[dict]] = None,
) -> dict:
    """The ``GET /api/series`` body (SPEC §10.2) from the RAM rings plus optional ``rollups.jsonl`` rows.

    ``file_rows`` (older rows read from the store) are applied first and the
    RAM rings overwrite them, so a resumed session or a replayed one gets the
    union. ``res`` is always 5 here (the report never embeds 1 s data).
    """
    res = 5
    t_from = int(math.floor(t_from / res) * res)
    t_to = int(math.ceil(t_to))
    if t_to <= t_from:
        t_to = t_from + res
    grid = list(range(t_from, t_to, res))
    n = len(grid)
    idx = {t: i for i, t in enumerate(grid)}
    ids = set(target_ids) if target_ids is not None else None

    targets: Dict[str, Dict[str, list]] = {}

    def tarr(tid: int) -> Dict[str, list]:
        key = str(tid)
        d = targets.get(key)
        if d is None:
            d = {k: [None] * n for k in _TARGET_ARRAYS}
            targets[key] = d
        return d

    coll: Dict[str, Dict[str, list]] = {k: {a: [None] * n for a in arrs} for k, arrs in _COLLECTOR_ARRAYS.items()}
    slots_lost: List[Optional[list]] = [None] * n
    xbox_state: List[Optional[str]] = [None] * n
    stall: List[Optional[int]] = [None] * n
    ntp_offset: List[Optional[float]] = [None] * n

    def apply_probe(i: int, r: dict) -> None:
        tid = r.get("id")
        if not isinstance(tid, int) or (ids is not None and tid not in ids):
            return
        d = tarr(tid)
        for k in _TARGET_ARRAYS:
            d[k][i] = _num(r.get(k))

    def apply_collector(i: int, kind: str, row: dict) -> None:
        if not isinstance(row, dict):
            return
        if kind == "iface":
            c = coll["iface"]
            c["rx_mbps"][i] = _num(row.get("rx_mbps"))
            c["tx_mbps"][i] = _num(row.get("tx_mbps"))
            c["err"][i] = _sum_opt(row.get("rx_err"), row.get("tx_err"))
            c["drop"][i] = _sum_opt(row.get("rx_drop"), row.get("tx_drop"))
            c["carrier_changes"][i] = _num(row.get("carrier_changes"))
            c["mcast_pps"][i] = _num(row.get("mcast_pps"))
        elif kind == "wan":
            coll["wan"]["rx_mbps"][i] = _num(row.get("rx_mbps"))
            coll["wan"]["tx_mbps"][i] = _num(row.get("tx_mbps"))
        elif kind == "wifi":
            coll["wifi"]["rssi"][i] = _num(row.get("rssi"))
            coll["wifi"]["noise"][i] = _num(row.get("noise"))
        elif kind == "docsis":
            for k in _COLLECTOR_ARRAYS["docsis"]:
                coll["docsis"][k][i] = _num(row.get(k))
        elif kind == "ntp":
            offs = [v for v in (_num(_get(x, "offset")) for x in row.values() if isinstance(x, dict)) if v is not None]
            ntp_offset[i] = (sum(offs) / len(offs)) if offs else None
        elif kind == "xbox":
            v = row.get("state")
            xbox_state[i] = str(v) if v is not None else None
        elif kind == "host":
            late = _num(row.get("late_ms_max")) or 0
            gap = _num(row.get("loop_gap_ms")) or 0
            stall[i] = 1 if (row.get("stall") or late > 50 or gap > 200) else 0

    def apply_row(row: dict) -> None:
        t = row.get("t")
        if not isinstance(t, (int, float)):
            return
        i = idx.get(int(t))
        if i is None:
            return
        if "id" in row and "n" in row:
            apply_probe(i, row)
            return
        if "slots" in row:
            v = row.get("slots")
            slots_lost[i] = list(v) if isinstance(v, list) else None
            return
        for kind in ("iface", "host", "wifi", "wan", "ntp", "docsis", "xbox"):
            if kind in row:
                apply_collector(i, kind, row[kind])

    for row in file_rows or ():
        if isinstance(row, dict):
            apply_row(row)
    try:
        for tid, rl in state.rollups(5, t_from, t_to, target_ids).items():
            for r in rl:
                i = idx.get(int(r.t))
                if i is not None:
                    apply_probe(i, r.to_row())
        for kind in ("iface", "host", "wifi", "wan", "ntp", "docsis", "xbox", "slots"):
            for row in state.rows5(kind, t_from, t_to):
                apply_row(row)
    except Exception:  # noqa: BLE001 - a ring hiccup must not kill the report
        log.exception("series: ring read failed")

    # NTP offset shift: change of the mean offset between consecutive windows.
    prev: Optional[float] = None
    for i in range(n):
        cur = ntp_offset[i]
        if cur is not None and prev is not None:
            coll["ntp"]["offset_shift"][i] = round(cur - prev, 3)
        if cur is not None:
            prev = cur

    segments = _segments(state, targets, n)
    out = {
        "res": res,
        "from": t_from,
        "to": t_to,
        "t": grid,
        "targets": targets,
        "iface": coll["iface"],
        "wan": coll["wan"],
        "wifi": coll["wifi"],
        "docsis": coll["docsis"],
        "ntp": coll["ntp"],
        "segments": segments,
        "slots_lost": slots_lost,
        "xbox_state": xbox_state,
        "stall": stall,
    }
    return out


def _segments(state: State, targets: Dict[str, Dict[str, list]], n: int) -> Dict[str, list]:
    """Approximate path segments from p50s (SPEC §8.3 timeline 4), clamped ≥ 0."""
    def p50_of(key: str) -> Optional[list]:
        t = state.target(key)
        if t is None:
            return None
        d = targets.get(str(t.id))
        return d["p50"] if d else None

    gw = p50_of("gw4")
    isp = p50_of("isp_hop4")
    mid = p50_of("mid_hop4")
    inets = [a for a in (p50_of("inet4_cf"), p50_of("inet4_g")) if a]
    lan: List[Optional[float]] = [None] * n
    docsis: List[Optional[float]] = [None] * n
    comcast: List[Optional[float]] = [None] * n
    internet: List[Optional[float]] = [None] * n
    for i in range(n):
        g = gw[i] if gw else None
        s = isp[i] if isp else None
        m = mid[i] if mid else None
        vals = [a[i] for a in inets if a[i] is not None]
        inet = min(vals) if vals else None
        lan[i] = g
        if g is not None and s is not None:
            docsis[i] = round(max(0.0, s - g), 2)
        if s is not None and m is not None:
            comcast[i] = round(max(0.0, m - s), 2)
        base = m if m is not None else (s if s is not None else g)
        if inet is not None and base is not None:
            internet[i] = round(max(0.0, inet - base), 2)
    return {"lan": lan, "docsis": docsis, "comcast": comcast, "internet": internet}


def _fold(values: Sequence[Any], how: str) -> Any:
    nums = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if how == "sum":
        return sum(nums) if nums else None
    if how == "max":
        return max(nums) if nums else None
    if how == "mean":
        return round(sum(nums) / len(nums), 2) if nums else None
    if how == "first":
        for v in values:
            if v is not None:
                return v
        return None
    return None


_FOLD_TARGET = {"p50": "mean", "p95": "max", "max": "max", "lost": "sum", "late": "sum", "n": "sum", "jit": "mean"}
SLOTS_PER_WINDOW = 20


def _fold_slots(values: Sequence[Any], factor: int, width: int) -> Optional[list]:
    """Concatenate ``factor`` slot-bitmask rows; a missing row is padded with ``None`` so slot positions stay aligned."""
    rows = [v if isinstance(v, list) else None for v in values]
    if not any(r is not None for r in rows):
        return None
    out: list = []
    for i in range(factor):
        r = rows[i] if i < len(rows) else None
        if r is None:
            out.extend([None] * width)
        else:
            out.extend(list(r[:width]) + [None] * max(0, width - len(r)))
    return out


def thin_series(series: dict, factor: int = THIN_FACTOR) -> dict:
    """Fold every ``factor`` consecutive windows into one (counts summed, p95/max kept as max).

    The ``t`` grid keeps the first window's time of each group so the result
    is still a regular grid at ``res * factor`` seconds; ``res`` is updated.
    ``slots_lost`` rows are concatenated (``factor × 20`` masks per group); a
    window without a slots row contributes 20 ``None`` so the masks keep
    their 250 ms positions.
    """
    if factor <= 1:
        return series
    t = series.get("t") or []
    n = len(t)
    groups = list(range(0, n, factor))
    if not groups:
        return series

    def fold_arr(arr: Sequence[Any], how: str) -> list:
        return [_fold(arr[g:g + factor], how) for g in groups]

    slots_src = series.get("slots_lost") or []
    width = next((len(v) for v in slots_src if isinstance(v, list) and v), SLOTS_PER_WINDOW)

    out = dict(series)
    out["res"] = int(series.get("res", SERIES_RES_S)) * factor
    out["thinned"] = factor
    out["t"] = [t[g] for g in groups]
    out["targets"] = {
        tid: {k: fold_arr(arrs.get(k, []), _FOLD_TARGET[k]) for k in _TARGET_ARRAYS}
        for tid, arrs in (series.get("targets") or {}).items()
    }
    counters = ("err", "drop", "carrier_changes", "uncorr_delta", "us_pwr_max")
    for kind, arrs in _COLLECTOR_ARRAYS.items():
        src = series.get(kind) or {}
        out[kind] = {k: fold_arr(src.get(k, []), "max" if k in counters else "mean") for k in arrs}
    seg = series.get("segments") or {}
    out["segments"] = {k: fold_arr(seg.get(k, []), "mean") for k in ("lan", "docsis", "comcast", "internet")}
    out["slots_lost"] = [_fold_slots(slots_src[g:g + factor], factor, width) for g in groups]
    out["xbox_state"] = fold_arr(series.get("xbox_state") or [], "first")
    out["stall"] = fold_arr(series.get("stall") or [], "max")
    return out


# ---------------------------------------------------------------------------
# Hour heatmap, activity stats
# ---------------------------------------------------------------------------
def reference_ids(state: State) -> List[int]:
    ids = [t.id for t in (state.target(k) for k in REFERENCE_KEYS) if t is not None]
    if not ids:
        ids = [t.id for t in state.targets_list() if t.kind == "icmp" and t.role in ("anycast", "isp_hop")]
    return ids


def hour_heatmap(state: State, t_from: float, t_to: float, episodes: Sequence[dict]) -> List[dict]:
    """24 rows ``{"hour","loss_pct","p95","episodes","windows"}`` from the 5 s rollups of the reference targets."""
    rows = [{"hour": h, "loss_pct": None, "p95": None, "episodes": 0, "windows": 0} for h in range(24)]
    sent = [0] * 24
    lost = [0] * 24
    p95s: List[List[float]] = [[] for _ in range(24)]
    try:
        for tid, rl in state.rollups(5, t_from, t_to, reference_ids(state)).items():
            for r in rl:
                h = _local_hour(r.t)
                sent[h] += r.n
                lost[h] += r.lost
                rows[h]["windows"] += 1
                if r.p95 is not None:
                    p95s[h].append(r.p95)
    except Exception:  # noqa: BLE001
        log.exception("hour heatmap: ring read failed")
    for ep in episodes:
        t0 = ep.get("t0") if isinstance(ep, dict) else None
        if isinstance(t0, (int, float)):
            rows[_local_hour(t0)]["episodes"] += 1
    for h in range(24):
        if sent[h]:
            rows[h]["loss_pct"] = round(100.0 * lost[h] / sent[h], 2)
        if p95s[h]:
            rows[h]["p95"] = round(rollupmod.percentile(sorted(p95s[h]), 95) or 0.0, 2)
    return rows


def activity_stats(state: State, now: Optional[float] = None) -> Dict[str, dict]:
    """``{"<activity>": <stats targets dict>}`` for every activity seen in the tags."""
    with state.lock:
        seen: List[str] = []
        for tag in state.tags:
            a = tag.get("activity")
            if isinstance(a, str) and a and a not in seen:
                seen.append(a)
        cur = state.activity.get("current")
    if isinstance(cur, str) and cur and cur not in seen:
        seen.append(cur)
    out: Dict[str, dict] = {}
    for a in seen:
        try:
            out[a] = rollupmod.stats(state, "session", activity=a, now=now).get("targets", {})
        except Exception:  # noqa: BLE001
            log.exception("activity stats for %r failed", a)
            out[a] = {}
    return out


# ---------------------------------------------------------------------------
# Raw slices
# ---------------------------------------------------------------------------
class SliceWindow:
    """One ±90 s raw window around an episode or a mark."""

    __slots__ = ("id", "ref", "from_ms", "to_ms", "rows", "complete")

    def __init__(self, sid: str, ref: float, t_from: float, t_to: float) -> None:
        self.id = sid
        self.ref = float(ref)
        self.from_ms = int(t_from * 1000)
        self.to_ms = int(t_to * 1000)
        self.rows: List[list] = []
        self.complete = False

    def to_dict(self) -> dict:
        return {"from_ms": self.from_ms, "to_ms": self.to_ms, "rows": self.rows}


def slice_windows(episodes: Sequence[dict], marks: Sequence[dict], now: float, limit: int = RAW_MAX_SLICES) -> List[SliceWindow]:
    """The newest ``limit`` windows (episodes and marks together), newest first."""
    wins: List[SliceWindow] = []
    for ep in episodes:
        if not isinstance(ep, dict) or not isinstance(ep.get("t0"), (int, float)):
            continue
        t0 = float(ep["t0"])
        t1 = ep.get("t1")
        t1 = float(t1) if isinstance(t1, (int, float)) else now
        start = t0 - RAW_SLICE_PAD_S
        end = min(t1 + RAW_SLICE_PAD_S, start + RAW_SLICE_MAX_S)
        wins.append(SliceWindow(str(ep.get("id")), t0, start, end))
    for m in marks:
        if not isinstance(m, dict):
            continue
        ref = m.get("t_est") if isinstance(m.get("t_est"), (int, float)) else m.get("t_pressed")
        if not isinstance(ref, (int, float)):
            continue
        wins.append(SliceWindow(str(m.get("id")), float(ref), ref - RAW_SLICE_PAD_S, ref + RAW_SLICE_PAD_S))
    wins.sort(key=lambda w: w.ref, reverse=True)
    return wins[:limit]


def collect_slices(rows: Iterable[Sequence[int]], windows: Sequence[SliceWindow], per_slice: int = RAW_ROWS_PER_SLICE) -> None:
    """Single pass over time-ordered sample rows; fills ``w.rows`` as ``[ts_ms,id,kind,flags,value]``.

    Rows may be slightly out of order (late replies up to 10 s): a window stays
    "active" 15 s past its end so those are still caught.
    """
    wins = sorted(windows, key=lambda w: w.from_ms)
    ptr = 0
    active: List[SliceWindow] = []
    for row in rows:
        ts = row[0]
        while ptr < len(wins) and wins[ptr].from_ms <= ts:
            active.append(wins[ptr])
            ptr += 1
        if not active:
            continue
        keep: List[SliceWindow] = []
        for w in active:
            if ts >= w.to_ms + 15_000:
                continue
            keep.append(w)
            if w.from_ms <= ts < w.to_ms and len(w.rows) < per_slice:
                w.rows.append([row[0], row[1], row[2], row[3], row[5]])
        active = keep


def iter_sample_rows(session_dir: Path) -> Iterator[Tuple[int, int, int, int, int, int]]:
    """Stream ``samples.bin`` (or ``.gz``) as ``(ts_ms,id,kind,flags,seq,value)`` without loading it all.

    A torn trailing record and a truncated gzip stream yield what was readable.
    """
    plain = Path(session_dir) / "samples.bin"
    gz = plain.with_name("samples.bin.gz")
    carry = b""

    def records(chunk: bytes) -> Iterator[Tuple[int, int, int, int, int, int]]:
        nonlocal carry
        buf = carry + chunk
        usable = len(buf) - (len(buf) % SAMPLE_SIZE)
        for off in range(0, usable, SAMPLE_SIZE):
            yield SAMPLE_STRUCT.unpack_from(buf, off)
        carry = buf[usable:]

    try:
        if plain.exists():
            with open(plain, "rb") as fh:
                while True:
                    chunk = fh.read(GZ_CHUNK)
                    if not chunk:
                        break
                    for rec in records(chunk):
                        yield rec
        elif gz.exists():
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            with open(gz, "rb") as fh:
                while True:
                    raw = fh.read(GZ_CHUNK)
                    if not raw:
                        break
                    out = d.decompress(raw)
                    if out:
                        for rec in records(out):
                            yield rec
                    while d.eof and d.unused_data:
                        rest = d.unused_data
                        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        out = d.decompress(rest)
                        if out:
                            for rec in records(out):
                                yield rec
            tail = d.flush()
            if tail:
                for rec in records(tail):
                    yield rec
    except (OSError, EOFError, zlib.error) as exc:
        log.warning("samples.bin read stopped early: %s", exc)


class SliceCache:
    """Keeps the raw slices a live builder already captured (the raw ring is only 15 min)."""

    def __init__(self) -> None:
        self._done: Dict[str, SliceWindow] = {}

    def get(self, sid: str, w: SliceWindow) -> Optional[SliceWindow]:
        c = self._done.get(sid)
        if c is None or not c.complete or c.from_ms != w.from_ms or c.to_ms != w.to_ms:
            return None
        return c

    def put(self, w: SliceWindow) -> None:
        self._done[w.id] = w
        if len(self._done) > RAW_MAX_SLICES * 2:
            for k in sorted(self._done, key=lambda k: self._done[k].ref)[: len(self._done) - RAW_MAX_SLICES]:
                self._done.pop(k, None)


def live_raw_slices(
    state: State,
    store: Optional[Store],
    windows: Sequence[SliceWindow],
    now: float,
    cache: Optional[SliceCache] = None,
    file_reads: int = RAW_FILE_READS_PER_BUILD,
) -> Dict[str, dict]:
    """Raw slices for the live builder: raw ring first, cache second, ``samples.bin`` last (bounded)."""
    out: Dict[str, dict] = {}
    budget = RAW_ROWS_BUDGET
    now_ms = int(now * 1000)
    ring_start_ms = now_ms - (15 * 60 - 30) * 1000
    reads = 0
    for w in windows:
        if budget <= 0:
            break
        cached = cache.get(w.id, w) if cache is not None else None
        if cached is not None:
            w = cached
        elif w.from_ms >= ring_start_ms:
            try:
                for s in state.raw_all(w.from_ms / 1000.0, w.to_ms / 1000.0):
                    if len(w.rows) >= RAW_ROWS_PER_SLICE:
                        break
                    w.rows.append(s.to_row())
            except Exception:  # noqa: BLE001
                log.exception("raw slice %s from ring failed", w.id)
            w.complete = w.to_ms + RAW_SETTLE_S * 1000 <= now_ms
            if w.complete and cache is not None:
                cache.put(w)
        elif store is not None and reads < file_reads:
            reads += 1
            try:
                rows = store.read_samples(w.from_ms, w.to_ms, max_rows=RAW_ROWS_PER_SLICE)
                w.rows = [[r[0], r[1], r[2], r[3], r[5]] for r in rows]
            except Exception:  # noqa: BLE001
                log.exception("raw slice %s from samples.bin failed", w.id)
            w.complete = w.to_ms + RAW_SETTLE_S * 1000 <= now_ms
            if w.complete and cache is not None:
                cache.put(w)
        else:
            continue
        out[w.id] = w.to_dict()
        budget -= len(w.rows)
    return out


# ---------------------------------------------------------------------------
# File-derived blocks (docsis / igd / path) — used when the component is absent
# ---------------------------------------------------------------------------
def docsis_from_rows(rows: Sequence[dict], last: int = DOCSIS_RECENT_POLLS) -> Optional[dict]:
    """``GET /api/docsis`` shape from ``xb7.jsonl`` rows; ``None`` when there are none."""
    polls = [r for r in rows if isinstance(r, dict)]
    if not polls:
        return None
    recent = polls[-last:]
    logs: List[dict] = []
    for p in polls:
        for line in p.get("log_new") or []:
            if isinstance(line, dict):
                logs.append(line)
    ok = any(p.get("ok") for p in recent)
    return {"status": "ok" if ok else "error", "source": "file", "polls": recent, "log": logs[-200:]}


def igd_from_rows(rows: Sequence[dict]) -> Optional[dict]:
    """``GET /api/igd`` shape from ``igd.jsonl`` rows; ``None`` when there are none."""
    last = None
    for r in rows:
        if isinstance(r, dict):
            last = r
    if last is None:
        return None
    out = dict(last)
    out.setdefault("status", "ok")
    out["source"] = "file"
    return out


def path_from_rows(rows: Sequence[dict], base: Optional[dict] = None) -> dict:
    """``GET /api/path`` shape from ``path.jsonl`` rows (last v4 and v6 discovery)."""
    out = {"v4": [], "v6": [], "roles": {}, "discovered_at": None, "changes": 0, "history": [], "method": None}
    if isinstance(base, dict):
        out.update({k: v for k, v in base.items() if v is not None})
    changes = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        dst = str(r.get("dst") or "")
        hops = r.get("hops") if isinstance(r.get("hops"), list) else []
        fam = "v6" if ":" in dst else "v4"
        out[fam] = hops
        if isinstance(r.get("roles"), dict):
            out["roles"] = r["roles"]
        if r.get("changed"):
            changes += 1
        if r.get("t") is not None:
            out["discovered_at"] = r.get("t")
        if r.get("method"):
            out["method"] = r.get("method")
    if rows:
        out["changes"] = max(int(out.get("changes") or 0), changes)
        out["history"] = [r for r in rows if isinstance(r, dict)][-PATH_HISTORY_MAX:]
    return out


# ---------------------------------------------------------------------------
# Blob assembly
# ---------------------------------------------------------------------------
class BlobSources:
    """Everything :func:`assemble_blob` needs, gathered by the live builder or :func:`rebuild`."""

    def __init__(self, state: State, store: Optional[Store], cfg: dict) -> None:
        self.state = state
        self.store = store
        self.cfg = cfg or {}
        self.now: Optional[float] = None
        self.t_from: Optional[float] = None
        self.session: Optional[dict] = None
        self.events: Optional[List[dict]] = None
        self.episodes: Optional[List[dict]] = None
        self.marks: Optional[List[dict]] = None
        self.tags: Optional[List[dict]] = None
        self.path: Optional[dict] = None
        self.docsis: Any = "unset"
        self.igd: Any = "unset"
        self.loadtests: Optional[List[dict]] = None
        self.doctor: Optional[List[dict]] = None
        self.collectors: Optional[dict] = None
        self.verdict: Optional[dict] = None
        self.comcast_text: Optional[str] = None
        self.series: Optional[dict] = None
        self.file_rollups: Optional[List[dict]] = None
        self.raw_slices: Optional[Dict[str, dict]] = None
        self.secrets: List[str] = []
        self.extra: Dict[str, Any] = {}


def assemble_blob(src: BlobSources) -> dict:
    """Build the INTERFACES §10.3 blob from a :class:`BlobSources`."""
    st = src.state
    store = src.store
    now = float(src.now if src.now is not None else st.now())
    t_from = float(src.t_from if src.t_from is not None else st.t0)

    with st.lock:
        events = src.events if src.events is not None else [e.to_dict() for e in st.events]
        episodes = src.episodes if src.episodes is not None else [e.to_dict(brief=False) for e in st.episodes]
        marks = src.marks if src.marks is not None else [m.to_dict() for m in st.marks]
        tags = src.tags if src.tags is not None else [dict(t) for t in st.tags]
        verdict = dict(src.verdict if src.verdict is not None else st.verdict)
        doctor = list(src.doctor if src.doctor is not None else st.doctor)
        path = dict(src.path if src.path is not None else st.path)
        targets = [t.to_dict() for t in st.targets_list()]

    session = src.session
    if session is None:
        session = _read_file_json(store, "session.json") or {"id": st.session_id, "started": st.t0, "label": st.label}

    snapshot = st.snapshot()
    stats_session = _safe(lambda: rollupmod.stats(st, "session", now=now), {"window": "session", "targets": {}})
    stats_1h = _safe(lambda: rollupmod.stats(st, "1h", now=now), {"window": "1h", "targets": {}})

    series = src.series
    if series is None:
        series = build_series_local(st, store, t_from, now, file_rows=src.file_rollups)
    if now - t_from > THIN_AFTER_S:
        series = thin_series(series, THIN_FACTOR)

    raw_slices = src.raw_slices if src.raw_slices is not None else {}
    docsis = src.docsis if src.docsis != "unset" else (docsis_from_rows(_read_json(store, "xb7")) if store else None)
    igd = src.igd if src.igd != "unset" else (igd_from_rows(_read_json(store, "igd")) if store else None)
    loadtests = src.loadtests if src.loadtests is not None else _read_json(store, "loadtests")
    collectors = src.collectors if src.collectors is not None else st.collectors()
    comcast = src.comcast_text if src.comcast_text is not None else (verdict.get("comcast") or "")

    blob = {
        "version": __version__,
        "generated_at": now,
        "generated_local": _local(now),
        "static": True,
        "session": session,
        "targets": targets,
        "state": snapshot,
        "stats": stats_session,
        "stats_1h": stats_1h,
        "series": series,
        "events": events,
        "episodes": episodes,
        "marks": marks,
        "tags": tags,
        "raw_slices": raw_slices,
        "path": path,
        "docsis": docsis,
        "igd": igd,
        "loadtests": loadtests,
        "doctor": doctor,
        "collectors": collectors,
        "config": configmod.public(src.cfg),
        "verdict": verdict,
        "comcast_text": comcast or "",
        "activity_stats": activity_stats(st, now=now),
        "hour_heatmap": hour_heatmap(st, t_from, now, episodes),
        "methodology": list(METHODOLOGY),
    }
    blob.update(src.extra)
    return scrub(blob, src.secrets)


def _safe(fn: Callable[[], Any], default: Any) -> Any:
    try:
        return fn()
    except Exception:  # noqa: BLE001
        log.exception("report: a blob section failed; using a placeholder")
        return default


def _read_json(store: Optional[Store], name: str) -> List[dict]:
    if store is None:
        return []
    try:
        return store.read_json(name)
    except Exception:  # noqa: BLE001
        log.exception("cannot read %s.jsonl", name)
        return []


def _read_file_json(store: Optional[Store], name: str) -> Optional[Any]:
    if store is None:
        return None
    try:
        return store.read_file_json(name)
    except Exception:  # noqa: BLE001
        return None


def _secrets_of(cfg: dict, token: Optional[str]) -> List[str]:
    out: List[str] = []
    pw = _get(cfg, "docsis", "password")
    if isinstance(pw, str) and len(pw) >= 3:
        out.append(pw)
    if isinstance(token, str) and len(token) >= 8:
        out.append(token)
    return out


# ---------------------------------------------------------------------------
# Live builder
# ---------------------------------------------------------------------------
class ReportBuilder:
    """Live ``report.html`` builder (INTERFACES §10.2: ``start``/``stop``/``build``).

    ``interval_s`` and ``debounce_s`` are constructor overrides for tests. The
    thread polls every ``poll_s`` and builds when the interval elapsed or an
    ``episode_close`` was seen ``debounce_s`` ago; it never builds while
    ``store.writing`` is False (full disk) and says so in the ``report``
    collector entry.
    """

    def __init__(self, ctx: Any, interval_s: float = REPORT_INTERVAL_S, debounce_s: float = EPISODE_DEBOUNCE_S,
                 poll_s: float = 0.5) -> None:
        self.ctx = ctx
        self.state: State = ctx.state
        self.store: Store = ctx.store
        self.cfg: dict = getattr(ctx, "cfg", None) or {}
        self.root: Path = Path(getattr(ctx, "root", None) or repo_root())
        self.interval_s = float(interval_s)
        self.debounce_s = float(debounce_s)
        self.poll_s = float(poll_s)
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._unsub: Optional[Callable[[], None]] = None
        self._pending_close: Optional[float] = None
        self._last_build: float = 0.0
        self._last_comcast: Optional[str] = None
        self.last_path: Optional[Path] = None
        self.last_size: int = 0
        self.builds: int = 0
        self.cache = SliceCache()
        self._assets: Optional[Dict[str, Any]] = None
        self._assets_at: float = 0.0
        self._file_rollups: Optional[List[dict]] = None
        self._file_rollups_at: float = 0.0

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        try:
            self._unsub = self.state.subscribe(self._on_publish)
        except Exception:  # noqa: BLE001
            log.exception("report: cannot subscribe to state")
        self.thread = start_thread("report", self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        if self._unsub is not None:
            try:
                self._unsub()
            except Exception:  # noqa: BLE001
                pass
            self._unsub = None
        t = self.thread
        if t is not None and t.is_alive():
            t.join(timeout)

    def _on_publish(self, name: str, _obj: Any) -> None:
        if name == "episode_close":
            self._pending_close = time.monotonic()

    def _loop(self) -> None:
        st = self.state
        self._last_build = time.monotonic()
        while not st.stop_event.wait(self.poll_s):
            now = time.monotonic()
            due = now - self._last_build >= self.interval_s
            pend = self._pending_close
            if pend is not None and now - pend >= self.debounce_s:
                due = True
            if not due:
                continue
            self._pending_close = None
            self._last_build = now
            self.build(final=False)

    # ---------------------------------------------------------------- build
    def build(self, final: bool = False) -> Optional[Path]:
        """Build and atomically write ``report.html``; returns its path (``None`` when skipped/failed)."""
        with self._lock:
            if not getattr(self.store, "writing", True):
                reason = _get(getattr(self.store, "disk", {}), "reason") or "store is not writing"
                log.warning("report: skipped (%s)", reason)
                self.state.set_collector("report", "degraded", reason="report.html not written: %s" % reason)
                return None
            t_start = time.monotonic()
            # The registry entry normally comes from the supervised thread; a build() without
            # start() (shutdown path, tests, server-triggered rebuild) must still show up there,
            # and the blob's "collectors" block is read during _blob().
            if self.state.collector("report") is None:
                self.state.set_collector("report", "ok", reason=None)
            try:
                blob = self._blob(final)
                html = render_html(blob, self._get_assets())
                html = self._fit(blob, html)
                path = self.store.write_atomic(REPORT_FILE, html)
                self._write_comcast(blob.get("comcast_text") or "")
            except Exception as exc:  # noqa: BLE001 - never let the builder kill anything
                log.exception("report: build failed")
                self.state.set_collector("report", "degraded", reason="build failed: %s" % exc)
                return None
            self.builds += 1
            self.last_path = path
            self.last_size = len(html)
            self.state.set_collector("report", "ok", reason=None, last_build=time.time(), size=len(html),
                                     build_ms=int((time.monotonic() - t_start) * 1000), final=bool(final))
            log.info("report: wrote %s (%d KB, %d ms)%s", path.name, len(html) // 1024,
                     int((time.monotonic() - t_start) * 1000), " final" if final else "")
            return path

    def _get_assets(self) -> Dict[str, Any]:
        now = time.monotonic()
        if self._assets is None or now - self._assets_at > 300:
            self._assets = load_assets(self.root)
            self._assets_at = now
            if self._assets.get("missing"):
                log.warning("report: web assets missing (%s); using fallbacks", ", ".join(self._assets["missing"]))
        return self._assets

    def _fit(self, blob: dict, html: str) -> str:
        """Drop the oldest raw slices until the page fits :data:`SIZE_LIMIT_BYTES`."""
        tries = 0
        while len(html.encode("utf-8")) > SIZE_LIMIT_BYTES and tries < 4:
            slices = blob.get("raw_slices") or {}
            if not slices:
                break
            keep = sorted(slices, key=lambda k: slices[k].get("from_ms", 0), reverse=True)[: max(0, len(slices) // 2)]
            blob["raw_slices"] = {k: slices[k] for k in keep}
            blob["raw_slices_truncated"] = True
            html = render_html(blob, self._get_assets())
            tries += 1
        if len(html.encode("utf-8")) > SIZE_LIMIT_BYTES:
            log.warning("report: %d bytes exceeds the %d byte target even without raw slices",
                        len(html), SIZE_LIMIT_BYTES)
        return html

    def _write_comcast(self, text: str) -> None:
        if not text or text == self._last_comcast:
            return
        try:
            self.store.write_atomic(COMCAST_FILE, text if text.endswith("\n") else text + "\n")
            self._last_comcast = text
        except Exception:  # noqa: BLE001
            log.exception("report: cannot write %s", COMCAST_FILE)

    def _component(self, name: str) -> Any:
        try:
            return self.ctx.component(name)
        except Exception:  # noqa: BLE001
            return None

    def _blob(self, final: bool) -> dict:
        st = self.state
        store = self.store
        ctx = self.ctx
        now = st.now()
        src = BlobSources(st, store, self.cfg)
        src.now = now
        src.t_from = st.t0
        src.secrets = _secrets_of(self.cfg, _safe(lambda: getattr(ctx, "token", None), None))
        src.session = _safe(lambda: _session_doc(ctx), None)
        src.file_rollups = self._older_rollups(now)
        src.series = self._series(now)

        tracer = self._component("tracer")
        if tracer is not None and hasattr(tracer, "current"):
            src.path = _safe(lambda: dict(tracer.current()), None)
        docsis = self._component("docsis")
        if docsis is not None and hasattr(docsis, "recent"):
            src.docsis = _safe(lambda: docsis.recent(DOCSIS_RECENT_POLLS), None)
            if src.docsis is None:
                src.docsis = "unset"
        igd = self._component("igd")
        if igd is not None and hasattr(igd, "status"):
            src.igd = _safe(lambda: igd.status(), None)
            if src.igd is None:
                src.igd = "unset"
        src.comcast_text = _comcast_text(ctx)

        with st.lock:
            episodes = [e.to_dict(brief=False) for e in st.episodes]
            marks = [m.to_dict() for m in st.marks]
        src.episodes = episodes
        src.marks = marks
        windows = slice_windows(episodes, marks, now)
        src.raw_slices = live_raw_slices(st, store, windows, now, cache=self.cache,
                                         file_reads=RAW_FILE_READS_PER_BUILD)
        src.extra = {"final": bool(final), "builds": self.builds + 1}
        return assemble_blob(src)

    def _series(self, now: float) -> Optional[dict]:
        """``laglens.server.series.build_series`` when present, else ``None`` (local builder)."""
        seriesmod = _optional_module("laglens.server.series")
        if seriesmod is None:
            return None
        fn = getattr(seriesmod, "build_series", None)
        if fn is None:
            return None
        try:
            out = fn(self.ctx, self.store, self.state.t0, now, SERIES_RES_S, None)
            if isinstance(out, dict) and "t" in out:
                return out
            log.warning("report: server.series.build_series returned an unexpected shape; using the local builder")
        except Exception:  # noqa: BLE001
            log.exception("report: server.series.build_series failed; using the local builder")
        return None

    def _older_rollups(self, now: float) -> Optional[List[dict]]:
        """Rows of ``rollups.jsonl`` when the 5 s ring does not reach back to ``t0`` (resumed or > 24 h sessions).

        The RAM ring normally covers the whole session (24 h, sessions rotate
        daily), so the file is only parsed when the ring has data but none
        within the first two minutes of the session; the rows are cached for
        10 minutes because parsing a 12 h ``rollups.jsonl`` is not free.
        """
        st = self.state
        try:
            head = st.rollups(5, st.t0 - 10, st.t0 + 120)
            if any(head.values()):
                return None
            if not any(st.last_rollup(5, t.id) is not None for t in st.targets_list()):
                return None  # nothing in the ring at all: a young session
        except Exception:  # noqa: BLE001
            return None
        mono = time.monotonic()
        if self._file_rollups is not None and mono - self._file_rollups_at < 600:
            return self._file_rollups
        self._file_rollups = [r for r in _read_json(self.store, "rollups") if isinstance(r.get("t"), (int, float))]
        self._file_rollups_at = mono
        return self._file_rollups


def _optional_module(name: str) -> Any:
    """Import a sibling module that may not exist yet (``None`` when it does not).

    ``importlib.import_module`` honours ``sys.modules`` first, so a module
    swapped in there (tests, hot fixes) is seen even after the real one was
    imported as an attribute of its package.
    """
    try:
        return importlib.import_module(name)
    except ImportError:
        return None
    except Exception:  # noqa: BLE001 - a broken sibling must not kill the report
        log.exception("report: importing %s failed", name)
        return None


def _session_doc(ctx: Any) -> Optional[dict]:
    appmod = _optional_module("laglens.app")
    fn = getattr(appmod, "session_document", None) if appmod is not None else None
    if fn is None:
        return None
    return fn(ctx)


def _comcast_text(ctx: Any) -> Optional[str]:
    verdictmod = _optional_module("laglens.engine.verdict")
    if verdictmod is None:
        return None
    fn = getattr(verdictmod, "comcast_text", None)
    if fn is None:
        return None
    try:
        out = fn(ctx)
        return out if isinstance(out, str) else None
    except Exception:  # noqa: BLE001
        log.exception("report: engine.verdict.comcast_text failed")
        return None


# ---------------------------------------------------------------------------
# Offline rebuild
# ---------------------------------------------------------------------------
class _OfflineContext:
    """Just enough of ``AppContext`` for ``engine.verdict.compute_verdict/comcast_text(ctx)``.

    ``store`` is ``None`` on purpose: the verdict engine writes
    ``comcast_evidence.txt`` through ``ctx.store`` when it has one, and the
    rebuild decides itself what lands in the session directory.
    """

    def __init__(self, state: State, store: Optional[Store], cfg: dict) -> None:
        self.state = state
        self.store = store
        self.cfg = cfg
        self.components: Dict[str, Any] = {}
        self.root = repo_root()
        self.platform = None

    def component(self, name: str) -> Any:
        return self.components.get(name)


def _seed_latest(state: State, collector_rows: Sequence[dict], igd_rows: Sequence[dict]) -> None:
    """Restore ``state.latest(kind)`` from the newest 5 s collector rows / ``igd.jsonl`` row.

    The live verdict engine reads the WAN IP, IPv6 prefix, DOCSIS levels and
    link facts from ``state.latest``; without this the offline Tell-Comcast
    text would say "WAN IP: unknown" for a session that recorded it.
    """
    last: Dict[str, dict] = {}
    for row in collector_rows:
        if not isinstance(row, dict):
            continue
        for kind in ("iface", "host", "wifi", "wan", "ntp", "docsis", "xbox"):
            body = row.get(kind)
            if isinstance(body, dict):
                last[kind] = body
    for r in igd_rows:
        if isinstance(r, dict):
            last["igd"] = r
    for kind, body in last.items():
        try:
            state.set_latest(kind, body)
        except Exception:  # noqa: BLE001
            log.debug("cannot seed latest %s", kind, exc_info=True)


def _offline_verdict(ctx: Any, now: float) -> Optional[dict]:
    """``engine.verdict.compute_verdict`` on the rebuilt state (``None`` when the engine is absent/fails)."""
    verdictmod = _optional_module("laglens.engine.verdict")
    fn = getattr(verdictmod, "compute_verdict", None) if verdictmod is not None else None
    if fn is None:
        return None
    try:
        out = fn(ctx, now=now)
    except TypeError:
        out = _safe(lambda: fn(ctx), None)
    except Exception:  # noqa: BLE001
        log.exception("report: offline verdict failed")
        return None
    return out if isinstance(out, dict) and out.get("text") else None


def _offline_health(state: State, now: float) -> None:
    """``engine.health.refresh`` on the rebuilt state; leaves ``state.health`` alone when unavailable."""
    healthmod = _optional_module("laglens.engine.health")
    fn = getattr(healthmod, "refresh", None) if healthmod is not None else None
    if fn is None:
        return
    try:
        fn(state, now=now, session=True)
    except Exception:  # noqa: BLE001
        log.exception("report: offline health failed")


def _make_event(d: dict) -> Optional[Event]:
    try:
        known = {f for f in Event.__dataclass_fields__}  # type: ignore[attr-defined]
        kw = {k: v for k, v in d.items() if k in known}
        for req in ("id", "t0", "type"):
            if req not in kw:
                return None
        kw.setdefault("t1", None)
        kw.setdefault("target", None)
        kw.setdefault("severity", 1)
        return Event(**kw)
    except (TypeError, ValueError):
        return None


def _make_mark(d: dict) -> Optional[Mark]:
    try:
        known = {f for f in Mark.__dataclass_fields__}  # type: ignore[attr-defined]
        kw = {k: v for k, v in d.items() if k in known}
        for req in ("id", "t_pressed"):
            if req not in kw:
                return None
        kw.setdefault("offset_s", 0.0)
        kw.setdefault("t_est", kw["t_pressed"])
        return Mark(**kw)
    except (TypeError, ValueError):
        return None


def _make_episode(d: dict) -> Optional[Episode]:
    try:
        ep = Episode.from_dict(d)
        return ep if isinstance(ep.id, str) and isinstance(ep.t0, (int, float)) else None
    except (TypeError, ValueError):
        return None


def replay_samples(state: State, session_dir: Path, windows: Sequence[SliceWindow], cfg: Optional[dict] = None) -> int:
    """Replay ``samples.bin[.gz]`` into ``state`` (raw ring, totals, 1 s and 5 s rollups) in one pass.

    Mirrors the live ticker: seconds close ``second_close_lag_s`` behind the
    newest sample and 5 s windows ``WINDOW5_LAG_S`` behind it, both through
    :mod:`laglens.engine.rollup`, so the replayed rollups match what the live
    run produced. The raw ±90 s slices for ``windows`` are collected in the
    same pass. Returns the number of samples replayed.
    """
    lag1 = rollupmod.second_close_lag_s(cfg)
    lag5 = rollupmod.WINDOW5_LAG_S
    count = 0
    last_close = None  # last second passed to close_second
    next_w5: Optional[int] = None
    last_sec: Optional[int] = None

    wins = sorted(windows, key=lambda w: w.from_ms)
    ptr = 0
    active: List[SliceWindow] = []

    for rec in iter_sample_rows(session_dir):
        ts, tid, kind, flags, seq, value = rec
        s = Sample(ts_ms=ts, target_id=tid, kind=kind, flags=flags, seq=seq, value=value)
        try:
            state.add_sample(s)
        except Exception:  # noqa: BLE001 - a bad record must not stop the replay
            continue
        count += 1
        # raw slices (same pass)
        while ptr < len(wins) and wins[ptr].from_ms <= ts:
            active.append(wins[ptr])
            ptr += 1
        if active:
            keep: List[SliceWindow] = []
            for w in active:
                if ts >= w.to_ms + 15_000:
                    continue
                keep.append(w)
                if w.from_ms <= ts < w.to_ms and len(w.rows) < RAW_ROWS_PER_SLICE:
                    w.rows.append([ts, tid, kind, flags, value])
            active = keep
        # rollups, lagging like the ticker
        sec = ts // 1000
        if last_sec is None or sec > last_sec:
            last_sec = sec
            close_to = sec - lag1
            if last_close is None or close_to > last_close:
                rollupmod.close_second(state, close_to)
                last_close = close_to
            if next_w5 is None:
                next_w5 = (sec // 5) * 5
            while next_w5 + 5 + lag5 <= sec:
                rollupmod.close_window5(state, next_w5)
                next_w5 += 5
    if last_sec is not None:
        rollupmod.close_second(state, last_sec + 1)
        if next_w5 is None:
            next_w5 = (last_sec // 5) * 5
        while next_w5 <= last_sec:
            rollupmod.close_window5(state, next_w5)
            next_w5 += 5
    for w in wins:
        w.complete = True
    return count


def rebuild(session_dir: Any, cfg: Optional[dict] = None, root: Optional[Path] = None) -> Path:
    """Offline reconstruction of ``report.html`` for ``session_dir`` (``--report DIR``).

    Works on a closed session (``samples.bin.gz``) and on one that crashed
    (torn files, no ``stopped``). Loads ``targets.json`` into a fresh
    :class:`State` (``t0`` from ``session.json``), replays the samples into
    rollups, loads events/episodes/marks/tags/path/xb7/igd/loadtests/doctor
    from the files, assembles the blob and writes ``report.html`` atomically.
    Returns the path. Raises ``FileNotFoundError`` when the directory does
    not exist.
    """
    sdir = Path(session_dir)
    if not sdir.is_dir():
        raise FileNotFoundError("session directory not found: %s" % sdir)
    cfg = cfg if cfg is not None else configmod.load_config(None)
    t_wall = time.time()

    store = Store(sdir, cfg, resume=False)
    session = store.read_file_json("session.json")
    if not isinstance(session, dict):
        session = salvage_session_json(sdir / "session.json")
    t0 = _num(session.get("started"))
    first_ts, last_ts = _sample_span(sdir)
    if t0 is None:
        t0 = (first_ts / 1000.0) if first_ts else _dir_time(sdir)
    stopped = _num(session.get("stopped"))

    state = State(t0=float(t0), session_id=sdir.name, cfg=cfg)
    state.label = session.get("label") if isinstance(session.get("label"), str) else None
    try:
        state.resumed_count = int(session.get("resumed_count") or 0)
    except (TypeError, ValueError):
        state.resumed_count = 0
    targets = store.read_targets() or []
    for d in targets:
        if not isinstance(d, dict):
            continue
        try:
            t = Target.from_dict(d)
            if isinstance(t.id, int) and 0 <= t.id <= 255 and isinstance(t.key, str):
                state.add_target(t)
        except (TypeError, ValueError):
            log.warning("targets.json: skipping malformed entry %r", d)

    # events/episodes/marks are appended again on update and on close: the last row per id wins
    events_rows = _dedupe_by_id(store.read_json("events"))
    episodes_rows = _dedupe_by_id(store.read_json("episodes"))
    marks_rows = _dedupe_by_id(store.read_json("marks"))
    tags_rows = store.read_json("tags")
    with state.lock:
        state.events = [e for e in (_make_event(r) for r in events_rows) if e is not None]
        state.episodes = [e for e in (_make_episode(r) for r in episodes_rows) if e is not None]
        state.marks = [m for m in (_make_mark(r) for r in marks_rows) if m is not None]
        state.tags = [dict(r) for r in tags_rows if isinstance(r, dict)]
        if state.tags:
            last_tag = state.tags[-1]
            state.activity = {"current": last_tag.get("activity", "idle"), "since": last_tag.get("t0", t0)}
    episodes = [e.to_dict(brief=False) for e in state.episodes]
    marks = [m.to_dict() for m in state.marks]

    t_end = stopped
    if t_end is None:
        rollups_last = _last_rollup_t(store)
        cands = [c for c in ((last_ts / 1000.0) if last_ts else None, rollups_last) if c is not None]
        t_end = max(cands) if cands else t0 + 1.0
    t_end = max(float(t_end), float(t0) + 1.0)
    state.now = lambda: float(t_end)  # type: ignore[assignment]

    windows = slice_windows(episodes, marks, t_end)
    replayed = replay_samples(state, sdir, windows, cfg)
    raw_slices: Dict[str, dict] = {}
    budget = RAW_ROWS_BUDGET
    for w in windows:
        if budget <= 0:
            break
        raw_slices[w.id] = w.to_dict()
        budget -= len(w.rows)

    summary = session.get("summary") if isinstance(session.get("summary"), dict) else {}
    verdict = summary.get("verdict") if isinstance(summary.get("verdict"), dict) else {}
    if verdict:
        state.verdict = dict(verdict)
    health = summary.get("health") if isinstance(summary.get("health"), dict) else {}
    if health:
        state.health = dict(health)
    collectors = summary.get("collectors") if isinstance(summary.get("collectors"), dict) else {}
    # A crashed session (torn/missing session.json) has no stored verdict or health: both are pure
    # functions of the state just rebuilt (episodes, marks, totals, rollups), so recompute them
    # offline. The offline ctx carries no store: nothing the engine does may write into the session
    # directory behind the rebuild's back (comcast_evidence.txt is handled below).
    offline = _OfflineContext(state, None, cfg)
    if not verdict.get("text"):
        verdict = _offline_verdict(offline, t_end) or verdict
    if health.get("session") is None and health.get("now") is None:
        _offline_health(state, t_end)
    doctor = store.read_file_json("doctor.json")
    if isinstance(doctor, dict) and isinstance(doctor.get("checks"), list):
        doctor = doctor["checks"]
    if not isinstance(doctor, list):
        doctor = []
    state.doctor = doctor
    state.path = path_from_rows(store.read_json("path"), state.path)
    host = session.get("host")
    state.host = {
        "os": session.get("os"), "hostname": host, "iface": session.get("iface"), "wifi": session.get("wifi"),
        "lan_ip": session.get("lan"), "gateway": session.get("gateway"), "gw6": session.get("gw6"),
        "v6": bool(session.get("gw6")), "v6_prefix": session.get("v6_prefix"),
    }
    collector_rows = [r for r in store.read_json("rollups") if "id" not in r]  # collector + slots rows
    igd_rows = store.read_json("igd")
    _seed_latest(state, collector_rows, igd_rows)
    state.set_status(STATUS_STOPPED, "Stopped" if stopped else "Stopped (no clean shutdown recorded)")

    comcast = _read_text(sdir / COMCAST_FILE)
    if not comcast:
        comcast = _comcast_text(offline) or (verdict.get("comcast") or "")
        if comcast and not (sdir / COMCAST_FILE).exists():
            # SPEC §7.7: the same text lives in comcast_evidence.txt (the export packs ship it).
            try:
                write_atomic_file(sdir / COMCAST_FILE, comcast if comcast.endswith("\n") else comcast + "\n")
            except OSError as exc:
                log.warning("report: cannot write %s: %s", COMCAST_FILE, exc)

    src = BlobSources(state, store, cfg)
    src.now = t_end
    src.t_from = float(t0)
    src.session = session or {"id": sdir.name, "started": t0, "stopped": stopped, "label": state.label}
    src.events = [r for r in events_rows if isinstance(r, dict)]
    src.episodes = episodes
    src.marks = marks
    src.tags = state.tags
    src.raw_slices = raw_slices
    src.file_rollups = collector_rows
    src.igd = igd_from_rows(igd_rows)
    src.collectors = collectors
    src.verdict = dict(state.verdict)
    src.comcast_text = comcast
    src.secrets = _secrets_of(cfg, _read_text(sdir / "token"))
    src.extra = {
        "final": True,
        "rebuilt": True,
        "rebuilt_at": t_wall,
        "replayed_samples": replayed,
        "clean_shutdown": stopped is not None,
    }
    blob = assemble_blob(src)
    html = render_html(blob, load_assets(root))
    if len(html.encode("utf-8")) > SIZE_LIMIT_BYTES and blob.get("raw_slices"):
        slices = blob["raw_slices"]
        keep = sorted(slices, key=lambda k: slices[k].get("from_ms", 0), reverse=True)[: len(slices) // 2]
        blob["raw_slices"] = {k: slices[k] for k in keep}
        blob["raw_slices_truncated"] = True
        html = render_html(blob, load_assets(root))
    out = write_atomic_file(sdir / REPORT_FILE, html)
    log.info("report: rebuilt %s from %d samples (%d KB)", out, replayed, len(html) // 1024)
    return out


_SALVAGE_RE = {
    "id": re.compile(r'"id"\s*:\s*"([^"\\]{1,64})"'),
    "label": re.compile(r'"label"\s*:\s*"([^"\\]{0,200})"'),
    "started": re.compile(r'"started"\s*:\s*(-?\d+(?:\.\d+)?)'),
    "stopped": re.compile(r'"stopped"\s*:\s*(-?\d+(?:\.\d+)?)'),
    "resumed_count": re.compile(r'"resumed_count"\s*:\s*(\d+)'),
    "version": re.compile(r'"version"\s*:\s*"([^"\\]{1,32})"'),
}


def salvage_session_json(path: Path) -> dict:
    """Scalars of a torn/unparsable ``session.json`` (``{}`` when nothing is readable).

    ``session.json`` is written atomically, so a torn one means a crash of the
    filesystem rather than of Lag Lens, but the top-level scalars (``id``,
    ``started``, ``label``, ``resumed_count``) sit at the front of the file
    and are worth more than the directory mtime as a fallback for ``t0``.
    The result carries ``"torn": True`` and never a ``summary``.
    """
    text = _read_text(path)
    if not text:
        return {}
    out: Dict[str, Any] = {}
    for key, rx in _SALVAGE_RE.items():
        m = rx.search(text)
        if not m:
            continue
        val = m.group(1)
        if key in ("started", "stopped"):
            try:
                out[key] = float(val)
            except ValueError:
                continue
        elif key == "resumed_count":
            out[key] = int(val)
        else:
            out[key] = val
    if out:
        out["torn"] = True
    return out


def _dedupe_by_id(rows: List[dict]) -> List[dict]:
    """Keep the last row per ``id`` (episodes are appended on open and again on close)."""
    out: Dict[str, dict] = {}
    order: List[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id"))
        if rid not in out:
            order.append(rid)
        out[rid] = r
    return [out[k] for k in order]


def _sample_span(sdir: Path) -> Tuple[Optional[int], Optional[int]]:
    """First and last ``ts_ms`` of ``samples.bin[.gz]`` (last one via a cheap tail read on the plain file)."""
    plain = sdir / "samples.bin"
    try:
        if plain.exists():
            size = plain.stat().st_size
            if size < SAMPLE_SIZE:
                return None, None
            with open(plain, "rb") as fh:
                first = SAMPLE_STRUCT.unpack(fh.read(SAMPLE_SIZE))[0]
                usable = size - size % SAMPLE_SIZE
                fh.seek(usable - SAMPLE_SIZE)
                last = SAMPLE_STRUCT.unpack(fh.read(SAMPLE_SIZE))[0]
            return first, last
    except Exception:  # noqa: BLE001 - a broken plain file falls through to the streaming reader
        pass
    first_ts: Optional[int] = None
    last_ts: Optional[int] = None
    for rec in iter_sample_rows(sdir):
        if first_ts is None:
            first_ts = rec[0]
        last_ts = rec[0]
    return first_ts, last_ts


def _last_rollup_t(store: Store) -> Optional[float]:
    best: Optional[float] = None
    for r in store.read_json("rollups"):
        t = _num(r.get("t"))
        if t is not None and (best is None or t > best):
            best = t
    return (best + 5) if best is not None else None


def _dir_time(sdir: Path) -> float:
    """``t0`` fallback: parse ``YYYYMMDD-HHMMSS`` from the directory name, else its mtime."""
    m = re.match(r"^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})", sdir.name)
    if m:
        try:
            return time.mktime((int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)),
                                int(m.group(5)), int(m.group(6)), 0, 0, -1))
        except (ValueError, OverflowError):
            pass
    try:
        return sdir.stat().st_mtime
    except OSError:
        return time.time()


def _read_text(p: Path) -> Optional[str]:
    try:
        return p.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


__all__ = [
    "ReportBuilder", "rebuild", "assemble_blob", "BlobSources", "render_html", "load_assets",
    "build_series_local", "thin_series", "hour_heatmap", "activity_stats", "scrub", "escape_json_for_html",
    "slice_windows", "collect_slices", "iter_sample_rows", "replay_samples", "docsis_from_rows", "igd_from_rows",
    "path_from_rows", "write_atomic_file", "salvage_session_json", "truncate_v6_prefix", "METHODOLOGY",
    "REPORT_INTERVAL_S", "EPISODE_DEBOUNCE_S",
    "SIZE_LIMIT_BYTES", "THIN_AFTER_S", "THIN_FACTOR", "RAW_MAX_SLICES", "REFERENCE_KEYS", "REPORT_FILE",
    "COMCAST_FILE", "DATA_SCRIPT_ID",
]
