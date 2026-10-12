"""Sessions index: ``GET /api/sessions`` rows and the static ``sessions/index.html``.

* :func:`list_sessions` — one row per session directory (SPEC_FULL §10.2):
  ``id, label, started, stopped, dur_s, score, loss_pct, p95, episodes,
  top_class, spark``. Everything that ``session.json`` carries is taken from
  there; ``loss_pct``/``p95``/``spark`` are computed from ``rollups.jsonl``
  with a cheap streaming scan (cached in ``sessions/.index-cache.json`` keyed
  by the file's size and mtime so finished sessions are scanned once).
* :func:`session_summary` — the ``session.json`` document (a minimal one is
  synthesised when the file is missing).
* :func:`rebuild_index` — writes ``sessions/index.html``, a self-contained
  dark-theme table page linking every ``report.html`` and export zip.
"""
import gzip
import json
import logging
import math
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from laglens.engine import rollup as rollupmod
from laglens.version import __version__

log = logging.getLogger("laglens.report.sessions")

INDEX_FILE = "index.html"
CACHE_FILE = ".index-cache.json"
SPARK_POINTS = 60
REFERENCE_KEYS = ("inet4_cf", "inet4_g", "inet6_cf", "inet6_g", "isp_hop4")
_SESSION_DIR_RE = re.compile(r"^\d{8}-\d{6}(-\d+)?$")
_SESSION_FILES = ("session.json", "targets.json", "samples.bin", "samples.bin.gz", "rollups.jsonl")


# ---------------------------------------------------------------------------
# Reading helpers
# ---------------------------------------------------------------------------
def _read_json_file(p: Path) -> Optional[Any]:
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def iter_jsonl(path: Path) -> Iterator[dict]:
    """Stream the objects of ``path`` (``.jsonl`` or ``.jsonl.gz``); torn/bad lines are skipped."""
    gz = path.with_name(path.name + ".gz")
    opener = None
    if path.exists():
        opener = lambda: open(path, "rb")  # noqa: E731
    elif gz.exists():
        opener = lambda: gzip.open(gz, "rb")  # noqa: E731
    if opener is None:
        return
    try:
        with opener() as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(obj, dict):
                    yield obj
    except (OSError, EOFError) as exc:
        log.warning("%s: read stopped early: %s", path.name, exc)


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)


def _file_sig(p: Path) -> Optional[Tuple[int, int]]:
    for cand in (p, p.with_name(p.name + ".gz")):
        try:
            st = cand.stat()
            return int(st.st_size), int(st.st_mtime)
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Rollup scan
# ---------------------------------------------------------------------------
def _targets_doc(session_dir: Path) -> List[dict]:
    doc = _read_json_file(Path(session_dir) / "targets.json")
    if not isinstance(doc, dict) or not isinstance(doc.get("targets"), list):
        return []
    return [t for t in doc["targets"] if isinstance(t, dict) and isinstance(t.get("id"), int)]


def reference_target_ids(session_dir: Path) -> Optional[List[int]]:
    """Ids of the reference targets from ``targets.json`` (``None`` = unknown → use every target)."""
    targets = _targets_doc(session_dir)
    if not targets:
        return None
    by_key: Dict[str, int] = {t["key"]: t["id"] for t in targets if isinstance(t.get("key"), str)}
    ids = [by_key[k] for k in REFERENCE_KEYS if k in by_key]
    if not ids:
        ids = [t["id"] for t in targets if t.get("kind") == "icmp"]
    return ids or None


def target_rates(session_dir: Path) -> Dict[int, float]:
    """``{id: rate_hz}`` from ``targets.json`` (used to turn lost-probe runs into seconds)."""
    out: Dict[int, float] = {}
    for t in _targets_doc(session_dir):
        r = _num(t.get("rate_hz"))
        if r and r > 0:
            out[t["id"]] = r
    return out


def _min_run_in_window(n: int, lost: int) -> int:
    """Lower bound on the longest run of consecutive lost probes inside one window.

    ``lost`` lost probes sit between at most ``n - lost + 1`` received ones,
    so some run holds at least ``ceil(lost / (n - lost + 1))`` of them; exact
    when the losses are spread evenly, an underestimate when they cluster.
    """
    if lost <= 0 or n <= 0:
        return 0
    if lost >= n:
        return lost
    gaps = n - lost + 1
    return -(-lost // gaps)


def rollup_scan(session_dir: Path, started: Optional[float] = None, stopped: Optional[float] = None,
                spark_points: int = SPARK_POINTS) -> dict:
    """Cheap single pass over ``rollups.jsonl``: per-target totals and a p95 sparkline.

    Returns ``{"targets": {"<id>": {sent,lost,late,err,loss_pct,p50,p95,max,jitter,longest_outage_s}},
    "loss_pct", "p95", "spark": [...], "t_first", "t_last", "windows"}`` where
    ``loss_pct``/``p95``/``spark`` are over the reference targets.
    """
    sdir = Path(session_dir)
    ref = reference_target_ids(sdir)
    rates = target_rates(sdir)
    per: Dict[int, dict] = {}
    t_first: Optional[float] = None
    t_last: Optional[float] = None
    windows = 0
    ref_sent = ref_lost = 0
    ref_p95s: List[float] = []
    ref_rows: List[Tuple[float, float]] = []  # (t, p95) for the sparkline

    for row in iter_jsonl(sdir / "rollups.jsonl"):
        t = _num(row.get("t"))
        tid = row.get("id")
        if t is None or not isinstance(tid, int) or "n" not in row:
            continue
        windows += 1
        t_first = t if t_first is None else min(t_first, t)
        t_last = t if t_last is None else max(t_last, t)
        d = per.get(tid)
        if d is None:
            d = {"sent": 0, "lost": 0, "late": 0, "err": 0, "p50s": [], "p95s": [], "max": None, "jits": [],
                 "run": 0, "max_run": 0}
            per[tid] = d
        n = int(_num(row.get("n")) or 0)
        lost = int(_num(row.get("lost")) or 0)
        d["sent"] += n
        d["lost"] += lost
        d["late"] += int(_num(row.get("late")) or 0)
        d["err"] += int(_num(row.get("err")) or 0)
        p50 = _num(row.get("p50"))
        p95 = _num(row.get("p95"))
        mx = _num(row.get("max"))
        jit = _num(row.get("jit"))
        if p50 is not None:
            d["p50s"].append(p50)
        if p95 is not None:
            d["p95s"].append(p95)
        if mx is not None:
            d["max"] = mx if d["max"] is None else max(d["max"], mx)
        if jit is not None:
            d["jits"].append(jit)
        # Longest outage from 5 s windows: fully lost windows chain into one run; a partly lost
        # window contributes the pigeonhole lower bound (exact samples are not available here).
        if n and lost == n:
            d["run"] += lost
            d["max_run"] = max(d["max_run"], d["run"])
        else:
            d["max_run"] = max(d["max_run"], _min_run_in_window(n, lost))
            d["run"] = 0
        if ref is None or tid in ref:
            ref_sent += n
            ref_lost += lost
            if p95 is not None:
                ref_p95s.append(p95)
                ref_rows.append((t, p95))

    targets: Dict[str, dict] = {}
    for tid, d in per.items():
        p50s = sorted(d["p50s"])
        p95s = sorted(d["p95s"])
        sent = d["sent"]
        targets[str(tid)] = {
            "sent": sent,
            "lost": d["lost"],
            "late": d["late"],
            "err": d["err"],
            "loss_pct": round(100.0 * d["lost"] / sent, 2) if sent else None,
            "late_pct": round(100.0 * d["late"] / sent, 2) if sent else None,
            "p50": _round(rollupmod.percentile(p50s, 50)),
            "p95": _round(rollupmod.percentile(p95s, 95)),
            "max": _round(d["max"]),
            "jitter": _round(sum(d["jits"]) / len(d["jits"])) if d["jits"] else None,
            "longest_outage_s": round(d["max_run"] / float(rates.get(tid) or 4.0), 2),
            "approx": True,
        }
    spark = _sparkline(ref_rows, started if started is not None else t_first,
                       stopped if stopped is not None else (t_last + 5 if t_last is not None else None), spark_points)
    return {
        "targets": targets,
        "loss_pct": round(100.0 * ref_lost / ref_sent, 2) if ref_sent else None,
        "p95": _round(rollupmod.percentile(sorted(ref_p95s), 95)),
        "spark": spark,
        "t_first": t_first,
        "t_last": t_last,
        "windows": windows,
    }


def _round(v: Optional[float]) -> Optional[float]:
    return None if v is None else round(v, 2)


def _sparkline(rows: List[Tuple[float, float]], t_from: Optional[float], t_to: Optional[float], points: int,
               window_s: float = float(rollupmod.WINDOW5_S)) -> List[Optional[float]]:
    """Max p95 per bucket over ``points`` equal buckets of ``[t_from, t_to]`` (``None`` where empty).

    A 5 s window ``[t, t + window_s)`` counts in every bucket it overlaps, so
    a bucket is only empty when no window covered any part of it (a real gap),
    not because the buckets happen to be narrower than, or misaligned with,
    the rollup grid.
    """
    if not rows or t_from is None or t_to is None or t_to <= t_from or points <= 0:
        return []
    out: List[Optional[float]] = [None] * points
    span = float(t_to - t_from)
    scale = points / span
    for t, p95 in rows:
        lo = int(math.floor((t - t_from) * scale))
        hi = int(math.ceil((t + window_s - t_from) * scale)) - 1
        lo = min(max(lo, 0), points - 1)
        hi = min(max(hi, lo), points - 1)
        for i in range(lo, hi + 1):
            cur = out[i]
            out[i] = p95 if cur is None else max(cur, p95)
    return [None if v is None else round(v, 1) for v in out]


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
def _load_cache(root: Path) -> dict:
    data = _read_json_file(root / CACHE_FILE)
    return data if isinstance(data, dict) else {}


def _save_cache(root: Path, cache: dict) -> None:
    try:
        tmp = root / (CACHE_FILE + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, separators=(",", ":"))
        os.replace(tmp, root / CACHE_FILE)
    except OSError as exc:
        log.debug("cannot write %s: %s", CACHE_FILE, exc)


def _scan_cached(root: Path, sdir: Path, cache: dict, started: Optional[float], stopped: Optional[float]) -> dict:
    sig = _file_sig(sdir / "rollups.jsonl")
    entry = cache.get(sdir.name)
    if isinstance(entry, dict) and sig is not None and entry.get("sig") == list(sig) and isinstance(entry.get("scan"), dict):
        return entry["scan"]
    scan = rollup_scan(sdir, started, stopped)
    light = {k: scan[k] for k in ("loss_pct", "p95", "spark", "t_first", "t_last", "windows")}
    if sig is not None:
        cache[sdir.name] = {"sig": list(sig), "scan": light}
    return light


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def is_session_dir(p: Path) -> bool:
    if not p.is_dir() or p.name.startswith("."):
        return False
    if _SESSION_DIR_RE.match(p.name):
        return True
    return any((p / f).exists() for f in _SESSION_FILES)


def session_dirs(root: Path) -> List[Path]:
    root = Path(root)
    try:
        return sorted((p for p in root.iterdir() if is_session_dir(p)), key=lambda p: p.name)
    except OSError:
        return []


def _dir_started(sdir: Path) -> Optional[float]:
    m = re.match(r"^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})", sdir.name)
    if not m:
        return None
    try:
        return time.mktime((int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                            int(m.group(6)), 0, 0, -1))
    except (ValueError, OverflowError):
        return None


def session_summary(session_dir: Any) -> dict:
    """The ``session.json`` document; a minimal synthesised one (``"missing": true``) when absent."""
    sdir = Path(session_dir)
    doc = _read_json_file(sdir / "session.json")
    if isinstance(doc, dict):
        doc.setdefault("id", sdir.name)
        return doc
    started = _dir_started(sdir)
    stopped = None
    if started is None:
        try:
            started = sdir.stat().st_mtime
        except OSError:
            started = None
    return {
        "id": sdir.name,
        "version": None,
        "started": started,
        "stopped": stopped,
        "stop_reason": None,
        "resumed_count": 0,
        "label": None,
        "summary": {},
        "missing": True,
    }


def session_row(session_dir: Any, cache: Optional[dict] = None, root: Optional[Path] = None) -> dict:
    """One ``GET /api/sessions`` row for ``session_dir``."""
    sdir = Path(session_dir)
    doc = session_summary(sdir)
    summary = doc.get("summary") if isinstance(doc.get("summary"), dict) else {}
    started = _num(doc.get("started"))
    stopped = _num(doc.get("stopped"))
    verdict = summary.get("verdict") if isinstance(summary.get("verdict"), dict) else {}
    top = verdict.get("top") if isinstance(verdict.get("top"), list) else []
    top_class = None
    if top and isinstance(top[0], dict):
        top_class = top[0].get("class")
    health = summary.get("health") if isinstance(summary.get("health"), dict) else {}
    score = _num(health.get("session"))
    if score is None:
        score = _num(health.get("now"))
    episodes = summary.get("episodes")
    if not isinstance(episodes, int):
        episodes = _count_jsonl_ids(sdir / "episodes.jsonl")

    stats = summary.get("stats") if isinstance(summary.get("stats"), dict) else {}
    loss_pct = _num(stats.get("loss_pct"))
    p95 = _num(stats.get("p95"))
    spark = stats.get("spark") if isinstance(stats.get("spark"), list) else None
    t_last: Optional[float] = None
    if loss_pct is None or p95 is None or spark is None:
        scan = _scan_cached(Path(root) if root else sdir.parent, sdir, cache if cache is not None else {}, started, stopped)
        loss_pct = scan.get("loss_pct") if loss_pct is None else loss_pct
        p95 = scan.get("p95") if p95 is None else p95
        spark = scan.get("spark") if spark is None else spark
        t_last = _num(scan.get("t_last"))
        if started is None:
            started = _num(scan.get("t_first"))
    dur_s = None
    if started is not None:
        end = stopped if stopped is not None else t_last
        if end is not None and end >= started:
            dur_s = round(end - started, 1)
    return {
        "id": doc.get("id") or sdir.name,
        "label": doc.get("label"),
        "started": started,
        "stopped": stopped,
        "dur_s": dur_s,
        "score": score,
        "loss_pct": loss_pct,
        "p95": p95,
        "episodes": episodes,
        "top_class": top_class,
        "spark": spark or [],
        "stop_reason": doc.get("stop_reason"),
        "resumed_count": doc.get("resumed_count"),
        "has_report": (sdir / "report.html").exists(),
        "has_zip": (sdir.parent / ("laglens-%s.zip" % sdir.name)).exists(),
    }


def _count_jsonl_ids(path: Path) -> int:
    ids = set()
    for row in iter_jsonl(path):
        if "id" in row:
            ids.add(str(row["id"]))
    return len(ids)


def list_sessions(root: Any) -> List[dict]:
    """Rows for every session under ``root``, newest first (``GET /api/sessions``)."""
    root = Path(root)
    cache = _load_cache(root)
    before = json.dumps(cache, sort_keys=True)
    rows: List[dict] = []
    for sdir in session_dirs(root):
        try:
            rows.append(session_row(sdir, cache, root))
        except Exception:  # noqa: BLE001 - one broken session must not hide the others
            log.exception("sessions: cannot summarise %s", sdir.name)
            rows.append({"id": sdir.name, "label": None, "started": _dir_started(sdir), "stopped": None, "dur_s": None,
                         "score": None, "loss_pct": None, "p95": None, "episodes": None, "top_class": None,
                         "spark": [], "error": "unreadable"})
    if json.dumps(cache, sort_keys=True) != before:
        _save_cache(root, cache)
    rows.sort(key=lambda r: (r.get("started") or 0, r.get("id") or ""), reverse=True)
    return rows


# ---------------------------------------------------------------------------
# Static index page
# ---------------------------------------------------------------------------
_INDEX_CSS = """
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--text:#e6e8ee;--muted:#8b93a7;--accent:#4f8cff;--good:#3ddc84;--warn:#ffb454;--bad:#ff5c5c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}
h1{font-size:26px;font-weight:600;margin:0 0 4px}
.muted{color:var(--muted)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 12px;margin-top:16px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px;white-space:nowrap}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:500;position:sticky;top:0;background:var(--panel)}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
a.btn{display:inline-block;padding:3px 9px;border:1px solid var(--line);border-radius:6px;margin-right:6px;font-size:13px}
.score{display:inline-block;min-width:38px;padding:2px 8px;border-radius:12px;text-align:center;font-weight:600;color:#0b0d11}
.score.good{background:var(--good)}.score.warn{background:var(--warn)}.score.bad{background:var(--bad)}.score.na{background:var(--line);color:var(--muted)}
.cls{display:inline-block;padding:2px 8px;border-radius:6px;background:#22283a;font-size:13px}
svg.spark{width:140px;height:28px;display:block}
.empty{padding:32px;text-align:center;color:var(--muted)}
@media (max-width:700px){table{font-size:13px}th,td{padding:6px}}
"""


def _esc(s: Any) -> str:
    return str("" if s is None else s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _fmt_dur(dur_s: Optional[float]) -> str:
    if dur_s is None:
        return "-"
    s = int(dur_s)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return "%dh %02dm" % (h, m)
    if m:
        return "%dm %02ds" % (m, sec)
    return "%ds" % sec


def _fmt_local(t: Optional[float]) -> str:
    if t is None:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t)))
    except (ValueError, OverflowError, OSError):
        return str(t)


def _score_html(score: Optional[float]) -> str:
    if score is None:
        return '<span class="score na">-</span>'
    cls = "good" if score >= 80 else ("warn" if score >= 50 else "bad")
    return '<span class="score %s">%d</span>' % (cls, int(round(score)))


def _spark_svg(spark: List[Optional[float]]) -> str:
    vals = [v for v in spark if isinstance(v, (int, float))]
    if not vals:
        return '<span class="muted">-</span>'
    n = len(spark)
    w, h = 140.0, 28.0
    lo = 0.0
    hi = max(max(vals), 1.0)
    pts: List[str] = []
    for i, v in enumerate(spark):
        if not isinstance(v, (int, float)):
            continue
        x = (i / max(1, n - 1)) * (w - 2) + 1
        y = h - 2 - (min(float(v), hi) - lo) / (hi - lo) * (h - 4)
        pts.append("%.1f,%.1f" % (x, y))
    return ('<svg class="spark" viewBox="0 0 %d %d" preserveAspectRatio="none" aria-label="p95 ms over the session">'
            '<polyline fill="none" stroke="#4f8cff" stroke-width="1.5" points="%s"/></svg>' % (int(w), int(h), " ".join(pts)))


def render_index(rows: List[dict], generated_at: Optional[float] = None) -> str:
    """The static ``sessions/index.html`` page for ``rows`` (from :func:`list_sessions`)."""
    generated_at = time.time() if generated_at is None else generated_at
    body: List[str] = []
    if not rows:
        body.append('<div class="empty">No sessions yet. Run <code>bash start.sh</code> to start monitoring.</div>')
    else:
        body.append("<table><thead><tr><th>Started</th><th>Label</th><th class=\"num\">Duration</th><th class=\"num\">Score</th>"
                    "<th class=\"num\">Loss %</th><th class=\"num\">p95 ms</th><th class=\"num\">Episodes</th><th>Top class</th>"
                    "<th>p95 trend</th><th>Files</th></tr></thead><tbody>")
        for r in rows:
            sid = _esc(r.get("id"))
            links = ['<a class="btn" href="%s/report.html">report</a>' % sid]
            if r.get("has_zip"):
                links.append('<a class="btn" href="laglens-%s.zip">zip</a>' % sid)
            else:
                links.append('<a class="btn" href="/sessions/%s/export.zip" title="available while Lag Lens is running">export</a>' % sid)
            loss = r.get("loss_pct")
            p95 = r.get("p95")
            body.append(
                "<tr><td>%s<div class=\"muted\" style=\"font-size:12px\">%s</div></td><td>%s</td><td class=\"num\">%s</td>"
                "<td class=\"num\">%s</td><td class=\"num\">%s</td><td class=\"num\">%s</td><td class=\"num\">%s</td>"
                "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    _esc(_fmt_local(r.get("started"))), sid, _esc(r.get("label") or ""), _esc(_fmt_dur(r.get("dur_s"))),
                    _score_html(_num(r.get("score"))),
                    ("%.2f" % loss) if isinstance(loss, (int, float)) else "-",
                    ("%.1f" % p95) if isinstance(p95, (int, float)) else "-",
                    _esc(r.get("episodes") if r.get("episodes") is not None else "-"),
                    ('<span class="cls">%s</span>' % _esc(r["top_class"])) if r.get("top_class") else '<span class="muted">-</span>',
                    _spark_svg(r.get("spark") or []),
                    " ".join(links),
                )
            )
        body.append("</tbody></table>")
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Lag Lens sessions</title><style>%s</style></head><body><main>"
        "<h1>Lag Lens sessions</h1><div class=\"muted\">%d session%s - generated %s - Lag Lens %s</div>"
        "<div class=\"panel\">%s</div>"
        "<p class=\"muted\" style=\"font-size:13px\">Score is the session health (0-100). Loss %% and p95 are over the reference "
        "targets (internet v4/v6 and the Comcast hop). Export links work while Lag Lens is running; a zip link appears once "
        "<code>bash start.sh --export sessions/&lt;id&gt;</code> was run.</p>"
        "</main></body></html>\n"
    ) % (_INDEX_CSS, len(rows), "" if len(rows) == 1 else "s", _esc(_fmt_local(generated_at)), _esc(__version__), "".join(body))


def rebuild_index(root: Any) -> int:
    """Write ``<root>/index.html`` from :func:`list_sessions`; returns 0 (1 when it cannot be written)."""
    root = Path(root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        rows = list_sessions(root)
        html = render_index(rows)
        tmp = root / (INDEX_FILE + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(html)
        os.replace(tmp, root / INDEX_FILE)
        log.info("sessions index: %d rows -> %s", len(rows), root / INDEX_FILE)
        return 0
    except OSError as exc:
        log.error("sessions index: cannot write %s: %s", root / INDEX_FILE, exc)
        return 1


__all__ = [
    "list_sessions", "session_summary", "session_row", "rebuild_index", "render_index", "rollup_scan",
    "reference_target_ids", "target_rates", "iter_jsonl", "session_dirs", "is_session_dir", "INDEX_FILE", "CACHE_FILE",
]
