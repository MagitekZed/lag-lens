"""XB7 (Comcast RDK-B) DOCSIS poller: login, schema-agnostic table parsing, event log classes.

SPEC_FULL §4.9 with the BUILD_PLAN §0 facts: the login form POSTs
``username``/``password``/``locale=false`` to ``/check.jst`` (``/check.jsp``
on older firmware), status pages are ``.jst`` (``.jsp`` twins are tried as
well and dropped after three 404s), and an unauthenticated request returns
either the login form (``name="password"``) or a page redirecting to
``home_loggedout.jst``.

Parsing is deliberately layout-agnostic: every ``<table>`` becomes rows of
cell text; a table whose header mentions SNR / Signal to Noise / Unerrored /
Uncorrectable is a **downstream** table, Symbol Rate / Channel Type / Power
Level-without-SNR is **upstream**, rows starting with a timestamp are the
**event log**. The XB7 renders channel tables transposed (one row per metric,
one column per channel, ``Index`` in the corner); the orientation is detected
by counting header keywords in the first row versus the first column and the
table is transposed when needed. Columns are then mapped by keyword
(Channel ID/Index, Lock Status, Frequency, SNR, Power Level, Modulation,
Unerrored/Correctable/Uncorrectable, Symbol Rate, Channel Type).

Per poll the collector derives per-channel SNR / power / codeword counts,
deltas since the previous poll and the flags ``ds_snr_low``, ``ds_power_out``,
``us_power_high``, ``us_power_low``, ``uncorr_burst``, ``partial_service``,
``reboot``; raises ``docsis_<class>`` notes for new log lines of the classes
t3 / t4 / drw / ranging / partial and ``docsis_uncorr`` / ``docsis_power_snr``
/ ``docsis_reboot`` / ``docsis_partial`` for the flags; publishes the
``docsis`` latest row and appends the full snapshot to ``xb7.jsonl``. The
first successful fetch of every page is kept under ``xb7_raw/`` (max 50
files, 200 KB each) when ``docsis.save_raw`` is on.

The password is only ever sent to ``docsis.url``: it never appears in log
lines, rows, state or exception text (see :func:`Xb7Client.scrub`).
"""
from __future__ import annotations

import http.cookiejar
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple

from laglens.supervisor import start_thread

log = logging.getLogger("laglens.docsis")

HTTP_TIMEOUT_S = 10.0
LOGIN_FAILURES_BEFORE_PAUSE = 3
LOGIN_PAUSE_S = 600.0
LOGIN_REJECTED_CHIP = "XB7: login rejected, retry in 10 min"
PAGE_404_DROP_AFTER = 3
REFRESH_RATE_LIMIT_S = 60.0
REFRESH_SECOND_POLL_S = 15.0
RAW_MAX_FILES = 50
RAW_MAX_BYTES = 200 * 1024
DS_SNR_LOW_DB = 33.0
DS_POWER_MIN = -8.0
DS_POWER_MAX = 8.0
US_POWER_HIGH = 50.0
US_POWER_LOW = 35.0
UNCORR_BURST_PER_MIN = 100.0
NOTE_CLASSES = ("t3", "t4", "drw", "ranging", "partial")
CLASS_SEVERITY = {"t3": 3, "t4": 3, "drw": 3, "ranging": 3, "partial": 3, "uncorr": 3, "power_snr": 2, "reboot": 4}
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 LagLens/1.0"

_TS_PATTERNS = (
    re.compile(r"^\d{4}-\d{2}-\d{2}[ ,T]"),
    re.compile(r"^[A-Za-z]{3} [A-Za-z]{3} \d{1,2}"),
    re.compile(r"^[A-Za-z]{3} \d{1,2} \d{2}:\d{2}"),
    re.compile(r"^\d{1,2}/\d{1,2}/\d{4}"),
)
_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d, %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",  # TG4482A log JSON: "2026/9/30 02:41:54"
    "%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
)
_LOG_CLASSES: Sequence[Tuple[str, "re.Pattern[str]"]] = (
    ("t3", re.compile(r"\bT3\b", re.I)),
    ("t4", re.compile(r"\bT4\b", re.I)),
    ("drw", re.compile(r"dynamic range window", re.I)),
    ("reg_rsp", re.compile(r"REG-RSP", re.I)),
    ("lost_mdd", re.compile(r"lost MDD", re.I)),
    ("sync", re.compile(r"SYNC Timing", re.I)),
    ("ranging", re.compile(r"Unicast (?:Maintenance )?Ranging.*(?:Abort|No Response)", re.I)),
    ("partial", re.compile(r"Partial Service", re.I)),
)
_UPTIME_RE = re.compile(r"System\s*Up\s*time\s*:?\s*([0-9][0-9dDhHmMsS :,a-z]*)", re.I)
_FW_RE = re.compile(r"(?:Software Version|Firmware(?: Version)?|Software Image Name|Download Version)\s*:?\s*([A-Za-z0-9][A-Za-z0-9._+-]{2,})")
_LOCAL_TIME_RE = re.compile(r"Local time\s*:?\s*(\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{2}:\d{2})")
# The RDK-B troubleshooting page renders empty tables and fills them from this JSON endpoint.
LOG_PAGE = "/troubleshooting_logs.jst"
LOG_ENDPOINT = "/actionHandler/ajax_troubleshooting_logs.jst"
LOG_MODES = ("event", "system")
LOG_HISTORY_TIMEF = "Last week"
LOG_TIMEOUT_S = 45.0
_CSRF_RES = (re.compile(r"\bvar\s+token\s*=\s*[\"']([A-Za-z0-9_\-]{4,128})[\"']"),
             re.compile(r"\bsessionCsrf\s*=\s*[\"']([A-Za-z0-9_\-]{4,128})[\"']"))
_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")
_HEADER_KEYWORDS = ("channel id", "index", "lock status", "frequency", "snr", "signal to noise", "power level",
                    "modulation", "unerrored", "correctable", "uncorrectable", "symbol rate", "channel type",
                    "channel", "time", "priority", "description", "codewords")


class Xb7Error(Exception):
    """Transport-level failure talking to the XB7 (message already scrubbed)."""


# ---------------------------------------------------------------------------
# HTML → tables
# ---------------------------------------------------------------------------
class _TableParser(HTMLParser):
    """Collect every ``<table>`` as rows of cell text plus the page's visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: List[List[List[str]]] = []
        self._stack: List[List[List[str]]] = []
        self._row: Optional[List[str]] = None
        self._cell: Optional[List[str]] = None
        self._skip = 0
        self._text: List[str] = []

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style"):
            self._skip += 1
            return
        if tag == "table":
            self._stack.append([])
        elif tag == "tr":
            self._end_row()
            self._row = []
        elif tag in ("td", "th"):
            self._end_cell()
            if self._row is None:
                self._row = []
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
            return
        if tag in ("td", "th"):
            self._end_cell()
        elif tag == "tr":
            self._end_row()
        elif tag == "table":
            self._end_cell()
            self._end_row()
            if self._stack:
                t = self._stack.pop()
                if t:
                    self.tables.append(t)

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._cell is not None:
            self._cell.append(data)
        self._text.append(data)

    def _end_cell(self) -> None:
        if self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
        self._cell = None

    def _end_row(self) -> None:
        self._end_cell()
        if self._row is not None and self._stack and any(c for c in self._row):
            self._stack[-1].append(self._row)
        self._row = None

    @property
    def text(self) -> str:
        return " ".join(" ".join(self._text).split())


def extract_tables(html: str) -> Tuple[List[List[List[str]]], str]:
    """``(tables, visible_text)``; every table is a list of rows of cell strings."""
    p = _TableParser()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # noqa: BLE001 - html.parser is lenient but let us be sure
        log.debug("docsis: html parse error", exc_info=True)
    return p.tables, p.text


def _title_of(html: str) -> str:
    """The <title> text of a page (first 80 chars), for diagnostics."""
    m = re.search(r"<title>\s*([^<]{0,80})", html or "", re.I)
    return m.group(1).strip() if m else ""


# A logged-in RDK-B page carries a "Logout" link to home_loggedout.jst in its user toolbar. It also
# mentions home_loggedout.jst in its inactivity-timer script and "Please Login First" in its i18n
# tables, so neither of those can be used as a logged-out marker.
_LOGGED_IN_RX = re.compile(r'<a\b[^>]*\bhref\s*=\s*["\']home_loggedout\.jst["\']|\bid\s*=\s*["\']logout["\']', re.I)
# What an unauthenticated status page actually is: a script whose only job is to bounce to the logout page.
_REDIRECT_ONLY_RX = re.compile(r'<script[^>]*>\s*(?:alert\w*\s*\([^)]*\)\s*;?\s*)?(?:window\.)?location(?:\.href)?\s*=\s*'
                               r'["\']home_loggedout\.jst["\']\s*;?\s*</script>', re.I)


def logged_out(html: str) -> bool:
    """True when a page is the login form or the bare ``home_loggedout`` redirect (no session)."""
    h = html or ""
    if _LOGGED_IN_RX.search(h):
        return False
    if 'name="password"' in h or "name='password'" in h:
        return True
    return bool(_REDIRECT_ONLY_RX.search(h))


def _is_ts(cell: str) -> bool:
    return any(p.match(cell or "") for p in _TS_PATTERNS)


def _kw_score(cells: Sequence[str]) -> int:
    score = 0
    for c in cells:
        lc = (c or "").lower()
        if lc and any(k in lc for k in _HEADER_KEYWORDS):
            score += 1
    return score


def orient(rows: List[List[str]]) -> List[List[str]]:
    """Transpose a row-header (metric per row, channel per column) table into header-row form."""
    if not rows:
        return rows
    width = max(len(r) for r in rows)
    padded = [list(r) + [""] * (width - len(r)) for r in rows]
    row0 = _kw_score(padded[0])
    col0 = _kw_score([r[0] for r in padded])
    if col0 > row0 and col0 >= 2:
        return [[padded[r][c] for r in range(len(padded))] for c in range(width)]
    return padded


def classify_table(rows: List[List[str]]) -> Optional[str]:
    """``'downstream'`` / ``'upstream'`` / ``'log'`` / ``None`` for a table (any orientation)."""
    if not rows:
        return None
    ts_rows = sum(1 for r in rows if r and _is_ts(r[0]))
    if ts_rows >= 1 and ts_rows >= len(rows) - 1:
        return "log"
    rows = orient(rows)
    header = " | ".join(c.lower() for c in rows[0])
    if any(k in header for k in ("snr", "signal to noise", "unerrored", "uncorrectable")):
        return "downstream"
    if "symbol rate" in header or "channel type" in header or ("power level" in header and "snr" not in header):
        return "upstream"
    return None


def _col_map(header: Sequence[str]) -> Dict[str, int]:
    cols: Dict[str, int] = {}
    for i, h in enumerate(header):
        lh = (h or "").lower()
        if not lh:
            continue

        def put(key: str) -> None:
            cols.setdefault(key, i)

        if "channel type" in lh:
            put("type")
        elif "channel id" in lh or lh == "index" or lh in ("channel", "ch", "chan", "channel index", "index/channel"):
            put("ch")
        elif "lock" in lh:
            put("lock")
        elif "frequency" in lh or lh == "freq":
            put("freq")
        elif "snr" in lh or "signal to noise" in lh or "mer" == lh:
            put("snr")
        elif "power" in lh:
            put("pwr")
        elif "modulation" in lh:
            put("mod")
        elif "unerrored" in lh:
            put("unerr")
        elif "uncorrectable" in lh:
            put("uncorr")
        elif "correctable" in lh:
            put("corr")
        elif "symbol rate" in lh:
            put("symrate")
    return cols


def _num(cell: Optional[str]) -> Optional[float]:
    if cell is None:
        return None
    m = _NUM_RE.search(cell.replace(",", ""))
    return float(m.group(0)) if m else None


def _int(cell: Optional[str]) -> Optional[int]:
    v = _num(cell)
    return int(v) if v is not None else None


def _freq_hz(cell: Optional[str]) -> Optional[int]:
    v = _num(cell)
    if v is None:
        return None
    lc = (cell or "").lower()
    if "mhz" in lc:
        v = v * 1e6
    elif "khz" in lc:
        v = v * 1e3
    elif "hz" not in lc and v < 100000:
        v = v * 1e6  # bare number: MHz on every firmware we have seen
    return int(v)


def parse_channel_table(rows: List[List[str]], kind: str) -> List[Dict[str, Any]]:
    """Rows of a downstream/upstream table (any orientation) → channel dicts keyed by ``ch``."""
    rows = orient(rows)
    if len(rows) < 2:
        return []
    cols = _col_map(rows[0])
    out: List[Dict[str, Any]] = []
    for i, r in enumerate(rows[1:]):
        if not any(r):
            continue

        def cell(key: str) -> Optional[str]:
            j = cols.get(key)
            return r[j] if j is not None and j < len(r) else None

        ch_txt = cell("ch")
        ch = _int(ch_txt)
        if ch is None and not (ch_txt or "").strip():
            ch = i + 1  # tables without a channel-id column: number them
        if ch is None or ch <= 0:
            continue  # DOCSIS channel ids are 1-255; "0" is an unused placeholder column on the XB7
        lock_txt = (cell("lock") or "").lower()
        lock = None
        if lock_txt:
            lock = ("locked" in lock_txt) and not (lock_txt.startswith("un") or lock_txt.startswith("not"))
        d: Dict[str, Any] = {"ch": ch, "lock": lock, "freq_hz": _freq_hz(cell("freq")), "pwr_dbmv": _num(cell("pwr")),
                             "mod": cell("mod") or None}
        if kind == "downstream":
            d["snr_db"] = _num(cell("snr"))
            d["unerr"] = _int(cell("unerr"))
            d["corr"] = _int(cell("corr"))
            d["uncorr"] = _int(cell("uncorr"))
        else:
            d["type"] = cell("type") or None
            d["symrate"] = _num(cell("symrate"))
        out.append(d)
    return out


def classify_log_line(text: str) -> str:
    for name, rx in _LOG_CLASSES:
        if rx.search(text or ""):
            return name
    return "other"


def parse_log_ts(text: str) -> Optional[float]:
    """Epoch seconds of a log timestamp cell (local time); ``None`` when unparseable or epoch-1970."""
    t = " ".join((text or "").split())
    for fmt in _TS_FORMATS:
        try:
            st = time.strptime(t, fmt)
        except ValueError:
            continue
        if st.tm_year < 2000:
            return None
        try:
            return time.mktime(st)
        except (OverflowError, ValueError):
            return None
    return None


def parse_log_table(rows: List[List[str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rows:
        if not r or not _is_ts(r[0]):
            continue
        ts = r[0]
        rest = [c for c in r[1:] if c]
        if not rest:
            continue
        text = max(rest, key=len)
        prio = rest[0] if len(rest) > 1 and rest[0] != text else None
        out.append({"ts": ts, "text": text, "class": classify_log_line(text), "prio": prio})
    return out


def parse_uptime(text: str) -> Optional[int]:
    """``System Uptime: 3 days 04h:22m:15s`` / ``12d 3h 4m 5s`` / ``0 days 01:02:03`` → seconds."""
    m = _UPTIME_RE.search(text or "")
    if not m:
        return None
    s = m.group(1).lower()
    total = 0
    found = False
    for val, unit in re.findall(r"(\d+)\s*(d|day|days|h|hr|hour|hours|m|min|mins|minute|minutes|s|sec|secs|second|seconds)\b", s):
        found = True
        n = int(val)
        if unit.startswith("d"):
            total += n * 86400
        elif unit.startswith("h"):
            total += n * 3600
        elif unit.startswith("m"):
            total += n * 60
        else:
            total += n
    hms = re.search(r"(\d{1,2}):(\d{2}):(\d{2})", s)
    if hms:
        found = True
        total += int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3))
    return total if found else None


def parse_fw(text: str) -> Optional[str]:
    m = _FW_RE.search(text or "")
    return m.group(1) if m else None


def extract_csrf_token(html: str) -> Optional[str]:
    """The per-session CSRF token the log page's script sends as ``csrfp_token``."""
    for rx in _CSRF_RES:
        m = rx.search(html or "")
        if m:
            return m.group(1)
    return None


def parse_log_json(body: str, mode: str) -> List[Dict[str, Any]]:
    """The ``ajax_troubleshooting_logs.jst`` reply → log lines; raises ``ValueError`` when it is not JSON.

    System/event entries are ``{"Des", "time", "Level"}``; firewall entries (``Count``/``Type``) are kept too.
    """
    data = json.loads(body)
    items = list(data.values()) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    out: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        text = " ".join(str(it.get("Des") or it.get("des") or "").split())
        if not text:
            continue
        ts = " ".join(str(it.get("time") or it.get("Time") or "").split())
        prio = " ".join(str(it.get("Level") or it.get("Type") or "").split())  # values end in " \n" on the XB7
        out.append({"ts": ts, "text": text, "class": classify_log_line(text), "prio": prio or None, "mode": mode})
    return out


def parse_local_time(text: str) -> Optional[float]:
    """Epoch seconds of the gateway's own "Local time:" line (its clock, which can be off by hours)."""
    m = _LOCAL_TIME_RE.search(text or "")
    return parse_log_ts(m.group(1)) if m else None


def parse_page(html: str) -> Dict[str, Any]:
    """Everything one page yields: ``ds``/``us`` channels, ``log`` lines, ``uptime_s``, ``fw``, ``tables``."""
    tables, text = extract_tables(html)
    res: Dict[str, Any] = {"ds": [], "us": [], "log": [], "uptime_s": parse_uptime(text), "fw": parse_fw(text),
                           "local_ts": parse_local_time(text), "tables": [], "logged_out": logged_out(html)}
    ds: Dict[int, Dict[str, Any]] = {}
    us: Dict[int, Dict[str, Any]] = {}
    for t in tables:
        kind = classify_table(t)
        info = {"kind": kind, "rows": len(t), "cols": max(len(r) for r in t) if t else 0}
        if kind == "downstream":
            chans = parse_channel_table(t, "downstream")
            info["channels"] = len(chans)
            _merge_channels(ds, chans)  # the XB7 splits SNR/power and codewords into two tables
        elif kind == "upstream":
            chans = parse_channel_table(t, "upstream")
            info["channels"] = len(chans)
            _merge_channels(us, chans)
        elif kind == "log":
            lines = parse_log_table(t)
            info["lines"] = len(lines)
            res["log"].extend(lines)
        res["tables"].append(info)
    res["ds"] = [ds[k] for k in sorted(ds)]
    res["us"] = [us[k] for k in sorted(us)]
    return res


def _merge_channels(dst: Dict[int, Dict[str, Any]], chans: List[Dict[str, Any]]) -> None:
    for c in chans:
        cur = dst.setdefault(c["ch"], {"ch": c["ch"]})
        for k, v in c.items():
            if v is not None or k not in cur:
                cur[k] = v


def merge_pages(pages: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Merge the per-page results of one poll (channels by id; log lines deduped by (ts, text))."""
    ds: Dict[int, Dict[str, Any]] = {}
    us: Dict[int, Dict[str, Any]] = {}
    logs: "OrderedDict[Tuple[str, str], Dict[str, Any]]" = OrderedDict()
    uptime = None
    fw = None
    local_ts = None
    for _path, p in pages.items():
        if local_ts is None and p.get("local_ts") is not None:
            local_ts = p["local_ts"]
        _merge_channels(ds, p.get("ds") or [])
        _merge_channels(us, p.get("us") or [])
        for ln in p.get("log") or []:
            logs.setdefault((ln["ts"], ln["text"]), ln)
        if uptime is None and p.get("uptime_s") is not None:
            uptime = p["uptime_s"]
        if fw is None and p.get("fw"):
            fw = p["fw"]
    return {"ds": [ds[k] for k in sorted(ds)], "us": [us[k] for k in sorted(us)], "log": list(logs.values()),
            "uptime_s": uptime, "fw": fw, "local_ts": local_ts}


def _is_locked(c: Dict[str, Any]) -> bool:
    return c.get("lock") is not False


def derive(cur: Dict[str, Any], prev: Optional[Dict[str, Any]], dt_s: Optional[float]) -> Dict[str, Any]:
    """Flags and deltas of one poll versus the previous one."""
    flags: List[str] = []
    ds = cur.get("ds") or []
    us = cur.get("us") or []
    snrs = [c["snr_db"] for c in ds if _is_locked(c) and c.get("snr_db") is not None]
    pwrs = [c["pwr_dbmv"] for c in ds if _is_locked(c) and c.get("pwr_dbmv") is not None]
    upwr = [c["pwr_dbmv"] for c in us if _is_locked(c) and c.get("pwr_dbmv") is not None]
    if any(s < DS_SNR_LOW_DB for s in snrs):
        flags.append("ds_snr_low")
    if any(p < DS_POWER_MIN or p > DS_POWER_MAX for p in pwrs):
        flags.append("ds_power_out")
    if any(p >= US_POWER_HIGH for p in upwr):
        flags.append("us_power_high")
    if any(p < US_POWER_LOW for p in upwr):
        flags.append("us_power_low")
    deltas: Dict[str, Dict[str, Optional[int]]] = {"uncorr": {}, "corr": {}, "unerr": {}}
    uncorr_delta = 0
    corr_delta = 0
    if prev is not None:
        pmap = {c["ch"]: c for c in prev.get("ds") or []}
        for c in ds:
            p = pmap.get(c["ch"])
            for key in ("uncorr", "corr", "unerr"):
                a = c.get(key)
                b = p.get(key) if p else None
                d = (a - b) if (a is not None and b is not None) else None
                if d is not None and d < 0:
                    d = None  # counter reset (reboot); not a burst
                deltas[key][str(c["ch"])] = d
                if key == "uncorr" and d:
                    uncorr_delta += d
                    if dt_s and dt_s > 0 and d / (dt_s / 60.0) > UNCORR_BURST_PER_MIN and "uncorr_burst" not in flags:
                        flags.append("uncorr_burst")
                elif key == "corr" and d:
                    corr_delta += d
        locked_now = sum(1 for c in ds if _is_locked(c))
        locked_prev = sum(1 for c in prev.get("ds") or [] if _is_locked(c))
        if ds and (prev.get("ds") or []) and locked_now < locked_prev:
            flags.append("partial_service")
        if cur.get("uptime_s") is not None and prev.get("uptime_s") is not None and cur["uptime_s"] < prev["uptime_s"]:
            flags.append("reboot")
    return {
        "flags": flags,
        "deltas": deltas,
        "uncorr_delta": uncorr_delta,
        "corr_delta": corr_delta,
        "ds_snr_min": min(snrs) if snrs else None,
        "ds_pwr_min": min(pwrs) if pwrs else None,
        "ds_pwr_max": max(pwrs) if pwrs else None,
        "us_pwr_max": max(upwr) if upwr else None,
        "ds_locked": sum(1 for c in ds if _is_locked(c)),
    }


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
class Xb7Client:
    """Cookie-jar HTTP client for the XB7 web UI; never lets the password leak."""

    def __init__(self, dcfg: dict, opener: Optional[Any] = None, timeout: float = HTTP_TIMEOUT_S) -> None:
        self.base = str(dcfg.get("url") or "http://10.0.0.1").rstrip("/")
        self.username = str(dcfg.get("username") or "admin").strip().lower()  # the login page JS lower-cases it too
        self._password = dcfg.get("password") or ""
        self.login_paths = list(dcfg.get("login_paths") or ["/check.jst", "/check.jsp"])
        self.verify_path = (list(dcfg.get("pages") or []) or ["/at_a_glance.jst"])[0]
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = opener or urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.logged_in = False
        self.login_path_used: Optional[str] = None

    def scrub(self, text: Any) -> str:
        s = str(text)
        if self._password:
            s = s.replace(self._password, "***")
            s = s.replace(urllib.parse.quote_plus(self._password), "***")
        return s

    def __repr__(self) -> str:
        return "<Xb7Client %s user=%s>" % (self.base, self.username)

    def _open(self, req: Any, timeout: Optional[float] = None) -> Tuple[int, str]:
        try:
            resp = self.opener.open(req, timeout=timeout if timeout is not None else self.timeout)
            try:
                body = resp.read(4 * 1024 * 1024)
                code = getattr(resp, "status", None) or resp.getcode()
            finally:
                try:
                    resp.close()
                except Exception:  # noqa: BLE001
                    pass
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(1024 * 1024)
            except Exception:  # noqa: BLE001
                body = b""
            code = exc.code
        except Exception as exc:  # noqa: BLE001
            raise Xb7Error("%s: %s" % (type(exc).__name__, self.scrub(str(exc))[:160]))
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        return int(code), body

    def fetch(self, path: str) -> Tuple[int, str]:
        """GET ``base + path`` → ``(status, html)``; raises :class:`Xb7Error` on transport errors."""
        url = self.base + (path if path.startswith("/") else "/" + path)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        return self._open(req)

    def post(self, path: str, form: Dict[str, str]) -> Tuple[int, str]:
        url = self.base + (path if path.startswith("/") else "/" + path)
        data = urllib.parse.urlencode(form).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, "Referer": self.base + "/",
                                                             "Content-Type": "application/x-www-form-urlencoded"})
        return self._open(req)

    def fetch_logs(self, token: str, mode: str, timef: str, timeout: float = LOG_TIMEOUT_S) -> List[Dict[str, Any]]:
        """GET the log JSON the troubleshooting page loads (``mode`` event/system/firewall, ``timef`` Today…)."""
        q = urllib.parse.urlencode({"mode": mode, "timef": timef, "csrfp_token": token})
        req = urllib.request.Request(self.base + LOG_ENDPOINT + "?" + q, headers={
            "User-Agent": USER_AGENT, "Referer": self.base + LOG_PAGE, "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01"})
        code, body = self._open(req, timeout=timeout)
        if code >= 400:
            raise Xb7Error("log endpoint HTTP %d" % code)
        if logged_out(body):
            raise Xb7Error("log endpoint answered with the login page")
        try:
            return parse_log_json(body, mode)
        except ValueError:
            raise Xb7Error("log endpoint did not return JSON (%d bytes)" % len(body))

    def login(self) -> bool:
        """GET the login page, POST the credentials to each login path, verify with a status page."""
        self.logged_in = False
        try:
            self.fetch("/")
        except Xb7Error as exc:
            log.info("docsis: login page GET failed: %s", exc)
            raise
        form = {"username": self.username, "password": self._password, "locale": "false"}
        self.login_diag: List[Dict[str, Any]] = []
        for lp in self.login_paths:
            try:
                code, body = self.post(lp, form)
            except Xb7Error as exc:
                log.info("docsis: POST %s failed: %s", lp, exc)
                self.login_diag.append({"path": lp, "error": str(exc)})
                continue
            diag: Dict[str, Any] = {"path": lp, "status": code, "bytes": len(body), "login_form": 'name="password"' in body,
                                    "loggedout_script": "home_loggedout" in body, "title": _title_of(body), "response": body}
            if code == 404:
                self.login_diag.append(diag)
                continue
            ok = False
            if code < 400 and body.strip() and not logged_out(body):
                ok = True
            else:
                try:
                    vcode, vbody = self.fetch(self.verify_path)
                    diag.update({"verify_path": self.verify_path, "verify_status": vcode, "verify_bytes": len(vbody),
                                 "verify_login_form": 'name="password"' in vbody, "verify_loggedout_script": "home_loggedout" in vbody,
                                 "verify_title": _title_of(vbody), "verify_response": vbody})
                    ok = vcode < 400 and not logged_out(vbody)
                except Xb7Error as exc:
                    diag["verify_error"] = str(exc)
                    ok = False
            self.login_diag.append(diag)
            log.info("docsis: POST %s -> HTTP %s, %d bytes, login_form=%s loggedout=%s title=%r%s", lp, code, len(body),
                     diag["login_form"], diag["loggedout_script"], diag["title"],
                     (" | verify %s -> HTTP %s login_form=%s loggedout=%s" % (self.verify_path, diag.get("verify_status"),
                      diag.get("verify_login_form"), diag.get("verify_loggedout_script"))) if "verify_status" in diag else "")
            if ok:
                self.logged_in = True
                self.login_path_used = lp
                log.info("docsis: logged in to %s via %s", self.base, lp)
                return True
        log.warning("docsis: login rejected by %s (user %s)", self.base, self.username)
        return False


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
class DocsisCollector:
    """``DocsisCollector(ctx)``; ``.refresh()``, ``.recent(n)`` (the ``GET /api/docsis`` body)."""

    name = "docsis"

    def __init__(self, ctx: Any, client: Optional[Xb7Client] = None, clock: Callable[[], float] = time.time,
                 mono: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.store = ctx.store
        self.cfg = ctx.cfg or {}
        self.dcfg = dict(self.cfg.get("docsis") or {})
        self._clock = clock
        self._mono = mono
        self.enabled = bool(self.dcfg.get("password"))
        self.client = client or (Xb7Client(self.dcfg) if self.enabled else None)
        try:
            self.interval_s = max(10.0, float(self.dcfg.get("interval_s", 60)))
        except (TypeError, ValueError):
            self.interval_s = 60.0
        self.save_raw = bool(self.dcfg.get("save_raw", True))
        self.pages: List[Dict[str, Any]] = [{"path": p, "fail404": 0, "dropped": False, "raw_saved": False, "status": None}
                                            for p in (self.dcfg.get("pages") or [])]
        self.thread = None
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._login_failures = 0
        self._paused_until: Optional[float] = None
        self._next_poll: Optional[float] = None
        self._extra: Deque[float] = deque()
        self._last_refresh: Optional[float] = None
        self._raw_files = 0
        self._seen: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
        self._log_history_done = False
        self._log_day: Optional[str] = None
        self.log_status: Optional[str] = None
        self._prev: Optional[Dict[str, Any]] = None
        self._prev_t: Optional[float] = None
        self._prev_flags: set = set()
        self.polls: Deque[Dict[str, Any]] = deque(maxlen=200)
        self.log_lines: Deque[Dict[str, Any]] = deque(maxlen=500)
        self.poll_count = 0
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if not self.enabled:
            self.state.set_collector(self.name, "disabled", reason="docsis.password not set")
            return
        self.state.set_collector(self.name, "ok", url=self.client.base if self.client else None)
        self.thread = start_thread(self.name, self._loop, self.state)

    def stop(self, timeout: float = 2.0) -> None:
        self._wake.set()
        t = self.thread
        if t is not None:
            t.join(timeout)

    def _loop(self) -> None:
        st = self.state
        while not st.stop_event.is_set():
            now = self._mono()
            due = self._due(now)
            if due:
                self.poll()
                continue
            wait_for = self._next_wait(now)
            self._wake.wait(min(1.0, max(0.05, wait_for)))
            self._wake.clear()

    def _due(self, mono_now: float) -> bool:
        with self._lock:
            if self._paused_until is not None:
                if mono_now < self._paused_until:
                    return False
                self._paused_until = None
                self._login_failures = 0
            if self._extra and self._extra[0] <= mono_now:
                self._extra.popleft()
                return True
            return self._next_poll is None or mono_now >= self._next_poll

    def _next_wait(self, mono_now: float) -> float:
        with self._lock:
            cands = []
            if self._paused_until is not None:
                cands.append(self._paused_until - mono_now)
            else:
                if self._next_poll is not None:
                    cands.append(self._next_poll - mono_now)
                if self._extra:
                    cands.append(self._extra[0] - mono_now)
            return min(cands) if cands else 1.0

    # ----------------------------------------------------------------- API
    def refresh(self) -> bool:
        """Request an immediate extra poll pair (now and +15 s); rate-limited to one pair per 60 s."""
        if not self.enabled or self.client is None:
            return False
        now = self._mono()
        with self._lock:
            if self._paused_until is not None and now < self._paused_until:
                return False
            if self._last_refresh is not None and now - self._last_refresh < REFRESH_RATE_LIMIT_S:
                return False
            self._last_refresh = now
            self._extra.append(now)
            self._extra.append(now + REFRESH_SECOND_POLL_S)
        self._wake.set()
        return True

    def recent(self, n: int = 20) -> Dict[str, Any]:
        """The ``GET /api/docsis`` body."""
        coll = self.state.collector(self.name) or {}
        with self._lock:
            polls = list(self.polls)[-max(0, int(n)):]
            lines = list(self.log_lines)[-50:]
            prev = self._prev or {}
        summary = {
            "enabled": self.enabled,
            "url": self.client.base if self.client else None,
            "logged_in": bool(self.client and self.client.logged_in),
            "polls": self.poll_count,
            "last_poll_t": polls[-1]["t"] if polls else None,
            "ds_channels": len(prev.get("ds") or []),
            "us_channels": len(prev.get("us") or []),
            "uptime_s": prev.get("uptime_s"),
            "fw": prev.get("fw"),
            "flags": list(polls[-1].get("flags") or []) if polls else [],
            "pages": {p["path"]: ("dropped" if p["dropped"] else p["status"]) for p in self.pages},
            "last_error": self.last_error,
            "reason": coll.get("reason"),
        }
        return {"status": coll.get("status", "disabled"), "polls": polls, "log": lines, "summary": summary}

    # ---------------------------------------------------------------- poll
    def _ensure_login(self) -> bool:
        assert self.client is not None
        if self.client.logged_in:
            return True
        try:
            ok = self.client.login()
        except Xb7Error as exc:
            self.last_error = str(exc)
            self.state.set_collector(self.name, "degraded", reason="XB7 unreachable: %s" % exc)
            return False
        if ok:
            self._login_failures = 0
            return True
        self._login_failures += 1
        if self._login_failures >= LOGIN_FAILURES_BEFORE_PAUSE:
            with self._lock:
                self._paused_until = self._mono() + LOGIN_PAUSE_S
                self._extra.clear()
            self.state.set_collector(self.name, "degraded", reason=LOGIN_REJECTED_CHIP, login_failures=self._login_failures)
            log.warning("docsis: %s", LOGIN_REJECTED_CHIP)
        else:
            self.state.set_collector(self.name, "degraded", reason="XB7: login rejected (%d/%d)" % (self._login_failures, LOGIN_FAILURES_BEFORE_PAUSE))
        return False

    def _fetch_pages(self) -> Tuple[Dict[str, str], Dict[str, int]]:
        """Fetch every active page once; returns ``{path: html}`` and ``{path: status}``."""
        assert self.client is not None
        htmls: Dict[str, str] = {}
        codes: Dict[str, int] = {}
        ok_bases = set()
        relogged = False
        for page in self.pages:
            path = page["path"]
            if page["dropped"]:
                continue
            base, ext = _split_ext(path)
            if ext == ".jsp" and base in ok_bases:
                page["status"] = "skipped (.jst ok)"
                continue
            try:
                code, body = self.client.fetch(path)
            except Xb7Error as exc:
                self.last_error = str(exc)
                page["status"] = "error"
                raise
            if code < 400 and logged_out(body) and not relogged:
                relogged = True
                self.client.logged_in = False
                if not self._ensure_login():
                    raise Xb7Error("session expired and re-login failed")
                code, body = self.client.fetch(path)
            codes[path] = code
            if code == 404:
                page["fail404"] += 1
                page["status"] = "404"
                if page["fail404"] >= PAGE_404_DROP_AFTER:
                    page["dropped"] = True
                    log.info("docsis: %s dropped after %d 404s", path, page["fail404"])
                continue
            if code >= 400 or logged_out(body):
                page["status"] = "HTTP %d" % code if code >= 400 else "logged out"
                continue
            page["status"] = "ok"
            htmls[path] = body
            ok_bases.add(base)
            if self.save_raw and not page["raw_saved"]:
                page["raw_saved"] = True
                self._save_raw(path, body)
        return htmls, codes

    def _save_raw(self, path: str, body: str) -> None:
        if self._raw_files >= RAW_MAX_FILES:
            return
        name = "xb7_raw/%s.html" % _page_name(path)
        try:
            self.store.write_atomic(name, body.encode("utf-8", "replace")[:RAW_MAX_BYTES])
            self._raw_files += 1
        except Exception:  # noqa: BLE001
            log.debug("docsis: raw save failed for %s", path, exc_info=True)

    def poll(self, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """One full poll: login if needed, fetch, parse, derive, publish, store."""
        if not self.enabled or self.client is None:
            return None
        now = self._clock() if now is None else now
        with self._lock:
            self._next_poll = self._mono() + self.interval_s
        if not self._ensure_login():
            return None
        try:
            htmls, codes = self._fetch_pages()
        except Xb7Error as exc:
            self.state.set_collector(self.name, "degraded", reason="XB7 unreachable: %s" % exc)
            return None
        if not htmls:
            self.state.set_collector(self.name, "degraded", reason="no XB7 status page could be fetched")
            return None
        parsed = {p: parse_page(h) for p, h in htmls.items()}
        merged = merge_pages(parsed)
        extra = self._fetch_json_logs(htmls, now)
        if extra:
            have = {(ln["ts"], ln["text"]) for ln in merged["log"]}
            for ln in extra:
                key = (ln["ts"], ln["text"])
                if key not in have:
                    have.add(key)
                    merged["log"].append(ln)
        row = self._build_row(now, merged, parsed)
        self._publish(now, row, merged)
        return row

    def _fetch_json_logs(self, htmls: Dict[str, str], now: float) -> List[Dict[str, Any]]:
        """Event/system log lines from the JSON endpoint (a week of history once, then today's lines).

        Lines from the history fetch carry ``history: True`` and never become events, whichever poll
        they arrive in; the gateway's clock can be off by hours, so timestamps are not used for that.
        """
        html = htmls.get(LOG_PAGE)
        if html is None or self.client is None:
            return []
        token = extract_csrf_token(html)
        if not token:
            self.log_status = "no CSRF token on %s" % LOG_PAGE
            return []
        today = time.strftime("%Y-%m-%d", time.localtime(now))
        history = not self._log_history_done
        if history:
            timefs = [LOG_HISTORY_TIMEF]
        elif self._log_day is not None and self._log_day != today:
            timefs = ["Yesterday", "Today"]  # do not lose the lines logged just before midnight
        else:
            timefs = ["Today"]
        out: List[Dict[str, Any]] = []
        ok = 0
        errors: List[str] = []
        for mode in LOG_MODES:
            for tf in timefs:
                try:
                    lines = self.client.fetch_logs(token, mode, tf)
                except Xb7Error as exc:
                    errors.append("%s/%s: %s" % (mode, tf, exc))
                    continue
                ok += 1
                for ln in lines:
                    if history:
                        ln["history"] = True
                    out.append(ln)
        if ok:
            if history:
                self._log_history_done = True
            self._log_day = today
        self.log_status = ("ok: %d lines" % len(out)) if not errors else ("partial: " if ok else "failed: ") + "; ".join(errors)[:300]
        if errors:
            log.info("docsis: log endpoint %s", self.log_status)
        return out

    def _build_row(self, now: float, merged: Dict[str, Any], parsed: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        with self._lock:
            prev = self._prev
            prev_t = self._prev_t
            first = self.poll_count == 0
            dt = (now - prev_t) if prev_t is not None else None
            d = derive(merged, prev, dt)
            new_lines: List[Dict[str, Any]] = []
            for ln in merged["log"]:
                key = (ln["ts"], ln["text"])
                if key in self._seen:
                    continue
                self._seen[key] = None
                nl = {"ts": ln["ts"], "text": ln["text"], "class": ln["class"]}
                for k in ("history", "mode", "prio"):
                    if ln.get(k) is not None:
                        nl[k] = ln[k]
                new_lines.append(nl)
                self.log_lines.append(dict(nl, seen_t=round(now, 3)))
            while len(self._seen) > 20000:
                self._seen.popitem(last=False)
            offset = None
            if merged.get("local_ts") is not None:
                offset = round(now - merged["local_ts"], 1)  # the gateway's own clock vs this computer's
            elif new_lines and not first:
                stamps = [parse_log_ts(ln["ts"]) for ln in new_lines]
                stamps = [s for s in stamps if s is not None]
                if stamps:
                    offset = round(now - max(stamps), 1)
            tables = {p: [t for t in r.get("tables") or []] for p, r in parsed.items()}
            row = {
                "t": round(now, 3),
                "ok": True,
                "uptime_s": merged.get("uptime_s"),
                "fw": merged.get("fw"),
                "ds": merged["ds"],
                "us": merged["us"],
                "log_new": new_lines,
                "flags": d["flags"],
                "log_clock_offset_s": offset,
                "deltas": d["deltas"],
                "ds_snr_min": d["ds_snr_min"],
                "ds_pwr_min": d["ds_pwr_min"],
                "ds_pwr_max": d["ds_pwr_max"],
                "us_pwr_max": d["us_pwr_max"],
                "uncorr_delta": d["uncorr_delta"],
                "corr_delta": d["corr_delta"],
                "initial": first,
                "pages": {p: len(t) for p, t in tables.items()},
            }
            self._prev = merged
            self._prev_t = now
            self.poll_count += 1
            self.polls.append(row)
        return row

    def _publish(self, now: float, row: Dict[str, Any], merged: Dict[str, Any]) -> None:
        flags = list(row["flags"])
        if not row.get("initial"):
            for ln in row["log_new"]:
                if ln["class"] in NOTE_CLASSES and not ln.get("history"):
                    self.state.raise_note("docsis_" + ln["class"], t=now, severity=CLASS_SEVERITY.get(ln["class"], 3),
                                          note="XB7 log: %s %s" % (ln["ts"], ln["text"][:200]), ts=ln["ts"], text=ln["text"][:400],
                                          log_ts=parse_log_ts(ln["ts"]))
        fset = set(flags)
        if "uncorr_burst" in fset:
            self.state.raise_note("docsis_uncorr", t=now, severity=CLASS_SEVERITY["uncorr"],
                                  note="uncorrectable codewords +%d since last poll" % row["uncorr_delta"],
                                  uncorr_delta=row["uncorr_delta"], per_channel=row["deltas"].get("uncorr"))
        ps = {f for f in fset if f in ("ds_snr_low", "ds_power_out", "us_power_high", "us_power_low")}
        if ps - self._prev_flags:
            self.state.raise_note("docsis_power_snr", t=now, severity=CLASS_SEVERITY["power_snr"],
                                  note="RF out of range: %s" % ", ".join(sorted(ps)), flags=sorted(ps),
                                  ds_snr_min=row["ds_snr_min"], ds_pwr_min=row["ds_pwr_min"], ds_pwr_max=row["ds_pwr_max"],
                                  us_pwr_max=row["us_pwr_max"])
        if "partial_service" in fset:
            self.state.raise_note("docsis_partial", t=now, severity=CLASS_SEVERITY["partial"],
                                  note="locked downstream channel count dropped", ds_locked=sum(1 for c in merged["ds"] if _is_locked(c)))
        if "reboot" in fset:
            self.state.raise_note("docsis_reboot", t=now, severity=CLASS_SEVERITY["reboot"],
                                  note="XB7 uptime decreased (modem rebooted)", uptime_s=row["uptime_s"])
        self._prev_flags = ps
        latest = {
            "ds_snr_min": row["ds_snr_min"], "ds_pwr_min": row["ds_pwr_min"], "ds_pwr_max": row["ds_pwr_max"],
            "us_pwr_max": row["us_pwr_max"], "uncorr_delta": row["uncorr_delta"], "corr_delta": row["corr_delta"],
            "uptime_s": row["uptime_s"], "flags": flags, "log_new": row["log_new"][:20], "fw": row["fw"],
            "log_clock_offset_s": row["log_clock_offset_s"], "t": row["t"], "ds_channels": len(row["ds"]),
            "us_channels": len(row["us"]),
            "log_lines_seen": len(self.log_lines),  # 0: this firmware hides the event log (no T3/T4 view)
        }
        self.state.set_latest("docsis", latest)
        try:
            self.store.append_json("xb7", row)
        except Exception:  # noqa: BLE001
            log.debug("docsis: append_json failed", exc_info=True)
        self.state.set_collector(self.name, "ok", url=self.client.base if self.client else None, polls=self.poll_count,
                                 ds=len(row["ds"]), us=len(row["us"]))
        try:
            self.state.publish("docsis", latest)
        except Exception:  # noqa: BLE001
            pass


def _split_ext(path: str) -> Tuple[str, str]:
    base, dot, ext = path.rpartition(".")
    if not dot:
        return path, ""
    return base, "." + ext.lower()


def _page_name(path: str) -> str:
    name = path.strip("/").replace("/", "_") or "index"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


# ---------------------------------------------------------------------------
# --docsis-dump
# ---------------------------------------------------------------------------
def dump_cli(cfg: dict, out_dir: Optional[Path] = None, client: Optional[Xb7Client] = None,
             out: Callable[[str], Any] = print, now: Optional[float] = None) -> int:
    """Log in, save every configured page plus the login page, print the recognised tables."""
    dcfg = dict((cfg or {}).get("docsis") or {})
    if not dcfg.get("password"):
        out("docsis-dump: docsis.password is not set in config.json; nothing to do")
        return 1
    cli = client or Xb7Client(dcfg)
    if out_dir is None:
        root = Path(__file__).resolve().parent.parent.parent
        out_dir = root / "sessions" / ("docsis-dump-%s" % time.strftime("%Y%m%d-%H%M%S", time.localtime(now)))
    out_dir = Path(out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        out("docsis-dump: cannot create %s: %s" % (out_dir, exc))
        return 1
    try:
        code, login_html = cli.fetch("/")
        (out_dir / "login_page.html").write_text(login_html, encoding="utf-8")
        out("saved login page (HTTP %d, logged_out=%s) -> %s" % (code, logged_out(login_html), out_dir / "login_page.html"))
    except Xb7Error as exc:
        out("docsis-dump: cannot reach %s: %s" % (cli.base, exc))
        return 1
    try:
        logged = cli.login()
    except Xb7Error as exc:
        out("docsis-dump: login failed: %s" % exc)
        return 1
    for i, d in enumerate(getattr(cli, "login_diag", []) or []):
        if "error" in d:
            out("login POST %s: error %s" % (d.get("path"), d["error"]))
            continue
        out("login POST %s: HTTP %s, %d bytes, title=%r, login_form=%s, loggedout_script=%s" % (
            d.get("path"), d.get("status"), d.get("bytes", 0), d.get("title"), d.get("login_form"), d.get("loggedout_script")))
        if "verify_status" in d:
            out("  then GET %s: HTTP %s, %d bytes, title=%r, login_form=%s, loggedout_script=%s" % (
                d.get("verify_path"), d.get("verify_status"), d.get("verify_bytes", 0), d.get("verify_title"),
                d.get("verify_login_form"), d.get("verify_loggedout_script")))
        for key, fname in (("response", "login_response_%d.html" % i), ("verify_response", "verify_page_%d.html" % i)):
            if d.get(key):
                try:
                    (out_dir / fname).write_text(cli.scrub(d[key]), encoding="utf-8")
                    out("  saved -> %s" % (out_dir / fname))
                except OSError:
                    pass
    if not logged:
        out("docsis-dump: login rejected (user %s). Check that the same username/password work in a browser at %s "
            "(this is the gateway admin tool login, not your Xfinity account), and that the gateway is not in a "
            "temporary lockout after failed attempts." % (cli.username, cli.base))
        return 1
    out("logged in via %s" % cli.login_path_used)
    recognised = 0
    ok_bases = set()
    log_html: Optional[str] = None
    for path in dcfg.get("pages") or []:
        base, ext = _split_ext(path)
        if ext == ".jsp" and base in ok_bases:
            continue  # the .jst twin worked: this firmware has no .jsp pages
        try:
            code, html = cli.fetch(path)
        except Xb7Error as exc:
            out("%-32s error: %s" % (path, exc))
            continue
        if code >= 400:
            # A missing twin (.jsp on .jst firmware or vice versa) is reported, not saved.
            out("%-32s HTTP %d (not saved)" % (path, code))
            continue
        fname = out_dir / (_page_name(path) + ".html")
        fname.write_text(html, encoding="utf-8")
        if code != 200:
            out("%-32s HTTP %d (saved)" % (path, code))
            continue
        if logged_out(html):
            out("%-32s logged-out page (saved)" % path)
            continue
        ok_bases.add(base)
        if path == LOG_PAGE:
            log_html = html
        res = parse_page(html)
        kinds = [t for t in res["tables"] if t["kind"]]
        desc = ", ".join("%s(%d)" % (t["kind"], t.get("channels", t.get("lines", t["rows"]))) for t in kinds) or "no table recognised"
        extra = []
        if res["uptime_s"] is not None:
            extra.append("uptime %ds" % res["uptime_s"])
        if res["fw"]:
            extra.append("fw %s" % res["fw"])
        out("%-32s %d tables: %s%s" % (path, len(res["tables"]), desc, (" [" + ", ".join(extra) + "]") if extra else ""))
        recognised += len(kinds)
    log_lines = _dump_logs(cli, log_html, out_dir, out)
    out("saved under %s; %d table(s) recognised, %d log line(s)" % (out_dir, recognised, log_lines))
    return 0 if recognised else 1


def _dump_logs(cli: "Xb7Client", log_html: Optional[str], out_dir: Path, out: Callable[[str], Any],
               timef: str = "Last month") -> int:
    """Fetch the event/system logs the troubleshooting page loads by script; save them and summarise."""
    if log_html is None:
        out("logs: %s was not fetched; no log endpoint call" % LOG_PAGE)
        return 0
    token = extract_csrf_token(log_html)
    if not token:
        out("logs: no CSRF token found on %s" % LOG_PAGE)
        return 0
    total = 0
    for mode in LOG_MODES:
        try:
            lines = cli.fetch_logs(token, mode, timef, timeout=120.0)
        except Xb7Error as exc:
            out("logs %-6s (%s): %s" % (mode, timef, exc))
            continue
        total += len(lines)
        fname = out_dir / ("%s_log_%s.json" % (mode, timef.lower().replace(" ", "_")))
        try:
            fname.write_text(json.dumps(lines, indent=1), encoding="utf-8")
        except OSError:
            pass
        counts: Dict[str, int] = {}
        for ln in lines:
            counts[ln["class"]] = counts.get(ln["class"], 0) + 1
        tally = ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts, key=lambda k: (-counts[k], k)))
        span = ""
        if lines:
            span = " from %s to %s" % (lines[-1]["ts"] or "?", lines[0]["ts"] or "?")
        if not lines:
            out("logs %-6s (%s): empty. This gateway's firmware does not show %s log entries to the admin login, so "
                "T3/T4 history is not available from it; the signal levels, codeword counters and reboots still are." % (mode, timef, mode))
            continue
        out("logs %-6s (%s): %d lines%s%s -> %s" % (mode, timef, len(lines), span, (" [" + tally + "]") if tally else "", fname))
        notable = [ln for ln in lines if ln["class"] in NOTE_CLASSES]
        for ln in notable[:15]:
            out("    %s  [%s] %s" % (ln["ts"], ln["class"], ln["text"][:140]))
        if len(notable) > 15:
            out("    ... %d more notable lines in the file" % (len(notable) - 15))
    return total


__all__ = [
    "DocsisCollector", "Xb7Client", "Xb7Error", "dump_cli", "extract_tables", "classify_table", "orient",
    "parse_channel_table", "parse_log_table", "parse_page", "merge_pages", "derive", "classify_log_line",
    "parse_log_ts", "parse_uptime", "parse_fw", "logged_out", "LOGIN_REJECTED_CHIP", "LOGIN_PAUSE_S",
    "extract_csrf_token", "parse_log_json", "parse_local_time", "LOG_ENDPOINT", "LOG_PAGE",
]
