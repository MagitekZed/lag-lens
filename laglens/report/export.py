"""Export ZIP (SPEC_FULL §9.2): ``build_zip`` for the server and ``export_cli`` for ``--export``.

``full`` pack: every file of the session directory except ``token``,
``laglens.pid`` and temp files, with ``config.json`` replaced by
``config.redacted.json`` (:func:`laglens.config.public`), ``xb7_raw/`` only
when ``raw`` is true, plus the generated ``summary.txt``, ``episodes.csv``,
``marks.csv``, ``comcast_evidence.txt`` and ``docsis_channels.csv``.
``comcast`` pack: ``report.html``, ``comcast_evidence.txt``, ``episodes.csv``,
``docsis_channels.csv``, ``summary.txt`` only.

The XB7 password never leaves the machine: text members are scrubbed for the
literal password (and the session token) on their way into the archive, the
token file is excluded, and the config is redacted. The archive is built with
``zipfile.ZIP_DEFLATED`` into a ``SpooledTemporaryFile`` and returned as bytes.
"""
import csv
import importlib
import io
import json
import logging
import os
import re
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from laglens import config as configmod
from laglens.report import sessions as sessionsmod
from laglens.version import __version__

log = logging.getLogger("laglens.report.export")

PACKS = ("full", "comcast")
EXCLUDED_NAMES = frozenset({"token", "laglens.pid", ".last", ".DS_Store"})
COMCAST_MEMBERS = ("report.html", "comcast_evidence.txt", "episodes.csv", "docsis_channels.csv", "summary.txt")
GENERATED = ("summary.txt", "episodes.csv", "marks.csv", "comcast_evidence.txt", "docsis_channels.csv")
TEXT_SUFFIXES = (".txt", ".json", ".jsonl", ".html", ".csv", ".log", ".md")
SPOOL_MAX = 64 * 1024 * 1024
#: Text members up to this size are read into memory to scrub secrets; larger
#: ones (impossible under the 500 MB session cap) are streamed as-is.
TEXT_SCRUB_MAX = 256 * 1024 * 1024

EPISODE_COLUMNS = (
    "id", "start_local", "start_unix", "end_unix", "duration_s", "class", "subclass", "confidence", "targets",
    "direction", "xbox_state", "activity", "host_tags", "comcast_relevant", "locus", "events", "marks", "evidence",
    "alt_class", "alt_why_rejected",
)
MARK_COLUMNS = (
    "id", "pressed_local", "t_pressed", "offset_s", "t_est", "activity", "note", "source", "episode", "assessment",
)
DOCSIS_COLUMNS = (
    "direction", "ch", "freq_hz", "mod", "lock", "snr_db", "pwr_dbmv", "unerr", "corr", "uncorr",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _local(t: Any) -> str:
    if not isinstance(t, (int, float)) or isinstance(t, bool):
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(t)))
    except (ValueError, OverflowError, OSError):
        return str(t)


def _fmt_dur(s: Any) -> str:
    if not isinstance(s, (int, float)):
        return "-"
    s = int(s)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return "%dh %02dm %02ds" % (h, m, sec)
    if m:
        return "%dm %02ds" % (m, sec)
    return "%ds" % sec


def _csv_text(columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(columns)
    for r in rows:
        w.writerow(["" if v is None else (round(v, 3) if isinstance(v, float) else v) for v in r])
    return buf.getvalue()


def _join(v: Any, sep: str = " ") -> str:
    if isinstance(v, (list, tuple)):
        return sep.join(str(x) for x in v)
    return "" if v is None else str(v)


def _dedupe_by_id(rows: Iterable[dict]) -> List[dict]:
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


def _secrets(cfg: Optional[dict], session_dir: Path) -> List[str]:
    out: List[str] = []
    pw = ((cfg or {}).get("docsis") or {}).get("password") if isinstance(cfg, dict) else None
    if isinstance(pw, str) and len(pw) >= 3:
        out.append(pw)
    ptok = ((cfg or {}).get("plex") or {}).get("token") if isinstance(cfg, dict) else None
    if isinstance(ptok, str) and len(ptok) >= 3 and ptok not in out:
        out.append(ptok)  # the Plex token, scrubbed like the XB7 password
    # The session's own config (if any) may carry a different password than the live cfg.
    local = sessionsmod._read_json_file(session_dir / "config.json")  # noqa: SLF001 - sibling module helper
    if isinstance(local, dict):
        lpw = (local.get("docsis") or {}).get("password") if isinstance(local.get("docsis"), dict) else None
        if isinstance(lpw, str) and len(lpw) >= 3 and lpw not in out:
            out.append(lpw)
    try:
        tok = (session_dir / "token").read_text(encoding="utf-8").strip()
        if len(tok) >= 8:
            out.append(tok)
    except OSError:
        pass
    return out


#: ``"prefix6": "2601:abcd:4321:abe0::/64"`` / ``"v6_prefix": …`` in JSON text members (rollups.jsonl,
#: session.json): the delegated /64 identifies the household, SPEC §6.7 ships it truncated.
_PREFIX_RE = re.compile(rb'"(prefix6|v6_prefix)"(\s*:\s*)"([0-9A-Fa-f:]+)/(\d{1,3})"')


def _truncate_prefix_match(m: "re.Match[bytes]") -> bytes:
    addr = m.group(3).decode("ascii", "replace")
    kept = ":".join(addr.split("::")[0].split(":")[:3])
    if not kept:
        return m.group(0)
    return b'"' + m.group(1) + b'"' + m.group(2) + b'"' + kept.encode("ascii") + b'::/64 (truncated)"'


#: An EUI-64 interface identifier inside an IPv6 literal (``…:211:22ff:fe33:4455``) is the device's MAC;
#: the XB7's global address is hop 1 of the v6 path (path.jsonl, report, marks snapshots). Masked like a MAC.
_EUI64_RE = re.compile(rb"(?<=:)[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,2}[fF][fF]:[fF][eE][0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])")
_EUI64_MASK = b"xxxx:xxff:fexx:xxxx"


def _scrub_text(data: bytes, secrets: Sequence[str]) -> bytes:
    for s in secrets:
        b = s.encode("utf-8")
        if b in data:
            data = data.replace(b, b"***")
    if b"prefix6" in data or b"v6_prefix" in data:
        data = _PREFIX_RE.sub(_truncate_prefix_match, data)
    if b"ff:fe" in data or b"FF:FE" in data or b"ff:FE" in data or b"FF:fe" in data:
        data = _EUI64_RE.sub(_EUI64_MASK, data)
    return data


# ---------------------------------------------------------------------------
# Generated members
# ---------------------------------------------------------------------------
def episodes_csv(rows: Iterable[dict]) -> str:
    """``episodes.csv`` from ``episodes.jsonl`` rows (last row per id wins)."""
    out: List[List[Any]] = []
    for e in _dedupe_by_id(rows):
        alt = e.get("alt") if isinstance(e.get("alt"), dict) else {}
        locus = e.get("locus") if isinstance(e.get("locus"), dict) else {}
        out.append([
            e.get("id"), _local(e.get("t0")), e.get("t0"), e.get("t1"), e.get("dur_s"), e.get("class"), e.get("subclass"),
            e.get("confidence"), _join(e.get("targets"), ";"), e.get("direction"), e.get("xbox_state"), e.get("activity"),
            _join(e.get("host_tags"), ";"), e.get("comcast_relevant"), locus.get("shallowest"), _join(e.get("events"), ";"),
            _join(e.get("marks"), ";"), _join(e.get("evidence"), " | "), alt.get("class"), alt.get("why_rejected"),
        ])
    return _csv_text(EPISODE_COLUMNS, out)


def marks_csv(rows: Iterable[dict]) -> str:
    """``marks.csv`` from ``marks.jsonl`` rows."""
    out: List[List[Any]] = []
    for m in _dedupe_by_id(rows):
        out.append([
            m.get("id"), _local(m.get("t_pressed")), m.get("t_pressed"), m.get("offset_s"), m.get("t_est"),
            m.get("activity"), m.get("note"), m.get("source"), m.get("episode"), m.get("assessment"),
        ])
    return _csv_text(MARK_COLUMNS, out)


def docsis_channels_csv(polls: Iterable[dict]) -> str:
    """``docsis_channels.csv`` from the last successful ``xb7.jsonl`` poll (header only when none)."""
    last: Optional[dict] = None
    for p in polls:
        if isinstance(p, dict) and (p.get("ds") or p.get("us")):
            if p.get("ok", True):
                last = p
    out: List[List[Any]] = []
    if last is not None:
        for ch in last.get("ds") or []:
            if isinstance(ch, dict):
                out.append(["ds", ch.get("ch"), ch.get("freq_hz"), ch.get("mod") or ch.get("type"), ch.get("lock"),
                            ch.get("snr_db"), ch.get("pwr_dbmv"), ch.get("unerr"), ch.get("corr"), ch.get("uncorr")])
        for ch in last.get("us") or []:
            if isinstance(ch, dict):
                out.append(["us", ch.get("ch"), ch.get("freq_hz"), ch.get("type") or ch.get("mod"), ch.get("lock"),
                            ch.get("snr_db"), ch.get("pwr_dbmv"), ch.get("unerr"), ch.get("corr"), ch.get("uncorr")])
    return _csv_text(DOCSIS_COLUMNS, out)


def summary_text(session: dict, stats: dict, episodes: Sequence[dict], marks: Sequence[dict], targets: Sequence[dict],
                 comcast: str) -> str:
    """``summary.txt``: session facts, verdict, what to try next, per-target stats table."""
    summ = session.get("summary") if isinstance(session.get("summary"), dict) else {}
    verdict = summ.get("verdict") if isinstance(summ.get("verdict"), dict) else {}
    health = summ.get("health") if isinstance(summ.get("health"), dict) else {}
    started = session.get("started")
    stopped = session.get("stopped")
    dur = (stopped - started) if isinstance(started, (int, float)) and isinstance(stopped, (int, float)) else None
    if dur is None and isinstance(started, (int, float)) and isinstance(stats.get("t_last"), (int, float)):
        dur = stats["t_last"] + 5 - started
    lines: List[str] = []
    lines.append("Lag Lens session summary")
    lines.append("=" * 72)
    facts = [
        ("Session", session.get("id")),
        ("Label", session.get("label") or "-"),
        ("Started", _local(started) or "-"),
        ("Stopped", _local(stopped) or ("still running / not recorded")),
        ("Duration", _fmt_dur(dur)),
        ("Stop reason", session.get("stop_reason") or "-"),
        ("Resumed", session.get("resumed_count") or 0),
        ("Host", "%s (%s)" % (session.get("host") or "-", session.get("os") or "-")),
        ("Interface", "%s%s" % (session.get("iface") or "-", " (Wi-Fi)" if session.get("wifi") else "")),
        ("Gateway", session.get("gateway") or "-"),
        ("IPv6", "yes" if session.get("gw6") else "no"),
        ("Lag Lens", session.get("version") or __version__),
        ("Health score", "%s (session) / %s (last)" % (health.get("session", "-"), health.get("now", "-"))),
        ("Samples", summ.get("samples", "-")),
        ("Episodes", summ.get("episodes", len(episodes))),
        ("Marks", summ.get("marks", len(marks))),
    ]
    for k, v in facts:
        lines.append("%-13s %s" % (k + ":", v))
    lines.append("")
    lines.append("Verdict")
    lines.append("-" * 72)
    lines.append(verdict.get("text") or "No verdict was computed for this session.")
    if verdict.get("confidence"):
        lines.append("Confidence: %s" % verdict.get("confidence"))
    top = verdict.get("top") if isinstance(verdict.get("top"), list) else []
    for t in top:
        if isinstance(t, dict):
            lines.append("  %-22s share %5.0f%%  episodes %-4s seconds %s" % (
                t.get("class", "?"), 100.0 * float(t.get("share") or 0), t.get("episodes", "-"), t.get("seconds", "-")))
    nxt = verdict.get("next") if isinstance(verdict.get("next"), list) else []
    if nxt:
        lines.append("")
        lines.append("What to try next")
        lines.append("-" * 72)
        for i, n in enumerate(nxt, 1):
            if isinstance(n, dict):
                lines.append("%d. %s" % (i, n.get("try", "")))
                if n.get("confirm_if"):
                    lines.append("   confirmed if: %s" % n["confirm_if"])
                if n.get("refute_if"):
                    lines.append("   refuted if:   %s" % n["refute_if"])
            else:
                lines.append("%d. %s" % (i, n))
    vm = verdict.get("marks") if isinstance(verdict.get("marks"), dict) else {}
    if vm:
        lines.append("Marks linked to an episode: %s of %s" % (vm.get("linked", "-"), vm.get("total", "-")))
    lines.append("")
    lines.append("Per-target stats (from 5 s rollups; percentiles approximate)")
    lines.append("-" * 72)
    labels = {str(t.get("id")): (t.get("label") or t.get("key") or str(t.get("id"))) for t in targets if isinstance(t, dict)}
    lines.append("%-30s %8s %7s %7s %8s %8s %8s %7s %8s" % (
        "target", "sent", "loss%", "late%", "p50", "p95", "max", "jitter", "outage s"))
    for tid in sorted((stats.get("targets") or {}), key=lambda x: int(x) if str(x).isdigit() else 0):
        s = stats["targets"][tid]
        lines.append("%-30s %8s %7s %7s %8s %8s %8s %7s %8s" % (
            str(labels.get(str(tid), tid))[:30], s.get("sent", "-"), _f(s.get("loss_pct")), _f(s.get("late_pct")),
            _f(s.get("p50")), _f(s.get("p95")), _f(s.get("max")), _f(s.get("jitter")), _f(s.get("longest_outage_s"))))
    if not stats.get("targets"):
        lines.append("(no rollups found)")
    lines.append("")
    lines.append("Episodes")
    lines.append("-" * 72)
    if episodes:
        for e in episodes:
            lines.append("%s  %-20s %6s s  %-22s conf %-4s %s%s" % (
                _local(e.get("t0")), e.get("id", ""), _f(e.get("dur_s")), "%s%s" % (e.get("class", "?"),
                ("/" + str(e["subclass"])) if e.get("subclass") else ""), _f(e.get("confidence")),
                e.get("direction", ""), "" if e.get("comcast_relevant", True) else "  (host-side; not Comcast-relevant)"))
    else:
        lines.append("(none)")
    lines.append("")
    lines.append("Tell Comcast")
    lines.append("-" * 72)
    lines.append(comcast.strip() if comcast and comcast.strip() else "(no Comcast-relevant episodes)")
    lines.append("")
    lines.append("Privacy: this export contains LAN IPs (10.0.0.x), Comcast hop IPs, the WAN IP and a truncated IPv6 prefix. "
                 "It does not contain the XB7 password, the session token or MAC addresses in the generated files; "
                 "config.redacted.json has every secret replaced by ***.")
    return "\n".join(lines) + "\n"


def _f(v: Any) -> str:
    if isinstance(v, bool) or v is None:
        return "-"
    if isinstance(v, float):
        return "%.2f" % v if abs(v) < 1000 else "%.0f" % v
    return str(v)


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------
def _should_skip(rel: str, raw: bool) -> bool:
    name = os.path.basename(rel)
    parts = rel.replace(os.sep, "/").split("/")
    if name in EXCLUDED_NAMES or name.startswith(".") or ".tmp" in name:
        return True
    if name.endswith(".zip") and name.startswith("laglens-"):
        return True
    if parts[0] == "xb7_raw" and not raw:
        return True
    return False


def _member_bytes(path: Path, secrets: Sequence[str]) -> Optional[bytes]:
    """Read a text member and scrub secrets; ``None`` means "stream it as-is" (binary)."""
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > TEXT_SCRUB_MAX:
        return None
    try:
        data = path.read_bytes()
    except OSError as exc:
        log.warning("export: cannot read %s: %s", path, exc)
        return b""
    return _scrub_text(data, secrets)


def _ensure_report(session_dir: Path, cfg: Optional[dict]) -> None:
    if (session_dir / "report.html").exists():
        return
    try:
        from laglens.report import build as buildmod

        buildmod.rebuild(session_dir, cfg)
    except Exception as exc:  # noqa: BLE001 - the pack is still useful without the report
        log.warning("export: report.html missing and rebuild failed: %s", exc)


def generated_members(session_dir: Path, cfg: Optional[dict] = None, ctx: Any = None) -> Dict[str, str]:
    """The five generated text members, keyed by file name."""
    sdir = Path(session_dir)
    session = sessionsmod.session_summary(sdir)
    episodes = _dedupe_by_id(sessionsmod.iter_jsonl(sdir / "episodes.jsonl"))
    marks = _dedupe_by_id(sessionsmod.iter_jsonl(sdir / "marks.jsonl"))
    polls = list(sessionsmod.iter_jsonl(sdir / "xb7.jsonl"))
    tdoc = sessionsmod._read_json_file(sdir / "targets.json")  # noqa: SLF001
    targets = tdoc.get("targets") if isinstance(tdoc, dict) and isinstance(tdoc.get("targets"), list) else []
    stats = sessionsmod.rollup_scan(sdir, session.get("started"), session.get("stopped"))
    comcast = _comcast_text(sdir, session, ctx)
    return {
        "summary.txt": summary_text(session, stats, episodes, marks, targets, comcast),
        "episodes.csv": episodes_csv(episodes),
        "marks.csv": marks_csv(marks),
        "comcast_evidence.txt": (comcast.rstrip("\n") + "\n") if comcast else "(no Comcast-relevant episodes)\n",
        "docsis_channels.csv": docsis_channels_csv(polls),
    }


def _comcast_text(sdir: Path, session: dict, ctx: Any) -> str:
    """Tell-Comcast text: live engine (``ctx`` given) → ``comcast_evidence.txt`` → ``session.json`` verdict → ``""``.

    ``ctx`` must be the live context *of this session*; the server passes
    none for past sessions, so their text always comes from the files.
    """
    if ctx is not None:
        try:
            verdictmod = importlib.import_module("laglens.engine.verdict")  # honours sys.modules (see build._optional_module)
            fn = getattr(verdictmod, "comcast_text", None)
            if fn is not None:
                txt = fn(ctx)
                if isinstance(txt, str) and txt.strip():
                    return txt
        except ImportError:
            pass
        except Exception:  # noqa: BLE001
            log.exception("export: engine.verdict.comcast_text failed")
    try:
        txt = (sdir / "comcast_evidence.txt").read_text(encoding="utf-8")
        if txt.strip():
            return txt
    except OSError:
        pass
    summ = session.get("summary") if isinstance(session.get("summary"), dict) else {}
    verdict = summ.get("verdict") if isinstance(summ.get("verdict"), dict) else {}
    c = verdict.get("comcast")
    return c if isinstance(c, str) else ""


def build_zip(session_dir: Any, pack: str = "full", raw: bool = True, cfg: Optional[dict] = None, ctx: Any = None) -> bytes:
    """Build the export archive for ``session_dir`` and return its bytes.

    ``pack`` is ``'full'`` or ``'comcast'``; ``raw`` includes ``xb7_raw/`` in
    the full pack; ``cfg`` is used for the redacted config and for the
    password to scrub; ``ctx`` (optional, the live app context) lets the
    Comcast text come from the live verdict engine. Raises ``ValueError``
    for an unknown pack and ``FileNotFoundError`` for a missing directory.
    """
    sdir = Path(session_dir)
    if pack not in PACKS:
        raise ValueError("unknown pack %r (expected one of %s)" % (pack, ", ".join(PACKS)))
    if not sdir.is_dir():
        raise FileNotFoundError("session directory not found: %s" % sdir)
    secrets = _secrets(cfg, sdir)
    _ensure_report(sdir, cfg)
    gen = generated_members(sdir, cfg, ctx)

    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX)
    try:
        with zipfile.ZipFile(spool, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if pack == "comcast":
                for name in COMCAST_MEMBERS:
                    if name in gen:
                        zf.writestr(name, gen[name])
                    else:
                        p = sdir / name
                        data = _member_bytes(p, secrets)
                        if data is not None:
                            zf.writestr(name, data)
                        elif p.exists():
                            zf.write(str(p), name)
            else:
                for root, dirs, files in os.walk(sdir):
                    dirs.sort()
                    rel_root = os.path.relpath(root, str(sdir))
                    for fname in sorted(files):
                        full = Path(root) / fname
                        rel = fname if rel_root == "." else os.path.join(rel_root, fname)
                        if _should_skip(rel, raw):
                            continue
                        arc = rel.replace(os.sep, "/")
                        if arc == "config.json":
                            local = sessionsmod._read_json_file(full)  # noqa: SLF001
                            pub = configmod.public(local if isinstance(local, dict) else (cfg or {}))
                            zf.writestr("config.redacted.json", json.dumps(pub, indent=1) + "\n")
                            continue
                        if arc in gen:
                            continue  # generated version wins (written below)
                        data = _member_bytes(full, secrets)
                        if data is not None:
                            zf.writestr(arc, data)
                        else:
                            try:
                                zf.write(str(full), arc)
                            except OSError as exc:
                                log.warning("export: skipping %s: %s", arc, exc)
                if not (sdir / "config.json").exists():
                    zf.writestr("config.redacted.json", json.dumps(configmod.public(cfg or {}), indent=1) + "\n")
                for name in GENERATED:
                    zf.writestr(name, gen[name])
        spool.seek(0)
        return spool.read()
    finally:
        spool.close()


def export_cli(session_dir: Any, pack: str = "full", cfg: Optional[dict] = None, raw: bool = True) -> int:
    """``--export DIR [--pack comcast]``: write ``laglens-<id>.zip`` next to the session; prints the path."""
    sdir = Path(session_dir)
    if not sdir.is_absolute() and not sdir.exists():
        from laglens.app import ROOT

        sdir = ROOT / sdir
    pack = (pack or "full").lower()
    try:
        data = build_zip(sdir, pack=pack, raw=raw, cfg=cfg)
    except (ValueError, FileNotFoundError) as exc:
        print("export: %s" % exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        log.exception("export failed")
        print("export: failed: %s" % exc)
        return 1
    suffix = "" if pack == "full" else "-" + pack
    out = sdir.parent / ("laglens-%s%s.zip" % (sdir.name, suffix))
    tmp = out.with_name(out.name + ".tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, out)
    except OSError as exc:
        print("export: cannot write %s: %s" % (out, exc))
        return 1
    print(str(out))
    return 0


__all__ = [
    "build_zip", "export_cli", "generated_members", "summary_text", "episodes_csv", "marks_csv",
    "docsis_channels_csv", "PACKS", "COMCAST_MEMBERS", "GENERATED", "EXCLUDED_NAMES",
]
