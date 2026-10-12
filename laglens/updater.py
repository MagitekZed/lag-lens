"""Update check and ``--update`` (SPEC_FULL §12.6).

``check_async(ctx)`` fetches ``<base>/version.json`` (3 s timeout) in a daemon
thread and sets ``state.update = {"available", "latest", "url", "sha256",
"checked_at", "error"}``; a newer version is also logged. Nothing is ever
auto-installed.

``run_cli(check_only, root)`` is the Python version of ``get.sh``: download
the zip, verify its SHA-256, extract it to a temp dir, swap the install
folder (``<root>`` → ``<root>.old-<version>``) while preserving
``config.json`` and ``sessions/``, then print the CHANGELOG excerpt.
``--update --check`` only reports. The base URL is
``https://magitekzed.github.io/lag-lens`` unless ``LAGLENS_BASE`` is set.

``version.json`` shape: ``{"version": "1.1.0", "url": ".../lag-lens.zip",
"sha256": "...", "changelog": "...", "previous": {...}}`` (``url`` may be
relative to the base; ``sha256`` is required for an install).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import List, Any, Callable, Dict, Optional, Tuple

from laglens.version import __version__

log = logging.getLogger("laglens.updater")

DEFAULT_BASE = "https://magitekzed.github.io/lag-lens"
VERSION_FILE = "version.json"
CHECK_TIMEOUT_S = 3.0
DOWNLOAD_TIMEOUT_S = 60.0
PRESERVE = ("config.json", "sessions", "config.local.json")
CHANGELOG_LINES = 30
USER_AGENT = "LagLens/%s" % __version__


def base_url(env: Optional[Dict[str, str]] = None) -> str:
    e = env if env is not None else os.environ
    return (e.get("LAGLENS_BASE") or DEFAULT_BASE).rstrip("/")


def parse_version(v: Any) -> Tuple[int, ...]:
    """``'1.2.3'`` / ``'v1.2.3-beta'`` → ``(1, 2, 3)``; unparseable → ``(0,)``."""
    nums = re.findall(r"\d+", str(v or ""))
    return tuple(int(n) for n in nums[:4]) or (0,)


def is_newer(latest: Any, current: Any = __version__) -> bool:
    return parse_version(latest) > parse_version(current)


def fetch_version(base: str, urlopen: Optional[Callable[..., Any]] = None, timeout: float = CHECK_TIMEOUT_S) -> Dict[str, Any]:
    """Download and parse ``version.json``; raises on any failure."""
    opener = urlopen or urllib.request.urlopen
    req = urllib.request.Request(base + "/" + VERSION_FILE, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    resp = opener(req, timeout=timeout)
    try:
        body = resp.read(65536)
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    data = json.loads(body)
    if not isinstance(data, dict) or not data.get("version"):
        raise ValueError("version.json has no 'version'")
    url = data.get("url") or "lag-lens.zip"
    data["url"] = urllib.parse.urljoin(base + "/", url)
    return data


def check_async(ctx: Any, urlopen: Optional[Callable[..., Any]] = None, base: Optional[str] = None,
                out: Optional[Callable[[str], Any]] = None) -> threading.Thread:
    """Start the 3 s version check in a daemon thread; returns the thread (join it in tests)."""
    st = ctx.state

    def body() -> None:
        b = base or base_url()
        try:
            data = fetch_version(b, urlopen=urlopen)
            latest = str(data["version"])
            newer = is_newer(latest)
            upd = {"available": newer, "latest": latest, "url": data.get("url"), "sha256": data.get("sha256"),
                   "checked_at": time.time(), "error": None}
            if newer:
                msg = "v%s available — bash start.sh --update" % latest
                log.info("update: %s", msg)
                if out is not None:
                    out(msg)
        except Exception as exc:  # noqa: BLE001 - offline is normal
            upd = {"available": False, "latest": None, "url": None, "sha256": None, "checked_at": time.time(),
                   "error": "%s: %s" % (type(exc).__name__, str(exc)[:120])}
            log.debug("update check failed: %s", upd["error"])
        try:
            with st.lock:
                st.update = upd
        except Exception:  # noqa: BLE001
            st.update = upd

    t = threading.Thread(target=body, name="update-check", daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# --update
# ---------------------------------------------------------------------------
def download(url: str, dest: Path, urlopen: Optional[Callable[..., Any]] = None, timeout: float = DOWNLOAD_TIMEOUT_S) -> str:
    """Stream ``url`` to ``dest``; returns the SHA-256 hex digest."""
    opener = urlopen or urllib.request.urlopen
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    h = hashlib.sha256()
    resp = opener(req, timeout=timeout)
    try:
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                h.update(chunk)
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass
    return h.hexdigest()


def safe_extract(zip_path: Path, dest: Path) -> Path:
    """Extract (refusing absolute / ``..`` members) and return the single top-level folder."""
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(zip_path)) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts or ":" in name.split("/")[0]:
                raise ValueError("unsafe zip member: %s" % name)
        zf.extractall(str(dest))
    tops = [p for p in dest.iterdir() if not p.name.startswith(".")]
    if len(tops) == 1 and tops[0].is_dir():
        return tops[0]
    if (dest / "run.py").exists():
        return dest
    raise ValueError("zip does not contain a single top-level folder")


def swap_install(root: Path, new_dir: Path, version: str) -> Path:
    """Replace the *contents* of ``root`` with ``new_dir``'s, keeping ``root`` itself in place.

    The directory inode of ``root`` never changes, so a terminal that is ``cd``'d into the
    install folder (or the ``start.sh`` restart loop) keeps pointing at the live copy after
    the update. The previous files are moved to ``<root>.old-<version>/`` (a complete backup:
    ``config.json`` and ``sessions/`` are copied there as well, but stay in ``root``).
    """
    root = Path(root)
    old = root.parent / ("%s.old-%s" % (root.name, version))
    n = 1
    while old.exists():
        old = root.parent / ("%s.old-%s-%d" % (root.name, version, n))
        n += 1
    staged = root.parent / ("%s.new-%s" % (root.name, version))
    if staged.exists():
        shutil.rmtree(str(staged))
    shutil.move(str(new_dir), str(staged))
    old.mkdir()
    # 1. the current files move aside (sibling directory: plain renames); preserved entries are copied
    moved: List[str] = []
    for entry in list(root.iterdir()):
        if entry.name in PRESERVE:
            if entry.is_dir():
                shutil.copytree(str(entry), str(old / entry.name), symlinks=True)
            else:
                shutil.copy2(str(entry), str(old / entry.name))
            continue
        os.replace(str(entry), str(old / entry.name))
        moved.append(entry.name)
    # 2. the new files move in
    try:
        for entry in list(staged.iterdir()):
            if entry.name in PRESERVE and (root / entry.name).exists():
                continue  # never clobber the user's data with a file from the archive
            os.replace(str(entry), str(root / entry.name))
    except OSError:
        # roll back: put every moved entry back over whatever landed in root
        for name in moved:
            target = root / name
            if target.exists():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(str(target))
                else:
                    target.unlink()
            os.replace(str(old / name), str(target))
        shutil.rmtree(str(staged), ignore_errors=True)
        shutil.rmtree(str(old), ignore_errors=True)
        raise
    shutil.rmtree(str(staged), ignore_errors=True)
    for name in ("start.sh", "get.sh", "run.py"):
        p = root / name
        if p.exists():
            try:
                os.chmod(str(p), 0o755)
            except OSError:
                pass
    return old


def changelog_excerpt(root: Path, latest: str, data: Optional[Dict[str, Any]] = None) -> str:
    if data and data.get("changelog"):
        return str(data["changelog"]).strip()
    p = Path(root) / "CHANGELOG.md"
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    out = []
    started = False
    for ln in lines:
        if ln.startswith("## "):
            if started:
                break
            if latest and latest in ln:
                started = True
        if started or not latest:
            out.append(ln)
        if len(out) >= CHANGELOG_LINES:
            break
    return "\n".join(out or lines[:CHANGELOG_LINES]).strip()


def run_cli(check_only: bool, root: Path, urlopen: Optional[Callable[..., Any]] = None, base: Optional[str] = None,
            out: Callable[[str], Any] = print, current: str = __version__, env: Optional[Dict[str, str]] = None) -> int:
    """``--update [--check]``; returns 0 on success/no-op, 1 on failure."""
    root = Path(root).resolve()
    b = base or base_url(env)
    try:
        data = fetch_version(b, urlopen=urlopen)
    except Exception as exc:  # noqa: BLE001
        out("update: cannot fetch %s/%s: %s" % (b, VERSION_FILE, exc))
        return 1
    latest = str(data["version"])
    newer = is_newer(latest, current)
    out("installed %s, latest %s%s" % (current, latest, " (newer)" if newer else ""))
    if not newer:
        out("already up to date")
        return 0
    if check_only:
        out("run: bash start.sh --update")
        excerpt = changelog_excerpt(root, latest, data)
        if excerpt:
            out(excerpt)
        return 0
    sha = str(data.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        out("update: version.json has no valid sha256; refusing to install")
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="laglens-update-", dir=str(root.parent)))
    try:
        zip_path = tmp / "lag-lens.zip"
        out("downloading %s" % data["url"])
        got = download(data["url"], zip_path, urlopen=urlopen)
        if got != sha:
            out("update: sha256 mismatch (expected %s, got %s); aborting" % (sha, got))
            return 1
        out("sha256 verified")
        new_dir = safe_extract(zip_path, tmp / "extract")
        if not (new_dir / "run.py").exists() or not (new_dir / "laglens").is_dir():
            out("update: the archive does not look like Lag Lens; aborting")
            return 1
        old = swap_install(root, new_dir, current)
        out("installed %s into %s (previous version kept at %s)" % (latest, root, old))
        excerpt = changelog_excerpt(root, latest, data)
        if excerpt:
            out("")
            out(excerpt)
        return 0
    except Exception as exc:  # noqa: BLE001
        out("update failed: %s: %s" % (type(exc).__name__, exc))
        return 1
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)


__all__ = ["check_async", "run_cli", "fetch_version", "is_newer", "parse_version", "download", "safe_extract", "swap_install",
           "changelog_excerpt", "base_url", "DEFAULT_BASE", "VERSION_FILE"]
