"""Tests for laglens.updater against a local http.server: check-only, install swap preserving config.json
and sessions/, checksum mismatch, unreachable base URL (clean message, no traceback), check_async."""
import functools
import hashlib
import http.server
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import updater as u  # noqa: E402
from laglens.state import State  # noqa: E402

NEW_VERSION = "1.1.0"
OLD_VERSION = "1.0.0"
NEW_RUN_PY = "# run.py %s\n" % NEW_VERSION
OLD_RUN_PY = "# run.py %s\n" % OLD_VERSION
CHANGELOG = "# Changelog\n\n## 1.1.0\n- faster doctor\n- updater\n\n## 1.0.0\n- first release\n"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: D401 - silence
        pass


def build_zip(path, version=NEW_VERSION, top="lag-lens", with_laglens=True):
    with zipfile.ZipFile(str(path), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(top + "/run.py", NEW_RUN_PY)
        zf.writestr(top + "/VERSION", version + "\n")
        zf.writestr(top + "/CHANGELOG.md", CHANGELOG)
        zf.writestr(top + "/start.sh", "#!/bin/sh\n")
        if with_laglens:
            zf.writestr(top + "/laglens/__init__.py", "# new\n")
            zf.writestr(top + "/laglens/version.py", "__version__ = %r\n" % version)
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Site:
    """A tiny Pages-like site: version.json + lag-lens.zip served by http.server on 127.0.0.1."""

    def __init__(self, root, version=NEW_VERSION, sha=None, url="lag-lens.zip", changelog=None, omit_sha=False):
        self.dir = Path(root) / "site"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.sha = build_zip(self.dir / "lag-lens.zip", version)
        doc = {"version": version, "url": url, "sha256": sha if sha is not None else self.sha}
        if omit_sha:
            del doc["sha256"]
        if changelog is not None:
            doc["changelog"] = changelog
        (self.dir / "version.json").write_text(json.dumps(doc), encoding="utf-8")
        handler = functools.partial(QuietHandler, directory=str(self.dir))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=functools.partial(self.server.serve_forever, poll_interval=0.05), daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5.0)


def make_install(parent):
    """An installed copy at <parent>/lag-lens with config.json and a session to preserve."""
    root = Path(parent) / "lag-lens"
    (root / "laglens").mkdir(parents=True)
    (root / "run.py").write_text(OLD_RUN_PY, encoding="utf-8")
    (root / "laglens" / "__init__.py").write_text("# old\n", encoding="utf-8")
    (root / "laglens" / "stale.py").write_text("# should vanish\n", encoding="utf-8")
    (root / "config.json").write_text('{"docsis": {"password": "keep-me"}}\n', encoding="utf-8")
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0.0\n- first release\n", encoding="utf-8")
    sess = root / "sessions" / "20261011-120000"
    sess.mkdir(parents=True)
    (sess / "session.json").write_text('{"id": "20261011-120000"}\n', encoding="utf-8")
    (root / "sessions" / ".last").write_text("sessions/20261011-120000\n", encoding="utf-8")
    return root


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-upd-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.sites = []

    def site(self, **kw):
        s = Site(self.tmp, **kw)
        self.sites.append(s)
        self.addCleanup(s.close)
        return s

    def siblings(self, root):
        return sorted(p.name for p in root.parent.iterdir() if p.name != "site")

    # ------------------------------------------------------------ check-only
    def test_check_only_reports_and_changes_nothing(self):
        s = self.site()
        root = make_install(self.tmp)
        lines = []
        rc = u.run_cli(True, root, base=s.base, out=lines.append, current=OLD_VERSION)
        self.assertEqual(rc, 0)
        self.assertEqual(lines[0], "installed 1.0.0, latest 1.1.0 (newer)")
        self.assertEqual(lines[1], "run: bash start.sh --update")
        # without a changelog in version.json the excerpt is the installed CHANGELOG head (which cannot know 1.1.0 yet)
        self.assertIn("# Changelog", "\n".join(lines))
        self.assertEqual((root / "run.py").read_text(encoding="utf-8"), OLD_RUN_PY)
        self.assertEqual(self.siblings(root), ["lag-lens"])

    def test_check_only_changelog_from_version_json(self):
        s = self.site(changelog="## 1.1.0\n- from version.json")
        root = make_install(self.tmp)
        lines = []
        self.assertEqual(u.run_cli(True, root, base=s.base, out=lines.append, current=OLD_VERSION), 0)
        self.assertIn("- from version.json", "\n".join(lines))

    def test_already_up_to_date(self):
        s = self.site()
        root = make_install(self.tmp)
        lines = []
        self.assertEqual(u.run_cli(False, root, base=s.base, out=lines.append, current=NEW_VERSION), 0)
        self.assertEqual(lines, ["installed 1.1.0, latest 1.1.0", "already up to date"])
        self.assertEqual(self.siblings(root), ["lag-lens"])
        lines = []
        self.assertEqual(u.run_cli(True, root, base=s.base, out=lines.append, current="1.2.0"), 0)
        self.assertEqual(lines[-1], "already up to date")

    # --------------------------------------------------------------- install
    def test_install_swaps_and_preserves_config_and_sessions(self):
        s = self.site()
        root = make_install(self.tmp)
        lines = []
        rc = u.run_cli(False, root, base=s.base, out=lines.append, current=OLD_VERSION)
        self.assertEqual(rc, 0, lines)
        text = "\n".join(lines)
        self.assertIn("downloading %s/lag-lens.zip" % s.base, text)
        self.assertIn("sha256 verified", text)
        self.assertIn("installed 1.1.0 into %s" % root.resolve(), text)  # macOS: /var -> /private/var
        self.assertIn("- faster doctor", text)
        # new code in place
        self.assertEqual((root / "run.py").read_text(encoding="utf-8"), NEW_RUN_PY)
        self.assertEqual((root / "laglens" / "__init__.py").read_text(encoding="utf-8"), "# new\n")
        self.assertFalse((root / "laglens" / "stale.py").exists())
        self.assertTrue((root / "laglens" / "version.py").exists())
        self.assertTrue(os.access(str(root / "start.sh"), os.X_OK))
        # preserved files
        self.assertEqual((root / "config.json").read_text(encoding="utf-8"), '{"docsis": {"password": "keep-me"}}\n')
        self.assertEqual((root / "sessions" / "20261011-120000" / "session.json").read_text(encoding="utf-8"), '{"id": "20261011-120000"}\n')
        self.assertEqual((root / "sessions" / ".last").read_text(encoding="utf-8"), "sessions/20261011-120000\n")
        # the previous install is kept next to it, temp dirs are gone
        old = root.parent / "lag-lens.old-1.0.0"
        self.assertEqual(self.siblings(root), ["lag-lens", "lag-lens.old-1.0.0"])
        self.assertEqual((old / "run.py").read_text(encoding="utf-8"), OLD_RUN_PY)
        self.assertTrue((old / "config.json").exists())
        self.assertIn(str(old.resolve()), text)
        # a second install of the same version keeps the first backup
        lines = []
        self.assertEqual(u.run_cli(False, root, base=s.base, out=lines.append, current=OLD_VERSION), 0)
        self.assertEqual(self.siblings(root), ["lag-lens", "lag-lens.old-1.0.0", "lag-lens.old-1.0.0-1"])

    def test_checksum_mismatch_aborts_cleanly(self):
        s = self.site(sha="0" * 64)
        root = make_install(self.tmp)
        lines = []
        rc = u.run_cli(False, root, base=s.base, out=lines.append, current=OLD_VERSION)
        self.assertEqual(rc, 1)
        self.assertTrue(any(ln.startswith("update: sha256 mismatch (expected %s, got %s)" % ("0" * 64, s.sha)) for ln in lines), lines)
        self.assertEqual((root / "run.py").read_text(encoding="utf-8"), OLD_RUN_PY)
        self.assertEqual(self.siblings(root), ["lag-lens"])  # no backup, no temp dir left behind

    def test_missing_or_bad_sha_refuses(self):
        s = self.site(omit_sha=True)
        root = make_install(self.tmp)
        lines = []
        self.assertEqual(u.run_cli(False, root, base=s.base, out=lines.append, current=OLD_VERSION), 1)
        self.assertIn("no valid sha256", "\n".join(lines))
        self.assertEqual(self.siblings(root), ["lag-lens"])
        lines = []
        self.assertEqual(u.run_cli(True, root, base=s.base, out=lines.append, current=OLD_VERSION), 0)  # check-only needs no sha

    def test_zip_without_laglens_refused(self):
        s = self.site()
        sha = build_zip(s.dir / "lag-lens.zip", with_laglens=False)
        (s.dir / "version.json").write_text(json.dumps({"version": NEW_VERSION, "url": "lag-lens.zip", "sha256": sha}), encoding="utf-8")
        root = make_install(self.tmp)
        lines = []
        self.assertEqual(u.run_cli(False, root, base=s.base, out=lines.append, current=OLD_VERSION), 1)
        self.assertIn("does not look like Lag Lens", "\n".join(lines))
        self.assertEqual(self.siblings(root), ["lag-lens"])

    def test_zip_404_is_reported(self):
        s = self.site(url="missing.zip")
        root = make_install(self.tmp)
        lines = []
        self.assertEqual(u.run_cli(False, root, base=s.base, out=lines.append, current=OLD_VERSION), 1)
        self.assertTrue(any(ln.startswith("update failed: HTTPError") for ln in lines), lines)
        self.assertEqual(self.siblings(root), ["lag-lens"])

    # ------------------------------------------------------------ unreachable
    def test_unreachable_base_url_clean_message(self):
        root = make_install(self.tmp)
        lines = []
        dead = "http://127.0.0.1:1"  # nothing listens on port 1
        stderr = io.StringIO()
        old_err = sys.stderr
        sys.stderr = stderr
        try:
            rc = u.run_cli(False, root, base=dead, out=lines.append, current=OLD_VERSION)
        finally:
            sys.stderr = old_err
        self.assertEqual(rc, 1)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("update: cannot fetch %s/version.json: " % dead), lines)
        self.assertNotIn("Traceback", lines[0] + stderr.getvalue())
        self.assertEqual(self.siblings(root), ["lag-lens"])

    def test_bad_version_json(self):
        s = self.site()
        (s.dir / "version.json").write_text("{not json", encoding="utf-8")
        root = make_install(self.tmp)
        lines = []
        self.assertEqual(u.run_cli(True, root, base=s.base, out=lines.append), 1)
        self.assertIn("cannot fetch", lines[0])
        (s.dir / "version.json").write_text('{"url": "x.zip"}', encoding="utf-8")
        lines = []
        self.assertEqual(u.run_cli(True, root, base=s.base, out=lines.append), 1)
        self.assertIn("no 'version'", lines[0])

    # ------------------------------------------------------------ check_async
    def test_check_async_sets_state_update(self):
        s = self.site()
        st = State(cfg={})
        ctx = type("Ctx", (), {})()
        ctx.state = st
        msgs = []
        t = u.check_async(ctx, base=s.base, out=msgs.append)
        t.join(5.0)
        self.assertFalse(t.is_alive())
        upd = st.update
        self.assertEqual((upd["available"], upd["latest"], upd["sha256"], upd["error"]), (u.is_newer(NEW_VERSION), NEW_VERSION, s.sha, None))
        self.assertEqual(upd["url"], s.base + "/lag-lens.zip")
        self.assertIsInstance(upd["checked_at"], float)
        if upd["available"]:
            self.assertEqual(msgs, ["v1.1.0 available — bash start.sh --update"])
        self.assertEqual(st.snapshot()["update"]["latest"], NEW_VERSION)

    def test_check_async_offline_is_quiet(self):
        st = State(cfg={})
        ctx = type("Ctx", (), {})()
        ctx.state = st
        msgs = []
        t = u.check_async(ctx, base="http://127.0.0.1:1", out=msgs.append)
        t.join(5.0)
        self.assertFalse(t.is_alive())
        self.assertEqual((st.update["available"], st.update["latest"]), (False, None))
        self.assertIn("URLError", st.update["error"])
        self.assertEqual(msgs, [])

    # ---------------------------------------------------------------- helpers
    def test_version_helpers(self):
        self.assertEqual(u.parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(u.parse_version("v1.10.0-beta"), (1, 10, 0))
        self.assertEqual(u.parse_version(None), (0,))
        self.assertTrue(u.is_newer("1.10.0", "1.9.9"))
        self.assertFalse(u.is_newer("1.0.0", "1.0.0"))
        self.assertFalse(u.is_newer("garbage", "1.0.0"))
        self.assertEqual(u.base_url({"LAGLENS_BASE": "http://example.test/x/"}), "http://example.test/x")
        self.assertEqual(u.base_url({}), u.DEFAULT_BASE)

    def test_fetch_version_resolves_relative_and_absolute_urls(self):
        s = self.site(url="dl/lag-lens.zip")
        data = u.fetch_version(s.base)
        self.assertEqual(data["url"], s.base + "/dl/lag-lens.zip")
        (s.dir / "version.json").write_text(json.dumps({"version": "2.0.0", "url": "https://cdn.example.test/a.zip"}), encoding="utf-8")
        self.assertEqual(u.fetch_version(s.base)["url"], "https://cdn.example.test/a.zip")
        (s.dir / "version.json").write_text(json.dumps({"version": "2.0.0"}), encoding="utf-8")
        self.assertEqual(u.fetch_version(s.base)["url"], s.base + "/lag-lens.zip")

    def test_safe_extract_refuses_traversal(self):
        bad = self.tmp / "bad.zip"
        with zipfile.ZipFile(str(bad), "w") as zf:
            zf.writestr("lag-lens/run.py", "x")
            zf.writestr("../evil.py", "x")
        with self.assertRaises(ValueError):
            u.safe_extract(bad, self.tmp / "out")
        self.assertFalse((self.tmp / "evil.py").exists())
        flat = self.tmp / "flat.zip"
        with zipfile.ZipFile(str(flat), "w") as zf:
            zf.writestr("run.py", "x")
            zf.writestr("laglens/__init__.py", "x")
        self.assertEqual(u.safe_extract(flat, self.tmp / "flat"), self.tmp / "flat")

    def test_changelog_excerpt(self):
        root = make_install(self.tmp)
        (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
        ex = u.changelog_excerpt(root, "1.1.0")
        self.assertTrue(ex.startswith("## 1.1.0"))
        self.assertIn("- updater", ex)
        self.assertNotIn("## 1.0.0", ex)
        self.assertEqual(u.changelog_excerpt(root, "1.1.0", {"changelog": " given \n"}), "given")
        self.assertEqual(u.changelog_excerpt(self.tmp / "nowhere", "1.1.0"), "")


if __name__ == "__main__":
    unittest.main()


class InPlaceSwapTests(unittest.TestCase):
    """The install folder keeps its identity across an update (a shell cd'd into it stays valid)."""

    def test_root_inode_is_unchanged_and_stray_files_move_to_old(self):
        import os as _os
        import tempfile
        from pathlib import Path as _P
        from laglens import updater as upd
        base = _P(tempfile.mkdtemp(prefix="laglens-inplace-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(str(base), ignore_errors=True))
        root = base / "lag-lens"
        (root / "laglens").mkdir(parents=True)
        (root / "run.py").write_text("old\n")
        (root / "stray.txt").write_text("gone after update\n")
        (root / "config.json").write_text('{"label": "mine"}\n')
        (root / "sessions" / "s1").mkdir(parents=True)
        (root / "sessions" / "s1" / "x").write_text("keep\n")
        new = base / "extract" / "lag-lens"
        (new / "laglens").mkdir(parents=True)
        (new / "run.py").write_text("new\n")
        (new / "start.sh").write_text("#!/bin/sh\n")
        ino = _os.stat(str(root)).st_ino
        old = upd.swap_install(root, new, "1.0.0")
        self.assertEqual(_os.stat(str(root)).st_ino, ino)
        self.assertEqual((root / "run.py").read_text(), "new\n")
        self.assertFalse((root / "stray.txt").exists())
        self.assertEqual((old / "stray.txt").read_text(), "gone after update\n")
        self.assertEqual((old / "run.py").read_text(), "old\n")
        self.assertEqual((root / "config.json").read_text(), '{"label": "mine"}\n')
        self.assertEqual((root / "sessions" / "s1" / "x").read_text(), "keep\n")
        self.assertTrue((old / "config.json").exists())  # backup copy
        self.assertFalse((base / "lag-lens.new-1.0.0").exists())
        self.assertTrue(_os.access(str(root / "start.sh"), _os.X_OK))
