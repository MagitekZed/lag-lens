"""Tests for get.sh, the curl | sh installer.

A throw-away zip is served from a local http.server on 127.0.0.1 and the real
get.sh is run against it with LAGLENS_BASE / LAGLENS_DIR pointing at temporary
directories. Covers the fresh install, the re-install that must carry user data
over, and the failure paths that must never lose config.json or sessions/.
"""

import hashlib
import http.server
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GET_SH = REPO / "get.sh"

ZIP_MEMBERS = {
    "lag-lens/run.py": "#!/usr/bin/env python3\nprint('run')\n",
    "lag-lens/start.sh": "#!/bin/sh\necho start\n",
    "lag-lens/get.sh": "#!/bin/sh\necho get\n",
    "lag-lens/VERSION": "9.8.7\n",
    "lag-lens/README.md": "# fake\n",
    "lag-lens/laglens/__init__.py": "",
    "lag-lens/laglens/cli.py": "def main():\n    pass\n",
}


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: D401 - silence per-request logging
        pass


def make_site(site: Path, corrupt_sum: bool = False) -> None:
    site.mkdir(parents=True, exist_ok=True)
    zpath = site / "lag-lens.zip"
    with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, body in ZIP_MEMBERS.items():
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.create_system = 3
            zi.external_attr = (0o100644) << 16
            zf.writestr(zi, body)
    digest = hashlib.sha256(zpath.read_bytes()).hexdigest()
    if corrupt_sum:
        digest = ("0" if digest[0] != "0" else "1") + digest[1:]
    (site / "lag-lens.zip.sha256").write_text("%s  lag-lens.zip\n" % digest)


class GetShTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="laglens-getsh-"))
        cls.site = cls.tmp / "site"
        make_site(cls.site)
        cls.bad_site = cls.tmp / "bad-site"
        make_site(cls.bad_site, corrupt_sum=True)
        cls.empty_site = cls.tmp / "empty-site"
        cls.empty_site.mkdir()
        cls.servers = {}
        for name, root in (("ok", cls.site), ("bad", cls.bad_site), ("empty", cls.empty_site)):
            cls.servers[name] = cls._serve(root)

    @classmethod
    def _serve(cls, root: Path):
        def handler(*args, **kwargs):
            return _Quiet(*args, directory=str(root), **kwargs)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers.values():
            srv.shutdown()
            srv.server_close()
        _fix_modes(cls.tmp)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def base(self, which: str = "ok") -> str:
        return "http://127.0.0.1:%d" % self.servers[which].server_address[1]

    def run_get(self, dest: Path, shell: str = "sh", base: str = "ok", path=None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["LAGLENS_BASE"] = self.base(base)
        env["LAGLENS_DIR"] = str(dest)
        env.pop("http_proxy", None)
        env.pop("HTTP_PROXY", None)
        if path is not None:
            env["PATH"] = path
        return subprocess.run(
            [shell, str(GET_SH)],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
            cwd=str(self.tmp),
        )

    def seed_install(self, dest: Path) -> None:
        """A previous install with user data, a stale file and an old backup."""
        dest.mkdir(parents=True)
        (dest / "VERSION").write_text("1.2.3\n")
        (dest / "start.sh").write_text("old\n")
        (dest / "stale.txt").write_text("from the old version\n")
        (dest / "config.json").write_text('{"docsis": {"password": "keep-me"}}\n')
        (dest / "sessions" / "20260101-000000").mkdir(parents=True)
        (dest / "sessions" / "20260101-000000" / "session.json").write_text("{}\n")
        old = Path(str(dest) + ".old")
        old.mkdir()
        (old / "ancient.txt").write_text("previous backup\n")

    def test_fresh_install_with_sh(self):
        dest = self.tmp / "fresh" / "lag-lens"
        proc = self.run_get(dest, "sh")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Installed Lag Lens 9.8.7", proc.stdout)
        self.assertTrue((dest / "laglens" / "cli.py").is_file())
        for name in ("start.sh", "get.sh", "run.py"):
            self.assertTrue((dest / name).stat().st_mode & stat.S_IXUSR, name)
        self.assertFalse(Path(str(dest) + ".old").exists())
        self.assertNotIn("Previous install kept", proc.stdout)

    def test_reinstall_with_bash_keeps_user_data(self):
        dest = self.tmp / "again" / "lag-lens"
        self.seed_install(dest)
        proc = self.run_get(Path(str(dest) + "/"), "bash")  # trailing slash is tolerated
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Previous install kept", proc.stdout)
        self.assertEqual((dest / "VERSION").read_text().strip(), "9.8.7")
        self.assertIn("keep-me", (dest / "config.json").read_text())
        self.assertTrue((dest / "sessions" / "20260101-000000" / "session.json").is_file())
        self.assertFalse((dest / "stale.txt").exists())
        old = Path(str(dest) + ".old")
        self.assertTrue((old / "stale.txt").is_file())
        self.assertFalse((old / "ancient.txt").exists(), "the older backup must be replaced")
        self.assertFalse((old / "config.json").exists())
        self.assertFalse((old / "sessions").exists())

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can delete anything")
    def test_undeletable_old_backup_aborts_before_touching_install(self):
        dest = self.tmp / "locked" / "lag-lens"
        self.seed_install(dest)
        old = Path(str(dest) + ".old")
        locked = old / "locked"
        locked.mkdir()
        (locked / "f").write_text("x\n")
        os.chmod(locked, 0)
        try:
            proc = self.run_get(dest, "sh")
        finally:
            os.chmod(locked, 0o755)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("cannot remove the previous backup", proc.stderr)
        self.assertIn("was not touched", proc.stderr)
        # The install is exactly as it was: old version, user data, stale file.
        self.assertEqual((dest / "VERSION").read_text().strip(), "1.2.3")
        self.assertIn("keep-me", (dest / "config.json").read_text())
        self.assertTrue((dest / "sessions" / "20260101-000000" / "session.json").is_file())
        self.assertTrue((dest / "stale.txt").is_file())
        # The stale backup itself is disposable (rm -rf may have partly emptied it).
        self.assertTrue((locked / "f").is_file())

    def test_checksum_mismatch_leaves_install_alone(self):
        dest = self.tmp / "badsum" / "lag-lens"
        self.seed_install(dest)
        proc = self.run_get(dest, "sh", base="bad")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("checksum mismatch", proc.stderr)
        self.assertEqual((dest / "VERSION").read_text().strip(), "1.2.3")
        self.assertIn("keep-me", (dest / "config.json").read_text())
        self.assertTrue((Path(str(dest) + ".old") / "ancient.txt").is_file())

    def test_download_failure(self):
        dest = self.tmp / "nozip" / "lag-lens"
        proc = self.run_get(dest, "sh", base="empty")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("download failed", proc.stderr)
        self.assertFalse(dest.exists())

    def test_python3_only_fallbacks(self):
        """No curl/wget/unzip/sha256sum/shasum on PATH: the python3 fallbacks carry the install."""
        bindir = self.tmp / "bin"
        bindir.mkdir(exist_ok=True)
        needed = ["sh", "mktemp", "cut", "tr", "mkdir", "mv", "rm", "chmod", "dirname", "uname", "head", "tail"]
        for tool in needed:
            path = shutil.which(tool)
            if path is None:
                self.skipTest("no %s on PATH" % tool)
            link = bindir / tool
            if not link.exists():
                os.symlink(path, link)
        py = bindir / "python3"
        if not py.exists():
            os.symlink(sys.executable, py)
        dest = self.tmp / "pyonly" / "lag-lens"
        proc = self.run_get(dest, str(bindir / "sh"), path=str(bindir))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((dest / "laglens" / "cli.py").is_file())
        self.assertIn("Checksum OK", proc.stdout)


def _fix_modes(root: Path) -> None:
    for dirpath, dirnames, _ in os.walk(root):
        for d in dirnames:
            try:
                os.chmod(os.path.join(dirpath, d), 0o755)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
