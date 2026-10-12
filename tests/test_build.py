"""Tests for build/make_zip.py against a temporary fake repository tree.

Runs the build script as a subprocess (python -I) so the test exercises the
same code path CI and the Pages workflow use. The fake tree contains every
distributable file plus the things that must be excluded from the zip.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MAKE_ZIP = REPO / "build" / "make_zip.py"

EXPECTED_ROOT = [
    "run.py",
    "start.sh",
    "get.sh",
    "config.example.json",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "VERSION",
]


def make_fake_repo(root: Path, version: str = "9.8.7", with_version_py: bool = True) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "VERSION").write_text(version + "\n")
    (root / "run.py").write_text("#!/usr/bin/env python3\nprint('run')\n")
    (root / "start.sh").write_text("#!/bin/sh\necho start\n")
    (root / "get.sh").write_text("#!/bin/sh\necho get\n")
    (root / "config.example.json").write_text("{}\n")
    (root / "README.md").write_text("# fake\n")
    (root / "LICENSE").write_text("MIT\n")
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n## 9.8.7 - 2026-01-02\n\n- first <thing>\n- second\n\n## 9.8.6\n\n- older\n"
    )
    # Things that must NOT end up in the zip.
    (root / "config.json").write_text('{"secret": 1}\n')
    (root / "sessions").mkdir()
    (root / "sessions" / "x.txt").write_text("runtime\n")

    pkg = root / "laglens"
    (pkg / "web" / "vendor").mkdir(parents=True)
    (pkg / "data").mkdir()
    (pkg / "__pycache__").mkdir()
    (pkg / "sessions").mkdir()
    (pkg / "__init__.py").write_text("")
    if with_version_py:
        (pkg / "version.py").write_text('__version__ = "engineer-owned"\n')
    (pkg / "cli.py").write_text("def main():\n    pass\n")
    (pkg / "web" / "index.html").write_text("<html></html>\n")
    (pkg / "web" / "vendor" / "uPlot.iife.min.js").write_text("/* js */\n")
    (pkg / "data" / "oui.txt").write_text("00:00:00\n")
    (pkg / "__pycache__" / "cli.cpython-39.pyc").write_bytes(b"\x00")
    (pkg / "cli.pyc").write_bytes(b"\x00")
    (pkg / ".DS_Store").write_bytes(b"\x00")
    (pkg / "config.json").write_text("{}\n")
    (pkg / "sessions" / "junk.jsonl").write_text("{}\n")

    site = root / "site"
    site.mkdir()
    shutil.copyfile(REPO / "site" / "index.html.tmpl", site / "index.html.tmpl")
    shutil.copyfile(REPO / "site" / "style.css", site / "style.css")


def run_make_zip(repo: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("SOURCE_DATE_EPOCH", None)
    # GIT_DIR/GIT_WORK_TREE must not leak from the caller: the fake tree is not a repo.
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    return subprocess.run(
        [sys.executable, "-I", str(MAKE_ZIP), "--repo", str(repo), "--out", str(out), *extra],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )


class MakeZipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="laglens-build-"))
        cls.repo = cls.tmp / "repo"
        cls.out = cls.tmp / "out"
        make_fake_repo(cls.repo)
        cls.proc = run_make_zip(cls.repo, cls.out, "--strict")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_build_succeeds_in_strict_mode(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stdout + self.proc.stderr)
        self.assertNotIn("WARNING", self.proc.stderr)

    def test_zip_member_list(self):
        with zipfile.ZipFile(self.out / "lag-lens.zip") as zf:
            names = sorted(zf.namelist())
        expected = sorted(
            ["lag-lens/" + n for n in EXPECTED_ROOT]
            + [
                "lag-lens/laglens/__init__.py",
                "lag-lens/laglens/version.py",
                "lag-lens/laglens/cli.py",
                "lag-lens/laglens/web/index.html",
                "lag-lens/laglens/web/vendor/uPlot.iife.min.js",
                "lag-lens/laglens/data/oui.txt",
            ]
        )
        self.assertEqual(names, expected)
        for name in names:
            self.assertTrue(name.startswith("lag-lens/"), name)
        joined = "\n".join(names)
        self.assertNotIn("__pycache__", joined)
        self.assertNotIn(".pyc", joined)
        self.assertNotIn(".DS_Store", joined)
        self.assertNotIn("config.json\n", joined + "\n")
        self.assertNotIn("sessions", joined)

    def test_engineer_version_py_not_overwritten(self):
        with zipfile.ZipFile(self.out / "lag-lens.zip") as zf:
            self.assertEqual(zf.read("lag-lens/laglens/version.py").decode(), '__version__ = "engineer-owned"\n')
            self.assertEqual(zf.read("lag-lens/VERSION").decode().strip(), "9.8.7")

    def test_executable_bits(self):
        with zipfile.ZipFile(self.out / "lag-lens.zip") as zf:
            for name in ("start.sh", "get.sh", "run.py"):
                mode = zf.getinfo("lag-lens/" + name).external_attr >> 16
                self.assertTrue(mode & stat.S_IXUSR, name)
                self.assertEqual(stat.S_IMODE(mode), 0o755, name)
            for name in ("README.md", "laglens/cli.py"):
                mode = zf.getinfo("lag-lens/" + name).external_attr >> 16
                self.assertFalse(mode & stat.S_IXUSR, name)
                self.assertEqual(stat.S_IMODE(mode), 0o644, name)

    def test_deterministic_timestamps_and_rebuild(self):
        with zipfile.ZipFile(self.out / "lag-lens.zip") as zf:
            for zi in zf.infolist():
                self.assertEqual(zi.date_time, (2026, 1, 1, 0, 0, 0), zi.filename)
        first = (self.out / "lag-lens.zip").read_bytes()
        out2 = self.tmp / "out2"
        proc = run_make_zip(self.repo, out2, "--strict")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(first, (out2 / "lag-lens.zip").read_bytes())
        self.assertEqual(first, (self.out / "lag-lens-9.8.7.zip").read_bytes())

    def test_sha256_file_format(self):
        text = (self.out / "lag-lens.zip.sha256").read_text()
        self.assertRegex(text, r"^[0-9a-f]{64}  lag-lens\.zip\n$")
        import hashlib

        digest = hashlib.sha256((self.out / "lag-lens.zip").read_bytes()).hexdigest()
        self.assertEqual(text.split()[0], digest)

    def test_version_json_and_version_file(self):
        data = json.loads((self.out / "version.json").read_text())
        self.assertEqual(set(data), {"version", "sha256", "built_at", "url", "zip_name", "previous"})
        self.assertIsNone(data["previous"], "no --previous given: first release")
        self.assertEqual(data["version"], "9.8.7")
        self.assertEqual(data["zip_name"], "lag-lens-9.8.7.zip")
        self.assertEqual(data["url"], "https://magitekzed.github.io/lag-lens/lag-lens.zip")
        self.assertRegex(data["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(data["built_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual((self.out / "VERSION").read_text(), "9.8.7\n")

    def test_index_html_rendered(self):
        html = (self.out / "index.html").read_text()
        self.assertNotRegex(html, r"\{\{\s*[A-Z_]+\s*\}\}")
        self.assertIn("9.8.7", html)
        self.assertIn("curl -fsSL https://magitekzed.github.io/lag-lens/get.sh | sh", html)
        self.assertIn("cd ~/lag-lens &amp;&amp; bash start.sh", html)
        self.assertIn('href="lag-lens.zip"', html)
        # First changelog section only, HTML-escaped, and not the older one.
        self.assertIn("first &lt;thing&gt;", html)
        self.assertNotIn("older", html.split("What's new")[1])
        self.assertTrue((self.out / "style.css").is_file())

    def test_get_sh_copied_and_executable(self):
        p = self.out / "get.sh"
        self.assertTrue(p.is_file())
        self.assertEqual(p.read_text(), (self.repo / "get.sh").read_text())
        self.assertTrue(p.stat().st_mode & stat.S_IXUSR)


class MissingFilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-build-missing-"))
        self.repo = self.tmp / "repo"
        make_fake_repo(self.repo, with_version_py=False)
        (self.repo / "LICENSE").unlink()
        (self.repo / "run.py").unlink()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_non_strict_warns_and_continues(self):
        proc = run_make_zip(self.repo, self.tmp / "out")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARNING", proc.stderr)
        self.assertIn("LICENSE", proc.stderr)
        self.assertIn("run.py", proc.stderr)
        with zipfile.ZipFile(self.tmp / "out" / "lag-lens.zip") as zf:
            names = zf.namelist()
        self.assertNotIn("lag-lens/LICENSE", names)
        self.assertIn("lag-lens/start.sh", names)
        self.assertTrue((self.tmp / "out" / "index.html").is_file())

    def test_strict_fails(self):
        proc = run_make_zip(self.repo, self.tmp / "out", "--strict")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("LICENSE", proc.stderr)

    def test_version_py_written_only_when_missing(self):
        target = self.repo / "laglens" / "version.py"
        self.assertFalse(target.exists())
        proc = run_make_zip(self.repo, self.tmp / "out")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(target.exists())
        ns = {"__file__": str(target), "__name__": "laglens.version"}
        exec(compile(target.read_text(), str(target), "exec"), ns)  # noqa: S102 (our own generated file)
        self.assertEqual(ns["__version__"], "9.8.7")
        # The fallback literal is embedded too, in case VERSION is unreadable.
        self.assertIn('"9.8.7"', target.read_text())
        with zipfile.ZipFile(self.tmp / "out" / "lag-lens.zip") as zf:
            self.assertIn("lag-lens/laglens/version.py", zf.namelist())

    def test_never_writes_outside_out_and_repo(self):
        before = sorted(p.relative_to(self.tmp).as_posix() for p in self.tmp.rglob("*"))
        run_make_zip(self.repo, self.tmp / "out")
        after = sorted(p.relative_to(self.tmp).as_posix() for p in self.tmp.rglob("*"))
        new = [p for p in after if p not in before]
        for p in new:
            self.assertTrue(p.startswith("out/") or p == "out" or p == "repo/laglens/version.py", p)


def _load_make_zip():
    import importlib.util

    spec = importlib.util.spec_from_file_location("laglens_make_zip", MAKE_ZIP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ChangelogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-build-changelog-"))
        self.repo = self.tmp / "repo"
        make_fake_repo(self.repo)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def whats_new(self, out: Path) -> str:
        html = (out / "index.html").read_text()
        return html.split("What's new")[1].split("</section>")[0]

    def test_unreleased_section_is_skipped_for_the_released_version(self):
        (self.repo / "CHANGELOG.md").write_text(
            "# Changelog\n\n"
            "## [Unreleased]\n\n- not yet shipped\n\n"
            "## [9.8.7] - 2026-01-02\n\n### Added\n- shipped feature\n\n"
            "## [9.8.6] - 2026-01-01\n\n- older\n"
        )
        proc = run_make_zip(self.repo, self.tmp / "out", "--strict")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        section = self.whats_new(self.tmp / "out")
        self.assertIn("shipped feature", section)
        self.assertIn("<h4>Added</h4>", section)
        self.assertNotIn("not yet shipped", section)
        self.assertNotIn("older", section)

    def test_first_section_when_version_not_found(self):
        (self.repo / "CHANGELOG.md").write_text("# Changelog\n\n## 0.1.0\n\n- very first\n")
        proc = run_make_zip(self.repo, self.tmp / "out")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("very first", self.whats_new(self.tmp / "out"))

    def test_heading_matching_is_token_exact(self):
        mz = _load_make_zip()
        f = mz._heading_names_version
        self.assertTrue(f("[1.0.0] - 2026-10-11", "1.0.0"))
        self.assertTrue(f("1.0.0", "1.0.0"))
        self.assertTrue(f("v1.0.0 (2026)", "1.0.0"))
        self.assertFalse(f("[1.0.0-rc1] - 2026", "1.0.0"))
        self.assertFalse(f("[11.0.0]", "1.0.0"))
        self.assertFalse(f("[Unreleased]", "1.0.0"))
        self.assertFalse(f("1.0.01", "1.0.0"))


class OutDirTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-build-out-"))
        self.repo = self.tmp / "repo"
        make_fake_repo(self.repo)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_relative_out_is_resolved_against_cwd(self):
        cwd = self.tmp / "elsewhere"
        cwd.mkdir()
        env = dict(os.environ)
        env.pop("SOURCE_DATE_EPOCH", None)
        proc = subprocess.run(
            [sys.executable, "-I", str(MAKE_ZIP), "--repo", str(self.repo), "--out", "dist"],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(cwd),
            timeout=120,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((cwd / "dist" / "lag-lens.zip").is_file())
        self.assertFalse((self.repo / "dist").exists())

    def test_default_out_is_repo_site(self):
        env = dict(os.environ)
        env.pop("SOURCE_DATE_EPOCH", None)
        cwd = self.tmp / "elsewhere"
        cwd.mkdir()
        proc = subprocess.run(
            [sys.executable, "-I", str(MAKE_ZIP), "--repo", str(self.repo)],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(cwd),
            timeout=120,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((self.repo / "site" / "lag-lens.zip").is_file())
        self.assertTrue((self.repo / "site" / "index.html").is_file())
        self.assertFalse((cwd / "site").exists())


class PreviousReleaseTests(unittest.TestCase):
    """version.json['previous'] is the rollback target for `--update --version X`."""

    BASE = "https://magitekzed.github.io/lag-lens"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-build-prev-"))
        self.repo = self.tmp / "repo"
        make_fake_repo(self.repo)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build_with_live(self, live_text) -> dict:
        live = self.tmp / "live.json"
        live.write_text(live_text)
        proc = run_make_zip(self.repo, self.tmp / "out", "--strict", "--previous", str(live))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads((self.tmp / "out" / "version.json").read_text())

    def test_older_live_version_becomes_previous(self):
        data = self.build_with_live(
            json.dumps({"version": "9.8.6", "sha256": "ab" * 32, "zip_name": "lag-lens-9.8.6.zip",
                        "url": self.BASE + "/lag-lens.zip", "previous": {"version": "9.8.5", "url": "x"}})
        )
        self.assertEqual(
            data["previous"],
            {"version": "9.8.6", "url": self.BASE + "/lag-lens-9.8.6.zip", "sha256": "ab" * 32},
        )

    def test_rebuild_of_same_version_keeps_live_previous(self):
        prev = {"version": "9.8.6", "url": self.BASE + "/lag-lens-9.8.6.zip", "sha256": "cd" * 32}
        data = self.build_with_live(json.dumps({"version": "9.8.7", "sha256": "ef" * 32, "previous": prev}))
        self.assertEqual(data["previous"], prev)

    def test_rebuild_of_same_version_without_previous(self):
        data = self.build_with_live(json.dumps({"version": "9.8.7", "sha256": "ef" * 32}))
        self.assertIsNone(data["previous"])

    def test_empty_live_file_means_first_deploy(self):
        data = self.build_with_live("")
        self.assertIsNone(data["previous"])

    def test_garbage_live_file_is_a_warning_not_a_failure(self):
        live = self.tmp / "live.json"
        live.write_text("<html>404</html>")
        proc = run_make_zip(self.repo, self.tmp / "out", "--previous", str(live))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARNING", proc.stderr)
        data = json.loads((self.tmp / "out" / "version.json").read_text())
        self.assertIsNone(data["previous"])

    def test_zip_name_defaults_from_version(self):
        mz = _load_make_zip()
        entry = mz.previous_entry({"version": "0.9.0"}, "1.0.0", self.BASE)
        self.assertEqual(entry, {"version": "0.9.0", "url": self.BASE + "/lag-lens-0.9.0.zip"})


if __name__ == "__main__":
    unittest.main()
