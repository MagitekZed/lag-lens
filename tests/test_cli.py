"""Tests for laglens.cli (argparse + dispatch) and the laglens.app run/shutdown wiring."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import signal
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = Path(__file__).resolve().parent.parent

from laglens import app, cli  # noqa: E402
from laglens.config import DEFAULTS, load_config  # noqa: E402
from laglens.platform.base import Platform  # noqa: E402
from laglens.version import __version__  # noqa: E402


def _missing(argv, timeout):
    raise FileNotFoundError(argv[0])


def offline_platform() -> Platform:
    return Platform(runner=_missing, reader=lambda p: None, exists=lambda p: False, env={}, which=lambda n: None)


def no_resolver(name, family):
    return None


class ParserTests(unittest.TestCase):
    def test_defaults(self):
        a = cli.parse_args([])
        self.assertFalse(a.doctor)
        self.assertFalse(a.version)
        self.assertIsNone(a.port)
        self.assertIsNone(a.resume)
        self.assertEqual(a.pack, "full")
        self.assertFalse(a.verbose)

    def test_all_flags(self):
        a = cli.parse_args([
            "--doctor", "--no-net", "--selftest", "--port", "9000", "--no-browser", "--label", "xbox on port 2",
            "--xbox", "10.0.0.23", "--no-docsis", "--no-igd", "--config", "c.json", "--resume", "sessions/a",
            "--report", "sessions/b", "--export", "sessions/c", "--pack", "comcast", "--index", "--loadtest",
            "--docsis-dump", "--update", "--check", "--stop", "--version", "-v",
        ])
        self.assertTrue(a.doctor and a.no_net and a.selftest and a.no_browser and a.no_docsis and a.no_igd)
        self.assertEqual(a.port, 9000)
        self.assertEqual(a.label, "xbox on port 2")
        self.assertEqual(a.xbox, "10.0.0.23")
        self.assertEqual(a.config, "c.json")
        self.assertEqual((a.resume, a.report, a.export), ("sessions/a", "sessions/b", "sessions/c"))
        self.assertEqual(a.pack, "comcast")
        self.assertTrue(a.index and a.loadtest and a.docsis_dump and a.update and a.check and a.stop and a.version and a.verbose)

    def test_bad_pack_and_port(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli.parse_args(["--pack", "bogus"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["--port", "70000"]), cli.EXIT_ERROR)

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["--version"]), 0)
        self.assertEqual(out.getvalue().strip(), __version__)
        # the version comes from the VERSION file next to the package; never pin it here
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+")
        self.assertEqual(__version__, (ROOT / "VERSION").read_text().strip())


class DispatchTests(unittest.TestCase):
    """Each command flag must route to its app.cmd_* function."""

    def _patch(self, name):
        calls = []
        orig = getattr(app, name)
        setattr(app, name, lambda args: calls.append(args) or 42)
        self.addCleanup(setattr, app, name, orig)
        return calls

    def test_dispatch_table(self):
        table = {
            "cmd_doctor": ["--doctor"],
            "cmd_selftest": ["--selftest"],
            "cmd_report": ["--report", "x"],
            "cmd_export": ["--export", "x"],
            "cmd_index": ["--index"],
            "cmd_loadtest": ["--loadtest"],
            "cmd_docsis_dump": ["--docsis-dump"],
            "cmd_update": ["--update"],
            "cmd_stop": ["--stop"],
            "cmd_run": [],
        }
        for fn, argv in table.items():
            calls = self._patch(fn)
            self.assertEqual(cli.main(argv), 42, fn)
            self.assertEqual(len(calls), 1, fn)
        calls = self._patch("cmd_update")
        cli.main(["--check"])
        self.assertTrue(calls[0].check)

    def test_keyboard_interrupt_maps_to_130(self):
        def boom(args):
            raise KeyboardInterrupt

        orig = app.cmd_run
        app.cmd_run = boom
        self.addCleanup(setattr, app, "cmd_run", orig)
        self.assertEqual(cli.main([]), cli.EXIT_INTERRUPTED)


class NotImplementedTests(unittest.TestCase):
    def _expect_not_implemented(self, argv, module):
        try:
            exists = importlib.util.find_spec(module) is not None
        except ModuleNotFoundError:
            exists = False
        if exists:
            self.skipTest("%s exists now" % module)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(argv + ["--config", os.devnull])
        self.assertEqual(rc, cli.EXIT_NOT_IMPLEMENTED)
        self.assertIn("not implemented yet", out.getvalue())

    def test_doctor(self):
        self._expect_not_implemented(["--doctor"], "laglens.doctor")

    def test_index(self):
        self._expect_not_implemented(["--index"], "laglens.report.sessions")

    def test_loadtest(self):
        self._expect_not_implemented(["--loadtest"], "laglens.loadtest")

    def test_update(self):
        self._expect_not_implemented(["--update", "--check"], "laglens.updater")

    def test_lazy_import_helper(self):
        self.assertIsNone(app._lazy("laglens.definitely_missing_module"))
        self.assertIsNone(app._lazy("laglens.missing_pkg.sub.mod"))
        self.assertIsNotNone(app._lazy("laglens.state"))

    def test_lazy_reraises_import_errors_inside_an_existing_module(self):
        """A module that exists but has a broken import is a failure, not 'not available yet'."""
        tmp = Path(tempfile.mkdtemp(prefix="laglens-lazy-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        pkg = tmp / "laglens_lazy_pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "typo.py").write_text("from laglens.state import DoesNotExist\n")
        (pkg / "helper.py").write_text("import laglens.nonexistent_helper\n")
        sys.path.insert(0, str(tmp))
        self.addCleanup(sys.path.remove, str(tmp))
        self.addCleanup(lambda: [sys.modules.pop(k, None) for k in list(sys.modules) if k.startswith("laglens_lazy_pkg")])
        with self.assertRaises(ImportError):
            app._lazy("laglens_lazy_pkg.typo")
        with self.assertRaises(ImportError):
            app._lazy("laglens_lazy_pkg.helper")
        self.assertIsNone(app._lazy("laglens_lazy_pkg.absent"))


class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-run-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.sessions = self.tmp / "sessions"
        self.addCleanup(self._reset_logging)

    @staticmethod
    def _reset_logging():
        import logging

        lg = logging.getLogger("laglens")
        for h in list(lg.handlers):
            lg.removeHandler(h)
            h.close()
        lg.addHandler(logging.NullHandler())

    def run_once(self, extra=(), stop_after=0.2, components=None, overrides=None, out=None):
        args = cli.parse_args(["--no-browser", "--label", "test run", "--config", str(self.tmp / "config.json")] + list(extra))
        ov = {"label": "test run"}
        ov.update(overrides or {})
        cfg = load_config(None, ov)
        with contextlib.redirect_stdout(out if out is not None else io.StringIO()):
            rc = app.run(cfg, args, sessions_root=self.sessions, platform=offline_platform(), resolver=no_resolver,
                         stop_after=stop_after, install_signals=False, components=components, quiet=False)
        return rc

    def test_run_creates_session_files_and_exits_zero(self):
        self.assertEqual(self.run_once(), 0)
        dirs = [p for p in self.sessions.iterdir() if p.is_dir()]
        self.assertEqual(len(dirs), 1)
        sd = dirs[0]
        for name in ("targets.json", "session.json", "token", "log.txt"):
            self.assertTrue((sd / name).exists(), name)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE((sd / "token").stat().st_mode), 0o600)
        last = (self.sessions / ".last").read_text().strip()
        self.assertTrue(last.endswith(sd.name))
        self.assertFalse((self.sessions / "laglens.pid").exists())
        session = json.loads((sd / "session.json").read_text())
        self.assertEqual(session["label"], "test run")
        self.assertEqual(session["stop_reason"], "test")
        self.assertIsNotNone(session["stopped"])
        self.assertEqual(session["resumed_count"], 0)
        self.assertEqual(session["version"], __version__)
        self.assertNotIn("password", json.dumps(session["config"]).replace('"password": null', ""))
        targets = json.loads((sd / "targets.json").read_text())["targets"]
        keys = [t["key"] for t in targets]
        for k in ("gw4", "gw6", "inet4_cf", "inet4_g", "inet6_cf", "inet6_g", "dns_gw", "dns_cf4", "tcp_cf4", "tcp_cf6", "tcp_gw",
                  "tcp_xbl_auth4", "tcp_xbl_auth6", "tcp_xbl_profile4", "tcp_live6", "ntp_cf", "ntp_g", "cdn_0", "cdn_1"):
            self.assertIn(k, keys)
        self.assertEqual([t["id"] for t in targets], list(range(len(targets))))
        gw4 = targets[0]
        self.assertEqual(gw4["key"], "gw4")
        self.assertFalse(gw4["enabled"])
        self.assertIn("no default route", gw4["reason"])
        auth = next(t for t in targets if t["key"] == "tcp_xbl_auth4")
        self.assertIsNone(auth["addr"])
        self.assertEqual(auth["reason"], "cannot resolve")
        ntp = next(t for t in targets if t["key"] == "ntp_cf")
        self.assertEqual(ntp["addr"], "162.159.200.1")
        # every real component (incl. ntp, BUILD_PLAN §3.3) was wired, not skipped as "not available yet"
        collectors = session["summary"]["collectors"]
        for name, _m, _a, _k in app.COMPONENTS:
            self.assertIn(name, collectors, name)
            self.assertNotEqual(collectors[name].get("reason"), "not available yet", name)
        self.assertIn(collectors["engine"]["status"], ("ok", "degraded", "disabled"))
        self.assertFalse(str(collectors["engine"].get("reason") or "").startswith("not available"))
        for name in ("docsis", "notify"):  # off by configuration, never "missing"
            self.assertEqual(collectors[name]["status"], "disabled")
        self.assertIn("matrix", session["summary"])
        self.assertIn("health", session["summary"])
        self.assertTrue((self.sessions / "index.html").exists())  # shutdown rebuilt the static index
        self.assertIn(sd.name, (self.sessions / "index.html").read_text(encoding="utf-8"))
        self.assertEqual(app.LAST_RUN["stop_reason"], "test")
        self.assertEqual(app.LAST_RUN["session_id"], sd.name)

    def test_components_order_has_ntp_after_dns_before_cdn(self):
        names = [c[0] for c in app.COMPONENTS]
        self.assertEqual(names[:7], ["engine", "tracer", "tcp", "dns", "ntp", "cdn", "host"])
        self.assertEqual(names[-6:], ["igd", "ticker", "report", "http", "keepawake", "notify"])
        self.assertIn(("ntp", "laglens.probes.ntp", "NtpProber", "class"), app.COMPONENTS)

    def test_rotation_stops_with_reason_rotate_and_cmd_run_starts_a_new_session(self):
        # an old session (started 2 h ago) resumed with rotate_hours=1 rotates at once
        self.run_once()
        sd = [p for p in self.sessions.iterdir() if p.is_dir()][0]
        doc = json.loads((sd / "session.json").read_text())
        doc["started"] = doc["started"] - 2 * 3600
        (sd / "session.json").write_text(json.dumps(doc))
        self.assertEqual(self.run_once(["--resume", str(sd)], stop_after=30.0, overrides={"rotate_hours": 1}), 0)
        self.assertEqual(app.LAST_RUN["stop_reason"], app.STOP_REASON_ROTATE)
        self.assertEqual(json.loads((sd / "session.json").read_text())["stop_reason"], "rotate")
        # cmd_run loops on that reason with a fresh session (resume cleared), then returns the final rc
        calls = []

        def fake_run(cfg, args, **kw):
            calls.append((args.resume, kw.get("terminal_marks"), kw.get("update_check")))
            app.LAST_RUN.clear()
            app.LAST_RUN.update({"stop_reason": "rotate" if len(calls) == 1 else "sigint", "session_id": "s%d" % len(calls)})
            return 0

        orig = app.run
        app.run = fake_run
        self.addCleanup(setattr, app, "run", orig)
        args = cli.parse_args(["--no-browser", "--resume", str(sd), "--config", str(self.tmp / "config.json")])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.cmd_run(args), 0)
        self.assertEqual([c[0] for c in calls], [str(sd), None])
        self.assertTrue(all(c[1] is True and c[2] is True for c in calls))

    def test_startup_box_has_urls_doctor_lines_and_chips(self):
        from laglens.state import State
        from laglens.store import Store

        store = Store(self.tmp / "sess", DEFAULTS, disk_usage=lambda p: types.SimpleNamespace(free=10 ** 12))
        state = State(1.0, "20261011-190000", DEFAULTS)
        store.state = state
        state.label = "xbox on port 2"
        ctx = app.AppContext(DEFAULTS, cli.parse_args([]), state, store, offline_platform(), sessions_root=self.sessions)
        ctx.components = {"engine": object(), "http": object()}
        ctx.urls = ["http://10.0.0.35:8787", "http://mac.local:8787"]
        state.host = {"gateway": "10.0.0.1", "iface": "en0", "wifi": True, "gw6": "fe80::1%en0"}
        state.doctor = [
            {"check": "icmp_v4_socket", "status": "ok", "detail": "DGRAM ICMP works"},
            {"check": "local_network", "status": "warn", "detail": "denied", "fallback": "allow Terminal in System Settings"},
            {"check": "disk", "status": "fail", "detail": "x" * 200},
            {"check": "xb7_login", "status": "skip", "detail": "no password"},
        ]
        state.set_collector("engine", "ok")
        state.set_collector("http", "ok")
        state.set_collector("docsis", "disabled", reason="docsis.password not set")
        state.set_collector("keepawake", "degraded", reason="on battery: " + "y" * 150)
        box = app.startup_box(ctx)
        for needle in ("Lag Lens %s" % __version__, "20261011-190000", "xbox on port 2",
                       "Dashboard: http://10.0.0.35:8787", "http://mac.local:8787", "Phone:     http://10.0.0.35:8787/phone",
                       "http://mac.local:8787/phone", "Gateway: 10.0.0.1 via en0 (Wi-Fi)", "Doctor: 1 ok, 1 warn, 1 fail, 1 skipped",
                       "OK   icmp_v4_socket: DGRAM ICMP works", "WARN local_network: denied -> allow Terminal",
                       "FAIL disk: ", "Running: engine, http", "Not running:\n", "  docsis: docsis.password not set",
                       "Degraded:\n", "  keepawake: on battery: yyy", "Ctrl-C"):
            self.assertIn(needle, "\n".join(ln.replace("│", "").rstrip() for ln in box.splitlines()) + "\n", needle)
        self.assertNotIn("xb7_login", box)  # SKIPs are not listed
        self.assertNotIn("Press Enter", box)  # no terminal reader attached
        lines = box.splitlines()
        self.assertTrue(all(len(ln) == len(lines[0]) for ln in lines), "box is rectangular")
        self.assertLessEqual(len(lines[0]), app.BOX_MAX_WIDTH + 4)  # the long reason was cut, not the box widened
        ctx.terminal_marks = object()
        self.assertIn('Press Enter here to mark "Lag happened"', app.startup_box(ctx))

    def test_terminal_marks_records_a_mark_per_line_and_ignores_stopped_ctx(self):
        from laglens.state import State
        from laglens.store import Store

        store = Store(self.tmp / "sess", DEFAULTS, disk_usage=lambda p: types.SimpleNamespace(free=10 ** 12))
        state = State(1.0, "20261011-190000", DEFAULTS)
        store.state = state
        store.ensure_token()
        store.start()
        self.addCleanup(store.stop)
        ctx = app.AppContext(DEFAULTS, cli.parse_args([]), state, store, offline_platform(), sessions_root=self.sessions)
        printed = []
        reader = app.TerminalMarks(ctx, stream=io.StringIO("\nlaggy\n"), out=printed.append)
        reader._loop()  # two lines then EOF
        self.assertEqual(reader.marks, 2)
        self.assertEqual([m.source for m in state.marks], ["terminal", "terminal"])
        self.assertEqual(state.marks[1].note, "laggy")
        self.assertEqual(len(printed), 2)
        self.assertTrue(printed[0].startswith("Marked mk-1 at "), printed[0])
        self.assertIs(ctx.component("marks"), app._mark_service(ctx))  # one shared MarkService
        # a stopped context ignores input instead of writing into a closed session
        state.request_stop("test", publish=False)
        reader.stream = io.StringIO("\n")
        reader._loop()
        self.assertEqual(reader.marks, 2)
        # the reader only starts on a TTY
        self.assertIsNone(app._terminal_marks(ctx, stream=io.StringIO("")))

    def test_desktop_session_and_browser_opener(self):
        mk = lambda name, env: types.SimpleNamespace(name=name, env=lambda k, d="": env.get(k, d), which=lambda n: "/usr/bin/" + n)  # noqa: E731
        self.assertFalse(app._desktop_session(mk("darwin", {"SSH_CONNECTION": "1.2.3.4 1 5.6.7.8 22"})))
        self.assertFalse(app._desktop_session(mk("linux", {})))
        self.assertTrue(app._desktop_session(mk("linux", {"DISPLAY": ":0"})))
        self.assertTrue(app._desktop_session(mk("linux", {"WAYLAND_DISPLAY": "wayland-0"})))
        self.assertTrue(app._desktop_session(mk("darwin", {})))
        argvs = []
        popen = lambda argv, **kw: argvs.append(argv)  # noqa: E731
        self.assertTrue(app._open_browser("http://x:1", mk("darwin", {}), popen=popen))
        self.assertTrue(app._open_browser("http://x:1", mk("linux", {}), popen=popen))
        self.assertEqual(argvs, [["/usr/bin/open", "http://x:1"], ["/usr/bin/xdg-open", "http://x:1"]])

        def boom(argv, **kw):
            raise OSError("no")

        self.assertFalse(app._open_browser("http://x:1", mk("darwin", {}), popen=boom))

    def test_session_document_truncates_the_v6_prefix(self):
        self.assertEqual(app.truncate_v6_prefix("2601:abcd:4321:abe0::/64"), "2601:abcd:4321::/64 (truncated)")
        self.assertEqual(app.truncate_v6_prefix("2601:abcd:4321::/64 (truncated)"), "2601:abcd:4321::/64 (truncated)")
        self.assertIsNone(app.truncate_v6_prefix(None))
        from laglens.state import State
        from laglens.store import Store

        store = Store(self.tmp / "sess", DEFAULTS, disk_usage=lambda p: types.SimpleNamespace(free=10 ** 12))
        state = State(1.0, "s", DEFAULTS)
        store.state = state
        ctx = app.AppContext(DEFAULTS, cli.parse_args([]), state, store, offline_platform(), sessions_root=self.sessions)
        state.host = {"v6_prefix": "2601:abcd:4321:abe0::/64"}
        doc = app.session_document(ctx)
        self.assertEqual(doc["v6_prefix"], "2601:abcd:4321::/64 (truncated)")
        self.assertNotIn("abe0", json.dumps(doc))
        self.assertEqual(doc["summary"]["matrix"], state.matrix)

    def test_cmd_report_and_cmd_index_return_zero_and_print_paths(self):
        sdir = self.tmp / "sessions" / "20261011-190000"
        sdir.mkdir(parents=True)
        fake_build = types.ModuleType("laglens.report.build")

        def fake_rebuild(d, cfg):
            if not Path(d).is_dir():
                raise FileNotFoundError("session directory not found: %s" % d)
            return Path(d) / "report.html"

        fake_build.rebuild = fake_rebuild
        fake_sessions = types.ModuleType("laglens.report.sessions")
        fake_sessions.rebuild_index = lambda root: 0
        saved = {k: sys.modules.get(k) for k in ("laglens.report.build", "laglens.report.sessions")}

        def restore():
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

        self.addCleanup(restore)
        sys.modules["laglens.report.build"] = fake_build
        sys.modules["laglens.report.sessions"] = fake_sessions
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(app.cmd_report(cli.parse_args(["--report", str(sdir), "--config", os.devnull])), 0)
        self.assertEqual(out.getvalue().strip(), str(sdir / "report.html"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(app.cmd_report(cli.parse_args(["--report", str(self.tmp / "nope"), "--config", os.devnull])), 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(app.cmd_index(cli.parse_args(["--index"])), 0)
        self.assertTrue(out.getvalue().strip().endswith("index.html"))

    def test_resume_keeps_ids_and_logs_gap(self):
        self.run_once()
        sd = [p for p in self.sessions.iterdir() if p.is_dir()][0]
        before = {t["id"]: t["key"] for t in json.loads((sd / "targets.json").read_text())["targets"]}
        started = json.loads((sd / "session.json").read_text())["started"]
        self.assertEqual(self.run_once(["--resume", str(sd)]), 0)
        self.assertEqual(len([p for p in self.sessions.iterdir() if p.is_dir()]), 1)
        after = {t["id"]: t["key"] for t in json.loads((sd / "targets.json").read_text())["targets"]}
        self.assertEqual(before, after)
        session = json.loads((sd / "session.json").read_text())
        self.assertEqual(session["resumed_count"], 1)
        self.assertEqual(session["started"], started)
        events = [json.loads(ln) for ln in (sd / "events.jsonl").read_text().splitlines() if ln]
        # other components (the tracer on a host without a default route, for instance) may have
        # logged events of their own first; the resume gap must be there regardless
        gaps = [e for e in events if e["type"] == "monitor_gap"]
        self.assertEqual(len(gaps), 1, events)
        gap = gaps[0]
        self.assertEqual(gap["peak"], {"reason": "monitor restarted"})
        self.assertEqual(gap["note"], "monitor restarted")
        self.assertRegex(gap["id"], r"^ev-\d{6}$")
        # the file row has exactly the SPEC §6.4 keys (same shape as the in-memory Event)
        self.assertEqual(set(gap), {"id", "t0", "t1", "type", "target", "severity", "peak", "episode", "stall", "source", "note"})

    def test_resume_tolerates_malformed_targets_and_session_json(self):
        self.run_once()
        sd = [p for p in self.sessions.iterdir() if p.is_dir()][0]
        doc = json.loads((sd / "targets.json").read_text())
        doc["targets"][0]["id"] = "zero"  # not an int
        doc["targets"][1]["id"] = 300  # out of range
        doc["targets"].append("junk")
        doc["targets"].append({"id": 7})  # no key
        (sd / "targets.json").write_text(json.dumps(doc))
        session = json.loads((sd / "session.json").read_text())
        session["started"] = "yesterday"
        session["resumed_count"] = "many"
        (sd / "session.json").write_text(json.dumps(session))
        self.assertEqual(self.run_once(["--resume", str(sd)]), 0)
        after = json.loads((sd / "targets.json").read_text())["targets"]
        ids = [t["id"] for t in after]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(isinstance(i, int) and 0 <= i <= 255 for i in ids), ids)
        self.assertIn("gw4", [t["key"] for t in after])
        session = json.loads((sd / "session.json").read_text())
        self.assertEqual(session["resumed_count"], 1)
        self.assertIsInstance(session["started"], float)

    def test_resume_missing_dir_starts_fresh(self):
        self.assertEqual(self.run_once(["--resume", str(self.tmp / "nope")]), 0)
        self.assertEqual(len([p for p in self.sessions.iterdir() if p.is_dir()]), 1)

    def test_component_protocol_and_shutdown_order(self):
        import types

        log = []

        class Comp:
            def __init__(self, ctx):
                self.ctx = ctx
                log.append("init")

            def start(self):
                log.append("start")

            def stop(self, timeout=2.0):
                log.append("stop")

        class Bad:
            def __init__(self, ctx):
                raise RuntimeError("cannot bind")

        mod = types.ModuleType("laglens_test_components")
        mod.Comp = Comp
        mod.Bad = Bad
        mod.serve = lambda ctx: Comp(ctx)
        sys.modules["laglens_test_components"] = mod
        self.addCleanup(sys.modules.pop, "laglens_test_components", None)
        comps = [
            ("engine", "laglens_test_components", "Comp", "class"),
            ("igd", "laglens_test_components", "Bad", "class"),
            ("http", "laglens_test_components", "serve", "func"),
            ("wan", "laglens.collectors.nope", "X", "class"),
        ]
        self.assertEqual(self.run_once(components=comps, extra=["--no-igd"]), 0)
        self.assertEqual(log, ["init", "start", "init", "stop", "stop"])
        sd = [p for p in self.sessions.iterdir() if p.is_dir()][0]
        collectors = json.loads((sd / "session.json").read_text())["summary"]["collectors"]
        self.assertEqual(collectors["engine"]["status"], "ok")
        self.assertEqual(collectors["igd"]["reason"], "disabled by --no-igd")
        self.assertEqual(collectors["wan"]["reason"], "not available yet")
        self.assertEqual(collectors["http"]["status"], "ok")

    def test_shutdown_flushes_the_writer_before_the_final_report(self):
        order = []

        class Ticker:
            def __init__(self, ctx):
                self.ctx = ctx

            def start(self):
                pass

            def stop(self, timeout=2.0):
                order.append("ticker.stop")

            def close_final(self):
                self.ctx.store.append_json("rollups", {"t": 1, "id": 0, "n": 4})
                order.append("close_final")

        class Report:
            def __init__(self, ctx):
                self.ctx = ctx

            def start(self):
                pass

            def stop(self, timeout=2.0):
                order.append("report.stop")

            def build(self, final=False):
                # a ReportBuilder that reads rollups.jsonl from disk must see the row close_final queued
                order.append("build")
                order.append(("rows", len(self.ctx.store.read_json("rollups"))))
                order.append(("plain samples.bin.gz absent", not self.ctx.store.path("samples.bin.gz").exists()))

        mod = types.ModuleType("laglens_test_shutdown")
        mod.Ticker = Ticker
        mod.Report = Report
        sys.modules["laglens_test_shutdown"] = mod
        self.addCleanup(sys.modules.pop, "laglens_test_shutdown", None)
        comps = [("ticker", "laglens_test_shutdown", "Ticker", "class"), ("report", "laglens_test_shutdown", "Report", "class")]
        self.assertEqual(self.run_once(components=comps), 0)
        self.assertEqual(order, ["report.stop", "ticker.stop", "close_final", "build", ("rows", 1), ("plain samples.bin.gz absent", True)])

    def test_broken_component_import_is_reported_not_skipped(self):
        tmp = Path(tempfile.mkdtemp(prefix="laglens-broken-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        pkg = tmp / "laglens_broken_pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "scheduler.py").write_text("from laglens.state import DoesNotExist\nclass Engine: pass\n")
        sys.path.insert(0, str(tmp))
        self.addCleanup(sys.path.remove, str(tmp))
        self.addCleanup(lambda: [sys.modules.pop(k, None) for k in list(sys.modules) if k.startswith("laglens_broken_pkg")])
        comps = [("engine", "laglens_broken_pkg.scheduler", "Engine", "class")]
        self.assertEqual(self.run_once(components=comps), 0)
        sd = [p for p in self.sessions.iterdir() if p.is_dir()][0]
        eng = json.loads((sd / "session.json").read_text())["summary"]["collectors"]["engine"]
        self.assertEqual(eng["status"], "disabled")
        self.assertTrue(eng["reason"].startswith("import failed:"), eng)
        self.assertIn("DoesNotExist", eng["reason"])

    def test_cmd_stop_without_pidfile(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.cmd_stop(cli.parse_args(["--stop"]), sessions_root=self.sessions), 1)

    def test_signal_handler_counts_only_sigints_and_does_not_publish(self):
        from laglens.state import State

        st = State(1.0, "s")
        seen = []
        st.subscribe(lambda n, o: seen.append(n))
        clock = {"t": 10.0}
        exits = []
        h = app._make_signal_handler(st, clock=lambda: clock["t"], force_exit=exits.append)
        with contextlib.redirect_stderr(io.StringIO()):
            h(signal.SIGINT, None)  # Ctrl-C
            self.assertTrue(st.stop_event.is_set())
            self.assertEqual(st.stop_reason, "sigint")
            self.assertEqual(seen, [])  # no subscriber callbacks inside the handler
            h(signal.SIGTERM, None)  # start.sh forwards TERM: ignored
            h(signal.SIGTERM, None)
            clock["t"] += 0.3
            h(signal.SIGINT, None)  # impatient second Ctrl-C: still graceful
            h(signal.SIGINT, None)  # third within 1 s: still graceful
            self.assertEqual(exits, [])
            clock["t"] += 1.0
            h(signal.SIGINT, None)
        self.assertEqual(exits, [130])
        # a SIGTERM first (e.g. --stop) also requests a graceful stop
        st2 = State(1.0, "s")
        h2 = app._make_signal_handler(st2, clock=lambda: 0.0, force_exit=exits.append)
        with contextlib.redirect_stderr(io.StringIO()):
            h2(signal.SIGTERM, None)
        self.assertEqual(st2.stop_reason, "sigterm")

    def test_shutdown_budget_derives_from_stop_grace(self):
        from laglens.state import State

        seen = []

        class Slow:
            def __init__(self, name):
                self.name = name

            def stop(self, timeout=2.0):
                seen.append((self.name, round(timeout, 2)))

        tmp = self.tmp / "sess"
        from laglens.store import Store

        store = Store(tmp, DEFAULTS, disk_usage=lambda p: types.SimpleNamespace(free=10 ** 12))
        state = State(1.0, "s")
        store.state = state
        ctx = app.AppContext(DEFAULTS, cli.parse_args([]), state, store, offline_platform(), sessions_root=self.sessions)
        ctx.components = {"engine": Slow("engine"), "a": Slow("a"), "b": Slow("b"), "keepawake": Slow("keepawake")}
        orig = store.stop
        store.stop = lambda timeout=15.0: seen.append(("store", timeout)) or orig(timeout)
        self.assertEqual(app.shutdown(ctx, grace_s=1.0), 0)
        d = dict(seen)
        self.assertEqual(d["engine"], 1.0)  # min(2 s, budget)
        self.assertLessEqual(d["a"], 0.5)  # the remaining ~1 s split between a and b
        self.assertGreaterEqual(d["a"], 0.2)  # ...but never below the floor
        self.assertEqual(d["a"], d["b"])
        self.assertEqual(d["store"], 1.0)  # the writer always gets at least 1 s
        # engine first, then the others in reverse start order, writer, keepawake last
        self.assertEqual([n for n, _ in seen], ["engine", "b", "a", "store", "keepawake"])
        # with the default 4 s grace the engine keeps its full 2 s
        del seen[:]
        ctx.components = {"engine": Slow("engine"), "a": Slow("a")}
        store._stopped = False
        self.assertEqual(app.shutdown(ctx), 0)
        self.assertEqual(dict(seen)["engine"], 2.0)
        self.assertAlmostEqual(dict(seen)["a"], 4.0, delta=0.2)  # the lone remaining component gets what is left

    def test_load_app_config_overrides(self):
        args = cli.parse_args(["--port", "9100", "--xbox", "10.0.0.9", "--no-browser", "--label", "L", "--config", str(self.tmp / "c.json")])
        cfg = app.load_app_config(args)
        self.assertEqual(cfg["port"], 9100)
        self.assertEqual(cfg["targets"]["xbox_ip"], "10.0.0.9")
        self.assertFalse(cfg["open_browser"])
        self.assertEqual(cfg["label"], "L")
        self.assertTrue((self.tmp / "c.json").exists())
        self.assertEqual(json.loads((self.tmp / "c.json").read_text()), DEFAULTS)


if __name__ == "__main__":
    unittest.main()


class SingleInstanceTests(unittest.TestCase):
    """One monitor per folder: a second start is refused, a stale pidfile is ignored."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-single-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.sessions = self.tmp / "sessions"
        (self.sessions / "20261011-231139").mkdir(parents=True)
        (self.sessions / ".last").write_text("sessions/20261011-231139\n")
        (self.sessions / "20261011-231139" / "session.json").write_text(json.dumps({"id": "20261011-231139", "port": 8788}))

    def fake_monitor(self):
        """A live process whose command line contains run.py (like a running monitor)."""
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "run.py"])
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        return p

    def test_live_monitor_is_found_with_its_session_and_port(self):
        p = self.fake_monitor()
        (self.sessions / "laglens.pid").write_text("%d\n" % p.pid)
        info = app.running_instance(self.sessions)
        self.assertEqual(info, {"pid": p.pid, "session": "20261011-231139", "port": 8788})

    def test_stale_or_foreign_pid_is_not_a_monitor(self):
        (self.sessions / "laglens.pid").write_text("999999\n")
        self.assertIsNone(app.running_instance(self.sessions))
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])  # alive, but not run.py
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        (self.sessions / "laglens.pid").write_text("%d\n" % other.pid)
        self.assertIsNone(app.running_instance(self.sessions))
        (self.sessions / "laglens.pid").write_text("%d\n" % os.getpid())
        self.assertIsNone(app.running_instance(self.sessions))  # ourselves (a --resume after a crash)

    def test_second_start_is_refused_without_creating_a_session(self):
        p = self.fake_monitor()
        (self.sessions / "laglens.pid").write_text("%d\n" % p.pid)
        saved_root = app.ROOT
        app.ROOT = self.tmp
        self.addCleanup(setattr, app, "ROOT", saved_root)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = app.cmd_run(cli.parse_args(["--no-browser", "--config", os.devnull]))
        self.assertEqual(rc, app.EXIT_ALREADY_RUNNING)
        self.assertIn("already running from this folder: pid %d (session 20261011-231139, dashboard port 8788)" % p.pid, out.getvalue())
        self.assertEqual(sorted(x.name for x in self.sessions.iterdir() if x.is_dir()), ["20261011-231139"])
        self.assertEqual((self.sessions / "laglens.pid").read_text().strip(), str(p.pid))
