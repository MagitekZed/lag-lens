"""Application wiring (BUILD_PLAN §3.3): ``cmd_*`` entry points and ``run``.

``run(cfg, args)`` builds platform → Store → State → targets, then starts the
optional components by importing them. A component whose module does not
exist yet is logged as "component not available yet" and skipped, so the
skeleton starts, writes the session files and exits cleanly on SIGINT/SIGTERM.

Component protocol
------------------
Every component is constructed with one argument, the :class:`AppContext`,
and must offer ``start()`` and ``stop(timeout: float = 2.0)``; neither may
block for long. Thread bodies run under :func:`laglens.supervisor.supervised`
(use :func:`laglens.supervisor.start_thread`). The HTTP server is a function
``serve(ctx)`` returning such an object. Components are stopped in reverse
start order during shutdown.

Shutdown sequence (BUILD_PLAN §3.3 / SPEC_FULL §3.4): stop_event set →
``stopping`` published once → engine stops → other components stop → ticker
closes the last second/window → writer **drains** (``store.flush()``) so the
report sees every queued row → final report → writer closes and gzips →
``session.json`` finalised → inhibitor killed → pidfile removed → exit 0
within ``STOP_GRACE_S`` (~4 s; the per-component and writer timeouts are
derived from that deadline).

Signals: the first SIGINT/SIGTERM requests a graceful stop (sets
``stop_event`` only; no subscriber callbacks run inside the handler). Only
SIGINTs count toward the forced exit: the third Ctrl-C, at least 1 s after
the first, calls ``os._exit(130)``. SIGTERMs after a stop was requested are
ignored (``start.sh`` forwards one on Ctrl-C).
"""
import argparse
import importlib
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from laglens import config as configmod
from laglens.log import setup_logging
from laglens.state import STATUS_STARTING, STATUS_STOPPED, State
from laglens.store import LAST_FILE, PID_FILE, Store
from laglens.targets import build_targets
from laglens.version import __version__

log = logging.getLogger("laglens.app")

ROOT = Path(__file__).resolve().parent.parent
SESSIONS_DIRNAME = "sessions"
EXIT_NOT_IMPLEMENTED = 2
EXIT_ALREADY_RUNNING = 3  # start.sh does not restart on this code
SESSION_JSON_INTERVAL_S = 30.0
STOP_GRACE_S = 4.0
GIL_SWITCH_S = 0.001
#: ``stop_reason`` of a session that reached ``cfg.rotate_hours``: ``cmd_run`` starts a fresh one.
STOP_REASON_ROTATE = "rotate"
#: Filled by :func:`run` when it returns (``stop_reason``, ``session_dir``); read by :func:`cmd_run`.
LAST_RUN: Dict[str, Any] = {}

#: (name, module, attribute, kind) — kind 'class' → ``obj = Cls(ctx); obj.start()``,
#: 'func' → ``obj = fn(ctx)``. Order = start order; stopped in reverse.
COMPONENTS: List[Tuple[str, str, str, str]] = [
    ("engine", "laglens.engine.scheduler", "Engine", "class"),
    ("tracer", "laglens.probes.path", "Tracer", "class"),
    ("tcp", "laglens.probes.tcp", "TcpProber", "class"),
    ("dns", "laglens.probes.dns", "DnsProber", "class"),
    ("ntp", "laglens.probes.ntp", "NtpProber", "class"),
    ("cdn", "laglens.probes.cdn", "CdnProber", "class"),
    ("host", "laglens.collectors.host", "HostCollector", "class"),
    ("wifi", "laglens.collectors.wifi", "WifiCollector", "class"),
    ("wan", "laglens.collectors.wan", "WanCollector", "class"),
    ("xbox", "laglens.collectors.xbox", "XboxCollector", "class"),
    ("docsis", "laglens.collectors.docsis", "DocsisCollector", "class"),
    ("igd", "laglens.collectors.igd", "IgdCollector", "class"),
    ("plex", "laglens.collectors.plex", "PlexCollector", "class"),
    ("ticker", "laglens.engine.ticker", "Ticker", "class"),
    ("report", "laglens.report.build", "ReportBuilder", "class"),
    ("http", "laglens.server.http", "serve", "func"),
    ("keepawake", "laglens.keepawake", "KeepAwake", "class"),
    ("notify", "laglens.notify", "Notifier", "class"),
]


class AppContext:
    """Everything a component needs, passed to its constructor."""

    def __init__(
        self,
        cfg: dict,
        args: argparse.Namespace,
        state: State,
        store: Store,
        platform: Any,
        root: Path = ROOT,
        sessions_root: Optional[Path] = None,
    ) -> None:
        self.cfg = cfg
        self.args = args
        self.state = state
        self.store = store
        self.platform = platform
        self.root = root
        self.sessions_root = sessions_root or (root / SESSIONS_DIRNAME)
        self.log = logging.getLogger("laglens")
        self.components: Dict[str, Any] = {}
        self.port: int = int(getattr(args, "port", None) or cfg.get("port", 8787))
        self.started_at: float = time.time()
        self.route: dict = {}
        self.urls: List[str] = []
        #: ``config.json`` of this run; ``POST /api/xbox`` persists ``targets.xbox_ip`` into it.
        self.config_file: Path = config_path(args)
        #: The Enter-to-mark reader (:class:`TerminalMarks`) when stdin is a TTY, else ``None``.
        self.terminal_marks: Optional[Any] = None

    @property
    def token(self) -> str:
        return self.store.token

    def component(self, name: str) -> Optional[Any]:
        return self.components.get(name)

    def wants(self, name: str) -> bool:
        """Whether a component is enabled by config/flags (docsis/igd/wifi/cdn/notify)."""
        a = self.args
        if name == "docsis":
            return not getattr(a, "no_docsis", False) and bool(self.cfg.get("docsis", {}).get("password"))
        if name == "igd":
            return not getattr(a, "no_igd", False) and bool(self.cfg.get("igd", {}).get("enabled", True))
        if name == "cdn":
            return bool(self.cfg.get("cdn", {}).get("enabled", True))
        if name == "wifi":
            return self.cfg.get("wifi", {}).get("enabled", "auto") is not False
        if name == "notify":
            n = self.cfg.get("notify", {})
            return bool(n.get("ntfy_topic") or n.get("webhook_url"))
        if name == "plex":
            return bool(getattr(a, "plex", False)) or bool((self.cfg.get("plex") or {}).get("enabled"))
        return True


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------
def config_path(args: argparse.Namespace) -> Path:
    return Path(args.config) if getattr(args, "config", None) else ROOT / "config.json"


def load_app_config(args: argparse.Namespace, create: bool = True) -> dict:
    """``config.json`` (created on first run) merged with the CLI overrides."""
    path = config_path(args)
    if create:
        configmod.ensure_config_file(path)
    overrides: Dict[str, Any] = {}
    if getattr(args, "port", None):
        overrides["port"] = args.port
    if getattr(args, "label", None):
        overrides["label"] = args.label
    if getattr(args, "xbox", None):
        overrides["targets.xbox_ip"] = args.xbox
    if getattr(args, "no_browser", False):
        overrides["open_browser"] = False
    if getattr(args, "plex", False):
        overrides["plex.enabled"] = True
    return configmod.load_config(path, overrides)


def _lazy(modname: str) -> Optional[Any]:
    """Import ``modname``; ``None`` only when *that* module (or a parent package) is absent.

    Any other ``ImportError`` — the module exists but one of its own imports
    fails (a typo in ``from laglens.state import ...``, a missing helper
    module) — is re-raised so it is reported as a failure, not silently
    treated as "component not available yet".
    """
    try:
        return importlib.import_module(modname)
    except ImportError as exc:
        missing = getattr(exc, "name", None) or ""
        if missing and (missing == modname or modname.startswith(missing + ".")):
            return None
        if not missing and isinstance(exc, ModuleNotFoundError):
            return None
        raise


def _not_implemented(what: str) -> int:
    print("%s: not implemented yet" % what)
    return EXIT_NOT_IMPLEMENTED


# ---------------------------------------------------------------------------
# One-shot commands
# ---------------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace) -> int:
    setup_logging(None, args.verbose)
    mod = _lazy("laglens.doctor")
    if mod is None:
        return _not_implemented("doctor")
    cfg = load_app_config(args)
    from laglens.platform import get_platform

    return int(mod.run_cli(cfg, get_platform(), no_net=bool(getattr(args, "no_net", False))) or 0)


def cmd_selftest(args: argparse.Namespace) -> int:
    """Offline unit tests (``tests/``) then the loopback checks of ``laglens.doctor``."""
    import unittest

    setup_logging(None, args.verbose)
    tests_dir = ROOT / "tests"
    rc = 0
    if tests_dir.is_dir():
        suite = unittest.defaultTestLoader.discover(str(tests_dir), top_level_dir=str(tests_dir))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        rc = 0 if result.wasSuccessful() else 1
    else:
        print("selftest: tests/ directory not found (zip build); unit tests skipped")
    mod = _lazy("laglens.doctor")
    if mod is None or not hasattr(mod, "selftest"):
        print("loopback checks: not implemented yet")
        return rc or EXIT_NOT_IMPLEMENTED
    # the unit tests already ran above; only the loopback checks are left
    return rc or int(mod.selftest(run_tests=False) or 0)


def _session_arg(value: str) -> Path:
    """``sessions/<id>`` relative to the repo root unless it exists as given / is absolute."""
    p = Path(value)
    if not p.is_absolute() and not p.exists():
        p = ROOT / p
    return p


def cmd_report(args: argparse.Namespace) -> int:
    """``--report DIR``: offline rebuild of ``report.html`` (+ ``comcast_evidence.txt``); prints the path."""
    setup_logging(None, args.verbose)
    mod = _lazy("laglens.report.build")
    if mod is None or not hasattr(mod, "rebuild"):
        return _not_implemented("report")
    sdir = _session_arg(args.report)
    try:
        path = mod.rebuild(sdir, load_app_config(args, create=False))
    except FileNotFoundError as exc:
        print("report: %s" % exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        log.exception("report rebuild failed")
        print("report: failed: %s" % exc)
        return 1
    print(str(path or (sdir / "report.html")))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    setup_logging(None, args.verbose)
    mod = _lazy("laglens.report.export")
    if mod is None or not hasattr(mod, "export_cli"):
        return _not_implemented("export")
    return int(mod.export_cli(_session_arg(args.export), pack=args.pack, cfg=load_app_config(args, create=False)) or 0)


def cmd_index(args: argparse.Namespace) -> int:
    """``--index``: rewrite ``sessions/index.html``; prints its path."""
    setup_logging(None, args.verbose)
    mod = _lazy("laglens.report.sessions")
    if mod is None or not hasattr(mod, "rebuild_index"):
        return _not_implemented("index")
    root = ROOT / SESSIONS_DIRNAME
    rc = int(mod.rebuild_index(root) or 0)
    if rc == 0:
        print(str(root / "index.html"))
    else:
        print("index: cannot write %s" % (root / "index.html"))
    return rc


def cmd_loadtest(args: argparse.Namespace) -> int:
    setup_logging(None, args.verbose)
    mod = _lazy("laglens.loadtest")
    if mod is None or not hasattr(mod, "run_cli"):
        return _not_implemented("loadtest")
    return int(mod.run_cli(load_app_config(args)) or 0)


def cmd_docsis_dump(args: argparse.Namespace) -> int:
    setup_logging(None, args.verbose)
    mod = _lazy("laglens.collectors.docsis")
    if mod is None or not hasattr(mod, "dump_cli"):
        return _not_implemented("docsis-dump")
    return int(mod.dump_cli(load_app_config(args)) or 0)


def cmd_update(args: argparse.Namespace) -> int:
    setup_logging(None, args.verbose)
    mod = _lazy("laglens.updater")
    if mod is None or not hasattr(mod, "run_cli"):
        return _not_implemented("update")
    return int(mod.run_cli(check_only=bool(args.check), root=ROOT) or 0)


def cmd_stop(args: argparse.Namespace, sessions_root: Optional[Path] = None, wait_s: float = 10.0) -> int:
    """Send SIGTERM to the pid in ``sessions/laglens.pid`` and wait for it to exit."""
    root = sessions_root or (ROOT / SESSIONS_DIRNAME)
    pidfile = root / PID_FILE
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        print("no running instance (no %s)" % pidfile)
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print("stale pidfile (pid %d not running); removing it" % pid)
        _unlink(pidfile)
        return 1
    except OSError as exc:
        print("cannot signal pid %d: %s" % (pid, exc))
        return 1
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            print("stopped pid %d" % pid)
            return 0
        time.sleep(0.2)
    print("pid %d is still running after %.0f s" % (pid, wait_s))
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    """The monitor: :func:`run` once, and again with a fresh session after a rotation.

    A session that reaches ``cfg.rotate_hours`` stops with ``stop_reason``
    ``rotate`` (report finalised, index rebuilt) and the loop starts a new
    session directory in the same process — cheap, and every component
    goes through its normal shutdown/startup. The config is re-read between
    sessions so a choice made on ``/setup`` (Xbox IP) is picked up.
    """
    setup_logging(None, args.verbose)
    # How long a probe thread waits for the GIL while another thread computes (Python's default is
    # 5 ms per hand-off; measured median gateway RTT beside a CPU-bound thread: 131 ms at 5 ms, 1.4 ms at 1 ms).
    sys.setswitchinterval(GIL_SWITCH_S)
    other = running_instance(ROOT / SESSIONS_DIRNAME)
    if other is not None:
        where = (" (session %s, dashboard port %s)" % (other["session"], other["port"])) if other.get("session") else ""
        print("Lag Lens is already running from this folder: pid %d%s.\n"
              "Use that one, or stop it first with the Stop button on its dashboard or:  bash start.sh --stop"
              % (other["pid"], where), flush=True)
        return EXIT_ALREADY_RUNNING
    while True:
        cfg = load_app_config(args)
        rc = run(cfg, args, terminal_marks=True, update_check=bool(cfg.get("update_check", True)))
        if rc == 0 and LAST_RUN.get("stop_reason") == STOP_REASON_ROTATE:
            args.resume = None
            print("Session %s rotated after %s h; starting a new one." % (LAST_RUN.get("session_id"), cfg.get("rotate_hours")),
                  flush=True)
            continue
        return rc


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def _is_laglens_process(pid: int) -> bool:
    """Whether ``pid`` is alive and is a Lag Lens monitor (``run.py``), not a recycled pid."""
    if pid <= 0 or pid == os.getpid():
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # alive but not ours to signal: check its command line anyway
    except OSError:
        return False
    cmdline = ""
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            cmdline = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        try:
            out = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
            cmdline = out.stdout
        except (OSError, subprocess.SubprocessError):
            return True  # cannot tell: assume it is ours rather than run two monitors in one folder
    return "run.py" in cmdline


def running_instance(sessions_root: Path) -> Optional[Dict[str, Any]]:
    """The live monitor that owns ``sessions/laglens.pid`` (``{"pid", "session", "port"}``), or ``None``."""
    try:
        pid = int((sessions_root / PID_FILE).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if not _is_laglens_process(pid):
        return None
    info: Dict[str, Any] = {"pid": pid, "session": None, "port": None}
    try:
        last = (sessions_root / LAST_FILE).read_text(encoding="utf-8").strip()
        sdir = Path(last) if Path(last).is_absolute() else (sessions_root.parent / last)
        doc = json.loads((sdir / "session.json").read_text(encoding="utf-8"))
        info["session"], info["port"] = doc.get("id"), doc.get("port")
    except (OSError, ValueError):
        pass
    return info


def _unlink(p: Path) -> None:
    try:
        p.unlink()
    except OSError:
        pass


def _session_dir_for(args: argparse.Namespace, sessions_root: Path, cfg: dict, state_holder: dict) -> Tuple[Store, bool]:
    resume = getattr(args, "resume", None)
    if resume:
        rdir = Path(resume)
        if not rdir.is_absolute():
            rdir = (ROOT / rdir) if not rdir.exists() else rdir
        if rdir.is_dir():
            return Store(rdir, cfg, resume=True), True
        log.warning("--resume %s: directory not found; starting a new session", resume)
    return Store.create(sessions_root, cfg), False


def _host_block(ctx: AppContext) -> dict:
    plat = ctx.platform
    route = ctx.route
    iface = route.get("iface")
    link = plat.link_info(iface) if iface else {}
    vpn = plat.vpn_routes("1.1.1.1") if iface else {"via_tunnel": False}
    return {
        "os": plat.name,
        "hostname": plat.hostname(),
        "iface": iface,
        "wifi": bool(link.get("wireless")),
        "speed": link.get("speed"),
        "duplex": link.get("duplex"),
        "lan_ip": route.get("lan_ip"),
        "gateway": route.get("gateway"),
        "gw6": route.get("gateway6"),
        "v6": bool(route.get("gateway6")),
        "vpn_route": bool(vpn.get("via_tunnel")),
        "link_up_mbps": ctx.cfg.get("link", {}).get("up_mbps"),
    }


def truncate_v6_prefix(prefix: Any) -> Any:
    """``2601:abcd:1234:5678::/64`` → ``2601:abcd:1234::/64 (truncated)`` (SPEC §6.7 privacy rule)."""
    if not prefix or not isinstance(prefix, str) or "(truncated)" in prefix:
        return prefix
    addr = prefix.split("/")[0]
    groups = addr.split("::")[0].split(":")
    kept = ":".join(groups[:3])
    return "%s::/64 (truncated)" % kept if kept else prefix


def session_document(ctx: AppContext, stopped: Optional[float] = None) -> dict:
    """The ``session.json`` object (SPEC_FULL §6.7)."""
    st = ctx.state
    host = st.host or {}
    return {
        "id": st.session_id,
        "version": __version__,
        "os": host.get("os"),
        "host": host.get("hostname"),
        "iface": host.get("iface"),
        "wifi": host.get("wifi"),
        "gateway": host.get("gateway"),
        "lan": host.get("lan_ip"),
        "gw6": host.get("gw6"),
        "v6_prefix": truncate_v6_prefix(host.get("v6_prefix")),
        "started": st.t0,
        "stopped": stopped,
        "stop_reason": st.stop_reason if stopped else None,
        "resumed_count": st.resumed_count,
        "label": st.label,
        "targets_file": "targets.json",
        "port": ctx.port,
        "config": configmod.public(ctx.cfg),
        "summary": {
            "samples": st.sample_count,
            "events": len(st.events),
            "episodes": len(st.episodes),
            "marks": len(st.marks),
            "blips": st.blips,
            "verdict": st.verdict,
            "health": st.health,
            "headline": st.headline,
            "matrix": st.matrix,
            "collectors": st.collectors(),
            "disk": st.disk,
        },
    }


def write_session_json(ctx: AppContext, stopped: Optional[float] = None) -> None:
    try:
        ctx.store.write_json_atomic("session.json", session_document(ctx, stopped))
    except Exception:  # noqa: BLE001
        log.exception("cannot write session.json")


def _start_components(ctx: AppContext, components: List[Tuple[str, str, str, str]]) -> None:
    st = ctx.state
    for name, modname, attr, kind in components:
        if not ctx.wants(name):
            reason = {
                "docsis": "docsis.password not set" if not getattr(ctx.args, "no_docsis", False) else "disabled by --no-docsis",
                "igd": "disabled by --no-igd" if getattr(ctx.args, "no_igd", False) else "igd.enabled is false",
                "notify": "not configured",
                "plex": "off (start with --plex, or turn Plex mode on in Setup)",
            }.get(name, "disabled in config")
            st.set_collector(name, "disabled", reason=reason)
            continue
        try:
            mod = _lazy(modname)
        except ImportError as exc:
            log.exception("%s: import of %s failed", name, modname)
            st.set_collector(name, "disabled", reason="import failed: %s" % exc)
            continue
        if mod is None or not hasattr(mod, attr):
            log.info("%s: component not available yet (%s.%s); skipped", name, modname, attr)
            st.set_collector(name, "disabled", reason="not available yet")
            continue
        try:
            factory = getattr(mod, attr)
            if kind == "func":
                obj = factory(ctx)
            else:
                obj = factory(ctx)
                if hasattr(obj, "start"):
                    obj.start()
            ctx.components[name] = obj
            if st.collector(name) is None:
                st.set_collector(name, "ok")
            log.info("%s: started", name)
        except Exception as exc:  # noqa: BLE001 - one bad component must not stop the run
            log.exception("%s: failed to start", name)
            st.set_collector(name, "disabled", reason="failed to start: %s" % exc)


def _stop_components(ctx: AppContext, timeout: float = 2.0) -> None:
    for name in reversed(list(ctx.components)):
        obj = ctx.components[name]
        stop = getattr(obj, "stop", None)
        if stop is None:
            continue
        try:
            try:
                stop(timeout)
            except TypeError:
                stop()
        except Exception:  # noqa: BLE001
            log.exception("%s: error while stopping", name)


FORCE_EXIT_INTS = 3
FORCE_EXIT_MIN_S = 1.0


def _make_signal_handler(state: State, clock: Callable[[], float] = time.monotonic,
                         force_exit: Callable[[int], Any] = os._exit) -> Callable[[int, Any], None]:
    """Build the SIGINT/SIGTERM handler (separate so tests can drive it).

    The handler only sets ``stop_event``/``stop_reason`` (no publish: running
    subscriber callbacks inside a signal handler on the main thread can
    deadlock on a non-reentrant lock the interrupted code holds). Only
    SIGINTs count toward the forced exit, and the third one must arrive at
    least ``FORCE_EXIT_MIN_S`` after the first signal, so the SIGTERM that
    ``start.sh`` forwards on Ctrl-C and an impatient double Ctrl-C do not
    abort the 2-4 s clean shutdown.
    """
    seen = {"ints": 0, "first": None}

    def handler(signum: int, _frame: Any) -> None:
        now = clock()
        name = {signal.SIGINT: "sigint", signal.SIGTERM: "sigterm"}.get(signum, "signal")
        if seen["first"] is None:
            seen["first"] = now
        if not state.stop_event.is_set():
            sys.stderr.write("\nStopping Lag Lens (%s)…\n" % name)
            state.request_stop(name, publish=False)
        if signum != signal.SIGINT:
            return
        seen["ints"] += 1
        if seen["ints"] == 2:
            sys.stderr.write("Still stopping… press Ctrl-C once more to force an unclean exit.\n")
        elif seen["ints"] >= FORCE_EXIT_INTS and now - seen["first"] >= FORCE_EXIT_MIN_S:
            sys.stderr.write("Forced exit.\n")
            force_exit(130)

    return handler


def _install_signal_handlers(state: State) -> bool:
    handler = _make_signal_handler(state)

    try:
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        return True
    except ValueError:  # not in the main thread (tests)
        return False


def _lan_urls(ctx: AppContext) -> List[str]:
    urls: List[str] = []
    ip = ctx.route.get("lan_ip") or ctx.platform.lan_ip(ctx.route.get("gateway") or "10.0.0.1")
    if ip:
        urls.append("http://%s:%d" % (ip, ctx.port))
    host = ctx.platform.hostname()
    if host and _resolves_quickly(host + ".local"):
        urls.append("http://%s.local:%d" % (host, ctx.port))
    if not urls:
        urls.append("http://127.0.0.1:%d" % ctx.port)
    return urls


def _resolves_quickly(name: str, timeout: float = 1.0) -> bool:
    result = {"ok": False}

    def worker() -> None:
        try:
            socket.getaddrinfo(name, None)
            result["ok"] = True
        except (socket.gaierror, OSError, UnicodeError):
            result["ok"] = False

    t = threading.Thread(target=worker, name="resolve-local", daemon=True)
    t.start()
    t.join(timeout)
    return result["ok"]


def _desktop_session(plat: Any) -> bool:
    """Whether a browser window can appear: not over SSH, and on Linux only with a display."""
    try:
        env = plat.env
        if env("SSH_CONNECTION") or env("SSH_TTY"):
            return False
        if getattr(plat, "name", "") == "linux":
            return bool(env("DISPLAY") or env("WAYLAND_DISPLAY"))
    except Exception:  # noqa: BLE001
        return False
    return True


def _open_browser(url: str, plat: Any, popen: Callable[..., Any] = subprocess.Popen) -> bool:
    """``open`` (macOS) / ``xdg-open`` (Linux) detached from our stdio; ``webbrowser`` as the fallback."""
    name = getattr(plat, "name", "")
    cmd = plat.which("open") if name == "darwin" else (plat.which("xdg-open") if name == "linux" else None)
    try:
        if cmd:
            popen([cmd, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  start_new_session=True)
            return True
        return bool(webbrowser.open(url))
    except Exception as exc:  # noqa: BLE001
        log.info("cannot open a browser for %s: %s", url, exc)
        return False


def _mark_service(ctx: AppContext) -> Optional[Any]:
    """The session's ``MarkService`` (shared with the HTTP server through ``ctx.components['marks']``)."""
    svc = ctx.component("marks")
    if svc is not None:
        return svc
    try:
        mod = _lazy("laglens.engine.marks")
    except ImportError:
        log.exception("marks: import failed")
        return None
    if mod is None or not hasattr(mod, "MarkService"):
        return None
    try:
        svc = mod.MarkService(ctx)
    except Exception:  # noqa: BLE001
        log.exception("marks: cannot construct MarkService")
        return None
    ctx.components["marks"] = svc
    return svc


class TerminalMarks:
    """Enter in the terminal = "Lag happened" (SPEC_FULL §8.1); one reader thread per process.

    Started only when stdin is a TTY. The thread blocks in ``readline`` and
    cannot be interrupted, so it is a daemon that outlives a session: after
    a rotation :meth:`attach` points it at the new context, and a line read
    while the current context is stopping is ignored.
    """

    def __init__(self, ctx: Optional[AppContext] = None, stream: Any = None, out: Optional[Callable[[str], Any]] = None) -> None:
        self.ctx = ctx
        self.stream = stream if stream is not None else sys.stdin
        self.out = out or (lambda s: print(s, flush=True))
        self.thread: Optional[threading.Thread] = None
        self.marks = 0

    def attach(self, ctx: AppContext) -> None:
        self.ctx = ctx

    def start(self) -> None:
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._loop, name="terminal-marks", daemon=True)
            self.thread.start()

    def stop(self, timeout: float = 0.0) -> None:  # the reader is a daemon blocked in readline()
        return None

    def _loop(self) -> None:
        while True:
            try:
                line = self.stream.readline()
            except (OSError, ValueError):
                return
            if not line:
                return  # EOF: stdin closed or redirected
            ctx = self.ctx
            if ctx is None or ctx.state.stop_event.is_set():
                continue
            try:
                self.press(line.strip(), ctx)
            except Exception:  # noqa: BLE001 - never kill the reader
                log.exception("terminal mark failed")

    def press(self, note: str = "", ctx: Optional[AppContext] = None) -> Optional[Any]:
        """Record one mark (``source='terminal'``) and print the instant assessment."""
        ctx = ctx or self.ctx
        svc = _mark_service(ctx) if ctx is not None else None
        if svc is None:
            self.out("Lag happened: not recorded (the marks service is not available)")
            return None
        try:
            mark = svc.create(offset_s=0.0, note=note, source="terminal")
        except Exception as exc:  # noqa: BLE001
            log.exception("terminal mark failed")
            self.out("Lag happened: could not record the mark (%s)" % exc)
            return None
        self.marks += 1
        stamp = time.strftime("%H:%M:%S", time.localtime(mark.t_est))
        linked = " — linked to episode %s" % mark.episode if getattr(mark, "episode", None) else ""
        self.out("Marked %s at %s: %s%s" % (mark.id, stamp, mark.assessment or "recorded", linked))
        return mark


_TERMINAL: Dict[str, Optional[TerminalMarks]] = {"reader": None}


def _terminal_marks(ctx: AppContext, stream: Any = None) -> Optional[TerminalMarks]:
    """Start (once per process) the Enter-to-mark reader when stdin is a TTY; attach it to ``ctx``."""
    stream = stream if stream is not None else sys.stdin
    try:
        if stream is None or not stream.isatty():
            return None
    except (AttributeError, ValueError, OSError):
        return None
    reader = _TERMINAL["reader"]
    if reader is None:
        reader = TerminalMarks(ctx, stream=stream)
        _TERMINAL["reader"] = reader
    reader.attach(ctx)
    reader.start()
    return reader


def _rebuild_index(sessions_root: Path) -> bool:
    """``sessions/index.html`` after a session closes (SPEC §8.5: usable when the tool is not running)."""
    try:
        mod = _lazy("laglens.report.sessions")
    except ImportError:
        log.exception("sessions index: import failed")
        return False
    if mod is None or not hasattr(mod, "rebuild_index"):
        return False
    t = time.monotonic()
    try:
        rc = mod.rebuild_index(sessions_root)
    except Exception:  # noqa: BLE001
        log.exception("sessions index: rebuild failed")
        return False
    log.info("sessions index rebuilt in %d ms", int((time.monotonic() - t) * 1000))
    return int(rc or 0) == 0


def _ensure_comcast_evidence(ctx: AppContext) -> None:
    """Write ``comcast_evidence.txt`` when neither the verdict nor the report builder did."""
    try:
        if ctx.store.path("comcast_evidence.txt").exists():
            return
        mod = _lazy("laglens.engine.verdict")
        if mod is not None and hasattr(mod, "comcast_text"):
            mod.comcast_text(ctx, write=True)
    except Exception:  # noqa: BLE001
        log.exception("comcast_evidence.txt could not be written")


#: Longest line in the startup box (a chip reason or a URL beyond this is cut with an ellipsis).
BOX_MAX_WIDTH = 110


def doctor_lines(checks: List[dict], detail_width: int = 72) -> List[str]:
    """``OK/WARN/FAIL <check>: <detail>`` lines for the startup box (SKIPs are omitted)."""
    out: List[str] = []
    for c in checks or []:
        status = str(c.get("status") or "").upper()
        if status in ("", "SKIP"):
            continue
        detail = str(c.get("detail") or "").replace("\n", " ")
        if status in ("WARN", "FAIL") and c.get("fallback"):
            detail += " -> " + str(c["fallback"]).replace("\n", " ")
        if len(detail) > detail_width:
            detail = detail[: detail_width - 1] + "…"
        out.append("  %-4s %s: %s" % (status, c.get("check", "?"), detail))
    return out


def startup_box(ctx: AppContext) -> str:
    """The terminal startup box (SPEC_FULL §8.1, without the QR code: the dashboard shows it)."""
    st = ctx.state
    label = " — %s" % st.label if st.label else ""
    lines = [
        "Lag Lens %s" % __version__,
        "Session: %s%s%s" % (st.session_id, "  (resumed)" if st.resumed_count else "", label),
    ]
    if ctx.component("http") is not None:
        for i, u in enumerate(ctx.urls):
            lines.append("%s %s" % ("Dashboard:" if i == 0 else "          ", u))
        for i, u in enumerate(ctx.urls):
            lines.append("%s %s/phone" % ("Phone:    " if i == 0 else "          ", u))
    else:
        http = st.collector("http") or {}
        lines.append("Dashboard: not running (%s)" % (http.get("reason") or "server component missing"))
        for u in ctx.urls:
            lines.append("           would be %s" % u)
    host = st.host or {}
    if host.get("gateway"):
        lines.append("Gateway: %s via %s%s%s" % (host["gateway"], host.get("iface"), " (Wi-Fi)" if host.get("wifi") else "",
                                                  "  IPv6: %s" % host["gw6"] if host.get("gw6") else ""))
    else:
        lines.append("Gateway: none found: is the network up?")
    checks = list(st.doctor or [])
    if checks:
        counts = {s: sum(1 for c in checks if str(c.get("status")) == s) for s in ("ok", "warn", "fail", "skip")}
        lines.append("Doctor: %d ok, %d warn, %d fail%s" % (counts["ok"], counts["warn"], counts["fail"],
                                                           ", %d skipped" % counts["skip"] if counts["skip"] else ""))
        lines.extend(doctor_lines(checks))
    cols = st.collectors()
    active = [n for n in ctx.components if (cols.get(n) or {}).get("status") != "disabled"]
    if active:
        lines.append("Running: " + ", ".join(active))
    known = [x[0] for x in COMPONENTS] + ["local_network", "store"]
    for status, title in (("disabled", "Not running:"), ("degraded", "Degraded:")):
        chips = [(n, c) for n, c in sorted(cols.items()) if c.get("status") == status and n in known]
        if chips:
            lines.append(title)
            for name, c in chips:
                lines.append("  %s: %s" % (name, c.get("reason") or status))
    if ctx.terminal_marks is not None:
        lines.append("Press Enter here to mark \"Lag happened\" (key L / the big button on the phone page). Ctrl-C stops.")
    else:
        lines.append("Press Ctrl-C to stop (or POST /api/stop, or bash start.sh --stop).")
    lines = [ln if len(ln) <= BOX_MAX_WIDTH else ln[: BOX_MAX_WIDTH - 1] + "…" for ln in lines]
    width = max(len(ln) for ln in lines)
    out = ["┌" + "─" * (width + 2) + "┐"]
    for ln in lines:
        out.append("│ " + ln.ljust(width) + " │")
    out.append("└" + "─" * (width + 2) + "┘")
    return "\n".join(out)


def run(
    cfg: dict,
    args: argparse.Namespace,
    sessions_root: Optional[Path] = None,
    platform: Optional[Any] = None,
    resolver: Optional[Callable[[str, int], Optional[str]]] = None,
    stop_after: Optional[float] = None,
    install_signals: bool = True,
    components: Optional[List[Tuple[str, str, str, str]]] = None,
    quiet: bool = False,
    terminal_marks: bool = False,
    update_check: bool = False,
) -> int:
    """Monitor until ``stop_event`` (SIGINT/SIGTERM/``POST /api/stop``/rotation); returns 0.

    ``sessions_root``, ``platform``, ``resolver``, ``stop_after`` (seconds),
    ``install_signals`` and ``components`` are injectable for tests.
    ``terminal_marks`` starts the Enter-to-mark reader (only when stdin is a
    TTY) and ``update_check`` the 3 s version check; ``cmd_run`` turns both
    on, tests leave them off. :data:`LAST_RUN` carries the ``stop_reason``
    and session id out of this function.
    """
    from laglens.platform import get_platform

    sessions_root = Path(sessions_root) if sessions_root else ROOT / SESSIONS_DIRNAME
    plat = platform or get_platform()
    store, resumed = _session_dir_for(args, sessions_root, cfg, {})
    setup_logging(store.dir, args.verbose if hasattr(args, "verbose") else False,
                  secrets=[cfg.get("docsis", {}).get("password"), (cfg.get("plex") or {}).get("token")])
    log.info("Lag Lens %s starting; session %s%s", __version__, store.dir, " (resume)" if resumed else "")

    session_id = store.dir.name
    t0 = time.time()
    resumed_count = 0
    prev = store.read_file_json("session.json") if resumed else None
    if isinstance(prev, dict):
        try:
            t0 = float(prev.get("started") or t0)
        except (TypeError, ValueError):
            log.warning("session.json: bad 'started' %r; using a new t0", prev.get("started"))
        try:
            resumed_count = int(prev.get("resumed_count") or 0) + 1
        except (TypeError, ValueError):
            log.warning("session.json: bad 'resumed_count' %r; counting from 1", prev.get("resumed_count"))
            resumed_count = 1
    elif resumed:
        log.warning("session.json missing or unreadable; keeping the session dir, counting this as resume 1")
        resumed_count = 1
    state = State(t0=t0, session_id=session_id, cfg=cfg)
    state.resumed_count = resumed_count
    state.label = cfg.get("label")
    store.state = state
    store.check_caps()
    store.ensure_token()
    store.start()

    ctx = AppContext(cfg, args, state, store, plat, sessions_root=sessions_root)
    ctx.resolver = resolver  # None = use getaddrinfo; tests inject an offline resolver
    try:
        ctx.route = plat.default_route() or {}
    except Exception:  # noqa: BLE001
        ctx.route = {}
    state.host = _host_block(ctx)
    state.port = ctx.port

    build_targets(cfg, plat, state, store=store, resume_targets=store.read_targets() if resumed else None,
                  resolver=resolver, route=ctx.route)
    if resumed:
        from laglens.state import Event

        state.seed_ids(
            events=_max_seq(store.read_json("events"), "ev-"),
            episodes=_max_seq(store.read_json("episodes"), "ep-"),
            marks=_max_seq(store.read_json("marks"), "mk-"),
        )
        # SPEC §3.4 wants {"reason": "monitor restarted"}; it lives in `peak`
        # so the events.jsonl row and the in-memory/API event are identical.
        ev = Event(id=state.next_event_id(), t0=time.time(), t1=time.time(), type="monitor_gap", target=None,
                   severity=1, peak={"reason": "monitor restarted"}, note="monitor restarted", source="auto")
        state.add_event(ev)
        store.append_json("events", ev.to_dict())

    write_session_json(ctx)
    _write_last(sessions_root, store.dir)
    pidfile = sessions_root / PID_FILE
    try:
        pidfile.write_text("%d\n" % os.getpid(), encoding="utf-8")
    except OSError as exc:
        log.warning("cannot write pidfile: %s", exc)

    if install_signals:
        _install_signal_handlers(state)
    state.set_status(STATUS_STARTING, "Checking your setup…")

    # the fast doctor runs BEFORE the engine: its OK/WARN/FAIL lines go into the startup box and
    # state.doctor / doctor.json, and a denied Local Network permission is known from the start
    doctor = None
    try:
        doctor = _lazy("laglens.doctor")
    except ImportError:
        log.exception("doctor: import failed")
    if doctor is not None and hasattr(doctor, "fast"):
        try:
            doctor.fast(ctx)
        except Exception:  # noqa: BLE001
            log.exception("fast doctor failed")

    # the MarkService exists before the server starts so GET /mark, POST /api/mark and the terminal
    # share one instance (the server would otherwise build its own lazily)
    _mark_service(ctx)
    _start_components(ctx, components if components is not None else COMPONENTS)
    ctx.urls = _lan_urls(ctx)
    if terminal_marks:
        ctx.terminal_marks = _terminal_marks(ctx)
    if not quiet:
        print(startup_box(ctx), flush=True)
    if update_check and cfg.get("update_check", True):
        try:
            updater = _lazy("laglens.updater")
            if updater is not None and hasattr(updater, "check_async"):
                updater.check_async(ctx)
        except Exception:  # noqa: BLE001
            log.exception("update check could not start")
    if ctx.component("http") is not None and cfg.get("open_browser", True) and not getattr(args, "no_browser", False):
        if _desktop_session(plat):
            _open_browser(ctx.urls[0], plat)
        else:
            log.info("no desktop session (SSH / no display): not opening a browser; dashboard at %s", ctx.urls[0])

    # ------------------------------------------------------------ main loop
    started = time.monotonic()
    next_session = time.monotonic() + SESSION_JSON_INTERVAL_S
    try:
        rotate_s = float(cfg.get("rotate_hours") or 0) * 3600.0
    except (TypeError, ValueError):
        rotate_s = 0.0
    try:
        while not state.stop_event.is_set():
            state.stop_event.wait(0.5)
            now = time.monotonic()
            if stop_after is not None and now - started >= stop_after:
                state.request_stop("test")
                break
            if rotate_s > 0 and time.time() - state.t0 >= rotate_s:
                log.info("session is %.1f h old (rotate_hours %s): rotating", (time.time() - state.t0) / 3600.0,
                         cfg.get("rotate_hours"))
                state.request_stop(STOP_REASON_ROTATE)
                break
            if now >= next_session:
                write_session_json(ctx)
                next_session = now + SESSION_JSON_INTERVAL_S
    except KeyboardInterrupt:
        state.request_stop("sigint")

    rc = shutdown(ctx, pidfile)
    LAST_RUN.update({"stop_reason": state.stop_reason, "session_id": state.session_id, "session_dir": str(store.dir)})
    return rc


def shutdown(ctx: AppContext, pidfile: Optional[Path] = None, grace_s: float = STOP_GRACE_S) -> int:
    """The shutdown sequence (module docstring); always returns 0 (the process exit status).

    Order: ``stopping`` published once → engine stops (2 s) → other components
    stop (the remaining budget split between them) → ticker ``close_final()``
    → ``store.flush()`` so the queued rollups/events hit disk → final report
    (reads the plain files) → ``store.stop()`` (close, gzip) → ``session.json``
    → keepawake → pidfile.
    """
    state = ctx.state
    t_stop = time.time()
    deadline = time.monotonic() + grace_s
    log.info("shutting down (%s)", state.stop_reason)
    state.publish("stopping", {"reason": state.stop_reason})
    engine = ctx.components.pop("engine", None)
    if engine is not None and hasattr(engine, "stop"):
        try:
            engine.stop(min(2.0, max(0.2, deadline - time.monotonic())))
        except TypeError:
            engine.stop()
        except Exception:  # noqa: BLE001
            log.exception("engine: error while stopping")
    keepawake = ctx.components.pop("keepawake", None)
    remaining = max(0.0, deadline - time.monotonic())
    _stop_components(ctx, timeout=max(0.2, remaining / max(1, len(ctx.components))))
    ticker = ctx.components.get("ticker")
    if ticker is not None and hasattr(ticker, "close_final"):
        try:
            ticker.close_final()
        except Exception:  # noqa: BLE001
            log.exception("ticker: final close failed")
    try:
        ctx.store.flush()  # the report must see every row queued so far
    except Exception:  # noqa: BLE001
        log.exception("store: flush before the final report failed")
    report = ctx.components.get("report")
    if report is not None and hasattr(report, "build"):
        try:
            report.build(final=True)
        except Exception:  # noqa: BLE001
            log.exception("report: final build failed")
    _ensure_comcast_evidence(ctx)
    state.set_status(STATUS_STOPPED, "Stopped — open report")
    ctx.store.stop(timeout=max(1.0, deadline - time.monotonic()))
    write_session_json(ctx, stopped=t_stop)
    # the static index last: it reads the finalised session.json of this session
    _rebuild_index(ctx.sessions_root)
    if keepawake is not None and hasattr(keepawake, "stop"):
        try:
            keepawake.stop()
        except Exception:  # noqa: BLE001
            log.exception("keepawake: error while stopping")
    if pidfile is not None:
        try:
            owner = int(pidfile.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            owner = None
        if owner in (None, os.getpid()):
            _unlink(pidfile)  # never remove another monitor's pidfile
    log.info("stopped in %.1f s (%s)", time.time() - t_stop, state.stop_reason)
    return 0


def _write_last(sessions_root: Path, session_dir: Path) -> None:
    try:
        rel = session_dir.resolve().relative_to(ROOT.resolve())
        value = str(rel)
    except ValueError:
        value = str(session_dir.resolve())
    Store.write_last(sessions_root, value)


def _max_seq(rows: List[dict], prefix: str) -> int:
    best = 0
    for r in rows:
        rid = str(r.get("id", ""))
        if rid.startswith(prefix):
            try:
                best = max(best, int(rid[len(prefix):]))
            except ValueError:
                pass
    return best


__all__ = [
    "AppContext", "COMPONENTS", "ROOT", "run", "shutdown", "startup_box", "doctor_lines", "session_document",
    "write_session_json", "truncate_v6_prefix", "TerminalMarks", "load_app_config", "config_path", "cmd_run",
    "cmd_doctor", "cmd_selftest", "cmd_report", "cmd_export", "cmd_index", "cmd_loadtest", "cmd_docsis_dump",
    "cmd_update", "cmd_stop", "LAST_FILE", "LAST_RUN", "STOP_GRACE_S", "STOP_REASON_ROTATE",
]
