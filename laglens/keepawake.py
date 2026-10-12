"""Sleep prevention (SPEC_FULL §4.6): spawn the OS inhibitor and keep it alive.

The command comes from ``platform.keepawake_cmd(pid)`` (``caffeinate -i -s -w
<pid>`` on macOS; ``kde-inhibit`` then ``systemd-inhibit`` on Linux). A
watchdog thread polls the child every 10 s and respawns it when it exits.
The registry entry ``keepawake`` carries ``method`` (the binary name) and a
visible reason when nothing could be spawned, when the machine runs on
battery (lid-closed sleep is not prevented) or in Bazzite Game Mode.
"""
from __future__ import annotations

import logging
import os
import subprocess
import time
from typing import Any, Callable, List, Optional

from laglens.supervisor import start_thread

log = logging.getLogger("laglens.keepawake")

WATCHDOG_S = 10.0
MAX_FAST_FAILURES = 5
LINUX_WARN = "cannot inhibit sleep; set KDE Power Management to never suspend for this run"
DARWIN_WARN = "caffeinate not found; macOS may sleep during the run"
BATTERY_WARN = "on battery: lid-closed sleep is not prevented"
GAME_MODE_WARN = "Bazzite Game Mode: no browser/inhibitor; use Desktop Mode or --install-service"


def _default_popen(argv: List[str]) -> Any:
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class KeepAwake:
    """``KeepAwake(ctx)``; ``start()`` spawns the inhibitor, ``stop()`` terminates it."""

    name = "keepawake"

    def __init__(self, ctx: Any, popen: Optional[Callable[[List[str]], Any]] = None,
                 pid: Optional[int] = None, mono: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.platform = ctx.platform
        self._popen = popen or _default_popen
        self._pid = pid if pid is not None else os.getpid()
        self._mono = mono
        self.cmd: Optional[List[str]] = None
        self.method: Optional[str] = None
        self.child: Any = None
        self.thread = None
        self.respawns = 0
        self._fast_failures = 0
        self._spawned_at: Optional[float] = None
        self.warnings: List[str] = []

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.cmd = self._select()
        self.warnings = self._warnings()
        if self.cmd is None:
            reason = DARWIN_WARN if self.platform.name == "darwin" else LINUX_WARN
            if self.warnings:
                reason = reason + "; " + "; ".join(self.warnings)
            self.state.set_collector(self.name, "disabled", reason=reason, method=None)
            log.warning("keepawake: %s", reason)
            return
        self.method = os.path.basename(self.cmd[0])
        if not self._spawn():
            return
        # The registry entry 'keepawake' is owned by this class (it carries method/respawns and
        # the battery / Game Mode warnings as a degraded reason); the supervisor would overwrite
        # it with a plain 'ok' when the watchdog thread starts, so it runs with state=None.
        self.thread = start_thread(self.name, self._loop, None, stop_event=self.state.stop_event)

    def stop(self, timeout: float = 2.0) -> None:
        self._terminate(timeout)
        t = self.thread
        if t is not None:
            t.join(timeout)

    def _select(self) -> Optional[List[str]]:
        try:
            cmd = self.platform.keepawake_cmd(self._pid)
        except Exception:  # noqa: BLE001
            log.exception("keepawake: keepawake_cmd failed")
            return None
        return list(cmd) if cmd else None

    def _warnings(self) -> List[str]:
        out: List[str] = []
        try:
            if self.platform.on_battery():
                out.append(BATTERY_WARN)
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.platform.is_game_mode():
                out.append(GAME_MODE_WARN)
        except Exception:  # noqa: BLE001
            pass
        return out

    # ---------------------------------------------------------------- child
    def _publish(self) -> None:
        if self.warnings:
            self.state.set_collector(self.name, "degraded", reason="; ".join(self.warnings), method=self.method,
                                     respawns=self.respawns)
        else:
            self.state.set_collector(self.name, "ok", method=self.method, respawns=self.respawns)

    def _spawn(self) -> bool:
        try:
            self.child = self._popen(list(self.cmd or []))
        except (OSError, ValueError) as exc:
            self.child = None
            reason = "%s failed to start: %s" % (self.method, exc)
            self.state.set_collector(self.name, "disabled", reason=reason, method=self.method)
            log.warning("keepawake: %s", reason)
            return False
        self._spawned_at = self._mono()
        log.info("keepawake: %s running (pid %s)", " ".join(self.cmd or []), getattr(self.child, "pid", "?"))
        self._publish()
        return True

    def check(self) -> bool:
        """Watchdog step: respawn the child if it exited. Returns True while healthy."""
        child = self.child
        if child is None:
            return False
        try:
            rc = child.poll()
        except Exception:  # noqa: BLE001
            rc = -1
        if rc is None:
            self._fast_failures = 0
            return True
        now = self._mono()
        if self._spawned_at is not None and now - self._spawned_at < WATCHDOG_S:
            self._fast_failures += 1
        else:
            self._fast_failures = 0
        if self._fast_failures >= MAX_FAST_FAILURES:
            reason = "%s keeps exiting (rc %s); sleep is not prevented" % (self.method, rc)
            self.state.set_collector(self.name, "disabled", reason=reason, method=self.method, respawns=self.respawns)
            log.warning("keepawake: %s", reason)
            self.child = None
            return False
        log.warning("keepawake: %s exited (rc %s); respawning", self.method, rc)
        self.respawns += 1
        return self._spawn()

    def _loop(self) -> None:
        st = self.state
        while not st.stop_event.wait(WATCHDOG_S):
            if not self.check():
                # Disabled for good: idle until stop so the supervisor keeps the entry as set.
                st.stop_event.wait()
                return

    def _terminate(self, timeout: float) -> None:
        child = self.child
        self.child = None
        if child is None:
            return
        try:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=max(0.2, timeout))
                except Exception:  # noqa: BLE001
                    try:
                        child.kill()
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            log.debug("keepawake: terminate failed", exc_info=True)


__all__ = ["KeepAwake", "WATCHDOG_S", "LINUX_WARN", "DARWIN_WARN", "BATTERY_WARN", "GAME_MODE_WARN"]
