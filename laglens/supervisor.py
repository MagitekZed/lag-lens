"""Thread supervision: restart with backoff, disable after repeated failures.

Every long-running thread body in Lag Lens runs under :func:`supervised`:

* exceptions are caught and logged, never propagated (no thread may crash the
  process);
* after a failure the body is restarted after an exponential backoff
  1 → 2 → 4 … → 60 s (the wait is interruptible by ``stop_event``);
* a body that fails 10 times within 10 minutes is **disabled** with a visible
  reason (``state.set_collector(name, 'disabled', reason=...)``) — except the
  engine (``engine=True``), which is always restarted;
* the status registry is kept up to date through ``state.set_collector``:
  ``ok`` while running, ``degraded`` with the last error while backing off.

A body is any callable taking no arguments. Use ``functools.partial`` or a
closure to bind its context. It should loop until ``stop_event`` is set and
return. Returning normally ends supervision: if ``stop_event`` is set the
status stays ``ok``; if the body returned *early* (stop not requested) the
registry entry becomes ``degraded`` with reason ``thread exited early`` so a
dead thread is visible in ``/api/state`` and the dashboard chips.
"""
import logging
import threading
import time
from typing import Callable, List, Optional

log = logging.getLogger("laglens.supervisor")

BACKOFF_MIN_S = 1.0
BACKOFF_MAX_S = 60.0
MAX_FAILURES = 10
FAILURE_WINDOW_S = 600.0
#: A run that lasted at least this long resets the backoff to the minimum.
HEALTHY_RUN_S = 60.0


def supervised(
    name: str,
    fn: Callable[[], None],
    state: Optional[object],
    stop_event: threading.Event,
    engine: bool = False,
    max_failures: int = MAX_FAILURES,
    window_s: float = FAILURE_WINDOW_S,
    backoff_min: float = BACKOFF_MIN_S,
    backoff_max: float = BACKOFF_MAX_S,
    clock: Callable[[], float] = time.monotonic,
    sleep: Optional[Callable[[float], None]] = None,
) -> str:
    """Run ``fn`` under supervision until it returns or ``stop_event`` is set.

    Returns the final status string: ``'ok'`` (body returned or stop
    requested) or ``'disabled'``. A body that returns before ``stop_event``
    is set is marked ``degraded`` (``thread exited early``) in the registry
    but still yields ``'ok'``. ``state`` may be ``None`` (tests); otherwise
    it must offer ``set_collector(name, status, reason=None, **kv)``.

    ``clock`` and ``sleep`` are injectable for tests; the default ``sleep``
    waits on ``stop_event`` so a shutdown interrupts the backoff.
    """
    def set_status(status: str, reason: Optional[str] = None, **kv) -> None:
        if state is None:
            return
        try:
            state.set_collector(name, status, reason=reason, **kv)
        except Exception:  # pragma: no cover - registry must never kill us
            log.exception("set_collector failed for %s", name)

    def wait(seconds: float) -> None:
        if sleep is not None:
            sleep(seconds)
        else:
            stop_event.wait(seconds)

    failures: List[float] = []
    backoff = backoff_min
    set_status("ok")
    while not stop_event.is_set():
        started = clock()
        try:
            fn()
            if not stop_event.is_set():
                log.warning("%s: thread body returned before stop was requested; supervision ends", name)
                set_status("degraded", reason="thread exited early")
            return "ok"
        except Exception as exc:  # noqa: BLE001 - this is the whole point
            now = clock()
            failures.append(now)
            failures = [t for t in failures if now - t <= window_s]
            reason = "%s: %s" % (type(exc).__name__, exc)
            log.exception("%s crashed (%d failures in the last %ds)", name, len(failures), int(window_s))
            if not engine and len(failures) >= max_failures:
                msg = "disabled after %d failures in %d min: %s" % (len(failures), int(window_s // 60), reason)
                log.error("%s %s", name, msg)
                set_status("disabled", reason=msg, failures=len(failures))
                return "disabled"
            if now - started >= HEALTHY_RUN_S:
                backoff = backoff_min
            set_status("degraded", reason=reason, failures=len(failures), retry_in_s=backoff)
            if stop_event.is_set():
                break
            wait(backoff)
            backoff = min(backoff * 2, backoff_max)
            if not stop_event.is_set():
                set_status("ok", restarted=len(failures))
    return "ok"


def start_thread(
    name: str,
    fn: Callable[[], None],
    state: Optional[object],
    stop_event: Optional[threading.Event] = None,
    engine: bool = False,
    daemon: bool = True,
    **kw,
) -> threading.Thread:
    """Start a daemon thread running ``fn`` under :func:`supervised`.

    ``stop_event`` defaults to ``state.stop_event``. Extra keyword arguments are
    passed to :func:`supervised`. The thread is named ``name`` so log lines
    carry it.
    """
    ev = stop_event if stop_event is not None else getattr(state, "stop_event")
    t = threading.Thread(
        target=supervised,
        args=(name, fn, state, ev),
        kwargs=dict(engine=engine, **kw),
        name=name,
        daemon=daemon,
    )
    t.start()
    return t


__all__ = ["supervised", "start_thread", "BACKOFF_MIN_S", "BACKOFF_MAX_S", "MAX_FAILURES", "FAILURE_WINDOW_S"]
