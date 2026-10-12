"""Logging setup: rotating ``log.txt`` in the session directory plus stderr."""
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Union

LOG_FILE = "log.txt"
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 3
_FMT = "%(asctime)s %(levelname)-5s %(threadName)s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


class _SecretFilter(logging.Filter):
    """Drop obvious secrets from log lines (defensive; callers must redact)."""

    def __init__(self, secrets: Optional[list] = None) -> None:
        super().__init__()
        self.secrets = [s for s in (secrets or []) if s]

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if self.secrets:
            msg = record.getMessage()
            for s in self.secrets:
                if s in msg:
                    record.msg = msg.replace(s, "***")
                    record.args = ()
                    msg = record.msg
        return True


def setup_logging(
    session_dir: Optional[Union[str, Path]] = None,
    verbose: bool = False,
    secrets: Optional[list] = None,
) -> logging.Logger:
    """Configure the ``laglens`` logger.

    * stderr handler at INFO (DEBUG when ``verbose``);
    * when ``session_dir`` is given, a ``RotatingFileHandler`` on
      ``<session_dir>/log.txt`` (5 MB × 3) at DEBUG when verbose else INFO.

    Safe to call more than once (handlers are replaced, not duplicated), so the
    app can call it early without a session and again once the session
    directory exists. Returns the ``laglens`` logger.
    """
    logger = logging.getLogger("laglens")
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        try:
            h.close()
        except Exception:  # pragma: no cover - best effort
            pass
    fmt = logging.Formatter(_FMT, _DATEFMT)
    flt = _SecretFilter(secrets)

    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(level)
    stream.setFormatter(fmt)
    stream.addFilter(flt)
    logger.addHandler(stream)

    if session_dir is not None:
        path = Path(session_dir) / LOG_FILE
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                str(path), maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
            )
            fh.setLevel(level)
            fh.setFormatter(fmt)
            fh.addFilter(flt)
            logger.addHandler(fh)
        except OSError as exc:
            logger.warning("cannot open %s for logging: %s", path, exc)
    return logger


def get_logger(name: str = "") -> logging.Logger:
    """Return ``laglens`` or ``laglens.<name>``."""
    return logging.getLogger("laglens." + name if name else "laglens")
