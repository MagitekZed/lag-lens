"""Lag Lens: a single-host home network lag monitor (stdlib only)."""
import logging as _logging

from laglens.version import __version__  # noqa: F401

# Library convention: silent unless the app configures handlers (laglens.log.setup_logging).
_logging.getLogger("laglens").addHandler(_logging.NullHandler())
