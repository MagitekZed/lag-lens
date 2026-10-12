"""Package version, read from the ``VERSION`` file shipped next to the package."""
import os
from typing import Optional

_FALLBACK = "0.0.0-dev"


def _read_version_file() -> Optional[str]:
    """Return the first non-empty line of ``<repo root>/VERSION`` or ``None``."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "VERSION")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    return line
    except OSError:
        return None
    return None


__version__ = _read_version_file() or _FALLBACK
