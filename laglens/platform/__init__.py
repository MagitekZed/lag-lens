"""Platform layer: ``get_platform()`` returns the object for the running OS.

Every method on the returned object never raises; see
:mod:`laglens.platform.base` for the full method list and return shapes.
"""
import sys
from typing import Any, Optional

from laglens.platform.base import Platform, is_private  # noqa: F401


def get_platform(name: Optional[str] = None, **kw: Any) -> Platform:
    """Return a :class:`LinuxPlatform`, :class:`DarwinPlatform` or generic :class:`Platform`.

    ``name`` overrides auto-detection (``'linux'`` / ``'darwin'``); keyword
    arguments (``runner``, ``reader``, ``exists``, ``env``, ``which``) are
    passed through for tests.
    """
    plat = name or sys.platform
    if plat.startswith("linux"):
        from laglens.platform.linux import LinuxPlatform

        return LinuxPlatform(**kw)
    if plat.startswith("darwin"):
        from laglens.platform.darwin import DarwinPlatform

        return DarwinPlatform(**kw)
    return Platform(**kw)


__all__ = ["get_platform", "Platform", "is_private"]
