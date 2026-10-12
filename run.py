#!/usr/bin/env python3
"""Lag Lens entry point.

Inserts its own directory into ``sys.path`` (so the ``laglens`` package next
to it is importable even under ``python -I``) and hands over to
:func:`laglens.cli.main`.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from laglens.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
