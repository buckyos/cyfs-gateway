#!/usr/bin/env python3
"""Repository-local wrapper for the performance-test CLI."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyfs_gateway_performance.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
