#!/usr/bin/env python3
"""MAL v4 launcher.   Usage: python MAL_v4.py <file|dir> [--intel] [--open]   (see --help)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mal.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
