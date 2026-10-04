#!/usr/bin/env python3
"""V2Scan entrypoint: ``python main.py <command> ...`` (see ``python main.py --help``)."""

from v2scan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
