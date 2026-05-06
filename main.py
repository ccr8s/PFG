#!/usr/bin/env python3
"""
FileGuard - Windows Security Scanner

Entry point for both CLI and GUI modes.

Usage:
    python main.py [--gui] [command] [options]
    python -m fileguard [--gui] [command] [options]
"""

import sys
from pathlib import Path

# Ensure the project root is in the Python path
_project_root = Path(__file__).resolve().parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))


def main() -> int:
    """Application entry point."""
    from cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
