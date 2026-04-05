#!/usr/bin/env python3
"""
WhiteHatHacker AI — GUI Launcher

Quick-start script for the desktop GUI.
Usage:
    python scripts/launch_gui.py
    # or via the .desktop shortcut
"""

import os
import sys
from pathlib import Path

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parent.parent
os.chdir(project_root)
sys.path.insert(0, str(project_root))

# Ensure output directories exist
for d in ("output/scans", "output/programs", "output/global_logs", "output/reports"):
    Path(d).mkdir(parents=True, exist_ok=True)

from src.gui.app import WhaiGuiApp


def main() -> None:
    app = WhaiGuiApp(sys.argv)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
