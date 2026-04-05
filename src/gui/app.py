"""
WhiteHatHacker AI — GUI Application Entry Point

Launches the PySide6 desktop application.
Can be invoked with::

    python -m src.gui.app
    python scripts/launch_gui.py

Or from the CLI::

    whai gui
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont


class WhaiGuiApp:
    """Application bootstrap — creates QApplication & MainWindow."""

    def __init__(self, argv: list[str] | None = None) -> None:
        self._argv = argv or sys.argv
        self._app: QApplication | None = None

    def run(self) -> int:
        """Start the event loop. Returns exit code."""
        self._app = QApplication(self._argv)
        self._app.setApplicationName("WhiteHatHacker AI")
        self._app.setApplicationVersion("2.7.0")
        self._app.setOrganizationName("WhiteHatHackerAI")

        # NOTE: AA_UseHighDpiPixmaps is a no-op in Qt6 (always enabled)
        # Removed deprecated setAttribute call

        # Default font — cross-platform fallback chain
        # "Segoe UI" (Windows), "Noto Sans" / "DejaVu Sans" (Linux/Kali)
        font = QFont()
        font.setFamilies(["Noto Sans", "DejaVu Sans", "Segoe UI", "Helvetica Neue", "Arial"])
        font.setPointSize(10)
        font.setStyleHint(QFont.StyleHint.SansSerif)
        self._app.setFont(font)

        # Load stylesheet
        qss_path = Path(__file__).parent / "styles" / "dark_theme.qss"
        if qss_path.exists():
            self._app.setStyleSheet(qss_path.read_text())

        # Import here to avoid circular
        from src.gui.main_window import MainWindow

        window = MainWindow()
        window.show()

        return self._app.exec()


def main() -> None:
    app = WhaiGuiApp()
    sys.exit(app.run())


if __name__ == "__main__":
    main()
