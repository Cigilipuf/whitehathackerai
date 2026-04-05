"""
WhiteHatHacker AI — Program Browser Widget

Left-side panel that shows HackerOne and Bugcrowd programs.
Features:
  - Platform selector (H1 / BC / All)
  - Search bar with live filtering
  - Program list with bounty / scope info
  - Favourite toggle
  - Program detail expansion
  - Background refresh with worker thread
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from loguru import logger
from PySide6.QtCore import Qt, Signal, QTimer, QThread, QObject, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QComboBox,
    QLabel,
    QPushButton,
    QGroupBox,
    QScrollArea,
    QFrame,
    QProgressBar,
    QCheckBox,
    QTextEdit,
)


# ────────────────────────────────────────────────────────────
# Background Worker
# ────────────────────────────────────────────────────────────


class ProgramFetchWorker(QObject):
    """Runs program fetching in a background thread."""

    finished = Signal(list)       # list of program dicts
    error = Signal(str)           # error message
    progress = Signal(str)        # status text

    def __init__(self, platform_filter: str = "all", force: bool = False):
        super().__init__()
        self._platform = platform_filter
        self._force = force

    @Slot()
    def run(self) -> None:
        try:
            self.progress.emit("Loading program cache...")

            from src.platforms.program_manager import ProgramManager

            manager = ProgramManager()

            # Run async refresh
            loop = asyncio.new_event_loop()
            try:
                self.progress.emit("Fetching programs from APIs...")
                platforms = None
                if self._platform == "hackerone":
                    platforms = ["hackerone"]
                elif self._platform == "bugcrowd":
                    platforms = ["bugcrowd"]

                loop.run_until_complete(
                    manager.refresh(force=self._force, platforms=platforms)
                )
            finally:
                loop.close()

            # Convert to dicts
            programs = manager.get_all(
                platform=self._platform if self._platform != "all" else None
            )
            data = [p.model_dump() for p in programs]
            self.finished.emit(data)

        except Exception as e:
            self.error.emit(str(e))


# ────────────────────────────────────────────────────────────
# Program Card
# ────────────────────────────────────────────────────────────


class ProgramCard(QFrame):
    """Compact card for a single program in the list."""

    clicked = Signal(dict)

    def __init__(self, data: dict, parent: QWidget | None = None):
        super().__init__(parent)
        self._data = data
        self.setObjectName("ProgramCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFixedHeight(80)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(2)

        # Row 1: Name + favourite star
        row1 = QHBoxLayout()
        name_lbl = QLabel(data.get("name", "Unknown"))
        name_lbl.setFont(QFont("", 10, QFont.Weight.Bold))
        name_lbl.setStyleSheet("color: #00d4ff;")
        row1.addWidget(name_lbl, 1)

        fav = "★" if data.get("favourite") else "☆"
        fav_lbl = QLabel(fav)
        fav_lbl.setStyleSheet("color: #ffd700; font-size: 14px;")
        row1.addWidget(fav_lbl)
        layout.addLayout(row1)

        # Row 2: Platform badge + bounty range
        row2 = QHBoxLayout()
        platform = data.get("platform", "")
        badge_color = "#6e40c9" if platform == "hackerone" else "#f26522"
        badge_text = "H1" if platform == "hackerone" else "BC"
        badge = QLabel(f" {badge_text} ")
        badge.setStyleSheet(
            f"background: {badge_color}; color: white; "
            f"border-radius: 3px; padding: 1px 6px; font-size: 9px; font-weight: bold;"
        )
        badge.setFixedWidth(28)
        row2.addWidget(badge)

        bounty_min = data.get("min_bounty", 0)
        bounty_max = data.get("max_bounty", 0)
        if bounty_max > 0:
            bounty_txt = f"${bounty_min:,} - ${bounty_max:,}"
        elif data.get("offers_bounties"):
            bounty_txt = "💰 Bounty"
        else:
            bounty_txt = "VDP"
        bounty_lbl = QLabel(bounty_txt)
        bounty_lbl.setStyleSheet("color: #66ff66; font-size: 10px;")
        row2.addWidget(bounty_lbl)
        row2.addStretch()

        scope_count = data.get("scope_count", len(data.get("scopes", [])))
        scope_lbl = QLabel(f"📎 {scope_count} assets")
        scope_lbl.setStyleSheet("color: #888; font-size: 9px;")
        row2.addWidget(scope_lbl)
        layout.addLayout(row2)

        # Row 3: Handle
        handle_lbl = QLabel(data.get("handle", ""))
        handle_lbl.setStyleSheet("color: #666; font-size: 9px;")
        layout.addWidget(handle_lbl)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._data)
        super().mousePressEvent(event)


# ────────────────────────────────────────────────────────────
# Main Widget
# ────────────────────────────────────────────────────────────


class ProgramBrowserWidget(QWidget):
    """Left-side panel for browsing bug bounty programs."""

    program_selected = Signal(dict)  # emitted when user clicks a program

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._programs: list[dict] = []
        self._filtered: list[dict] = []
        self._worker_thread: QThread | None = None

        self._build_ui()
        # Auto-load from cache on start
        QTimer.singleShot(500, lambda: self.refresh_programs(force=False))

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # ── Title ─────────────────────────────────────
        title = QLabel("🎯 Bug Bounty Programs")
        title.setFont(QFont("", 12, QFont.Weight.Bold))
        title.setStyleSheet("padding: 8px;")
        layout.addWidget(title)

        # ── Controls row ──────────────────────────────
        ctrl_box = QHBoxLayout()
        ctrl_box.setContentsMargins(4, 0, 4, 0)

        self._platform_combo = QComboBox()
        self._platform_combo.addItems(["All Platforms", "HackerOne", "Bugcrowd"])
        self._platform_combo.currentIndexChanged.connect(self._apply_filter)
        ctrl_box.addWidget(self._platform_combo)

        self._refresh_btn = QPushButton("⟳")
        self._refresh_btn.setToolTip("Refresh from API (force)")
        self._refresh_btn.setFixedWidth(32)
        self._refresh_btn.clicked.connect(lambda: self.refresh_programs(force=True))
        ctrl_box.addWidget(self._refresh_btn)

        layout.addLayout(ctrl_box)

        # ── Search ────────────────────────────────────
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("🔎 Search programs...")
        self._search_input.textChanged.connect(self._apply_filter)
        self._search_input.setContentsMargins(4, 0, 4, 0)
        layout.addWidget(self._search_input)

        # ── Filter toggles ────────────────────────────
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(4, 0, 4, 0)

        self._bounty_only = QCheckBox("Bounty only")
        self._bounty_only.stateChanged.connect(self._apply_filter)
        filter_row.addWidget(self._bounty_only)

        self._favs_only = QCheckBox("★ Favourites")
        self._favs_only.stateChanged.connect(self._apply_filter)
        filter_row.addWidget(self._favs_only)

        filter_row.addStretch()
        layout.addLayout(filter_row)

        # ── Progress bar ──────────────────────────────
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.hide()
        layout.addWidget(self._progress)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color: #888; font-size: 9px; padding: 0 4px;")
        layout.addWidget(self._status_lbl)

        # ── Scrollable program list ───────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._list_container = QWidget()
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setContentsMargins(4, 0, 4, 4)
        self._list_layout.setSpacing(4)
        self._list_layout.addStretch()

        scroll.setWidget(self._list_container)
        layout.addWidget(scroll, 1)

        # ── Detail panel (collapsed by default) ───────
        self._detail_panel = QGroupBox("Program Details")
        self._detail_panel.setMaximumHeight(160)
        detail_layout = QVBoxLayout(self._detail_panel)
        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setMaximumHeight(120)
        detail_layout.addWidget(self._detail_text)
        self._detail_panel.hide()
        layout.addWidget(self._detail_panel)

    # ─────────────────────────────────────────────────────
    # Refresh (background thread)
    # ─────────────────────────────────────────────────────

    def refresh_programs(self, force: bool = False) -> None:
        """Start fetching programs in a background thread."""
        if self._worker_thread and self._worker_thread.isRunning():
            return  # already fetching

        platform_map = {0: "all", 1: "hackerone", 2: "bugcrowd"}
        pf = platform_map.get(self._platform_combo.currentIndex(), "all")

        self._progress.show()
        self._status_lbl.setText("Fetching programs...")
        self._refresh_btn.setEnabled(False)

        self._worker_thread = QThread()
        self._worker = ProgramFetchWorker(platform_filter=pf, force=force)
        self._worker.moveToThread(self._worker_thread)

        self._worker_thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_fetch_done)
        self._worker.error.connect(self._on_fetch_error)
        self._worker.progress.connect(self._on_fetch_progress)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.error.connect(self._worker_thread.quit)

        self._worker_thread.start()

    def _on_fetch_done(self, programs: list[dict]) -> None:
        self._programs = programs
        self._progress.hide()
        self._refresh_btn.setEnabled(True)
        self._status_lbl.setText(f"{len(programs)} programs loaded")
        self._apply_filter()

    def _on_fetch_error(self, error: str) -> None:
        self._progress.hide()
        self._refresh_btn.setEnabled(True)
        self._status_lbl.setText(f"Error: {error[:80]}")

        # Try loading from cache
        self._load_from_cache()

    def _on_fetch_progress(self, msg: str) -> None:
        self._status_lbl.setText(msg)

    def _load_from_cache(self) -> None:
        """Fall back to cached JSON files."""
        cache_dir = Path("output/programs")
        if not cache_dir.exists():
            return

        all_programs: list[dict] = []
        for json_file in cache_dir.glob("*_programs.json"):
            try:
                data = json.loads(json_file.read_text())
                if isinstance(data, list):
                    all_programs.extend(data)
                elif isinstance(data, dict):
                    all_programs.extend(data.values())
            except Exception as _exc:
                logger.debug(f"program browser error: {_exc}")

        if all_programs:
            self._programs = all_programs
            self._status_lbl.setText(f"{len(all_programs)} programs (cached)")
            self._apply_filter()

    # ─────────────────────────────────────────────────────
    # Filtering
    # ─────────────────────────────────────────────────────

    def _apply_filter(self) -> None:
        search = self._search_input.text().lower().strip()
        platform_idx = self._platform_combo.currentIndex()
        bounty_only = self._bounty_only.isChecked()
        favs_only = self._favs_only.isChecked()

        platform_map = {0: None, 1: "hackerone", 2: "bugcrowd"}
        pf = platform_map.get(platform_idx)

        filtered = []
        for p in self._programs:
            # Platform filter
            if pf and p.get("platform") != pf:
                continue
            # Bounty filter
            if bounty_only and not p.get("offers_bounties"):
                continue
            # Favourites filter
            if favs_only and not p.get("favourite"):
                continue
            # Search
            if search:
                haystack = (
                    f"{p.get('name', '')} {p.get('handle', '')} "
                    f"{p.get('description', '')} {' '.join(p.get('tags', []))}"
                ).lower()
                if search not in haystack:
                    continue
            filtered.append(p)

        # Sort: favourites first, then by max_bounty desc, then by name
        filtered.sort(
            key=lambda x: (
                not x.get("favourite", False),
                -(x.get("max_bounty") or 0),
                (x.get("name") or "").lower(),
            )
        )
        self._filtered = filtered
        self._rebuild_list()

    def _rebuild_list(self) -> None:
        """Rebuild the visual list of program cards."""
        # Clear existing
        while self._list_layout.count() > 0:
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for prog in self._filtered[:200]:  # limit to 200 for performance
            card = ProgramCard(prog)
            card.clicked.connect(self._on_card_clicked)
            self._list_layout.addWidget(card)

        self._list_layout.addStretch()

    def _on_card_clicked(self, data: dict) -> None:
        """User clicked a program card."""
        # Show detail
        self._detail_panel.show()
        scopes = data.get("scopes", [])
        scope_lines = []
        for s in scopes[:20]:
            marker = "✅" if s.get("eligible_for_bounty") else "⬜"
            scope_lines.append(
                f"  {marker} {s.get('asset_type', '?')}: {s.get('identifier', '?')}"
            )

        detail = (
            f"<b>{data.get('name', '?')}</b><br>"
            f"Platform: {data.get('platform', '?')}<br>"
            f"Handle: {data.get('handle', '?')}<br>"
            f"URL: <a href='{data.get('url', '#')}'>{data.get('url', '-')}</a><br>"
            f"Bounty: ${data.get('min_bounty', 0):,} - ${data.get('max_bounty', 0):,}<br>"
            f"Scope ({len(scopes)} assets):<br>"
            + "<br>".join(scope_lines[:10])
        )
        self._detail_text.setHtml(detail)

        # Emit for scan tab
        self.program_selected.emit(data)
