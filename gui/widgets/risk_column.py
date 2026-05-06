"""Risk-category column widget for the FileGuard GUI."""

from typing import Any, List

import customtkinter as ctk

from core.models import ScanResult
from gui.styles import COLORS, FONTS, RISK_DISPLAY
from gui.widgets.tooltip import ToolTip


class RiskColumn(ctk.CTkFrame):
    """A single risk-category column with header count and file list."""

    def __init__(
        self,
        master: Any,
        risk_name: str,
        on_select: Any,
    ) -> None:
        display = RISK_DISPLAY.get(risk_name, {})
        self._color = display.get("color", COLORS["text_primary"])

        super().__init__(master, border_width=1, border_color=self._color)

        self.risk_name = risk_name
        self._on_select = on_select
        self._results: List[ScanResult] = []

        self.header = ctk.CTkLabel(
            self,
            text=(
                f"{display.get('icon', '')}  "
                f"{display.get('label', risk_name)}  (0)"
            ),
            font=FONTS["heading_sm"],
            text_color=self._color,
        )
        self.header.pack(fill="x", padx=6, pady=(6, 2))

        self.accent_line = ctk.CTkFrame(
            self, height=2, fg_color=self._color
        )
        self.accent_line.pack(fill="x", padx=6, pady=(0, 2))

        self.file_list = ctk.CTkScrollableFrame(
            self, fg_color="transparent"
        )
        self.file_list.pack(fill="both", expand=True, padx=4, pady=4)

    def add_file(self, result: ScanResult) -> None:
        """Add a file entry to this column."""
        self._results.append(result)

        name = result.file_path.name
        if len(name) > 24:
            name = name[:21] + "..."

        btn = ctk.CTkButton(
            self.file_list,
            text=f" {name}",
            font=FONTS["body_small"],
            anchor="w",
            height=28,
            fg_color="transparent",
            hover_color=COLORS["bg_tertiary"],
            text_color=COLORS["text_primary"],
            command=lambda r=result: self._on_select(r),
        )
        btn.pack(fill="x", pady=1)
        target = getattr(btn, "_canvas", btn)
        try:
            target.configure(cursor="hand2")
        except Exception:
            pass

        full_name = result.file_path.name
        ToolTip(btn, full_name)

        display = RISK_DISPLAY.get(self.risk_name, {})
        self.header.configure(
            text=(
                f"{display.get('icon', '')}  "
                f"{display.get('label', self.risk_name)}  "
                f"({len(self._results)})"
            )
        )

    def clear(self) -> None:
        """Clear all entries."""
        self._results.clear()
        for widget in self.file_list.winfo_children():
            widget.destroy()
        display = RISK_DISPLAY.get(self.risk_name, {})
        self.header.configure(
            text=(
                f"{display.get('icon', '')}  "
                f"{display.get('label', self.risk_name)}  (0)"
            )
        )
