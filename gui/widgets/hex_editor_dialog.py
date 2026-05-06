"""Dialog shown when no hex editor is configured.

Lists each known editor, marks ones already installed, gives a clickable
download link for missing ones, and offers a "Browse for .exe..." path
that pins a custom editor via :func:`utils.hex_editor.save_user_editor_path`.
"""

from __future__ import annotations

import logging
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog
from typing import Any, Callable, List, Optional

from utils.hex_editor import (
    available_editors,
    save_user_editor_path,
)

logger = logging.getLogger(__name__)


class HexEditorPickerDialog(tk.Toplevel):
    """Modal that lets the user pick or install a hex editor."""

    def __init__(
        self,
        master: Any,
        on_chosen: Optional[Callable[[Path], None]] = None,
    ) -> None:
        super().__init__(master)
        self.title("Choose a hex editor")
        self.configure(bg="#1a1a2e")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._on_chosen = on_chosen
        self._editors: List[dict] = available_editors()

        self._build()
        self._center_on(master)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build(self) -> None:
        header = tk.Label(
            self,
            text="No hex editor is configured",
            bg="#1a1a2e",
            fg="#e8e8e8",
            font=("Segoe UI", 14, "bold"),
            anchor="w",
            padx=14,
            pady=(14, 4),
        )
        header.pack(fill="x")

        sub = tk.Label(
            self,
            text=(
                "Pick one that's already installed, install one of the "
                "free options below, or point FileGuard at any .exe you "
                "already use. Hex viewing is read-only by nature - the "
                "file stays unchanged on disk unless you click Save in "
                "the editor."
            ),
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=560,
            padx=14,
            pady=(0, 10),
        )
        sub.pack(fill="x")

        for entry in self._editors:
            self._build_editor_row(entry)

        sep = tk.Frame(self, bg="#2c3e50", height=1)
        sep.pack(fill="x", padx=14, pady=(8, 8))

        custom = tk.Frame(self, bg="#1a1a2e")
        custom.pack(fill="x", padx=14, pady=(0, 14))

        custom_lbl = tk.Label(
            custom,
            text="Already have a hex editor?",
            bg="#1a1a2e",
            fg="#e8e8e8",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        )
        custom_lbl.pack(side="left")

        btn_browse = tk.Button(
            custom,
            text="Browse for .exe...",
            command=self._on_browse,
            bg="#2c3e50",
            fg="#e8e8e8",
            activebackground="#34495e",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_browse.pack(side="right")

        footer = tk.Frame(self, bg="#1a1a2e")
        footer.pack(fill="x", padx=14, pady=(0, 14))
        tk.Button(
            footer,
            text="Cancel",
            command=self.destroy,
            bg="#34495e",
            fg="#ffffff",
            activebackground="#2c3e50",
            activeforeground="#ffffff",
            font=("Segoe UI", 10),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
        ).pack(side="right")

    def _build_editor_row(self, entry: dict) -> None:
        row = tk.Frame(self, bg="#1a1a2e")
        row.pack(fill="x", padx=14, pady=4)

        name_text = entry["name"]
        installed = entry["path"] is not None

        title = tk.Label(
            row,
            text=name_text + ("  [installed]" if installed else "  [not installed]"),
            bg="#1a1a2e",
            fg="#27ae60" if installed else "#9b9b9b",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        )
        title.pack(side="top", fill="x")

        blurb = tk.Label(
            row,
            text=entry["blurb"],
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=420,
        )
        blurb.pack(side="left", fill="x", expand=True, padx=(0, 8))

        if installed:
            tk.Button(
                row,
                text="Use this",
                command=lambda p=entry["path"]: self._use(Path(p)),
                bg="#27ae60",
                fg="#ffffff",
                activebackground="#1e8449",
                activeforeground="#ffffff",
                font=("Segoe UI", 10, "bold"),
                relief="flat",
                cursor="hand2",
                padx=10,
                pady=4,
            ).pack(side="right")
        else:
            tk.Button(
                row,
                text="Download",
                command=lambda url=entry["download_url"]: self._open_url(url),
                bg="#2980b9",
                fg="#ffffff",
                activebackground="#1f618d",
                activeforeground="#ffffff",
                font=("Segoe UI", 10, "bold"),
                relief="flat",
                cursor="hand2",
                padx=10,
                pady=4,
            ).pack(side="right")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _open_url(self, url: str) -> None:
        try:
            webbrowser.open(url)
        except Exception:
            logger.exception("Could not open URL: %s", url)

    def _on_browse(self) -> None:
        chosen = filedialog.askopenfilename(
            parent=self,
            title="Select hex editor executable",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
        )
        if not chosen:
            return
        path = Path(chosen)
        if not path.exists():
            return
        self._use(path)

    def _use(self, path: Path) -> None:
        try:
            save_user_editor_path(path)
        except Exception:
            logger.exception("Could not save user editor preference")
        if self._on_chosen is not None:
            try:
                self._on_chosen(path)
            except Exception:
                logger.exception("on_chosen callback failed")
        self.destroy()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _center_on(self, master: Any) -> None:
        try:
            self.update_idletasks()
            mx = master.winfo_rootx()
            my = master.winfo_rooty()
            mw = master.winfo_width() or 800
            mh = master.winfo_height() or 600
            w = self.winfo_width() or 600
            h = self.winfo_height() or 400
            x = mx + (mw - w) // 2
            y = my + (mh - h) // 2
            self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except tk.TclError:
            pass


__all__ = ["HexEditorPickerDialog"]
