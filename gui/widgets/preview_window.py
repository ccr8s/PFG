"""Safe in-process file preview window for FileGuard.

Displays a flagged file's bytes in three non-executing tabs:

    * Hex - first ~4 KB rendered as a hex+ASCII dump
    * Strings - extracted ASCII / UTF-16 LE printable runs
    * PE Headers - parsed PE summary (only shown when applicable)

The window never invokes any shell handler. We read the file's bytes
through ``utils.safety.safe_read`` and render them in read-only Tk text
widgets - no ``os.startfile``, no subprocess, no Explorer preview.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from utils.safe_preview import extract_strings, hex_dump, summarize_pe
from utils.safety import safe_read

logger = logging.getLogger(__name__)


class SafePreviewWindow:
    """Modal Toplevel that previews bytes from a flagged file."""

    _WINDOW_WIDTH = 760
    _WINDOW_HEIGHT = 560

    @staticmethod
    def show(parent: Any, file_path: Path) -> None:
        """Open the preview window for ``file_path``.

        Failures (missing file, read error) are surfaced as a single
        error tab rather than raising; the caller should not have to
        wrap this in try/except.
        """
        import tkinter as tk
        from tkinter import ttk

        path = Path(file_path)
        popup = SafePreviewWindow._create_window(parent, f"Safe Preview: {path.name}")

        header = tk.Label(
            popup,
            text=str(path),
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Consolas", 10),
            anchor="w",
            padx=12,
            pady=6,
        )
        header.pack(fill="x")

        warning = tk.Label(
            popup,
            text=(
                "  Read-only byte view. The file is not executed and no "
                "shell handler is invoked."
            ),
            bg="#1a1a2e",
            fg="#f39c12",
            font=("Segoe UI", 10, "italic"),
            anchor="w",
            padx=12,
        )
        warning.pack(fill="x", pady=(0, 4))

        style = ttk.Style(popup)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Preview.TNotebook", background="#1a1a2e", borderwidth=0
        )
        style.configure(
            "Preview.TNotebook.Tab",
            background="#16213e",
            foreground="#e8e8e8",
            padding=(14, 6),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Preview.TNotebook.Tab",
            background=[("selected", "#0f3460")],
            foreground=[("selected", "#00adb5")],
        )

        notebook = ttk.Notebook(popup, style="Preview.TNotebook")
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        try:
            data = safe_read(path)
        except FileNotFoundError:
            SafePreviewWindow._add_error_tab(
                notebook, f"File not found:\n{path}"
            )
            return
        except (PermissionError, OSError) as exc:
            SafePreviewWindow._add_error_tab(
                notebook, f"Could not read file:\n{path}\n\n{exc}"
            )
            return

        SafePreviewWindow._add_text_tab(
            notebook, "Hex", hex_dump(data), monospace=True
        )

        strings = extract_strings(data)
        if strings:
            strings_body = "\n".join(strings)
        else:
            strings_body = "(no printable strings found)"
        SafePreviewWindow._add_text_tab(
            notebook,
            f"Strings ({len(strings)})",
            strings_body,
            monospace=True,
        )

        pe_info = summarize_pe(path)
        if pe_info is not None:
            SafePreviewWindow._add_text_tab(
                notebook,
                "PE Headers",
                SafePreviewWindow._format_pe(pe_info),
                monospace=True,
            )

        size_kb = len(data) / 1024.0
        footer = tk.Label(
            popup,
            text=f"  {len(data):,} bytes ({size_kb:.1f} KB) read",
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 9),
            anchor="w",
            padx=12,
            pady=4,
        )
        footer.pack(fill="x")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _create_window(parent: Any, title: str) -> Any:
        import tkinter as tk

        popup = tk.Toplevel(parent)
        popup.title(title)
        popup.configure(bg="#1a1a2e")
        popup.resizable(True, True)
        popup.attributes("-topmost", True)

        pw = SafePreviewWindow._WINDOW_WIDTH
        ph = SafePreviewWindow._WINDOW_HEIGHT
        try:
            px = parent.winfo_rootx() + (parent.winfo_width() - pw) // 2
            py = parent.winfo_rooty() + (parent.winfo_height() - ph) // 2
            popup.geometry(f"{pw}x{ph}+{max(px, 0)}+{max(py, 0)}")
        except tk.TclError:
            popup.geometry(f"{pw}x{ph}")

        popup.focus_force()
        try:
            popup.grab_set()
        except tk.TclError:
            pass
        return popup

    @staticmethod
    def _add_text_tab(
        notebook: Any, label: str, body: str, *, monospace: bool = False
    ) -> None:
        import tkinter as tk

        frame = tk.Frame(notebook, bg="#1a1a2e")
        font = ("Consolas", 10) if monospace else ("Segoe UI", 11)
        text = tk.Text(
            frame,
            bg="#0f1020",
            fg="#e8e8e8",
            insertbackground="#e8e8e8",
            selectbackground="#2c3e50",
            relief="flat",
            padx=10,
            pady=10,
            wrap="none" if monospace else "word",
            font=font,
            cursor="arrow",
        )
        yscroll = tk.Scrollbar(frame, orient="vertical", command=text.yview)
        xscroll = tk.Scrollbar(frame, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        yscroll.pack(side="right", fill="y")
        xscroll.pack(side="bottom", fill="x")
        text.pack(fill="both", expand=True)

        text.insert("1.0", body)
        text.configure(state="disabled")
        notebook.add(frame, text=label)

    @staticmethod
    def _add_error_tab(notebook: Any, message: str) -> None:
        SafePreviewWindow._add_text_tab(
            notebook, "Error", message, monospace=False
        )

    @staticmethod
    def _format_pe(info: Dict[str, Any]) -> str:
        lines = []
        lines.append(f"Machine        : {info.get('machine')}")
        lines.append(f"Subsystem      : {info.get('subsystem')}")
        lines.append(f"Is DLL         : {info.get('is_dll')}")
        lines.append(f"Timestamp      : {info.get('timestamp')}")
        lines.append("")

        sections = info.get("sections") or []
        if sections:
            lines.append("Sections:")
            lines.append(
                f"  {'Name':<10} {'VSize':>10} {'RSize':>10} "
                f"{'Entropy':>8}  Char"
            )
            for s in sections:
                lines.append(
                    f"  {s['name']:<10} {s['vsize']:>10} {s['rsize']:>10} "
                    f"{s['entropy']:>8.2f}  {s['characteristics']}"
                )
            lines.append("")

        notable = info.get("notable_imports") or []
        if notable:
            lines.append("Notable imports (worth a closer look):")
            for fn in notable:
                lines.append(f"  - {fn}")
            lines.append("")

        imports = info.get("imports") or []
        if imports:
            lines.append("Imports:")
            for entry in imports:
                lines.append(f"  {entry['dll']}")
                for fn in entry.get("functions", []):
                    lines.append(f"    {fn}")
        return "\n".join(lines)


__all__ = ["SafePreviewWindow"]
