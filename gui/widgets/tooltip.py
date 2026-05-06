"""Hover tooltip widget for the FileGuard GUI."""

from typing import Any


class ToolTip:
    """Simple hover tooltip for any widget."""

    def __init__(self, widget: Any, text: str) -> None:
        self.widget = widget
        self.text = text
        self._tw: Any = None
        self._after_id: Any = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)

    def _schedule(self, event: Any = None) -> None:
        """Show tooltip after a short delay to avoid flicker."""
        self._hide()
        self._after_id = self.widget.after(400, self._show)

    def _show(self) -> None:
        import tkinter as tk

        if not self.widget.winfo_exists():
            return

        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() - 32
        self._tw = tk.Toplevel(self.widget)
        self._tw.wm_overrideredirect(True)
        self._tw.wm_geometry(f"+{x}+{y}")
        self._tw.attributes("-topmost", True)
        label = tk.Label(
            self._tw,
            text=self.text,
            background="#1e2a45",
            foreground="#e8e8e8",
            relief="solid",
            borderwidth=1,
            font=("Consolas", 12),
            padx=6,
            pady=3,
        )
        label.pack()

    def _hide(self, event: Any = None) -> None:
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None
        if self._tw:
            self._tw.destroy()
            self._tw = None
