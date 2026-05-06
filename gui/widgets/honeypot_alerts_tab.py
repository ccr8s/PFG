"""Honeypot Alerts tab - dedicated screen for live decoy access alerts.

The :class:`gui.widgets.honeypot_tab.HoneypotTab` owns the monitor
lifecycle (start / stop, deploy / remove). When an alert fires, the
:class:`HoneypotAlertsTab` displays it here in a separate tab so the
tutorial and controls don't compete for screen real-estate.

Flashing animation: when alerts arrive while this tab is *not* active,
the parent ``ttk.Notebook`` tab text alternates between
``"\u25cf Honeypot Alerts (N)"`` and ``"\u25cb Honeypot Alerts (N)"``
every ~700ms. Switching to the tab marks the alerts viewed and stops
the animation.
"""

from __future__ import annotations

import logging
import tkinter as tk
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

_BASE_LABEL = "Honeypot Alerts"
_FLASH_INTERVAL_MS = 700


class HoneypotAlertsTab(tk.Frame):
    """A read-only tab that streams honeypot alerts."""

    def __init__(self, master: Any) -> None:
        super().__init__(master, bg="#1a1a2e")

        self._notebook: Optional[Any] = None
        self._tab_index: Optional[int] = None
        self._total_alerts = 0
        self._unread = 0
        self._flash_state = False
        self._flash_after_id: Optional[str] = None

        self._build_header()
        self._build_alerts_panel()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def attach_to_notebook(self, notebook: Any, tab_index: int) -> None:
        """Tell the tab where it lives in the notebook so it can flash."""
        self._notebook = notebook
        self._tab_index = tab_index
        self._refresh_tab_text()

    def _build_header(self) -> None:
        bar = tk.Frame(self, bg="#1a1a2e")
        bar.pack(fill="x", padx=10, pady=(8, 4))

        self.lbl_status = tk.Label(
            bar,
            text="Monitoring stopped - 0 alerts",
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        )
        self.lbl_status.pack(side="left", fill="x", expand=True)

        self.btn_clear = tk.Button(
            bar,
            text="Clear log",
            command=self.clear,
            bg="#34495e",
            fg="#ffffff",
            activebackground="#2c3e50",
            activeforeground="#ffffff",
            font=("Segoe UI", 10),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=4,
        )
        self.btn_clear.pack(side="right")

        legend = tk.Label(
            self,
            text=(
                "Live feed of decoy access events. Flash + counter on "
                "the tab title means new alerts arrived while you "
                "were on another tab."
            ),
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 10, "italic"),
            anchor="w",
            justify="left",
            wraplength=900,
        )
        legend.pack(fill="x", padx=10, pady=(0, 4))

    def _build_alerts_panel(self) -> None:
        wrapper = tk.Frame(self, bg="#1a1a2e")
        wrapper.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self.alerts_text = tk.Text(
            wrapper,
            bg="#0f1020",
            fg="#e8e8e8",
            relief="flat",
            padx=10,
            pady=8,
            wrap="word",
            font=("Consolas", 10),
            cursor="arrow",
            state="disabled",
        )
        scroll = tk.Scrollbar(
            wrapper, orient="vertical", command=self.alerts_text.yview
        )
        self.alerts_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.alerts_text.pack(side="left", fill="both", expand=True)

        self.alerts_text.tag_configure(
            "alert_delete",
            foreground="#e74c3c",
            font=("Consolas", 10, "bold"),
        )
        self.alerts_text.tag_configure(
            "alert_modify",
            foreground="#f39c12",
            font=("Consolas", 10, "bold"),
        )
        self.alerts_text.tag_configure(
            "alert_other",
            foreground="#3498db",
            font=("Consolas", 10, "bold"),
        )
        self.alerts_text.tag_configure("muted", foreground="#9b9b9b")
        self.alerts_text.tag_configure("info", foreground="#27ae60")
        self._set_placeholder()

    def _set_placeholder(self) -> None:
        self.alerts_text.configure(state="normal")
        self.alerts_text.delete("1.0", "end")
        self.alerts_text.insert(
            "1.0",
            "No alerts yet. Deploy decoys and click 'Start "
            "monitoring' on the Honeypot tab. Decoy modifications, "
            "creations, deletes, and renames will appear here in "
            "real time.",
            "muted",
        )
        self.alerts_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Public API used by FileGuardApp / HoneypotTab
    # ------------------------------------------------------------------
    def add_alert(self, alert: Any) -> None:
        """Append an incoming HoneypotAlert to the alerts panel."""
        self._total_alerts += 1
        if self._total_alerts == 1:
            try:
                self.alerts_text.configure(state="normal")
                self.alerts_text.delete("1.0", "end")
                self.alerts_text.configure(state="disabled")
            except tk.TclError:
                return

        ts = (
            alert.timestamp.strftime("%H:%M:%S")
            if getattr(alert, "timestamp", None)
            else datetime.now().strftime("%H:%M:%S")
        )
        access = (getattr(alert, "access_type", "?") or "?").lower()
        decoy = getattr(alert, "decoy_path", "?")
        proc = getattr(alert, "process_name", None) or "unknown"
        pid = getattr(alert, "process_id", None) or "?"
        user = getattr(alert, "user", None) or "?"

        if access in {"delete", "rename"}:
            tag = "alert_delete"
        elif access in {"write", "modify", "create"}:
            tag = "alert_modify"
        else:
            tag = "alert_other"

        try:
            self.alerts_text.configure(state="normal")
            self.alerts_text.insert(
                "end",
                f"[{ts}] {access.upper()} on {decoy}\n",
                tag,
            )
            self.alerts_text.insert(
                "end",
                f"          process: {proc} (pid {pid}) - user: {user}\n",
                "muted",
            )
            self.alerts_text.see("end")
            self.alerts_text.configure(state="disabled")
        except tk.TclError:
            return

        if not self._is_active_tab():
            self._unread += 1
            self._start_flash()
        self._refresh_status_label(monitoring=True)
        self._refresh_tab_text()

    def set_monitoring_state(
        self, *, monitoring: bool, message: Optional[str] = None
    ) -> None:
        """Update the status banner + append a state change line."""
        self._refresh_status_label(monitoring=monitoring)
        if message:
            try:
                self.alerts_text.configure(state="normal")
                self.alerts_text.insert(
                    "end",
                    f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n",
                    "info" if monitoring else "muted",
                )
                self.alerts_text.see("end")
                self.alerts_text.configure(state="disabled")
            except tk.TclError:
                pass

    def show_error(self, message: str) -> None:
        """Display a hard error in the panel."""
        try:
            self.alerts_text.configure(state="normal")
            self.alerts_text.insert(
                "end",
                f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: "
                f"{message}\n",
                "alert_delete",
            )
            self.alerts_text.see("end")
            self.alerts_text.configure(state="disabled")
        except tk.TclError:
            pass
        try:
            self.lbl_status.configure(text="Monitoring error", fg="#e74c3c")
        except tk.TclError:
            pass

    def mark_viewed(self) -> None:
        """Reset unread count and stop flashing.

        Call this from the notebook's ``<<NotebookTabChanged>>`` event
        when this tab becomes active.
        """
        if self._unread == 0 and self._flash_after_id is None:
            return
        self._unread = 0
        self._stop_flash()
        self._refresh_tab_text()

    def clear(self) -> None:
        """Wipe the alerts log (does not touch the monitor)."""
        self._total_alerts = 0
        self._unread = 0
        self._stop_flash()
        self._set_placeholder()
        self._refresh_status_label()
        self._refresh_tab_text()

    @property
    def total_alerts(self) -> int:
        return self._total_alerts

    @property
    def unread_alerts(self) -> int:
        return self._unread

    # ------------------------------------------------------------------
    # Tab decoration / flashing
    # ------------------------------------------------------------------
    def _refresh_status_label(self, monitoring: Optional[bool] = None) -> None:
        if monitoring is None:
            txt = (
                f"{self._total_alerts} alert"
                f"{'s' if self._total_alerts != 1 else ''} captured"
            )
            color = "#9b9b9b"
        elif monitoring:
            txt = (
                f"Monitoring active - {self._total_alerts} alert"
                f"{'s' if self._total_alerts != 1 else ''}"
            )
            color = "#27ae60" if self._total_alerts == 0 else "#e74c3c"
        else:
            txt = (
                f"Monitoring stopped - {self._total_alerts} alert"
                f"{'s' if self._total_alerts != 1 else ''}"
            )
            color = "#9b9b9b"
        try:
            self.lbl_status.configure(text=txt, fg=color)
        except tk.TclError:
            pass

    def _is_active_tab(self) -> bool:
        if self._notebook is None or self._tab_index is None:
            return False
        try:
            current = self._notebook.index(self._notebook.select())
        except tk.TclError:
            return False
        return current == self._tab_index

    def _refresh_tab_text(self) -> None:
        if self._notebook is None or self._tab_index is None:
            return
        if self._unread > 0:
            dot = "\u25cf" if self._flash_state else "\u25cb"
            label = f"{dot} {_BASE_LABEL} ({self._unread})"
        elif self._total_alerts > 0:
            label = f"{_BASE_LABEL} ({self._total_alerts})"
        else:
            label = _BASE_LABEL
        try:
            self._notebook.tab(self._tab_index, text=label)
        except tk.TclError:
            pass

    def _start_flash(self) -> None:
        if self._flash_after_id is not None:
            return
        self._flash_state = True
        self._flash_tick()

    def _stop_flash(self) -> None:
        if self._flash_after_id is not None:
            try:
                self.after_cancel(self._flash_after_id)
            except tk.TclError:
                pass
            self._flash_after_id = None
        self._flash_state = False

    def _flash_tick(self) -> None:
        if self._unread == 0 or self._is_active_tab():
            self._stop_flash()
            self._refresh_tab_text()
            return
        self._flash_state = not self._flash_state
        self._refresh_tab_text()
        try:
            self._flash_after_id = self.after(
                _FLASH_INTERVAL_MS, self._flash_tick
            )
        except tk.TclError:
            self._flash_after_id = None
