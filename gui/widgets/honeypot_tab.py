"""Honeypot tab: beginner-friendly tutorial + decoy deploy / remove UI.

Unlike the read-only :class:`ToolTab`, this tab is interactive:

    * top half explains what a honeypot is in plain English,
    * middle row exposes Deploy / Remove / Choose buttons,
    * bottom half shows current deployment status.

The "Choose decoy files..." dialog lets the user toggle on/off any of
the built-in decoy templates (or add a custom name) before deploying,
so they aren't forced to scatter all eight defaults across their
Desktop, Documents, and Downloads.
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


_TUTORIAL = [
    ("What is a honeypot?", (
        "A honeypot is a fake file that nobody on this machine should "
        "ever open. It exists for one reason: to trip an alarm if "
        "something - malware, a curious roommate, a leaked credential "
        "harvester - goes looking for valuable data."
    )),
    ("How does it help me?", (
        "Real ransomware and infostealers don't read every file on "
        "your disk. They look for filenames that scream 'open me': "
        "passwords.xlsx, bitcoin_wallet.dat, tax_returns_2024.pdf. "
        "If something touches one of those, it's a strong signal "
        "that you've been compromised."
    )),
    ("Where will the decoys go?", (
        "By default, FileGuard creates decoy files in three places: "
        "your Desktop, Documents, and Downloads folders. The files "
        "look real but contain a hidden marker so FileGuard always "
        "knows which ones belong to it."
    )),
    ("Will they get in my way?", (
        "Probably not. They're small (a few hundred bytes each), "
        "named like things you wouldn't recognize as yours, and "
        "easy to remove with one click using the Remove All button "
        "below."
    )),
    ("How do I get alerted?", (
        "Click 'Deploy decoys' to drop them in, then click 'Start "
        "monitoring' to begin watching. Live alerts appear in the "
        "Alerts panel below and are also written to the database. "
        "Heads-up: Windows can only tell us about modify / create / "
        "delete / rename events - simply opening a file to read it "
        "is invisible at this layer (you'd need ETW or a kernel "
        "driver for that). Ransomware and infostealers almost "
        "always modify or delete, so this is still useful."
    )),
]


class HoneypotTab(tk.Frame):
    """Top-level frame for the Honeypot tab body."""

    def __init__(self, master: Any) -> None:
        super().__init__(master, bg="#1a1a2e")

        self._selected_decoys: Optional[List[Dict[str, Any]]] = None
        self._busy = False
        self._monitor: Any = None
        self._alert_count = 0

        self._build_tutorial()
        self._build_action_bar()
        self._build_status()
        self._build_alerts_panel()

        self.refresh_status()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_tutorial(self) -> None:
        wrapper = tk.Frame(self, bg="#1a1a2e")
        wrapper.pack(fill="both", expand=True, padx=10, pady=(8, 4))

        text = tk.Text(
            wrapper,
            bg="#0f1020",
            fg="#e8e8e8",
            insertbackground="#e8e8e8",
            selectbackground="#2c3e50",
            relief="flat",
            padx=14,
            pady=12,
            wrap="word",
            font=("Segoe UI", 11),
            cursor="arrow",
            height=14,
        )
        scroll = tk.Scrollbar(wrapper, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)

        text.tag_configure(
            "h1",
            foreground="#00adb5",
            font=("Segoe UI", 14, "bold"),
            spacing1=4,
            spacing3=4,
        )
        text.tag_configure(
            "section",
            foreground="#f39c12",
            font=("Segoe UI", 12, "bold"),
            spacing1=8,
            spacing3=2,
        )
        text.tag_configure(
            "body",
            foreground="#e8e8e8",
            lmargin1=6,
            lmargin2=6,
            spacing3=4,
        )

        text.insert("end", "Honeypot - the basics\n", "h1")
        for heading, body in _TUTORIAL:
            text.insert("end", heading + "\n", "section")
            text.insert("end", body + "\n", "body")
        text.configure(state="disabled")
        self._tutorial_text = text

    def _build_action_bar(self) -> None:
        bar = tk.Frame(self, bg="#1a1a2e")
        bar.pack(fill="x", padx=10, pady=(2, 6))

        self.btn_choose = tk.Button(
            bar,
            text="Choose decoy files...",
            command=self._on_choose_decoys,
            bg="#2c3e50",
            fg="#e8e8e8",
            activebackground="#34495e",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=6,
        )
        self.btn_choose.pack(side="left", padx=(0, 6))

        self.btn_deploy = tk.Button(
            bar,
            text="Deploy decoys",
            command=self._on_deploy,
            bg="#27ae60",
            fg="#ffffff",
            activebackground="#1e8449",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=6,
        )
        self.btn_deploy.pack(side="left", padx=(0, 6))

        self.btn_remove = tk.Button(
            bar,
            text="Remove all decoys",
            command=self._on_remove,
            bg="#a93226",
            fg="#ffffff",
            activebackground="#7b241c",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=6,
        )
        self.btn_remove.pack(side="left", padx=(0, 6))

        self.btn_monitor = tk.Button(
            bar,
            text="Start monitoring",
            command=self._on_toggle_monitor,
            bg="#2980b9",
            fg="#ffffff",
            activebackground="#1f618d",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=12,
            pady=6,
        )
        self.btn_monitor.pack(side="left", padx=(0, 6))

        self.lbl_selection = tk.Label(
            bar,
            text="(using all default decoys)",
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 10, "italic"),
        )
        self.lbl_selection.pack(side="left", padx=(8, 0))

    def _build_status(self) -> None:
        self.lbl_status = tk.Label(
            self,
            text="0 decoys deployed",
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
            padx=10,
            pady=4,
        )
        self.lbl_status.pack(fill="x")

        self.status_text = tk.Text(
            self,
            bg="#0f1020",
            fg="#e8e8e8",
            relief="flat",
            padx=10,
            pady=8,
            wrap="word",
            font=("Consolas", 10),
            cursor="arrow",
            height=6,
            state="disabled",
        )
        self.status_text.pack(fill="both", expand=False, padx=10, pady=(0, 4))

    def _build_alerts_panel(self) -> None:
        """Live alerts panel populated by the watchdog monitor."""
        self.lbl_alerts = tk.Label(
            self,
            text="Monitoring stopped - 0 alerts",
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
            padx=10,
            pady=4,
        )
        self.lbl_alerts.pack(fill="x")

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
            height=6,
            state="disabled",
        )
        scroll = tk.Scrollbar(
            wrapper, orient="vertical", command=self.alerts_text.yview
        )
        self.alerts_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.alerts_text.pack(side="left", fill="both", expand=True)

        self.alerts_text.tag_configure(
            "alert",
            foreground="#e74c3c",
            font=("Consolas", 10, "bold"),
        )
        self.alerts_text.tag_configure("muted", foreground="#9b9b9b")
        self._set_alerts_placeholder()

    def _set_alerts_placeholder(self) -> None:
        self.alerts_text.configure(state="normal")
        self.alerts_text.delete("1.0", "end")
        self.alerts_text.insert(
            "1.0",
            "No alerts yet. After deploying decoys, click 'Start "
            "monitoring' above. Alerts will appear here when a "
            "decoy is modified, created, deleted, or renamed.",
            "muted",
        )
        self.alerts_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _on_choose_decoys(self) -> None:
        from honeypot.decoy_manager import DEFAULT_DECOYS

        DecoyChooser(
            self.winfo_toplevel(),
            DEFAULT_DECOYS,
            initial=self._selected_decoys,
            on_done=self._set_selection,
        )

    def _set_selection(self, selection: Optional[List[Dict[str, Any]]]) -> None:
        self._selected_decoys = selection
        if selection is None or len(selection) == 0:
            self.lbl_selection.configure(text="(using all default decoys)")
            self._selected_decoys = None
        else:
            n = len(selection)
            self.lbl_selection.configure(
                text=f"({n} custom decoy{'s' if n != 1 else ''} selected)"
            )

    def _on_deploy(self) -> None:
        if self._busy:
            return
        self._set_busy(True, "Deploying decoys...")

        selection = self._selected_decoys

        def _work() -> None:
            try:
                from honeypot.decoy_manager import DecoyManager
                manager = DecoyManager()
                deployed = manager.deploy_decoys(decoys=selection)
                err: Optional[str] = None
            except Exception as exc:
                logger.exception("Honeypot deploy failed")
                deployed = []
                err = str(exc)
            self.after(0, self._after_deploy, deployed, err)

        threading.Thread(target=_work, daemon=True).start()

    def _after_deploy(
        self, deployed: List[Path], err: Optional[str]
    ) -> None:
        self._set_busy(False)
        if err is not None:
            self._set_status_text(f"Deploy failed: {err}")
            self.lbl_status.configure(
                text="Deploy failed", fg="#e74c3c"
            )
            return
        self.refresh_status(highlight_just_deployed=deployed)

    def _on_remove(self) -> None:
        if self._busy:
            return
        from tkinter import messagebox

        if not messagebox.askyesno(
            "Remove all decoys",
            "Remove every honeypot decoy currently deployed?\n\n"
            "This is safe and reversible - just hit 'Deploy decoys' "
            "again to recreate them.",
            icon="question",
            parent=self.winfo_toplevel(),
        ):
            return

        self._set_busy(True, "Removing decoys...")

        def _work() -> None:
            try:
                from honeypot.decoy_manager import DecoyManager
                manager = DecoyManager()
                count = manager.remove_all_decoys()
                err: Optional[str] = None
            except Exception as exc:
                logger.exception("Honeypot remove failed")
                count = 0
                err = str(exc)
            self.after(0, self._after_remove, count, err)

        threading.Thread(target=_work, daemon=True).start()

    def _after_remove(self, count: int, err: Optional[str]) -> None:
        self._set_busy(False)
        if err is not None:
            self._set_status_text(f"Remove failed: {err}")
            self.lbl_status.configure(text="Remove failed", fg="#e74c3c")
            return
        self.refresh_status()
        self._set_status_text(
            f"Removed {count} decoy file(s). The Deploy button puts "
            "them back whenever you want."
        )

    # ------------------------------------------------------------------
    # Monitoring lifecycle
    # ------------------------------------------------------------------
    def _on_toggle_monitor(self) -> None:
        """Start the watchdog monitor if stopped, stop it if running."""
        if self.is_monitoring():
            self.stop_monitoring()
            return

        # Start path. Need at least one deployed decoy to watch.
        try:
            from honeypot.decoy_manager import DecoyManager
            from honeypot.monitor import HoneypotMonitor
        except ImportError as exc:
            self._show_alert_error(f"Honeypot modules unavailable: {exc}")
            return

        manager = DecoyManager()
        if not manager.get_deployed_paths():
            from tkinter import messagebox
            messagebox.showinfo(
                "No decoys to monitor",
                "Deploy at least one decoy first - the monitor "
                "watches the directories the decoys live in.",
                parent=self.winfo_toplevel(),
            )
            return

        try:
            monitor = HoneypotMonitor(
                decoy_manager=manager,
                alert_callback=self._on_alert_from_thread,
            )
            monitor.start()
        except Exception as exc:
            logger.exception("Failed to start honeypot monitor")
            self._show_alert_error(f"Could not start monitor: {exc}")
            return

        if not monitor.is_running:
            self._show_alert_error(
                "Monitor failed to start. Check that the watchdog "
                "package is installed and that decoy directories "
                "still exist on disk."
            )
            try:
                monitor.stop()
            except Exception:
                pass
            return

        self._monitor = monitor
        self._alert_count = 0
        self.btn_monitor.configure(
            text="Stop monitoring",
            bg="#a93226",
            activebackground="#7b241c",
        )
        self.lbl_alerts.configure(
            text="Monitoring active - 0 alerts",
            fg="#27ae60",
        )
        self.alerts_text.configure(state="normal")
        self.alerts_text.delete("1.0", "end")
        self.alerts_text.insert(
            "1.0",
            f"[{datetime.now().strftime('%H:%M:%S')}] Monitor started. "
            f"Watching {len(manager.get_deployed_paths())} decoy "
            "file(s). Alerts will stream into this panel.\n",
            "muted",
        )
        self.alerts_text.configure(state="disabled")

    def stop_monitoring(self) -> None:
        """Stop the watchdog monitor; safe to call when not running.

        Public so :class:`gui.app.FileGuardApp` can call it from the
        ``WM_DELETE_WINDOW`` handler.
        """
        if self._monitor is None:
            return
        try:
            self._monitor.stop()
        except Exception:
            logger.exception("Honeypot monitor stop raised")
        self._monitor = None

        try:
            self.btn_monitor.configure(
                text="Start monitoring",
                bg="#2980b9",
                activebackground="#1f618d",
            )
            self.lbl_alerts.configure(
                text=(
                    f"Monitoring stopped - {self._alert_count} alert"
                    f"{'s' if self._alert_count != 1 else ''}"
                ),
                fg="#9b9b9b",
            )
            self.alerts_text.configure(state="normal")
            self.alerts_text.insert(
                "end",
                f"[{datetime.now().strftime('%H:%M:%S')}] Monitor "
                "stopped.\n",
                "muted",
            )
            self.alerts_text.see("end")
            self.alerts_text.configure(state="disabled")
        except tk.TclError:
            # Widget destroyed (app shutting down) - cleanup is fine.
            pass

    def is_monitoring(self) -> bool:
        """Return True if the watchdog monitor is active."""
        return bool(self._monitor and getattr(self._monitor, "is_running", False))

    def _on_alert_from_thread(self, alert: Any) -> None:
        """Watchdog callback - marshal onto Tk main thread."""
        try:
            self.after(0, self._render_alert, alert)
        except Exception:
            pass

    def _render_alert(self, alert: Any) -> None:
        """Append an incoming HoneypotAlert to the alerts panel."""
        self._alert_count += 1
        ts = alert.timestamp.strftime("%H:%M:%S") if getattr(
            alert, "timestamp", None
        ) else datetime.now().strftime("%H:%M:%S")
        access = getattr(alert, "access_type", "?")
        decoy = getattr(alert, "decoy_path", "?")
        proc = getattr(alert, "process_name", None) or "unknown"
        pid = getattr(alert, "process_id", None) or "?"
        user = getattr(alert, "user", None) or "?"

        self.alerts_text.configure(state="normal")
        self.alerts_text.insert(
            "end",
            f"[{ts}] {access.upper()} on {decoy}\n",
            "alert",
        )
        self.alerts_text.insert(
            "end",
            f"          process: {proc} (pid {pid}) - user: {user}\n",
            "muted",
        )
        self.alerts_text.see("end")
        self.alerts_text.configure(state="disabled")

        self.lbl_alerts.configure(
            text=(
                f"Monitoring active - {self._alert_count} alert"
                f"{'s' if self._alert_count != 1 else ''}"
            ),
            fg="#e74c3c",
        )

    def _show_alert_error(self, message: str) -> None:
        self.alerts_text.configure(state="normal")
        self.alerts_text.delete("1.0", "end")
        self.alerts_text.insert("1.0", message, "alert")
        self.alerts_text.configure(state="disabled")
        self.lbl_alerts.configure(text="Monitoring error", fg="#e74c3c")

    # ------------------------------------------------------------------
    # Status refresh
    # ------------------------------------------------------------------
    def refresh_status(
        self, highlight_just_deployed: Optional[List[Path]] = None
    ) -> None:
        try:
            from honeypot.decoy_manager import DecoyManager
            status = DecoyManager().get_status()
        except Exception as exc:
            self._set_status_text(f"Could not read status: {exc}")
            return

        active = status.get("active_count", 0)
        deployed = status.get("deployed_count", 0)
        deployed_at = status.get("deployed_at")

        if active == 0:
            self.lbl_status.configure(
                text="No decoys deployed", fg="#9b9b9b"
            )
        else:
            self.lbl_status.configure(
                text=(
                    f"{active} decoy{'s' if active != 1 else ''} "
                    f"deployed"
                    + (
                        f" ({deployed - active} missing)"
                        if deployed > active else ""
                    )
                ),
                fg="#27ae60",
            )

        decoys = status.get("decoys") or []
        if not decoys:
            self._set_status_text(
                "No decoys yet. Click 'Deploy decoys' above to drop "
                "them into your Desktop, Documents, and Downloads "
                "folders."
            )
            return

        lines: List[str] = []
        if deployed_at:
            lines.append(f"Last deployment: {deployed_at}")
            lines.append("")

        just_deployed_set = {
            str(Path(p).resolve())
            for p in (highlight_just_deployed or [])
        }
        for d in decoys:
            path_str = d.get("path", "?")
            exists = Path(path_str).exists()
            mark = "+" if str(Path(path_str).resolve()) in just_deployed_set else (
                "*" if exists else "x"
            )
            desc = d.get("description", "")
            lines.append(f"  {mark} {path_str}")
            if desc:
                lines.append(f"     {desc}")
        if highlight_just_deployed:
            lines.append("")
            lines.append(f"Just deployed: {len(highlight_just_deployed)}")
        self._set_status_text("\n".join(lines))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _set_busy(self, busy: bool, message: str = "") -> None:
        self._busy = busy
        for btn in (self.btn_choose, self.btn_deploy, self.btn_remove):
            btn.configure(state="disabled" if busy else "normal")
        if busy and message:
            self.lbl_status.configure(text=message, fg="#f39c12")

    def _set_status_text(self, body: str) -> None:
        self.status_text.configure(state="normal")
        self.status_text.delete("1.0", "end")
        self.status_text.insert("1.0", body)
        self.status_text.configure(state="disabled")


# ---------------------------------------------------------------------------
# Decoy chooser modal
# ---------------------------------------------------------------------------
class DecoyChooser:
    """Modal Toplevel for picking which decoys to deploy."""

    def __init__(
        self,
        parent: Any,
        defaults: List[Dict[str, Any]],
        initial: Optional[List[Dict[str, Any]]],
        on_done: Any,
    ) -> None:
        self._defaults = defaults
        self._on_done = on_done

        self.win = tk.Toplevel(parent)
        self.win.title("Choose decoy files")
        self.win.configure(bg="#1a1a2e")
        self.win.geometry("520x520")
        self.win.transient(parent)
        try:
            self.win.grab_set()
        except tk.TclError:
            pass

        intro = tk.Label(
            self.win,
            text=(
                "Pick which decoys to deploy. Tick the templates you "
                "want, then add any custom filenames at the bottom. "
                "Leaving everything unchecked re-uses the full default "
                "set."
            ),
            bg="#1a1a2e",
            fg="#e8e8e8",
            font=("Segoe UI", 10),
            wraplength=480,
            justify="left",
            anchor="w",
            padx=12,
            pady=10,
        )
        intro.pack(fill="x")

        list_frame = tk.Frame(self.win, bg="#1a1a2e")
        list_frame.pack(fill="both", expand=True, padx=12, pady=4)

        canvas = tk.Canvas(
            list_frame, bg="#0f1020", highlightthickness=0
        )
        canvas.pack(side="left", fill="both", expand=True)
        scroll = tk.Scrollbar(
            list_frame, orient="vertical", command=canvas.yview
        )
        scroll.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scroll.set)
        inner = tk.Frame(canvas, bg="#0f1020")
        canvas.create_window((0, 0), window=inner, anchor="nw")

        initial_names = {d["name"] for d in (initial or [])}
        self._vars: List[tuple[tk.BooleanVar, Dict[str, Any]]] = []
        for d in defaults:
            var = tk.BooleanVar(
                value=(d["name"] in initial_names) if initial else True
            )
            row = tk.Frame(inner, bg="#0f1020")
            row.pack(fill="x", padx=8, pady=2)
            cb = tk.Checkbutton(
                row,
                variable=var,
                text=f"{d['name']}  -  {d.get('desc', '')}",
                bg="#0f1020",
                fg="#e8e8e8",
                activebackground="#0f1020",
                activeforeground="#ffffff",
                selectcolor="#1a1a2e",
                font=("Segoe UI", 10),
                anchor="w",
            )
            cb.pack(fill="x")
            self._vars.append((var, d))

        inner.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

        custom = tk.Frame(self.win, bg="#1a1a2e")
        custom.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(
            custom,
            text="Custom filename (optional):",
            bg="#1a1a2e",
            fg="#e8e8e8",
            font=("Segoe UI", 10),
        ).pack(side="left")
        self.custom_entry = tk.Entry(
            custom,
            bg="#0f1020",
            fg="#e8e8e8",
            insertbackground="#e8e8e8",
            relief="flat",
            font=("Consolas", 10),
        )
        self.custom_entry.pack(side="left", fill="x", expand=True, padx=6)

        button_row = tk.Frame(self.win, bg="#1a1a2e")
        button_row.pack(fill="x", padx=12, pady=(4, 12))
        tk.Button(
            button_row,
            text="Cancel",
            command=self._cancel,
            bg="#2c3e50",
            fg="#e8e8e8",
            activebackground="#34495e",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=6,
        ).pack(side="right", padx=4)
        tk.Button(
            button_row,
            text="Use selection",
            command=self._save,
            bg="#27ae60",
            fg="#ffffff",
            activebackground="#1e8449",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=6,
        ).pack(side="right", padx=4)

    def _save(self) -> None:
        chosen: List[Dict[str, Any]] = [
            dict(d) for var, d in self._vars if var.get()
        ]
        custom_name = self.custom_entry.get().strip()
        if custom_name:
            chosen.append({
                "name": custom_name,
                "content_type": "text_stub",
                "desc": "Custom decoy",
            })
        self._on_done(chosen if chosen else None)
        self.win.destroy()

    def _cancel(self) -> None:
        self.win.destroy()


__all__ = ["HoneypotTab"]
