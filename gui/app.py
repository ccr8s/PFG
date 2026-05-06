"""
FileGuard GUI application.

Main window built with CustomTkinter following the wireframe layout:
- Toolbar at top with scan controls and export menu
- 4-column risk category display with scrollable file lists
- File detail panel on the right
- Forensic tool buttons and information panel at the bottom
"""

import logging
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Dict, List, Optional

import customtkinter as ctk

from core.models import ScanResult, ScanSummary
from gui.styles import COLORS, DIMENSIONS, FONTS
from gui.widgets import DetailPanel, HoneypotTab, RiskColumn, ToolTab

logger = logging.getLogger(__name__)


class FileGuardApp(ctk.CTk):
    """Main FileGuard GUI application window."""

    def __init__(self) -> None:
        """Initialize the main application window."""
        super().__init__()

        # Window setup
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("FileGuard v1.0 - Security Scanner")
        self.geometry(
            f"{DIMENSIONS['window_min_width']}x{DIMENSIONS['window_min_height']}"
        )
        self.minsize(
            DIMENSIONS["window_min_width"],
            DIMENSIONS["window_min_height"],
        )

        # State
        self._scan_results: List[ScanResult] = []
        self._scan_running = False
        self._scan_cancelled = False
        self._stopping = False
        self._stop_anim_index = 0
        self._scan_thread: Optional[threading.Thread] = None
        self._cancel_event: Optional[threading.Event] = None
        self._selected_result: Optional[ScanResult] = None

        # Build UI
        self._build_toolbar()
        self._build_paned_layout()
        self._update_status("Ready")

        # Sweep stale sandbox staging dirs left over from prior runs
        # (e.g. previous crash or hard kill) before the user gets
        # confused by stuff hanging around in data/sandbox_staging/.
        try:
            from utils.sandbox_launcher import cleanup_staging
            stale = cleanup_staging(older_than_hours=24)
            if stale:
                logger.info(
                    "Cleaned %d stale sandbox staging dir(s) on startup",
                    stale,
                )
        except Exception:
            logger.exception("Startup sandbox staging sweep failed")

        # Catch the X button so we can terminate any active sandbox
        # and wipe its staging dir before exiting.
        self.protocol("WM_DELETE_WINDOW", self._on_close_window)

    # ── Toolbar ────────────────────────────────────────────────

    def _build_toolbar(self) -> None:
        """Build the top toolbar with scan controls."""
        self.toolbar = ctk.CTkFrame(self)
        self.toolbar.pack(fill="x", padx=4, pady=(4, 0))

        # Button font - use CTkFont for precise control
        btn_font = ctk.CTkFont(family="Segoe UI", size=17, weight="bold")

        # Scan button
        self.btn_scan = ctk.CTkButton(
            self.toolbar,
            text="\u25b6  Start Scan",
            font=btn_font,
            width=DIMENSIONS["button_width"],
            height=36,
            corner_radius=6,
            command=self._on_start_scan,
            fg_color=COLORS["accent_green"],
            hover_color="#27ae60",
        )
        self.btn_scan.pack(side="left", padx=6, pady=8)

        # Stop button
        self.btn_stop = ctk.CTkButton(
            self.toolbar,
            text="\u25a0  Stop",
            font=btn_font,
            width=100,
            height=36,
            corner_radius=6,
            command=self._on_stop_scan,
            fg_color="#555555",
            hover_color="#333333",
            text_color="#ffffff",
            state="disabled",
        )
        self.btn_stop.pack(side="left", padx=4, pady=8)

        # Progress bar
        self.progress = ctk.CTkProgressBar(
            self.toolbar, width=300, height=14
        )
        self.progress.pack(side="left", padx=12, pady=8)
        self.progress.set(0)

        # Status label
        self.lbl_status = ctk.CTkLabel(
            self.toolbar,
            text="Ready",
            font=FONTS["body_small"],
            text_color=COLORS["text_secondary"],
        )
        self.lbl_status.pack(side="left", padx=8)

        # Right-side controls
        self.btn_export = ctk.CTkButton(
            self.toolbar,
            text="Export Report",
            font=FONTS["button"],
            width=DIMENSIONS["button_width"],
            command=self._on_export,
        )
        self.btn_export.pack(side="right", padx=6, pady=8)

        self.lbl_title = ctk.CTkLabel(
            self.toolbar,
            text="FileGuard v1.0",
            font=FONTS["heading_md"],
            text_color=COLORS["text_accent"],
        )
        self.lbl_title.pack(side="right", padx=12)

    # ── Paned Layout ─────────────────────────────────────────

    def _build_paned_layout(self) -> None:
        """Build resizable paned layout with main area and bottom panel."""
        import tkinter as tk

        self.paned = tk.PanedWindow(
            self,
            orient=tk.VERTICAL,
            sashwidth=4,
            sashrelief=tk.FLAT,
            bg="#2b2b2b",
            opaqueresize=False,
        )
        self.paned.pack(fill="both", expand=True, padx=4, pady=4)

        # Top pane: horizontal PanedWindow for columns + detail
        self.h_paned = tk.PanedWindow(
            self.paned,
            orient=tk.HORIZONTAL,
            sashwidth=4,
            sashrelief=tk.FLAT,
            bg="#2b2b2b",
            opaqueresize=False,
        )

        self.risk_columns: Dict[str, RiskColumn] = {}
        for risk_name in [
            "SUSPICIOUS_CODE", "HIGH_TARGET", "POTENTIAL_RISK", "LOW_RISK"
        ]:
            col = RiskColumn(
                self.h_paned,
                risk_name=risk_name,
                on_select=self._on_file_selected,
            )
            self.h_paned.add(col, stretch="always", minsize=80)
            self.risk_columns[risk_name] = col

        self.detail_panel = DetailPanel(self.h_paned)
        self.h_paned.add(self.detail_panel, stretch="always", minsize=150)

        self.paned.add(self.h_paned, stretch="always", minsize=200)

        # Bottom pane: per-tool tabbed notebook. The old shared
        # forensic-button bar lived here; we removed it because each
        # tab now owns its own Start button so the user runs a tool
        # from inside the tab they're already looking at.
        self.bottom_frame = ctk.CTkFrame(self.paned)

        self._tool_labels = [
            "Event Logs", "Registry", "Timestamps",
            "Prefetch", "Amcache", "Bitmap Cache",
            "Honeypot",
        ]

        self._build_tool_notebook()

        self.paned.add(self.bottom_frame, stretch="always", minsize=100)

        # Initial Activity-tab message kept for parity with the old
        # single-textbox layout.
        self._info_write("FileGuard ready. Click 'Start Scan' to begin.\n")

    # ── Scan Controls ──────────────────────────────────────────

    def _on_start_scan(self) -> None:
        """Handle Start Scan button."""
        target = filedialog.askdirectory(title="Select directory to scan")
        if not target:
            return

        self._scan_running = True
        self._scan_cancelled = False
        self._stopping = False
        self._cancel_event = threading.Event()
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(
            state="normal",
            text="\u25a0  Stop",
            fg_color="#555555",
            hover_color="#333333",
        )
        self._clear_results()
        self._update_status(f"Scanning: {target}")
        self._info_write(f"\nStarting scan of {target}...\n")

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target,),
            daemon=True,
        )
        self._scan_thread.start()

    def _on_stop_scan(self) -> None:
        """Handle Stop button.

        Signals the background scanner via the cancel event. The
        scanner stops accepting new work, cancels pending workers,
        and returns; the worker thread's ``finally`` block calls
        :meth:`_scan_complete` once it actually exits.

        Also gives the user clear visual confirmation that the click
        registered: the button immediately recolours to amber, the
        status text latches to ``Stopping...`` (no longer overwritten
        by progress callbacks), and the progress bar switches into
        an indeterminate pulsing animation so it stops crawling
        forward.
        """
        if not self._scan_running or self._stopping:
            return
        self._stopping = True
        self._scan_cancelled = True
        if self._cancel_event is not None:
            self._cancel_event.set()

        self.btn_stop.configure(
            state="disabled",
            text="\u25a0  Stopping...",
            fg_color="#d68910",
            text_color="#1a1a2e",
        )
        try:
            self.btn_stop.update_idletasks()
        except Exception:
            pass

        self._update_status(
            "Stopping scan - waiting for in-flight workers..."
        )
        self._info_write(
            "\nStop requested - waiting for workers to finish...\n"
        )

        try:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
        except Exception:
            pass

        self._stop_anim_index = 0
        self._animate_stopping()

    def _run_scan(self, target: str) -> None:
        """Execute scan in background thread.

        Streams results via :meth:`FileScanner.scan` so the progress
        bar and status label can update per file. The progress
        callback runs on a worker thread; we marshal each tick onto
        the Tk main thread with ``after``.
        """
        import uuid
        from datetime import datetime

        try:
            from core.models import ScanSummary
            from core.scanner import FileScanner

            scanner = FileScanner()
            scan_id = str(uuid.uuid4())[:8]
            start_time = datetime.now()
            results: List[ScanResult] = []

            def on_progress(
                processed: int,
                total: int,
                current: Optional[Path],
            ) -> None:
                self.after(0, self._on_scan_progress, processed, total, current)

            self.after(0, self._update_status, "Enumerating files...")
            self.after(0, self.progress.set, 0)

            for result in scanner.scan(
                Path(target),
                progress_callback=on_progress,
                cancel_event=self._cancel_event,
            ):
                results.append(result)
                # Stream the flagged file into its risk column as soon
                # as it's classified, so partial results are visible
                # mid-scan and survive a Stop.
                self.after(0, self._add_live_result, result)

            summary = ScanSummary(
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(),
                target_path=Path(target),
                total_files=(
                    scanner.stats["scanned"]
                    + scanner.stats["skipped"]
                    + scanner.stats["errors"]
                ),
                files_scanned=scanner.stats["scanned"],
                files_skipped=scanner.stats["skipped"],
                files_error=scanner.stats["errors"],
                results=results,
            )

            self._scan_results = summary.results

            self.after(0, self._display_results, summary)

        except Exception as e:
            logger.error("Scan error: %s", e)
            self.after(
                0, self._info_write,
                f"\nScan error: {e}\n",
            )

        finally:
            self.after(0, self._scan_complete)

    def _on_scan_progress(
        self,
        processed: int,
        total: int,
        current: Optional[Path],
    ) -> None:
        """Update progress bar and status label on the main thread.

        Once the user has clicked Stop we leave the latched
        ``Stopping...`` status and indeterminate progress bar alone -
        otherwise late progress callbacks from in-flight workers would
        flash the per-file status back over our acknowledgement and
        make the click look like it was ignored.
        """
        if self._stopping:
            return

        if total <= 0:
            self.progress.set(0)
            self._update_status("Enumerating files...")
            return

        fraction = max(0.0, min(1.0, processed / total))
        self.progress.set(fraction)
        name = current.name if current else ""
        if len(name) > 40:
            name = name[:37] + "..."
        self._update_status(f"Scanning {processed}/{total}: {name}")

    def _animate_stopping(self) -> None:
        """Animate the status label while the scan winds down.

        Cycles ``Stopping`` / ``Stopping.`` / ``Stopping..`` /
        ``Stopping...`` so the user has continuous proof that the UI
        is alive and the click was honoured. Self-cancels via
        ``_stopping`` once the scan thread finishes.
        """
        if not self._stopping:
            return
        dots = "." * (self._stop_anim_index % 4)
        self._update_status(
            f"Stopping{dots} waiting for in-flight workers"
        )
        self._stop_anim_index += 1
        self.after(350, self._animate_stopping)

    def _scan_complete(self) -> None:
        """Reset UI after scan completes (or is cancelled)."""
        self._scan_running = False
        was_stopping = self._stopping
        self._stopping = False
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(
            state="disabled",
            text="\u25a0  Stop",
            fg_color="#555555",
            hover_color="#333333",
            text_color="#ffffff",
        )

        if was_stopping:
            try:
                self.progress.stop()
                self.progress.configure(mode="determinate")
            except Exception:
                pass

        if self._scan_cancelled:
            self.progress.set(0)
            self._update_status(
                f"Scan stopped - {len(self._scan_results)} files analyzed"
            )
            self._info_write(
                f"Scan stopped after {len(self._scan_results)} files.\n"
            )
        else:
            self.progress.set(1.0)
            self._update_status(
                f"Scan complete - {len(self._scan_results)} files analyzed"
            )
        self._cancel_event = None

    def _add_live_result(self, result: ScanResult) -> None:
        """Add a single result to its risk column on the main thread.

        Called per yielded ScanResult while the scan is still running
        so the user sees flagged files appearing immediately. The
        partial population also survives a Stop - any results already
        added to columns stay there for review.
        """
        risk_name = result.risk_level.name
        column = self.risk_columns.get(risk_name)
        if column is not None:
            column.add_file(result)

    def _display_results(self, summary: ScanSummary) -> None:
        """Write the end-of-scan summary to the info panel.

        Columns were already populated incrementally via
        :meth:`_add_live_result`; this method only emits the summary
        text so we don't duplicate entries.
        """
        counts = summary.risk_counts
        self._info_write(
            f"\nScan complete: {summary.files_scanned} files, "
            f"{summary.duration_seconds:.1f}s\n"
            f"  Suspicious Code: {counts.get('SUSPICIOUS_CODE', 0)}\n"
            f"  High Target:     {counts.get('HIGH_TARGET', 0)}\n"
            f"  Potential Risk:  {counts.get('POTENTIAL_RISK', 0)}\n"
            f"  Low Risk:        {counts.get('LOW_RISK', 0)}\n"
            f"  Clean:           {counts.get('CLEAN', 0)}\n"
        )

    def _clear_results(self) -> None:
        """Clear all risk columns."""
        self._scan_results.clear()
        for col in self.risk_columns.values():
            col.clear()
        self.detail_panel.clear()

    # ── Event Handlers ─────────────────────────────────────────

    def _on_file_selected(self, result: ScanResult) -> None:
        """Handle file selection in any risk column."""
        self._selected_result = result
        self.detail_panel.show(result)

    def _on_export(self) -> None:
        """Handle Export Report button."""
        if not self._scan_results:
            messagebox.showinfo("Export", "No scan results to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".html",
            filetypes=[
                ("HTML Report", "*.html"),
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("STIX 2.1", "*.stix.json"),
            ],
        )
        if not path:
            return

        try:
            from utils.report_generator import ReportGenerator

            gen = ReportGenerator(self._scan_results)
            ext = Path(path).suffix.lower()
            if ext == ".html":
                gen.export_html(Path(path))
            elif ext == ".csv":
                gen.export_csv(Path(path))
            else:
                gen.export_json(Path(path))

            self._info_write(f"\nReport exported to {path}\n")
            messagebox.showinfo("Export", f"Report saved to:\n{path}")

        except Exception as e:
            logger.error("Export error: %s", e)
            messagebox.showerror("Export Error", str(e))

    def _run_forensic(self, module_name: str) -> None:
        """Run a forensic analysis module and route output to its tab."""
        tab = self.tool_tabs.get(module_name)
        if tab is None:
            logger.warning("No tab for forensic tool: %s", module_name)
            return

        tab.set_running()
        self._info_write(f"Running {module_name} analysis...\n")

        def _run() -> None:
            try:
                module_map = {
                    "Event Logs": "forensics.event_logs.EventLogAnalyzer",
                    "Registry": "forensics.registry.RegistryAnalyzer",
                    "Timestamps": "forensics.timestomp.TimestompDetector",
                    "Prefetch": "forensics.prefetch.PrefetchParser",
                    "Amcache": "forensics.amcache.AmcacheParser",
                    "Bitmap Cache": "forensics.bitmap_cache.BitmapCacheParser",
                }

                import importlib

                fqn = module_map.get(module_name)
                if not fqn:
                    return

                module_path, class_name = fqn.rsplit(".", 1)
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)

                instance = cls({})
                if hasattr(instance, "analyze"):
                    findings = instance.analyze()
                elif hasattr(instance, "scan_system"):
                    findings = instance.scan_system()
                else:
                    findings = []

                self.after(0, self._on_forensic_done, module_name, findings, None)

            except Exception as e:
                logger.exception("Forensic tool %s failed", module_name)
                self.after(0, self._on_forensic_done, module_name, [], str(e))

        threading.Thread(target=_run, daemon=True).start()

    def _on_forensic_done(
        self,
        module_name: str,
        findings: list,
        err: Optional[str],
    ) -> None:
        """Main-thread continuation of :meth:`_run_forensic`."""
        tab = self.tool_tabs.get(module_name)
        if tab is None:
            return
        if err is not None:
            tab.set_error(
                f"{module_name} failed:\n\n{err}\n\n"
                "If this requires elevated privileges, try running "
                "FileGuard from an Administrator terminal."
            )
            self._info_write(f"  {module_name} error: {err}\n")
            return
        tab.set_results(findings)
        self._info_write(
            f"  {module_name}: {len(findings)} finding(s)\n"
        )

    # ── Helpers ────────────────────────────────────────────────

    def _update_status(self, text: str) -> None:
        """Update the status label."""
        self.lbl_status.configure(text=text)

    def _info_write(self, text: str) -> None:
        """Append text to the Activity tab.

        Kept for back-compat with all the existing call-sites that
        wrote scan progress, sandbox close logs, etc. into the old
        shared CTkTextbox. Now routes everything into the first tab
        of the notebook.
        """
        try:
            self.activity_text.configure(state="normal")
            self.activity_text.insert("end", text)
            self.activity_text.see("end")
            self.activity_text.configure(state="disabled")
        except Exception:
            pass

    # ── Tool notebook ──────────────────────────────────────────

    def _build_tool_notebook(self) -> None:
        """Replace the old shared CTkTextbox with a tk.ttk.Notebook.

        Every forensic tool gets its own tab so output from one tool
        no longer overwrites another's. The first tab ("Activity") is
        the legacy ``_info_write`` sink: scan progress, startup
        messages, sandbox-close logs, etc. all land there.
        """
        import tkinter as tk
        from tkinter import ttk

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Tools.TNotebook", background="#1a1a2e", borderwidth=0
        )
        style.configure(
            "Tools.TNotebook.Tab",
            background="#16213e",
            foreground="#e8e8e8",
            padding=(14, 6),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Tools.TNotebook.Tab",
            background=[("selected", "#0f3460")],
            foreground=[("selected", "#00adb5")],
        )

        self.tool_notebook = ttk.Notebook(
            self.bottom_frame, style="Tools.TNotebook"
        )
        self.tool_notebook.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 0: Activity (legacy info_write sink)
        activity_frame = tk.Frame(self.tool_notebook, bg="#1a1a2e")
        self.activity_text = tk.Text(
            activity_frame,
            bg="#0f1020",
            fg="#e8e8e8",
            insertbackground="#e8e8e8",
            selectbackground="#2c3e50",
            relief="flat",
            padx=10,
            pady=8,
            wrap="word",
            font=("Consolas", 10),
            cursor="arrow",
            state="disabled",
        )
        yscroll = tk.Scrollbar(
            activity_frame, orient="vertical", command=self.activity_text.yview
        )
        self.activity_text.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.activity_text.pack(fill="both", expand=True)
        self.tool_notebook.add(activity_frame, text="Activity")

        # Compatibility alias: a few old call sites still reference
        # ``self.info_text`` directly. Point it at the Activity Text.
        self.info_text = self.activity_text

        # Tabs 1-6: one ToolTab per read-only forensic tool. Each
        # tab owns its own Start button which calls _run_forensic
        # directly.
        self.tool_tabs: Dict[str, ToolTab] = {}
        for label in self._tool_labels:
            if label == "Honeypot":
                continue
            tab = ToolTab(
                self.tool_notebook,
                label,
                on_start=lambda lab=label: self._run_forensic(lab),
            )
            self.tool_notebook.add(tab, text=label)
            self.tool_tabs[label] = tab

        # Tab 7: Honeypot (interactive, not a ToolTab).
        self.honeypot_tab = HoneypotTab(self.tool_notebook)
        self.tool_notebook.add(self.honeypot_tab, text="Honeypot")

    # ── Shutdown ───────────────────────────────────────────────

    def _on_close_window(self) -> None:
        """Window-close handler: tear down sandboxes and exit cleanly.

        Bound to ``WM_DELETE_WINDOW`` so the X button (or Alt+F4)
        force-terminates any sandbox VM still running, deletes every
        staging dir from this session, and signals any in-flight scan
        to stop. We never block the user from closing.
        """
        try:
            self._scan_cancelled = True
            self._stopping = True
            if self._cancel_event is not None:
                self._cancel_event.set()
        except Exception:
            pass

        try:
            from utils.sandbox_launcher import (
                active_detonations,
                terminate_all,
            )
            if active_detonations():
                cleaned = terminate_all()
                logger.info(
                    "App close: terminated sandboxes and cleaned %d "
                    "staging dir(s)",
                    cleaned,
                )
            else:
                terminate_all()
        except Exception:
            logger.exception("Sandbox cleanup on app close failed")

        try:
            if hasattr(self, "honeypot_tab") and self.honeypot_tab.is_monitoring():
                self.honeypot_tab.stop_monitoring()
                logger.info("App close: stopped honeypot monitor")
        except Exception:
            logger.exception("Honeypot monitor stop on app close failed")

        try:
            self.destroy()
        except Exception:
            pass


# ── Entry Point ────────────────────────────────────────────────


def launch_gui() -> None:
    """Launch the FileGuard GUI."""
    app = FileGuardApp()
    app.mainloop()
