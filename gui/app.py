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
from gui.widgets import DetailPanel, RiskColumn

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
        self._scan_thread: Optional[threading.Thread] = None
        self._selected_result: Optional[ScanResult] = None

        # Build UI
        self._build_toolbar()
        self._build_paned_layout()
        self._update_status("Ready")

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

        # Bottom pane: forensics bar + info text
        self.bottom_frame = ctk.CTkFrame(self.paned)

        # Forensics toolbar
        forensic_bar = ctk.CTkFrame(self.bottom_frame)
        forensic_bar.pack(fill="x", padx=4, pady=(4, 0))

        for label in [
            "Event Logs", "Registry", "Timestamps",
            "Prefetch", "Amcache", "Bitmap Cache",
        ]:
            ctk.CTkButton(
                forensic_bar,
                text=label,
                font=FONTS["button"],
                width=120,
                height=34,
                command=lambda lab=label: self._run_forensic(lab),
            ).pack(side="left", padx=2, pady=2)

        # Information text area
        self.info_text = ctk.CTkTextbox(
            self.bottom_frame,
            font=FONTS["mono_small"],
            wrap="word",
        )
        self.info_text.pack(fill="both", expand=True, padx=4, pady=4)
        self._info_write("FileGuard ready. Click 'Start Scan' to begin.\n")

        self.paned.add(self.bottom_frame, stretch="always", minsize=100)

    # ── Scan Controls ──────────────────────────────────────────

    def _on_start_scan(self) -> None:
        """Handle Start Scan button."""
        target = filedialog.askdirectory(title="Select directory to scan")
        if not target:
            return

        self._scan_running = True
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
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
        """Handle Stop button."""
        self._scan_running = False
        self._update_status("Scan stopped")
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def _run_scan(self, target: str) -> None:
        """Execute scan in background thread."""
        try:
            from core.scanner import FileScanner

            scanner = FileScanner()
            summary = scanner.scan_full(Path(target))

            self._scan_results = summary.results

            # Update GUI on main thread
            self.after(0, self._display_results, summary)

        except Exception as e:
            logger.error("Scan error: %s", e)
            self.after(
                0, self._info_write,
                f"\nScan error: {e}\n",
            )

        finally:
            self.after(0, self._scan_complete)

    def _scan_complete(self) -> None:
        """Reset UI after scan completes."""
        self._scan_running = False
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.progress.set(1.0)
        self._update_status(
            f"Scan complete - {len(self._scan_results)} files analyzed"
        )

    def _display_results(self, summary: ScanSummary) -> None:
        """Populate the risk columns from scan results."""
        for result in summary.results:
            risk_name = result.risk_level.name
            if risk_name in self.risk_columns:
                self.risk_columns[risk_name].add_file(result)

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
        """Run a forensic analysis module."""
        self._info_write(f"\nRunning {module_name} analysis...\n")

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

                self.after(
                    0,
                    self._info_write,
                    f"  {module_name}: {len(findings)} findings\n",
                )

            except Exception as e:
                self.after(
                    0,
                    self._info_write,
                    f"  {module_name} error: {e}\n",
                )

        threading.Thread(target=_run, daemon=True).start()

    # ── Helpers ────────────────────────────────────────────────

    def _update_status(self, text: str) -> None:
        """Update the status label."""
        self.lbl_status.configure(text=text)

    def _info_write(self, text: str) -> None:
        """Append text to the info panel."""
        self.info_text.insert("end", text)
        self.info_text.see("end")


# ── Entry Point ────────────────────────────────────────────────


def launch_gui() -> None:
    """Launch the FileGuard GUI."""
    app = FileGuardApp()
    app.mainloop()
