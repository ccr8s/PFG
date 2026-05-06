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
import time
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any, Dict, List, Optional

import customtkinter as ctk

from core.models import RiskLevel, ScanResult, ScanSummary
from gui.knowledge_base import get_tactic_info, get_technique_info
from gui.styles import COLORS, DIMENSIONS, FONTS, RISK_DISPLAY

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

        self.risk_columns: Dict[str, _RiskColumn] = {}
        for risk_name in [
            "SUSPICIOUS_CODE", "HIGH_TARGET", "POTENTIAL_RISK", "LOW_RISK"
        ]:
            col = _RiskColumn(
                self.h_paned,
                risk_name=risk_name,
                on_select=self._on_file_selected,
            )
            self.h_paned.add(col, stretch="always", minsize=80)
            self.risk_columns[risk_name] = col

        self.detail_panel = _DetailPanel(self.h_paned)
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
                command=lambda l=label: self._run_forensic(l),
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


# ── Risk Column Widget ─────────────────────────────────────────


class _RiskColumn(ctk.CTkFrame):
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

        # Header
        self.header = ctk.CTkLabel(
            self,
            text=f"{display.get('icon', '')}  {display.get('label', risk_name)}  (0)",
            font=FONTS["heading_sm"],
            text_color=self._color,
        )
        self.header.pack(fill="x", padx=6, pady=(6, 2))

        # Colored accent line under header
        self.accent_line = ctk.CTkFrame(
            self, height=2, fg_color=self._color
        )
        self.accent_line.pack(fill="x", padx=6, pady=(0, 2))

        # Scrollable file list
        self.file_list = ctk.CTkScrollableFrame(
            self, fg_color="transparent"
        )
        self.file_list.pack(fill="both", expand=True, padx=4, pady=4)

    def add_file(self, result: ScanResult) -> None:
        """Add a file entry to this column."""
        self._results.append(result)

        # Truncate long filenames so they don't overflow
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

        # Tooltip showing full filename on hover
        full_name = result.file_path.name
        _ToolTip(btn, full_name)

        # Update header count
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
            text=f"{display.get('icon', '')}  {display.get('label', self.risk_name)}  (0)"
        )


# ── Detail Panel Widget ───────────────────────────────────────


class _DetailPanel(ctk.CTkFrame):
    """Right-side panel showing details for selected file."""

    def __init__(self, master: Any) -> None:
        super().__init__(
            master,
            width=DIMENSIONS["detail_panel_width"],
            border_width=1,
            border_color=COLORS["border_default"],
        )
        self.pack_propagate(False)

        self.lbl_title = ctk.CTkLabel(
            self,
            text="File Details",
            font=FONTS["heading_md"],
            text_color=COLORS["text_accent"],
        )
        self.lbl_title.pack(fill="x", padx=8, pady=(8, 4))

        self.detail_text = ctk.CTkTextbox(
            self, font=FONTS["mono_small"], wrap="word"
        )
        self.detail_text.pack(fill="both", expand=True, padx=6, pady=6)

        # Counter for unique clickable tag names
        self._link_counter = 0

    def show(self, result: ScanResult) -> None:
        """Display details for a scan result."""
        tw = self.detail_text
        tw.delete("1.0", "end")
        self._link_counter = 0

        # -- Configure text tags --
        tw.tag_config(
            "label", foreground=COLORS["text_accent"],
        )
        tw.tag_config(
            "hdr_val", lmargin1=0, lmargin2=0,
        )
        tw.tag_config(
            "heading", foreground=COLORS["accent_blue"],
        )
        tw.tag_config(
            "separator", foreground=COLORS["text_secondary"],
        )
        risk_disp = RISK_DISPLAY.get(result.risk_level.name, {})
        risk_color = risk_disp.get("color", COLORS["text_primary"])
        tw.tag_config("risk_val", foreground=risk_color)

        tw.tag_config(
            "f_head", lmargin1=1, lmargin2=40,
        )
        tw.tag_config(
            "f_desc", lmargin1=35, lmargin2=35,
        )
        tw.tag_config(
            "f_label", foreground=COLORS["text_accent"],
            lmargin1=35, lmargin2=35,
        )
        tw.tag_config(
            "f_val", lmargin1=0, lmargin2=130,
        )

        # -- File header --
        self._insert("FILE:   ", "label")
        self._insert(f"{result.file_path.name}\n")
        self._insert("Path:   ", "label")
        self._insert(f"{result.file_path}\n")
        self._insert("\n")

        self._insert("Risk:   ", "label")
        self._insert(
            f"{risk_disp.get('label', result.risk_level.name)}\n",
            "risk_val",
        )
        self._insert("Score:  ", "label")
        self._insert(f"{result.risk_score}\n")
        self._insert("Size:   ", "label")
        self._insert(f"{result.file_size:,} bytes\n")
        self._insert("\n")

        self._insert("MD5:    ", "label")
        self._insert(f"{result.file_hash_md5 or 'N/A'}\n")
        self._insert("\n")
        self._insert("SHA256: ", "label")
        self._insert(f"{result.file_hash_sha256 or 'N/A'}\n")
        self._insert("\n")

        # -- Findings --
        if result.findings:
            self._insert(
                f"─── Findings ({len(result.findings)}) "
                f"───────────────────\n",
                "separator",
            )

            for i, f in enumerate(result.findings, 1):
                self._insert("\n")
                self._insert(f"[{i}] {f.detector}\n", "f_head")
                self._insert(f"{f.description}\n", "f_desc")

                if f.evidence:
                    self._insert("Evidence: ", "f_label")
                    self._insert(f"{f.evidence[:200]}\n", "f_val")

                if f.attack_techniques:
                    self._insert("ATT&CK:   ", "f_label")
                    # Each technique is a clickable link
                    for idx, tech_id in enumerate(f.attack_techniques):
                        if idx > 0:
                            self._insert(", ", "f_val")
                        self._insert_link(
                            tech_id,
                            lambda _e, tid=tech_id: _InfoPopup.show_technique(
                                self.winfo_toplevel(), tid
                            ),
                            extra_tags=("f_val",),
                        )
                    self._insert("\n", "f_val")

                if f.attack_tactics:
                    self._insert("Tactics:  ", "f_label")
                    for idx, tactic in enumerate(f.attack_tactics):
                        if idx > 0:
                            self._insert(", ", "f_val")
                        self._insert_link(
                            tactic,
                            lambda _e, t=tactic: _InfoPopup.show_tactic(
                                self.winfo_toplevel(), t
                            ),
                            extra_tags=("f_val",),
                        )
                    self._insert("\n", "f_val")

                if f.remediation:
                    self._insert("Fix:      ", "f_label")
                    # Build the combined fix text from knowledge base
                    kb_fix_parts: List[str] = []
                    for tech_id in (f.attack_techniques or []):
                        info = get_technique_info(tech_id)
                        if info:
                            kb_fix_parts.append(info.get("fix", ""))
                    self._insert_link(
                        f"{f.remediation}  \u24d8",
                        lambda _e, rem=f.remediation, techs=list(
                            f.attack_techniques or []
                        ): _InfoPopup.show_fix(
                            self.winfo_toplevel(), rem, techs
                        ),
                        extra_tags=("f_val",),
                    )
                    self._insert("\n", "f_val")

        tw.see("1.0")

    def _insert(self, text: str, tag: str = "") -> None:
        """Insert text, optionally with a tag."""
        if tag:
            self.detail_text.insert("end", text, tag)
        else:
            self.detail_text.insert("end", text)

    def _insert_link(
        self,
        text: str,
        callback: Any,
        extra_tags: tuple = (),
    ) -> None:
        """Insert clickable link text into the detail textbox."""
        tw = self.detail_text
        tag_name = f"link_{self._link_counter}"
        self._link_counter += 1

        # Configure the link tag -- underlined, highlighted color, hand cursor
        tw.tag_config(
            tag_name,
            foreground="#5dade2",
            underline=True,
        )

        # Combine with any extra tags (e.g. f_val for indentation)
        all_tags = (tag_name,) + extra_tags

        tw.insert("end", text, all_tags)

        # Bind click and hover cursor
        tw.tag_bind(tag_name, "<Button-1>", callback)
        tw.tag_bind(
            tag_name, "<Enter>",
            lambda _e: tw.configure(cursor="hand2"),
        )
        tw.tag_bind(
            tag_name, "<Leave>",
            lambda _e: tw.configure(cursor=""),
        )

    def clear(self) -> None:
        """Clear the detail panel."""
        self.detail_text.delete("1.0", "end")


# ── Info Popup Window ──────────────────────────────────────────


class _InfoPopup:
    """Popup window that explains ATT&CK techniques, tactics, and fixes
    in beginner-friendly language."""

    _WINDOW_WIDTH = 560
    _WINDOW_HEIGHT = 480

    @staticmethod
    def show_technique(parent: Any, technique_id: str) -> None:
        """Show a popup explaining a MITRE ATT&CK technique."""
        import tkinter as tk

        info = get_technique_info(technique_id)

        popup = _InfoPopup._create_window(parent, f"ATT&CK: {technique_id}")
        text = _InfoPopup._create_text_widget(popup)

        if info:
            _InfoPopup._heading(text, f"{technique_id} — {info['name']}")
            _InfoPopup._spacer(text)

            _InfoPopup._section(text, "Danger Level")
            danger = info.get("danger", "Unknown")
            danger_color = {
                "CRITICAL": "#e74c3c",
                "High": "#e67e22",
                "Medium-High": "#f39c12",
                "Medium": "#f1c40f",
            }.get(danger, "#95a5a6")
            text.tag_config("danger_val", foreground=danger_color, font=("Segoe UI", 14, "bold"))
            text.insert("end", f"  {danger}\n", "danger_val")
            _InfoPopup._spacer(text)

            _InfoPopup._section(text, "What is this?")
            _InfoPopup._body(text, info["what"])
            _InfoPopup._spacer(text)

            _InfoPopup._section(text, "How to fix it (step by step)")
            _InfoPopup._body(text, info["fix"])
        else:
            _InfoPopup._heading(text, technique_id)
            _InfoPopup._spacer(text)
            _InfoPopup._body(
                text,
                f"No detailed description available for {technique_id} yet.\n\n"
                f"You can look it up at:\n"
                f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            )

        text.configure(state="disabled")

    @staticmethod
    def show_tactic(parent: Any, tactic_name: str) -> None:
        """Show a popup explaining a MITRE ATT&CK tactic."""
        info = get_tactic_info(tactic_name)

        popup = _InfoPopup._create_window(parent, f"Tactic: {tactic_name}")
        text = _InfoPopup._create_text_widget(popup)

        _InfoPopup._heading(text, f"Tactic — {tactic_name}")
        _InfoPopup._spacer(text)

        if info:
            _InfoPopup._section(text, "What does this mean?")
            _InfoPopup._body(text, info["what"])
        else:
            _InfoPopup._body(
                text,
                f"'{tactic_name}' is a category in the MITRE ATT&CK framework.\n\n"
                "ATT&CK tactics describe WHY an attacker does something. "
                "Each tactic represents a goal the attacker is trying to achieve, "
                "like stealing passwords or hiding their tracks.",
            )

        text.configure(state="disabled")

    @staticmethod
    def show_fix(
        parent: Any, short_remediation: str, technique_ids: List[str]
    ) -> None:
        """Show a popup with expanded, beginner-friendly fix guidance."""
        popup = _InfoPopup._create_window(parent, "How to Fix This")
        text = _InfoPopup._create_text_widget(popup)

        _InfoPopup._heading(text, "Remediation Guide")
        _InfoPopup._spacer(text)

        _InfoPopup._section(text, "Quick Summary")
        _InfoPopup._body(text, short_remediation)
        _InfoPopup._spacer(text)

        # Gather step-by-step fix info from knowledge base
        found_any = False
        for tech_id in technique_ids:
            info = get_technique_info(tech_id)
            if info:
                found_any = True
                _InfoPopup._section(
                    text, f"Detailed Steps for {tech_id} ({info['name']})"
                )
                _InfoPopup._body(text, info["fix"])
                _InfoPopup._spacer(text)

        if not found_any:
            _InfoPopup._section(text, "General Steps")
            _InfoPopup._body(
                text,
                "1. Don't panic -- but take this seriously.\n"
                "2. Disconnect from the internet (unplug cable or turn off WiFi).\n"
                "3. Run a full antivirus scan.\n"
                "4. If the scan finds something, follow its instructions to quarantine.\n"
                "5. Change your passwords from a different, clean device.\n"
                "6. If this is a work computer, contact your IT department.",
            )

        text.configure(state="disabled")

    # ── Helper methods ─────────────────────────────────────────

    @staticmethod
    def _create_window(parent: Any, title: str) -> Any:
        """Create and center a popup Toplevel window."""
        import tkinter as tk

        popup = tk.Toplevel(parent)
        popup.title(title)
        popup.configure(bg="#1a1a2e")
        popup.resizable(True, True)
        popup.attributes("-topmost", True)

        # Center on parent
        pw = _InfoPopup._WINDOW_WIDTH
        ph = _InfoPopup._WINDOW_HEIGHT
        px = parent.winfo_rootx() + (parent.winfo_width() - pw) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - ph) // 2
        popup.geometry(f"{pw}x{ph}+{px}+{py}")

        # Focus and grab
        popup.focus_force()
        popup.grab_set()

        return popup

    @staticmethod
    def _create_text_widget(popup: Any) -> Any:
        """Create the scrollable text widget inside the popup."""
        import tkinter as tk
        import tkinter.font as tkfont

        text = tk.Text(
            popup,
            bg="#1a1a2e",
            fg="#e8e8e8",
            insertbackground="#e8e8e8",
            selectbackground="#2c3e50",
            relief="flat",
            padx=20,
            pady=16,
            wrap="word",
            font=("Segoe UI", 13),
            cursor="arrow",
        )
        scroll = tk.Scrollbar(popup, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)

        # Pre-configure reusable tags
        text.tag_config(
            "heading",
            foreground="#00adb5",
            font=("Segoe UI", 18, "bold"),
        )
        text.tag_config(
            "section",
            foreground="#f39c12",
            font=("Segoe UI", 14, "bold"),
        )
        text.tag_config(
            "body",
            foreground="#e8e8e8",
            font=("Segoe UI", 13),
            lmargin1=8,
            lmargin2=8,
            spacing3=4,
        )

        return text

    @staticmethod
    def _heading(text: Any, content: str) -> None:
        text.insert("end", f"{content}\n", "heading")

    @staticmethod
    def _section(text: Any, content: str) -> None:
        text.insert("end", f"{content}\n", "section")

    @staticmethod
    def _body(text: Any, content: str) -> None:
        text.insert("end", f"{content}\n", "body")

    @staticmethod
    def _spacer(text: Any) -> None:
        text.insert("end", "\n")


# ── Tooltip Widget ─────────────────────────────────────────────


class _ToolTip:
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
        # Make tooltip click-through so it doesn't steal focus
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


# ── Entry Point ────────────────────────────────────────────────


def launch_gui() -> None:
    """Launch the FileGuard GUI."""
    app = FileGuardApp()
    app.mainloop()
