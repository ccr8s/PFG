"""File detail panel widget for the FileGuard GUI."""

import logging
from typing import Any, List, Optional

import customtkinter as ctk

from core.models import ScanResult
from gui.knowledge_base import get_technique_info
from gui.styles import COLORS, DIMENSIONS, FONTS, RISK_DISPLAY
from gui.widgets.info_popup import InfoPopup
from gui.widgets.preview_window import SafePreviewWindow
from gui.widgets.tooltip import ToolTip
from utils.sandbox_launcher import (
    Detonation,
    SandboxUnavailableError,
    detonate,
    force_close_sandbox,
    is_sandbox_available,
    sandbox_unavailable_reason,
)

logger = logging.getLogger(__name__)


class DetailPanel(ctk.CTkFrame):
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
        self.detail_text.pack(fill="both", expand=True, padx=6, pady=(6, 0))

        self._current_result: Optional[ScanResult] = None
        self._active_detonation: Optional[Detonation] = None

        self.action_bar = ctk.CTkFrame(self, fg_color="transparent")
        self.action_bar.pack(fill="x", padx=6, pady=(4, 6))

        self.btn_preview = ctk.CTkButton(
            self.action_bar,
            text="Preview (safe)",
            command=self._on_preview,
            state="disabled",
            width=140,
        )
        self.btn_preview.pack(side="left", padx=(0, 6))

        self.btn_detonate = ctk.CTkButton(
            self.action_bar,
            text="Detonate in Sandbox",
            command=self._on_detonate,
            state="disabled",
            fg_color="#a93226",
            hover_color="#7b241c",
            width=180,
        )
        self.btn_detonate.pack(side="left")

        self._sandbox_available = is_sandbox_available()
        self._sandbox_reason = (
            sandbox_unavailable_reason() if not self._sandbox_available else None
        )
        if self._sandbox_reason is not None:
            ToolTip(self.btn_detonate, self._sandbox_reason)

        self._link_counter = 0

    def show(self, result: ScanResult) -> None:
        """Display details for a scan result."""
        tw = self.detail_text
        tw.delete("1.0", "end")
        self._link_counter = 0
        self._current_result = result

        self.btn_preview.configure(state="normal")
        # Don't blindly re-enable Detonate while a sandbox is already
        # running - keep it pinned in the "Close Sandbox" state until
        # the user dismisses or the watcher reverts it.
        if self._active_detonation is None:
            if self._sandbox_available:
                self.btn_detonate.configure(state="normal")
            else:
                self.btn_detonate.configure(state="disabled")

        tw.tag_config("label", foreground=COLORS["text_accent"])
        tw.tag_config("hdr_val", lmargin1=0, lmargin2=0)
        tw.tag_config("heading", foreground=COLORS["accent_blue"])
        tw.tag_config("separator", foreground=COLORS["text_secondary"])
        risk_disp = RISK_DISPLAY.get(result.risk_level.name, {})
        risk_color = risk_disp.get("color", COLORS["text_primary"])
        tw.tag_config("risk_val", foreground=risk_color)

        tw.tag_config("f_head", lmargin1=1, lmargin2=40)
        tw.tag_config("f_desc", lmargin1=35, lmargin2=35)
        tw.tag_config(
            "f_label",
            foreground=COLORS["text_accent"],
            lmargin1=35,
            lmargin2=35,
        )
        tw.tag_config("f_val", lmargin1=0, lmargin2=130)

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
                    for idx, tech_id in enumerate(f.attack_techniques):
                        if idx > 0:
                            self._insert(", ", "f_val")
                        self._insert_link(
                            tech_id,
                            lambda _e, tid=tech_id: InfoPopup.show_technique(
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
                            lambda _e, t=tactic: InfoPopup.show_tactic(
                                self.winfo_toplevel(), t
                            ),
                            extra_tags=("f_val",),
                        )
                    self._insert("\n", "f_val")

                if f.remediation:
                    self._insert("Fix:      ", "f_label")
                    kb_fix_parts: List[str] = []
                    for tech_id in (f.attack_techniques or []):
                        info = get_technique_info(tech_id)
                        if info:
                            kb_fix_parts.append(info.get("fix", ""))
                    self._insert_link(
                        f"{f.remediation}  \u24d8",
                        lambda _e, rem=f.remediation, techs=list(
                            f.attack_techniques or []
                        ): InfoPopup.show_fix(
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

        tw.tag_config(
            tag_name,
            foreground="#5dade2",
            underline=True,
        )

        all_tags = (tag_name,) + extra_tags

        tw.insert("end", text, all_tags)

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
        self._current_result = None
        self.btn_preview.configure(state="disabled")
        # Keep Close Sandbox visible/enabled if a detonation is still
        # in flight - the user might have just kicked off a scan but
        # the sandbox VM is still running from earlier.
        if self._active_detonation is None:
            self.btn_detonate.configure(state="disabled")

    def _on_preview(self) -> None:
        """Open the safe in-process preview window."""
        if self._current_result is None:
            return
        try:
            SafePreviewWindow.show(
                self.winfo_toplevel(), self._current_result.file_path
            )
        except Exception as exc:
            logger.exception("Safe preview failed")
            self._show_error("Preview failed", str(exc))

    def _on_detonate(self) -> None:
        """Confirm and launch Windows Sandbox detonation.

        While a detonation is in flight this same button acts as
        "Close Sandbox", so we route to the close handler instead.
        """
        if self._active_detonation is not None:
            self._on_close_sandbox()
            return

        if self._current_result is None:
            return

        # Click-time re-verification. Defense in depth: even if the
        # cached ``_sandbox_available`` flag is stale (feature was
        # disabled mid-session, machine VPN'd into a managed config,
        # etc.), refuse to launch with a friendly explanation.
        reason = sandbox_unavailable_reason()
        if reason is not None:
            self._sandbox_available = False
            self._sandbox_reason = reason
            self.btn_detonate.configure(state="disabled")
            self._show_error("Windows Sandbox unavailable", reason)
            return

        from tkinter import messagebox

        path = self._current_result.file_path
        confirm = messagebox.askokcancel(
            "Detonate in Windows Sandbox",
            (
                "About to copy this file into an isolated Windows Sandbox "
                "VM with networking disabled, then launch it.\n\n"
                f"File: {path.name}\n\n"
                "The host system is not affected, but sandbox boot can take "
                "~30 seconds.\n\n"
                "When you close the sandbox window, FileGuard will "
                "automatically delete the staged copy.\n\n"
                "Continue?"
            ),
            icon="warning",
            default="cancel",
            parent=self.winfo_toplevel(),
        )
        if not confirm:
            return

        try:
            det = detonate(path, on_closed=self._sandbox_auto_closed)
            logger.info("Sandbox launched with config: %s", det.wsb_path)
        except SandboxUnavailableError as exc:
            self._show_error("Windows Sandbox unavailable", str(exc))
            return
        except FileNotFoundError as exc:
            self._show_error("File not found", str(exc))
            return
        except OSError as exc:
            logger.exception("Sandbox detonation I/O failure")
            self._show_error("Detonation failed", str(exc))
            return

        self._active_detonation = det
        self._set_close_sandbox_button()

    def _set_close_sandbox_button(self) -> None:
        """Flip the Detonate button into 'Close Sandbox' mode."""
        self.btn_detonate.configure(
            text="Close Sandbox",
            state="normal",
            fg_color="#d68910",
            hover_color="#b9770e",
            text_color="#1a1a2e",
        )

    def _reset_detonate_button(self) -> None:
        """Restore the original Detonate button styling."""
        self.btn_detonate.configure(
            text="Detonate in Sandbox",
            fg_color="#a93226",
            hover_color="#7b241c",
            text_color="#ffffff",
            state=(
                "normal"
                if (self._sandbox_available and self._current_result)
                else "disabled"
            ),
        )

    def _on_close_sandbox(self) -> None:
        """Force-terminate the running sandbox and clean up.

        Same effect the user gets by clicking the X on the sandbox
        window, but immediate - we don't wait for the watcher poll.
        """
        det = self._active_detonation
        if det is None:
            self._reset_detonate_button()
            return

        self.btn_detonate.configure(state="disabled", text="Closing...")
        try:
            self.btn_detonate.update_idletasks()
        except Exception:
            pass

        try:
            force_close_sandbox()
        except Exception:
            logger.exception("force_close_sandbox raised")
        try:
            det.cleanup()
        except Exception:
            logger.exception("Detonation cleanup raised")

        self._active_detonation = None
        self._reset_detonate_button()

    def _sandbox_auto_closed(self) -> None:
        """Watcher-thread callback: fired when the sandbox VM exits.

        Marshals back to the Tk main thread before touching widgets.
        """
        try:
            self.after(0, self._on_sandbox_auto_closed_main)
        except Exception:
            pass

    def _on_sandbox_auto_closed_main(self) -> None:
        """Main-thread continuation of :meth:`_sandbox_auto_closed`."""
        self._active_detonation = None
        self._reset_detonate_button()

    def _show_error(self, title: str, message: str) -> None:
        from tkinter import messagebox

        messagebox.showerror(title, message, parent=self.winfo_toplevel())
