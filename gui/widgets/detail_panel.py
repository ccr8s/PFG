"""File detail panel widget for the FileGuard GUI."""

from typing import Any, List

import customtkinter as ctk

from core.models import ScanResult
from gui.knowledge_base import get_technique_info
from gui.styles import COLORS, DIMENSIONS, FONTS, RISK_DISPLAY
from gui.widgets.info_popup import InfoPopup


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
        self.detail_text.pack(fill="both", expand=True, padx=6, pady=6)

        self._link_counter = 0

    def show(self, result: ScanResult) -> None:
        """Display details for a scan result."""
        tw = self.detail_text
        tw.delete("1.0", "end")
        self._link_counter = 0

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
