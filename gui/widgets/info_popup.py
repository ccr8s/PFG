"""ATT&CK info popup window for the FileGuard GUI."""

from typing import Any, List

from gui.knowledge_base import get_tactic_info, get_technique_info


class InfoPopup:
    """Popup window that explains ATT&CK techniques, tactics, and fixes
    in beginner-friendly language."""

    _WINDOW_WIDTH = 560
    _WINDOW_HEIGHT = 480

    @staticmethod
    def show_technique(parent: Any, technique_id: str) -> None:
        """Show a popup explaining a MITRE ATT&CK technique."""
        info = get_technique_info(technique_id)

        popup = InfoPopup._create_window(parent, f"ATT&CK: {technique_id}")
        text = InfoPopup._create_text_widget(popup)

        if info:
            InfoPopup._heading(text, f"{technique_id} — {info['name']}")
            InfoPopup._spacer(text)

            InfoPopup._section(text, "Danger Level")
            danger = info.get("danger", "Unknown")
            danger_color = {
                "CRITICAL": "#e74c3c",
                "High": "#e67e22",
                "Medium-High": "#f39c12",
                "Medium": "#f1c40f",
            }.get(danger, "#95a5a6")
            text.tag_config(
                "danger_val",
                foreground=danger_color,
                font=("Segoe UI", 14, "bold"),
            )
            text.insert("end", f"  {danger}\n", "danger_val")
            InfoPopup._spacer(text)

            InfoPopup._section(text, "What is this?")
            InfoPopup._body(text, info["what"])
            InfoPopup._spacer(text)

            InfoPopup._section(text, "How to fix it (step by step)")
            InfoPopup._body(text, info["fix"])
        else:
            InfoPopup._heading(text, technique_id)
            InfoPopup._spacer(text)
            InfoPopup._body(
                text,
                f"No detailed description available for {technique_id} yet.\n\n"
                f"You can look it up at:\n"
                f"https://attack.mitre.org/techniques/"
                f"{technique_id.replace('.', '/')}/",
            )

        text.configure(state="disabled")

    @staticmethod
    def show_tactic(parent: Any, tactic_name: str) -> None:
        """Show a popup explaining a MITRE ATT&CK tactic."""
        info = get_tactic_info(tactic_name)

        popup = InfoPopup._create_window(parent, f"Tactic: {tactic_name}")
        text = InfoPopup._create_text_widget(popup)

        InfoPopup._heading(text, f"Tactic — {tactic_name}")
        InfoPopup._spacer(text)

        if info:
            InfoPopup._section(text, "What does this mean?")
            InfoPopup._body(text, info["what"])
        else:
            InfoPopup._body(
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
        popup = InfoPopup._create_window(parent, "How to Fix This")
        text = InfoPopup._create_text_widget(popup)

        InfoPopup._heading(text, "Remediation Guide")
        InfoPopup._spacer(text)

        InfoPopup._section(text, "Quick Summary")
        InfoPopup._body(text, short_remediation)
        InfoPopup._spacer(text)

        found_any = False
        for tech_id in technique_ids:
            info = get_technique_info(tech_id)
            if info:
                found_any = True
                InfoPopup._section(
                    text, f"Detailed Steps for {tech_id} ({info['name']})"
                )
                InfoPopup._body(text, info["fix"])
                InfoPopup._spacer(text)

        if not found_any:
            InfoPopup._section(text, "General Steps")
            InfoPopup._body(
                text,
                "1. Don't panic -- but take this seriously.\n"
                "2. Disconnect from the internet (unplug cable or turn off WiFi).\n"
                "3. Run a full antivirus scan.\n"
                "4. If the scan finds something, follow its instructions to quarantine.\n"
                "5. Change your passwords from a different, clean device.\n"
                "6. If this is a work computer, contact your IT department.",
            )

        text.configure(state="disabled")

    @staticmethod
    def _create_window(parent: Any, title: str) -> Any:
        """Create and center a popup Toplevel window."""
        import tkinter as tk

        popup = tk.Toplevel(parent)
        popup.title(title)
        popup.configure(bg="#1a1a2e")
        popup.resizable(True, True)
        popup.attributes("-topmost", True)

        pw = InfoPopup._WINDOW_WIDTH
        ph = InfoPopup._WINDOW_HEIGHT
        px = parent.winfo_rootx() + (parent.winfo_width() - pw) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - ph) // 2
        popup.geometry(f"{pw}x{ph}+{px}+{py}")

        popup.focus_force()
        popup.grab_set()

        return popup

    @staticmethod
    def _create_text_widget(popup: Any) -> Any:
        """Create the scrollable text widget inside the popup."""
        import tkinter as tk

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
