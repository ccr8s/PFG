"""Read-only viewer tab for a forensic analysis tool.

Each forensic tool (Event Logs, Registry, Timestomp, Prefetch,
Amcache, Bitmap Cache) gets its own ``ToolTab`` inside the bottom
``ttk.Notebook`` so output from one tool no longer overwrites
another's. Honeypot has a richer custom tab; this base class is
specifically for the read-only "show me the findings" tools.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from typing import Any, Callable, List, Optional


class ToolTab(tk.Frame):
    """Tab body: action bar + header line + scrolling read-only text area.

    Each tab owns its own Start button so the user kicks off the
    analysis from inside the tab they're looking at, instead of
    hunting for the right button in a separate toolbar.
    """

    def __init__(
        self,
        master: Any,
        label: str,
        on_start: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(master, bg="#1a1a2e")
        self.label = label
        self._on_start = on_start
        self._last_run: Optional[datetime] = None
        self._finding_count: Optional[int] = None
        self._is_running = False

        action_bar = tk.Frame(self, bg="#1a1a2e")
        action_bar.pack(fill="x", padx=10, pady=(8, 4))

        self.btn_start = tk.Button(
            action_bar,
            text=f"Run {label}",
            command=self._handle_start,
            bg="#27ae60",
            fg="#ffffff",
            activebackground="#1e8449",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
        )
        self.btn_start.pack(side="left")

        self.header = tk.Label(
            self,
            text=f"{label}  -  not yet run",
            bg="#1a1a2e",
            fg="#9b9b9b",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
            padx=10,
            pady=6,
        )
        self.header.pack(fill="x")

        body = tk.Frame(self, bg="#1a1a2e")
        body.pack(fill="both", expand=True)

        self.text = tk.Text(
            body,
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
        yscroll = tk.Scrollbar(body, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.text.pack(fill="both", expand=True)

        self.text.tag_configure(
            "sev_high", foreground="#e74c3c", font=("Consolas", 10, "bold")
        )
        self.text.tag_configure(
            "sev_med", foreground="#f39c12", font=("Consolas", 10, "bold")
        )
        self.text.tag_configure(
            "sev_low", foreground="#5dade2"
        )
        self.text.tag_configure(
            "muted", foreground="#9b9b9b"
        )

        self._set_idle_placeholder()

    # ------------------------------------------------------------------
    # Start button
    # ------------------------------------------------------------------
    def _handle_start(self) -> None:
        """Forward Start button clicks to the registered callback.

        If a run is already in flight we ignore the click - the
        button is also visually disabled in :meth:`set_running` to
        make this obvious.
        """
        if self._is_running:
            return
        if self._on_start is not None:
            self._on_start()

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------
    def set_running(self) -> None:
        """Show a 'Running...' message and clear prior content."""
        self._is_running = True
        self.btn_start.configure(
            state="disabled",
            text=f"Running {self.label}...",
            cursor="watch",
        )
        self.header.configure(
            text=f"{self.label}  -  running...",
            fg="#f39c12",
        )
        self._replace(
            f"Running {self.label} analysis... this can take a few "
            "seconds.\n",
            tag="muted",
        )

    def set_results(self, findings: List[Any]) -> None:
        """Render a list of ``ForensicFinding`` objects."""
        self._is_running = False
        self._last_run = datetime.now()
        self._finding_count = len(findings)
        ts = self._last_run.strftime("%H:%M:%S")
        self.btn_start.configure(
            state="normal",
            text=f"Re-run {self.label}",
            cursor="hand2",
        )
        self.header.configure(
            text=(
                f"{self.label}  -  {self._finding_count} finding(s) "
                f"at {ts}"
            ),
            fg="#00adb5" if findings else "#9b9b9b",
        )

        self.text.configure(state="normal")
        self.text.delete("1.0", "end")

        if not findings:
            self.text.insert(
                "end",
                f"No {self.label.lower()} findings.\n\n"
                "This either means the tool found nothing notable, or "
                "it doesn't have permission to read the relevant "
                "artifacts. Run as Administrator for the most complete "
                "picture.",
                "muted",
            )
            self.text.configure(state="disabled")
            return

        for idx, finding in enumerate(findings, 1):
            sev = getattr(finding, "severity", 0) or 0
            tag = (
                "sev_high" if sev >= 70
                else "sev_med" if sev >= 40
                else "sev_low"
            )
            desc = getattr(finding, "description", str(finding))
            evidence = getattr(finding, "evidence", "") or ""
            artifact = getattr(finding, "artifact_path", "") or ""
            attack = getattr(finding, "attack_techniques", []) or []

            self.text.insert("end", f"[{idx:>2}] [sev {sev:>3}] ", tag)
            self.text.insert("end", f"{desc}\n")
            if artifact:
                self.text.insert("end", f"     where: {artifact}\n", "muted")
            if evidence:
                snippet = evidence if len(evidence) <= 200 else evidence[:200] + "..."
                self.text.insert("end", f"     evidence: {snippet}\n", "muted")
            if attack:
                self.text.insert(
                    "end",
                    f"     ATT&CK: {', '.join(attack)}\n",
                    "muted",
                )
            self.text.insert("end", "\n")

        self.text.configure(state="disabled")

    def set_error(self, message: str) -> None:
        """Show an error message in the body."""
        self._is_running = False
        self.btn_start.configure(
            state="normal",
            text=f"Retry {self.label}",
            cursor="hand2",
        )
        self.header.configure(
            text=f"{self.label}  -  error", fg="#e74c3c"
        )
        self._replace(message, tag="sev_high")

    def append(self, line: str, tag: str = "") -> None:
        """Append a line of text to the body."""
        self.text.configure(state="normal")
        if tag:
            self.text.insert("end", line, tag)
        else:
            self.text.insert("end", line)
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self) -> None:
        """Reset the tab back to the idle placeholder."""
        self._is_running = False
        self._last_run = None
        self._finding_count = None
        self.btn_start.configure(
            state="normal",
            text=f"Run {self.label}",
            cursor="hand2",
        )
        self.header.configure(
            text=f"{self.label}  -  not yet run",
            fg="#9b9b9b",
        )
        self._set_idle_placeholder()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _set_idle_placeholder(self) -> None:
        self._replace(
            f"Click 'Run {self.label}' above to scan this host. "
            "Some checks need Administrator privileges to read all "
            "the relevant artifacts.\n",
            tag="muted",
        )

    def _replace(self, body: str, *, tag: str = "") -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if tag:
            self.text.insert("1.0", body, tag)
        else:
            self.text.insert("1.0", body)
        self.text.configure(state="disabled")


__all__ = ["ToolTab"]
