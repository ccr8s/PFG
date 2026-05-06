"""FileGuard GUI custom widgets."""

from gui.widgets.detail_panel import DetailPanel
from gui.widgets.honeypot_alerts_tab import HoneypotAlertsTab
from gui.widgets.honeypot_tab import HoneypotTab
from gui.widgets.info_popup import InfoPopup
from gui.widgets.preview_window import SafePreviewWindow
from gui.widgets.risk_column import RiskColumn
from gui.widgets.tool_tab import ToolTab
from gui.widgets.tooltip import ToolTip


def use_hand_cursor(*widgets) -> None:
    """Apply a ``hand2`` (pointer) cursor to clickable widgets.

    Works for plain ``tk`` widgets and customtkinter ``CTkButton``-style
    wrappers (which bury the actual canvas under ``_canvas``). Failures
    are swallowed because cursor cosmetics should never crash the UI.
    """
    for w in widgets:
        if w is None:
            continue
        target = getattr(w, "_canvas", w)
        try:
            target.configure(cursor="hand2")
        except Exception:
            pass


__all__ = [
    "DetailPanel",
    "HoneypotAlertsTab",
    "HoneypotTab",
    "InfoPopup",
    "RiskColumn",
    "SafePreviewWindow",
    "ToolTab",
    "ToolTip",
    "use_hand_cursor",
]
