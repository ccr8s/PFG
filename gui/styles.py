"""
FileGuard GUI styles and theming.

Centralizes color schemes, font definitions, and widget styling
for the CustomTkinter-based GUI.
"""

from typing import Dict

# ── Color Palette ──────────────────────────────────────────────
COLORS: Dict[str, str] = {
    # Risk level colors
    "risk_critical": "#e74c3c",
    "risk_high": "#e67e22",
    "risk_medium": "#f1c40f",
    "risk_low": "#2ecc71",
    "risk_clean": "#95a5a6",

    # UI chrome
    "bg_primary": "#1a1a2e",
    "bg_secondary": "#16213e",
    "bg_tertiary": "#0f3460",
    "bg_card": "#1e2a45",

    # Text
    "text_primary": "#e8e8e8",
    "text_secondary": "#a0a0a0",
    "text_accent": "#00adb5",
    "text_warning": "#f39c12",

    # Accents
    "accent_blue": "#3498db",
    "accent_green": "#2ecc71",
    "accent_red": "#e74c3c",
    "accent_orange": "#e67e22",

    # Borders
    "border_default": "#2c3e50",
    "border_active": "#3498db",
}

# ── Font Definitions ───────────────────────────────────────────
FONTS = {
    "heading_lg": ("Segoe UI", 24, "bold"),
    "heading_md": ("Segoe UI", 19, "bold"),
    "heading_sm": ("Segoe UI", 17, "bold"),
    "body": ("Segoe UI", 16),
    "body_small": ("Segoe UI", 15),
    "mono": ("Consolas", 16),
    "mono_small": ("Consolas", 15),
    "button": ("Segoe UI", 16, "bold"),
}

# ── Risk Level Display Config ─────────────────────────────────
RISK_DISPLAY = {
    "SUSPICIOUS_CODE": {
        "label": "Suspicious Code",
        "color": COLORS["risk_critical"],
        "icon": "\u26a0",   # ⚠
    },
    "HIGH_TARGET": {
        "label": "High Target",
        "color": COLORS["risk_high"],
        "icon": "\u2622",   # ☢
    },
    "POTENTIAL_RISK": {
        "label": "Potential Risk",
        "color": COLORS["risk_medium"],
        "icon": "\u26a1",   # ⚡
    },
    "LOW_RISK": {
        "label": "Low Risk",
        "color": COLORS["risk_low"],
        "icon": "\u2139",   # ℹ
    },
    "CLEAN": {
        "label": "Clean",
        "color": COLORS["risk_clean"],
        "icon": "\u2714",   # ✔
    },
}

# ── Widget Dimensions ──────────────────────────────────────────
DIMENSIONS = {
    "window_min_width": 1200,
    "window_min_height": 800,
    "sidebar_width": 260,
    "detail_panel_width": 350,
    "toolbar_height": 60,
    "info_panel_height": 200,
    "button_width": 120,
    "button_height": 36,
    "card_padding": 10,
}
