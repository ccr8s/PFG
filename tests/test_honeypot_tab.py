"""Smoke tests for the HoneypotTab monitor wiring.

These tests skip on headless environments (CI without an X/Win32 display)
because they need a real Tk root to instantiate the widget.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture
def root():
    """Return a hidden Tk root, or skip if one can't be created."""
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk unavailable: {exc}")
    r.withdraw()
    yield r
    try:
        r.destroy()
    except Exception:
        pass


@pytest.fixture
def tab(root):
    from gui.widgets.honeypot_tab import HoneypotTab
    widget = HoneypotTab(root)
    widget.pack()
    root.update_idletasks()
    yield widget
    try:
        widget.destroy()
    except Exception:
        pass


def _fake_alert(access: str = "modify") -> MagicMock:
    a = MagicMock()
    a.timestamp = datetime.now()
    a.access_type = access
    a.decoy_path = Path("C:/fake/passwords.xlsx")
    a.process_name = "evil.exe"
    a.process_id = 1234
    a.user = "Chris"
    return a


def test_toggle_starts_and_stops_monitor(tab):
    """Click flow: button toggles monitor on, then back off."""
    fake_manager = MagicMock()
    fake_manager.get_deployed_paths.return_value = [Path("C:/fake/decoy.xlsx")]

    monitor_instance = MagicMock()
    monitor_instance.is_running = True

    with patch("honeypot.decoy_manager.DecoyManager", return_value=fake_manager), \
         patch("honeypot.monitor.HoneypotMonitor", return_value=monitor_instance) as M:
        tab._on_toggle_monitor()

        M.assert_called_once()
        kwargs = M.call_args.kwargs
        assert kwargs["decoy_manager"] is fake_manager
        assert callable(kwargs["alert_callback"])

        monitor_instance.start.assert_called_once()
        assert tab.is_monitoring() is True
        assert tab.btn_monitor.cget("text") == "Stop monitoring"

    tab._on_toggle_monitor()
    monitor_instance.stop.assert_called_once()
    assert tab.is_monitoring() is False
    assert tab.btn_monitor.cget("text") == "Start monitoring"


def test_start_aborts_when_no_decoys_deployed(tab):
    """If no decoys are deployed, start path must be a no-op."""
    fake_manager = MagicMock()
    fake_manager.get_deployed_paths.return_value = []

    with patch("honeypot.decoy_manager.DecoyManager", return_value=fake_manager), \
         patch("honeypot.monitor.HoneypotMonitor") as M, \
         patch("tkinter.messagebox.showinfo"):
        tab._on_toggle_monitor()

    M.assert_not_called()
    assert tab.is_monitoring() is False


def test_render_alert_increments_count_and_styles(tab):
    """Direct render path - independent of threading."""
    tab._render_alert(_fake_alert("delete"))
    tab._render_alert(_fake_alert("modify"))

    assert tab._alert_count == 2
    label_text = tab.lbl_alerts.cget("text")
    assert "2 alerts" in label_text
    assert tab.lbl_alerts.cget("fg") == "#e74c3c"

    body = tab.alerts_text.get("1.0", "end")
    assert "DELETE" in body
    assert "MODIFY" in body
    assert "evil.exe" in body


def test_stop_when_not_running_is_safe(tab):
    """Calling stop_monitoring without an active monitor is a no-op."""
    assert tab._monitor is None
    tab.stop_monitoring()
    assert tab._monitor is None
    assert tab.is_monitoring() is False


def test_failed_start_resets_state(tab):
    """If monitor.start() raises, we must not be left in 'monitoring'."""
    fake_manager = MagicMock()
    fake_manager.get_deployed_paths.return_value = [Path("C:/fake/decoy.xlsx")]

    monitor_instance = MagicMock()
    monitor_instance.start.side_effect = RuntimeError("watchdog blew up")

    with patch("honeypot.decoy_manager.DecoyManager", return_value=fake_manager), \
         patch("honeypot.monitor.HoneypotMonitor", return_value=monitor_instance):
        tab._on_toggle_monitor()

    assert tab.is_monitoring() is False
    assert tab.btn_monitor.cget("text") == "Start monitoring"
