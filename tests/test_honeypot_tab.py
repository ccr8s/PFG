"""Smoke tests for the HoneypotTab + HoneypotAlertsTab wiring.

Skipped on headless environments where Tk can't open a root window.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture(scope="module")
def root():
    """Module-scoped Tk root.

    Re-creating Tk roots per test confuses Python 3.13's tcl/tk
    bootstrap on Windows ("Can't find tk.tcl"), so we reuse one root
    for every test in the module and just destroy children between.
    """
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
def alerts_tab(root):
    from gui.widgets.honeypot_alerts_tab import HoneypotAlertsTab
    widget = HoneypotAlertsTab(root)
    widget.pack()
    root.update_idletasks()
    yield widget
    try:
        widget.destroy()
    except Exception:
        pass


@pytest.fixture
def tab(root, alerts_tab):
    """HoneypotTab wired to a real HoneypotAlertsTab via callbacks."""
    from gui.widgets.honeypot_tab import HoneypotTab
    widget = HoneypotTab(
        root,
        on_alert=alerts_tab.add_alert,
        on_monitor_state=lambda monitoring, msg: alerts_tab.set_monitoring_state(
            monitoring=monitoring, message=msg
        ),
    )
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


# ----------------------------------------------------------------------
# HoneypotTab (controls / lifecycle)
# ----------------------------------------------------------------------


def test_toggle_starts_and_stops_monitor(tab, alerts_tab):
    fake_manager = MagicMock()
    fake_manager.get_deployed_paths.return_value = [Path("C:/fake/decoy.xlsx")]
    monitor = MagicMock()
    monitor.is_running = True

    with patch("honeypot.decoy_manager.DecoyManager", return_value=fake_manager), \
         patch("honeypot.monitor.HoneypotMonitor", return_value=monitor) as M:
        tab._on_toggle_monitor()

        M.assert_called_once()
        kwargs = M.call_args.kwargs
        assert kwargs["decoy_manager"] is fake_manager
        assert callable(kwargs["alert_callback"])

        monitor.start.assert_called_once()
        assert tab.is_monitoring() is True
        assert tab.btn_monitor.cget("text") == "Stop monitoring"
        # Alerts tab heard the state change.
        assert "Monitoring active" in alerts_tab.lbl_status.cget("text")

    tab._on_toggle_monitor()
    monitor.stop.assert_called_once()
    assert tab.is_monitoring() is False
    assert tab.btn_monitor.cget("text") == "Start monitoring"
    assert "Monitoring stopped" in alerts_tab.lbl_status.cget("text")


def test_start_aborts_when_no_decoys_deployed(tab):
    fake_manager = MagicMock()
    fake_manager.get_deployed_paths.return_value = []
    with patch("honeypot.decoy_manager.DecoyManager", return_value=fake_manager), \
         patch("honeypot.monitor.HoneypotMonitor") as M, \
         patch("tkinter.messagebox.showinfo"):
        tab._on_toggle_monitor()
    M.assert_not_called()
    assert tab.is_monitoring() is False


def test_failed_start_resets_state(tab):
    fake_manager = MagicMock()
    fake_manager.get_deployed_paths.return_value = [Path("C:/fake/decoy.xlsx")]
    monitor = MagicMock()
    monitor.start.side_effect = RuntimeError("watchdog blew up")
    with patch("honeypot.decoy_manager.DecoyManager", return_value=fake_manager), \
         patch("honeypot.monitor.HoneypotMonitor", return_value=monitor):
        tab._on_toggle_monitor()
    assert tab.is_monitoring() is False
    assert tab.btn_monitor.cget("text") == "Start monitoring"


def test_stop_when_not_running_is_safe(tab):
    assert tab._monitor is None
    tab.stop_monitoring()
    assert tab._monitor is None
    assert tab.is_monitoring() is False


# ----------------------------------------------------------------------
# HoneypotAlertsTab (passive feed)
# ----------------------------------------------------------------------


def test_add_alert_increments_count_and_styles(alerts_tab):
    alerts_tab.add_alert(_fake_alert("delete"))
    alerts_tab.add_alert(_fake_alert("modify"))

    assert alerts_tab.total_alerts == 2
    body = alerts_tab.alerts_text.get("1.0", "end")
    assert "DELETE" in body
    assert "MODIFY" in body
    assert "evil.exe" in body


def test_alerts_tab_marks_unread_until_viewed(root, alerts_tab):
    """Without notebook attachment, unread is still tracked."""
    notebook = MagicMock()
    notebook.index.return_value = 1  # not the alerts tab idx (0)
    alerts_tab._notebook = notebook
    alerts_tab._tab_index = 0

    alerts_tab.add_alert(_fake_alert("delete"))
    assert alerts_tab.unread_alerts == 1

    # Simulate user opening the alerts tab.
    notebook.index.return_value = 0
    alerts_tab.mark_viewed()
    assert alerts_tab.unread_alerts == 0


def test_alerts_tab_clear_resets(alerts_tab):
    alerts_tab.add_alert(_fake_alert("modify"))
    alerts_tab.add_alert(_fake_alert("delete"))
    assert alerts_tab.total_alerts == 2

    alerts_tab.clear()
    assert alerts_tab.total_alerts == 0
    assert alerts_tab.unread_alerts == 0
    body = alerts_tab.alerts_text.get("1.0", "end")
    assert "No alerts yet" in body


def test_flash_animation_starts_and_stops(root, alerts_tab):
    notebook = MagicMock()
    notebook.index.return_value = 99  # never the alerts tab
    notebook.tab = MagicMock()
    alerts_tab._notebook = notebook
    alerts_tab._tab_index = 0

    alerts_tab.add_alert(_fake_alert("modify"))
    # Flash should be scheduled.
    assert alerts_tab._flash_after_id is not None

    # Tab title should include the unread count.
    last_call = notebook.tab.call_args
    assert last_call.kwargs.get("text", "").endswith("(1)")

    # Now simulate viewing.
    notebook.index.return_value = 0
    alerts_tab.mark_viewed()
    assert alerts_tab._flash_after_id is None
    assert alerts_tab.unread_alerts == 0
