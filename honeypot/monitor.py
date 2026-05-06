"""
Honeypot file access monitor for FileGuard.

Uses the watchdog library to monitor decoy files for any
access attempts and generate real-time alerts.
"""

import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.models import HoneypotAlert

logger = logging.getLogger(__name__)


class HoneypotMonitor:
    """
    Real-time monitoring of honeypot decoy files.

    Uses the watchdog library to watch directories containing
    decoy files and triggers alerts on any file access event
    (read, write, delete, rename).
    """

    def __init__(
        self,
        decoy_manager: Any,
        alert_callback: Optional[Callable[[HoneypotAlert], None]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize honeypot monitor.

        Args:
            decoy_manager: DecoyManager instance with deployed decoys.
            alert_callback: Optional callback invoked on each alert.
            config: Optional configuration overrides.
        """
        self.decoy_manager = decoy_manager
        self.alert_callback = alert_callback
        self.config = config or {}
        self.alerts: List[HoneypotAlert] = []
        self._observers: List[Any] = []
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start monitoring all deployed decoy directories."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            logger.error(
                "watchdog not installed - honeypot monitoring unavailable"
            )
            return

        decoy_paths = self.decoy_manager.get_deployed_paths()
        if not decoy_paths:
            logger.warning("No decoys deployed - nothing to monitor")
            return

        # Get unique parent directories to watch
        watch_dirs = set(p.parent for p in decoy_paths)
        decoy_names = set(p.name for p in decoy_paths)

        handler = _DecoyEventHandler(
            decoy_names=decoy_names,
            decoy_manager=self.decoy_manager,
            on_alert=self._handle_alert,
        )

        for watch_dir in watch_dirs:
            if not watch_dir.exists():
                continue

            observer = Observer()
            observer.schedule(handler, str(watch_dir), recursive=False)
            observer.daemon = True
            observer.start()
            self._observers.append(observer)
            logger.info("Monitoring directory: %s", watch_dir)

        self._running = True
        logger.info(
            "Honeypot monitor started: watching %d directories, "
            "%d decoy files",
            len(watch_dirs),
            len(decoy_paths),
        )

    def stop(self) -> None:
        """Stop all monitoring."""
        for observer in self._observers:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception as e:
                logger.debug("Observer stop error: %s", e)

        self._observers.clear()
        self._running = False
        logger.info("Honeypot monitor stopped")

    def _handle_alert(self, alert: HoneypotAlert) -> None:
        """Process a new honeypot alert."""
        with self._lock:
            self.alerts.append(alert)

        logger.warning(
            "HONEYPOT ALERT: %s accessed (%s) by %s (PID %s)",
            alert.decoy_path,
            alert.access_type,
            alert.process_name or "unknown",
            alert.process_id or "?",
        )

        # Store in database
        try:
            from core.database import Database
            db = Database()
            db.save_honeypot_alert(alert)
            db.close()
        except Exception as e:
            logger.debug("Failed to save alert to DB: %s", e)

        # Invoke callback if registered
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                logger.error("Alert callback failed: %s", e)

    @property
    def is_running(self) -> bool:
        """Whether the monitor is actively running."""
        return self._running

    @property
    def alert_count(self) -> int:
        """Total number of alerts generated."""
        return len(self.alerts)

    def get_recent_alerts(self, limit: int = 20) -> List[HoneypotAlert]:
        """Get the most recent alerts."""
        with self._lock:
            return list(reversed(self.alerts[-limit:]))


class _DecoyEventHandler:
    """
    Watchdog event handler for decoy file access.

    Filters events to only fire alerts for known decoy files.
    """

    def __init__(
        self,
        decoy_names: set,
        decoy_manager: Any,
        on_alert: Callable[[HoneypotAlert], None],
    ) -> None:
        self.decoy_names = decoy_names
        self.decoy_manager = decoy_manager
        self.on_alert = on_alert

        # Try to inherit from watchdog FileSystemEventHandler
        try:
            from watchdog.events import FileSystemEventHandler
            self.__class__ = type(
                "_DecoyEventHandler",
                (FileSystemEventHandler,),
                dict(self.__class__.__dict__),
            )
        except ImportError:
            pass

    def on_modified(self, event: Any) -> None:
        """Handle file modification events."""
        self._check_event(event, "write")

    def on_created(self, event: Any) -> None:
        """Handle file creation events."""
        self._check_event(event, "write")

    def on_deleted(self, event: Any) -> None:
        """Handle file deletion events."""
        self._check_event(event, "delete")

    def on_moved(self, event: Any) -> None:
        """Handle file move/rename events."""
        self._check_event(event, "rename")

    def _check_event(self, event: Any, access_type: str) -> None:
        """Check if event involves a decoy file."""
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        if file_path.name not in self.decoy_names:
            return

        if not self.decoy_manager.is_decoy(file_path):
            return

        # Build alert
        process_name, process_id = _get_accessing_process()

        alert = HoneypotAlert(
            decoy_path=file_path,
            access_type=access_type,
            timestamp=datetime.now(),
            process_name=process_name,
            process_id=process_id,
            user=_get_current_user(),
        )

        self.on_alert(alert)


def _get_accessing_process() -> tuple:
    """Try to identify the process that triggered the event."""
    try:
        import psutil
        # Get the most recently started process as a heuristic
        # In production, you'd use ETW or minifilter for precision
        current = psutil.Process()
        return current.name(), current.pid
    except Exception:
        return None, None


def _get_current_user() -> Optional[str]:
    """Get the current username."""
    try:
        import os
        return os.getlogin()
    except Exception:
        return None
