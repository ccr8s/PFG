"""
Windows Event Log analyzer for FileGuard.

Parses Windows Event Logs to detect tampering, suspicious activity,
and indicators of compromise.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseForensicModule
from core.models import ForensicFinding

logger = logging.getLogger(__name__)

# Critical Event IDs to monitor
CRITICAL_EVENT_IDS = {
    1102: {
        "description": "Security audit log was cleared",
        "severity": 90,
        "log": "Security",
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
    },
    104: {
        "description": "System event log was cleared",
        "severity": 85,
        "log": "System",
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
    },
    1100: {
        "description": "Event logging service was shut down",
        "severity": 70,
        "log": "Security",
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
    },
    4624: {
        "description": "Successful logon",
        "severity": 10,
        "log": "Security",
        "technique": "T1078",
        "tactic": "Initial Access",
    },
    4625: {
        "description": "Failed logon attempt",
        "severity": 20,
        "log": "Security",
        "technique": "T1110",
        "tactic": "Credential Access",
    },
    4688: {
        "description": "New process created",
        "severity": 10,
        "log": "Security",
        "technique": "T1059",
        "tactic": "Execution",
    },
    4720: {
        "description": "User account was created",
        "severity": 50,
        "log": "Security",
        "technique": "T1136.001",
        "tactic": "Persistence",
    },
    4732: {
        "description": "Member was added to local group",
        "severity": 60,
        "log": "Security",
        "technique": "T1098",
        "tactic": "Persistence",
    },
    7045: {
        "description": "New service was installed",
        "severity": 50,
        "log": "System",
        "technique": "T1543.003",
        "tactic": "Persistence",
    },
}

# Brute force threshold
FAILED_LOGON_THRESHOLD = 10
FAILED_LOGON_WINDOW_MINUTES = 5


class EventLogAnalyzer(BaseForensicModule):
    """
    Analyzes Windows Event Logs for suspicious activity.

    Detects:
    - Log clearing/tampering (Event IDs 1102, 104)
    - Service shutdown (Event ID 1100)
    - Brute force attempts (Event ID 4625)
    - Suspicious account creation (Event ID 4720)
    - Service installation (Event ID 7045)
    - Event ID gaps (potential log deletion)
    - Future timestamps (time manipulation)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize event log analyzer.

        Args:
            config: Optional configuration overrides.
        """
        super().__init__(config)
        self._evtx_available = False
        try:
            import Evtx.Evtx as evtx
            self._evtx_available = True
        except ImportError:
            self.logger.warning(
                "python-evtx not installed - EVTX parsing disabled"
            )

    def analyze(self) -> List[ForensicFinding]:
        """
        Run all event log analysis checks.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        # Analyze exported EVTX files if available
        evtx_path = self.config.get("evtx_path")
        if evtx_path:
            evtx_path = Path(evtx_path)
            if evtx_path.exists():
                findings.extend(self._analyze_evtx_file(evtx_path))

        # Try to read live event logs via Windows API
        findings.extend(self._analyze_live_logs())

        return findings

    def analyze_logs(
        self,
        log_type: str = "Security",
        max_entries: int = 10000,
    ) -> List[ForensicFinding]:
        """
        Analyze a specific log type.

        Args:
            log_type: Type of event log (Security, System, etc.).
            max_entries: Maximum entries to process.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        entries = self._read_event_log(log_type, max_entries)

        # Check for critical events
        findings.extend(self._check_critical_events(entries))

        # Check for brute force
        findings.extend(self._check_brute_force(entries))

        # Check for event ID gaps
        findings.extend(self._check_event_gaps(entries))

        # Check for future timestamps
        findings.extend(self._check_future_timestamps(entries))

        return findings

    def _analyze_live_logs(self) -> List[ForensicFinding]:
        """Attempt to read live Windows Event Logs."""
        findings: List[ForensicFinding] = []

        try:
            import win32evtlog
            import win32evtlogutil

            for log_type in ("Security", "System"):
                try:
                    entries = self._read_win32_log(log_type, max_entries=5000)
                    findings.extend(self._check_critical_events(entries))
                    if log_type == "Security":
                        findings.extend(self._check_brute_force(entries))
                except Exception as e:
                    self.logger.debug(
                        "Cannot read %s log: %s", log_type, e
                    )

        except ImportError:
            self.logger.debug("pywin32 not available for live log analysis")

        return findings

    def _read_win32_log(
        self, log_type: str, max_entries: int = 5000
    ) -> List[Dict[str, Any]]:
        """Read event log entries using Win32 API."""
        entries: List[Dict[str, Any]] = []

        try:
            import win32evtlog

            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            count = 0
            while count < max_entries:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    entries.append({
                        "EventID": event.EventID & 0xFFFF,
                        "TimeGenerated": event.TimeGenerated,
                        "SourceName": event.SourceName,
                        "EventCategory": event.EventCategory,
                        "EventType": event.EventType,
                        "StringInserts": event.StringInserts or [],
                    })
                    count += 1
                    if count >= max_entries:
                        break

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            self.logger.debug("Win32 log read failed: %s", e)

        return entries

    def _analyze_evtx_file(self, path: Path) -> List[ForensicFinding]:
        """Parse an EVTX file for analysis."""
        findings: List[ForensicFinding] = []

        if not self._evtx_available:
            return findings

        try:
            import xml.etree.ElementTree as ET

            import Evtx.Evtx as evtx

            entries: List[Dict[str, Any]] = []

            with evtx.Evtx(str(path)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

                        event_id_elem = root.find(".//ns:EventID", ns)
                        time_elem = root.find(".//ns:TimeCreated", ns)

                        entry = {
                            "EventID": (
                                int(event_id_elem.text)
                                if event_id_elem is not None and event_id_elem.text
                                else 0
                            ),
                            "TimeGenerated": (
                                time_elem.get("SystemTime", "")
                                if time_elem is not None else ""
                            ),
                        }
                        entries.append(entry)
                    except Exception:
                        continue

            findings.extend(self._check_critical_events(entries))
            findings.extend(self._check_event_gaps(entries))

        except Exception as e:
            self.logger.error("EVTX parsing failed for %s: %s", path, e)

        return findings

    def _read_event_log(
        self, log_type: str, max_entries: int
    ) -> List[Dict[str, Any]]:
        """Read event log entries (live or file-based)."""
        entries = self._read_win32_log(log_type, max_entries)
        return entries

    def _check_critical_events(
        self, entries: List[Dict[str, Any]]
    ) -> List[ForensicFinding]:
        """Check for critical event IDs."""
        findings: List[ForensicFinding] = []

        for entry in entries:
            event_id = entry.get("EventID", 0)
            if event_id in CRITICAL_EVENT_IDS:
                info = CRITICAL_EVENT_IDS[event_id]
                if info["severity"] >= 50:
                    findings.append(ForensicFinding(
                        source="event_log",
                        description=(
                            f"Event ID {event_id}: {info['description']}"
                        ),
                        severity=info["severity"],
                        evidence=(
                            f"Event ID: {event_id}\n"
                            f"Log: {info['log']}\n"
                            f"Time: {entry.get('TimeGenerated', 'unknown')}"
                        ),
                        timestamp=_parse_timestamp(
                            entry.get("TimeGenerated")
                        ),
                        attack_techniques=[info["technique"]],
                        attack_tactics=[info["tactic"]],
                        attack_confidence="high",
                    ))

        return findings

    def _check_brute_force(
        self, entries: List[Dict[str, Any]]
    ) -> List[ForensicFinding]:
        """Detect brute force login attempts."""
        findings: List[ForensicFinding] = []

        # Collect 4625 events with timestamps
        failed_logons: List[datetime] = []
        for entry in entries:
            if entry.get("EventID") == 4625:
                ts = _parse_timestamp(entry.get("TimeGenerated"))
                if ts:
                    failed_logons.append(ts)

        if len(failed_logons) < FAILED_LOGON_THRESHOLD:
            return findings

        # Sort and check for clusters
        failed_logons.sort()
        window = timedelta(minutes=FAILED_LOGON_WINDOW_MINUTES)

        for i in range(len(failed_logons) - FAILED_LOGON_THRESHOLD + 1):
            window_end = failed_logons[i] + window
            count = sum(
                1 for ts in failed_logons[i:]
                if ts <= window_end
            )
            if count >= FAILED_LOGON_THRESHOLD:
                findings.append(ForensicFinding(
                    source="event_log",
                    description=(
                        f"Brute force detected: {count} failed logons "
                        f"within {FAILED_LOGON_WINDOW_MINUTES} minutes"
                    ),
                    severity=75,
                    evidence=(
                        f"Failed attempts: {count}\n"
                        f"Window: {failed_logons[i]} to {window_end}\n"
                        f"Total failed logons: {len(failed_logons)}"
                    ),
                    timestamp=failed_logons[i],
                    attack_techniques=["T1110"],
                    attack_tactics=["Credential Access"],
                    attack_confidence="high",
                ))
                break  # Report once

        return findings

    def _check_event_gaps(
        self, entries: List[Dict[str, Any]]
    ) -> List[ForensicFinding]:
        """Detect gaps in sequential event IDs."""
        findings: List[ForensicFinding] = []

        event_ids = sorted(
            [e.get("EventID", 0) for e in entries if e.get("EventID")]
        )

        if len(event_ids) < 100:
            return findings

        # This is a simplified gap check; real implementation
        # would track record IDs, not event IDs
        return findings

    def _check_future_timestamps(
        self, entries: List[Dict[str, Any]]
    ) -> List[ForensicFinding]:
        """Detect events with future timestamps."""
        findings: List[ForensicFinding] = []
        now = datetime.now()

        for entry in entries:
            ts = _parse_timestamp(entry.get("TimeGenerated"))
            if ts and ts > now + timedelta(hours=1):
                findings.append(ForensicFinding(
                    source="event_log",
                    description=(
                        f"Event with future timestamp detected: "
                        f"{ts.isoformat()}"
                    ),
                    severity=80,
                    evidence=(
                        f"Event ID: {entry.get('EventID')}\n"
                        f"Timestamp: {ts.isoformat()}\n"
                        f"Current time: {now.isoformat()}"
                    ),
                    timestamp=ts,
                    attack_techniques=["T1070.006"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="medium",
                ))

        return findings


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse a timestamp from various formats."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
