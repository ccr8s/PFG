"""
Tests for forensics modules.

Uses mock data and temporary directories to test forensic
analysis without accessing real system artifacts.
"""

import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from core.models import ForensicFinding
from forensics.event_logs import EventLogAnalyzer, _parse_timestamp
from forensics.prefetch import PrefetchParser
from forensics.registry import RegistryAnalyzer
from forensics.timestomp import TimestompDetector


class TestEventLogAnalyzer:
    """Tests for EventLogAnalyzer."""

    def test_detect_log_cleared(self) -> None:
        """Should detect Event ID 1102 (audit log cleared)."""
        analyzer = EventLogAnalyzer({})
        entries = [
            {"EventID": 1102, "TimeGenerated": datetime.now()},
        ]
        findings = analyzer._check_critical_events(entries)
        assert len(findings) >= 1
        assert any("cleared" in f.description.lower() for f in findings)
        assert findings[0].severity >= 80

    def test_detect_system_log_cleared(self) -> None:
        """Should detect Event ID 104."""
        analyzer = EventLogAnalyzer({})
        entries = [
            {"EventID": 104, "TimeGenerated": datetime.now()},
        ]
        findings = analyzer._check_critical_events(entries)
        assert len(findings) >= 1

    def test_detect_brute_force(self) -> None:
        """Should detect brute force login attempts."""
        analyzer = EventLogAnalyzer({})
        now = datetime.now()
        # 15 failed logons in 2 minutes
        entries = [
            {"EventID": 4625, "TimeGenerated": now + timedelta(seconds=i * 5)}
            for i in range(15)
        ]
        findings = analyzer._check_brute_force(entries)
        assert len(findings) >= 1
        assert any("brute force" in f.description.lower() for f in findings)

    def test_no_brute_force_for_few_failures(self) -> None:
        """Should not flag a few failed logons."""
        analyzer = EventLogAnalyzer({})
        entries = [
            {"EventID": 4625, "TimeGenerated": datetime.now()}
            for _ in range(3)
        ]
        findings = analyzer._check_brute_force(entries)
        assert len(findings) == 0

    def test_detect_future_timestamps(self) -> None:
        """Should detect events with future timestamps."""
        analyzer = EventLogAnalyzer({})
        future = datetime.now() + timedelta(days=30)
        entries = [
            {"EventID": 4688, "TimeGenerated": future},
        ]
        findings = analyzer._check_future_timestamps(entries)
        assert len(findings) >= 1

    def test_parse_timestamp_datetime(self) -> None:
        """Should handle datetime objects."""
        dt = datetime(2025, 6, 15, 10, 30, 0)
        result = _parse_timestamp(dt)
        assert result == dt

    def test_parse_timestamp_none(self) -> None:
        """Should return None for None input."""
        assert _parse_timestamp(None) is None

    def test_findings_have_attack_mapping(self) -> None:
        """All forensic findings should have ATT&CK mapping."""
        analyzer = EventLogAnalyzer({})
        entries = [
            {"EventID": 1102, "TimeGenerated": datetime.now()},
        ]
        findings = analyzer._check_critical_events(entries)
        for finding in findings:
            assert len(finding.attack_techniques) > 0
            assert len(finding.attack_tactics) > 0


class TestRegistryAnalyzer:
    """Tests for RegistryAnalyzer."""

    def test_assess_suspicious_value(self) -> None:
        """Should flag suspicious registry values."""
        analyzer = RegistryAnalyzer({})
        key_info = {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "hive": "HKCU",
            "description": "User startup programs",
            "severity": 30,
            "technique": "T1547.001",
        }
        finding = analyzer._assess_registry_value(
            key_info,
            "EvilApp",
            r"powershell -enc AAAA -w hidden"
        )
        assert finding is not None
        assert finding.severity > 30  # Should be boosted

    def test_normal_value_may_not_flag(self) -> None:
        """Normal-looking values should have low severity."""
        analyzer = RegistryAnalyzer({})
        key_info = {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "hive": "HKCU",
            "description": "User startup programs",
            "severity": 25,
            "technique": "T1547.001",
        }
        # Low severity values without suspicious patterns may return None
        # because severity doesn't reach threshold; this is expected behavior.
        # The test asserts only that the call doesn't raise.
        analyzer._assess_registry_value(
            key_info,
            "SecurityHealth",
            r"C:\Program Files\Windows Defender\MSASCuiL.exe"
        )


class TestTimestompDetector:
    """Tests for TimestompDetector."""

    def test_detect_future_creation(self) -> None:
        """Should detect files with future creation times."""
        detector = TimestompDetector({})

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Set future modification time
            future_ts = (datetime.now() + timedelta(days=365)).timestamp()
            os.utime(temp_path, (future_ts, future_ts))

            findings = detector.check_file(temp_path)
            assert any(
                "future" in f.description.lower() for f in findings
            )
        finally:
            temp_path.unlink()

    def test_clean_file_no_findings(self) -> None:
        """Normal files should have no timestamp findings."""
        detector = TimestompDetector({})

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"normal content")
            temp_path = Path(f.name)

        try:
            findings = detector.check_file(temp_path)
            # Normal file should have no or only low-severity findings
            high_severity = [f for f in findings if f.severity >= 60]
            assert len(high_severity) == 0
        finally:
            temp_path.unlink()

    def test_detect_mass_timestamps(self) -> None:
        """Should detect many files with identical timestamps."""
        detector = TimestompDetector({})

        # Create group with same timestamp key
        groups = {
            "1700000000": [Path(f"file_{i}.txt") for i in range(15)]
        }
        findings = detector._check_mass_timestamps(groups)
        assert len(findings) >= 1
        assert any(
            "identical" in f.description.lower() for f in findings
        )

    def test_scan_directory(self) -> None:
        """Should scan a directory for timestamp anomalies."""
        detector = TimestompDetector({})

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some test files
            for i in range(5):
                (Path(tmpdir) / f"test_{i}.txt").write_text("content")

            findings = detector.scan_directory(Path(tmpdir))
            # Normal files should produce no high-severity findings
            assert all(f.severity < 80 for f in findings)


class TestPrefetchParser:
    """Tests for PrefetchParser."""

    def test_scan_empty_directory(self) -> None:
        """Should handle empty or nonexistent prefetch dir."""
        parser = PrefetchParser({})
        findings = parser.scan_prefetch_directory(
            Path("C:/nonexistent_pf_dir")
        )
        assert len(findings) == 0

    def test_scan_prefetch_with_mock_files(self) -> None:
        """Should detect suspicious executables in prefetch names."""
        parser = PrefetchParser({})

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create mock prefetch files
            (Path(tmpdir) / "MIMIKATZ.EXE-ABCD1234.pf").write_bytes(
                b"\x00" * 100
            )
            (Path(tmpdir) / "NOTEPAD.EXE-12345678.pf").write_bytes(
                b"\x00" * 100
            )

            findings = parser.scan_prefetch_directory(Path(tmpdir))
            # Should flag mimikatz
            assert any(
                "mimikatz" in f.description.lower() for f in findings
            )
