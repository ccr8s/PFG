"""
Tests for core/database.py - SQLite operations.

Uses temporary databases to verify storage and retrieval.
"""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from core.database import Database
from core.models import (
    Finding,
    ForensicFinding,
    HoneypotAlert,
    RiskLevel,
    ScanResult,
    ScanSummary,
)


@pytest.fixture
def db() -> Database:
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        database = Database(db_path)
        yield database
        database.close()


class TestDatabaseInit:
    """Tests for database initialization."""

    def test_creates_database_file(self) -> None:
        """Database file should be created on init."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            database = Database(db_path)
            assert db_path.exists()
            database.close()

    def test_creates_parent_directories(self) -> None:
        """Should create parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "sub" / "dir" / "test.db"
            database = Database(db_path)
            assert db_path.exists()
            database.close()


class TestScanOperations:
    """Tests for scan storage and retrieval."""

    def test_save_and_retrieve_scan(self, db: Database) -> None:
        """Should save a scan and retrieve it by ID."""
        summary = ScanSummary(
            scan_id="test-scan-001",
            start_time=datetime(2025, 1, 1, 12, 0, 0),
            end_time=datetime(2025, 1, 1, 12, 5, 0),
            target_path=Path("C:/test"),
            total_files=100,
            files_scanned=95,
            files_skipped=5,
        )
        db.save_scan(summary)

        result = db.get_scan("test-scan-001")
        assert result is not None
        assert result["scan_id"] == "test-scan-001"
        assert result["total_files"] == 100

    def test_save_scan_with_results(self, db: Database) -> None:
        """Should save scan results and findings."""
        finding = Finding(
            detector="pattern_detector",
            description="Suspicious pattern found",
            severity=75,
            evidence="invoke-mimikatz",
            attack_techniques=["T1003"],
            attack_tactics=["Credential Access"],
        )
        scan_result = ScanResult(
            file_path=Path("C:/test/malware.ps1"),
            risk_level=RiskLevel.SUSPICIOUS_CODE,
            risk_score=90,
            findings=[finding],
            file_hash_sha256="abc123",
            file_size=2048,
        )
        summary = ScanSummary(
            scan_id="test-scan-002",
            start_time=datetime.now(),
            results=[scan_result],
            files_scanned=1,
        )
        db.save_scan(summary)

        results = db.get_scan_results("test-scan-002")
        assert len(results) == 1
        assert results[0]["risk_level"] == "SUSPICIOUS_CODE"
        assert results[0]["risk_score"] == 90

    def test_get_nonexistent_scan_returns_none(self, db: Database) -> None:
        """Getting a nonexistent scan should return None."""
        result = db.get_scan("nonexistent")
        assert result is None

    def test_get_recent_scans(self, db: Database) -> None:
        """Should retrieve recent scans in order."""
        for i in range(3):
            summary = ScanSummary(
                scan_id=f"scan-{i}",
                start_time=datetime(2025, 1, i + 1),
            )
            db.save_scan(summary)

        scans = db.get_recent_scans(limit=2)
        assert len(scans) == 2


class TestForensicOperations:
    """Tests for forensic finding storage."""

    def test_save_and_retrieve_forensic_finding(
        self, db: Database
    ) -> None:
        """Should save and retrieve forensic findings."""
        finding = ForensicFinding(
            source="event_log",
            description="Audit log was cleared",
            severity=90,
            evidence="Event ID 1102 detected",
            attack_techniques=["T1070.001"],
            attack_tactics=["Defense Evasion"],
        )
        db.save_forensic_finding(finding)

        results = db.get_forensic_findings()
        assert len(results) >= 1
        assert results[0]["source"] == "event_log"

    def test_filter_forensic_by_source(self, db: Database) -> None:
        """Should filter forensic findings by source."""
        for source in ("event_log", "registry", "event_log"):
            db.save_forensic_finding(ForensicFinding(
                source=source,
                description=f"{source} finding",
                severity=50,
                evidence="test",
            ))

        results = db.get_forensic_findings(source="event_log")
        assert all(r["source"] == "event_log" for r in results)


class TestHoneypotOperations:
    """Tests for honeypot alert storage."""

    def test_save_and_retrieve_alert(self, db: Database) -> None:
        """Should save and retrieve honeypot alerts."""
        alert = HoneypotAlert(
            decoy_path=Path("C:/Users/Desktop/passwords.xlsx"),
            access_type="read",
            timestamp=datetime.now(),
            process_name="suspicious.exe",
            process_id=9999,
        )
        db.save_honeypot_alert(alert)

        alerts = db.get_honeypot_alerts()
        assert len(alerts) >= 1
        assert alerts[0]["access_type"] == "read"


class TestHashOperations:
    """Tests for hash database operations."""

    def test_add_and_check_hash(self, db: Database) -> None:
        """Should add and check known malware hashes."""
        db.add_known_hash(
            sha256="a" * 64,
            md5="b" * 32,
            malware_name="TestMalware",
            malware_family="TestFamily",
            severity=95,
        )

        result = db.check_hash("a" * 64)
        assert result is not None
        assert result["malware_name"] == "TestMalware"

    def test_check_unknown_hash_returns_none(self, db: Database) -> None:
        """Checking unknown hash should return None."""
        result = db.check_hash("unknown_hash")
        assert result is None
