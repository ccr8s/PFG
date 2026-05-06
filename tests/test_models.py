"""
Tests for core/models.py - Data models.

Verifies that all data models serialize correctly and maintain
required fields.
"""

from datetime import datetime
from pathlib import Path

from core.models import (
    Finding,
    ForensicFinding,
    HoneypotAlert,
    RiskLevel,
    ScanResult,
    ScanSummary,
)


class TestRiskLevel:
    """Tests for the RiskLevel enum."""

    def test_risk_levels_ordered(self) -> None:
        """Risk levels should be ordered by severity."""
        assert RiskLevel.CLEAN.value < RiskLevel.LOW_RISK.value
        assert RiskLevel.LOW_RISK.value < RiskLevel.POTENTIAL_RISK.value
        assert RiskLevel.POTENTIAL_RISK.value < RiskLevel.HIGH_TARGET.value
        assert RiskLevel.HIGH_TARGET.value < RiskLevel.SUSPICIOUS_CODE.value

    def test_risk_level_labels(self) -> None:
        """Each risk level should have a human-readable label."""
        assert RiskLevel.SUSPICIOUS_CODE.label == "Suspicious Code"
        assert RiskLevel.CLEAN.label == "Clean"

    def test_risk_level_colors(self) -> None:
        """Each risk level should have a color code."""
        assert RiskLevel.SUSPICIOUS_CODE.color == "#ff0000"
        assert RiskLevel.CLEAN.color == "#888888"


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_creation(self) -> None:
        """Should create a finding with all required fields."""
        finding = Finding(
            detector="pattern_detector",
            description="Suspicious PowerShell command found",
            severity=85,
            evidence="Invoke-Mimikatz",
            attack_techniques=["T1003"],
            attack_tactics=["Credential Access"],
        )
        assert finding.detector == "pattern_detector"
        assert finding.severity == 85

    def test_finding_to_dict(self) -> None:
        """Finding.to_dict() should include MITRE ATT&CK fields."""
        finding = Finding(
            detector="test",
            description="test finding",
            severity=50,
            evidence="evidence",
            attack_techniques=["T1059"],
            attack_tactics=["Execution"],
            attack_confidence="high",
        )
        data = finding.to_dict()
        assert "mitre_attack" in data
        assert data["mitre_attack"]["techniques"] == ["T1059"]
        assert data["mitre_attack"]["confidence"] == "high"

    def test_finding_defaults(self) -> None:
        """Findings should have sensible defaults."""
        finding = Finding(
            detector="test",
            description="test",
            severity=0,
            evidence="",
        )
        assert finding.attack_techniques == []
        assert finding.attack_tactics == []
        assert finding.attack_confidence == "medium"
        assert finding.line_number is None
        assert finding.remediation is None


class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_scan_result_creation(self) -> None:
        """Should create a scan result with file info."""
        result = ScanResult(
            file_path=Path("C:/test/file.exe"),
            risk_level=RiskLevel.HIGH_TARGET,
            risk_score=75,
            file_hash_sha256="abc123",
            file_size=1024,
        )
        assert result.risk_score == 75
        assert result.risk_level == RiskLevel.HIGH_TARGET

    def test_scan_result_to_dict(self) -> None:
        """ScanResult.to_dict() should serialize all fields."""
        result = ScanResult(
            file_path=Path("test.exe"),
            risk_level=RiskLevel.SUSPICIOUS_CODE,
            risk_score=95,
            findings=[
                Finding(
                    detector="yara",
                    description="YARA match",
                    severity=90,
                    evidence="rule_match",
                    attack_techniques=["T1204"],
                    attack_tactics=["Execution"],
                ),
            ],
        )
        data = result.to_dict()
        assert data["risk_level"] == "SUSPICIOUS_CODE"
        assert data["risk_score"] == 95
        assert len(data["findings"]) == 1


class TestScanSummary:
    """Tests for the ScanSummary dataclass."""

    def test_duration_calculation(self) -> None:
        """Should calculate scan duration correctly."""
        start = datetime(2025, 1, 1, 12, 0, 0)
        end = datetime(2025, 1, 1, 12, 5, 30)
        summary = ScanSummary(
            scan_id="test-001",
            start_time=start,
            end_time=end,
        )
        assert summary.duration_seconds == 330.0

    def test_risk_counts(self) -> None:
        """Should count results by risk level."""
        summary = ScanSummary(
            scan_id="test-002",
            start_time=datetime.now(),
            results=[
                ScanResult(
                    file_path=Path("a.exe"),
                    risk_level=RiskLevel.SUSPICIOUS_CODE,
                    risk_score=90,
                ),
                ScanResult(
                    file_path=Path("b.exe"),
                    risk_level=RiskLevel.SUSPICIOUS_CODE,
                    risk_score=85,
                ),
                ScanResult(
                    file_path=Path("c.txt"),
                    risk_level=RiskLevel.LOW_RISK,
                    risk_score=10,
                ),
            ],
        )
        counts = summary.risk_counts
        assert counts["SUSPICIOUS_CODE"] == 2
        assert counts["LOW_RISK"] == 1


class TestForensicFinding:
    """Tests for the ForensicFinding dataclass."""

    def test_forensic_finding_to_dict(self) -> None:
        """Should serialize with ATT&CK mapping."""
        finding = ForensicFinding(
            source="event_log",
            description="Audit log cleared",
            severity=90,
            evidence="Event ID 1102",
            attack_techniques=["T1070.001"],
            attack_tactics=["Defense Evasion"],
        )
        data = finding.to_dict()
        assert data["source"] == "event_log"
        assert "T1070.001" in data["mitre_attack"]["techniques"]


class TestHoneypotAlert:
    """Tests for the HoneypotAlert dataclass."""

    def test_honeypot_alert_to_dict(self) -> None:
        """Should serialize alert data."""
        alert = HoneypotAlert(
            decoy_path=Path("C:/Users/Desktop/passwords.xlsx"),
            access_type="read",
            timestamp=datetime(2025, 6, 15, 10, 30, 0),
            process_name="explorer.exe",
            process_id=1234,
        )
        data = alert.to_dict()
        assert data["access_type"] == "read"
        assert data["process_name"] == "explorer.exe"
