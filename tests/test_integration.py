"""
Integration tests for FileGuard.

Tests end-to-end workflows across multiple modules.
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestScanWorkflow:
    """Test the full scan-to-report workflow."""

    def test_scan_directory_produces_summary(self, tmp_path: Path) -> None:
        """Scanning a directory yields a ScanSummary with results."""
        # Create test files
        (tmp_path / "clean.txt").write_text("Hello world")
        (tmp_path / "suspicious.ps1").write_text(
            "Invoke-Expression (New-Object Net.WebClient).DownloadString"
        )

        from core.scanner import FileScanner

        scanner = FileScanner()
        summary = scanner.scan_full(tmp_path)

        assert summary is not None
        assert summary.files_scanned >= 1
        assert isinstance(summary.results, list)

    def test_scan_result_has_risk_levels(self, tmp_path: Path) -> None:
        """Each scan result has a valid RiskLevel."""
        (tmp_path / "test.txt").write_text("normal text content")

        from core.models import RiskLevel
        from core.scanner import FileScanner

        scanner = FileScanner()
        summary = scanner.scan_full(tmp_path)

        for result in summary.results:
            assert isinstance(result.risk_level, RiskLevel)
            assert isinstance(result.risk_score, int)


class TestReportExport:
    """Test report generation from scan results."""

    def _make_results(self) -> list:
        """Create mock scan results for testing."""
        from core.models import Finding, RiskLevel, ScanResult

        return [
            ScanResult(
                file_path=Path("C:/test/clean.txt"),
                risk_level=RiskLevel.CLEAN,
                risk_score=0,
                file_size=100,
            ),
            ScanResult(
                file_path=Path("C:/test/suspicious.ps1"),
                risk_level=RiskLevel.SUSPICIOUS_CODE,
                risk_score=85,
                file_size=2048,
                findings=[
                    Finding(
                        detector="pattern",
                        description="PowerShell download cradle",
                        severity=85,
                        evidence="Invoke-Expression",
                        attack_techniques=["T1059.001"],
                        attack_tactics=["TA0002"],
                    )
                ],
            ),
        ]

    def test_export_json(self, tmp_path: Path) -> None:
        """JSON export creates valid JSON file."""
        from utils.report_generator import ReportGenerator

        results = self._make_results()
        gen = ReportGenerator(results)
        output = tmp_path / "report.json"
        gen.export_json(output)

        assert output.exists()
        data = json.loads(output.read_text(encoding="utf-8"))
        assert data["total_files"] == 2
        assert "results" in data

    def test_export_csv(self, tmp_path: Path) -> None:
        """CSV export creates valid CSV file."""
        from utils.report_generator import ReportGenerator

        results = self._make_results()
        gen = ReportGenerator(results)
        output = tmp_path / "report.csv"
        gen.export_csv(output)

        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "File Path" in content
        assert "Risk Level" in content

    def test_export_html(self, tmp_path: Path) -> None:
        """HTML export creates valid HTML file."""
        from utils.report_generator import ReportGenerator

        results = self._make_results()
        gen = ReportGenerator(results)
        output = tmp_path / "report.html"
        gen.export_html(output)

        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "FileGuard" in content


class TestMitreAttackIntegration:
    """Test ATT&CK mapping across the detection pipeline."""

    def test_mapper_loads_techniques(self) -> None:
        """MitreAttackMapper loads technique database."""
        from core.mitre_attack import MitreAttackMapper

        mapper = MitreAttackMapper()
        assert len(mapper.techniques) > 0

    def test_technique_lookup(self) -> None:
        """Individual technique lookup works."""
        from core.mitre_attack import MitreAttackMapper

        mapper = MitreAttackMapper()
        tech = mapper.get_technique("T1059.001")
        assert tech is not None
        assert tech.name == "PowerShell"

    def test_navigator_layer_export(self) -> None:
        """ATT&CK Navigator layer JSON is valid."""
        from core.mitre_attack import MitreAttackMapper

        mapper = MitreAttackMapper()
        mapping = mapper.map_finding(["T1059.001", "T1105"])
        layer = mapper.generate_navigator_layer([mapping])

        assert layer["domain"] == "enterprise-attack"
        assert len(layer["techniques"]) > 0

    def test_unknown_technique_handled(self) -> None:
        """Unknown technique IDs don't crash the mapper."""
        from core.mitre_attack import MitreAttackMapper

        mapper = MitreAttackMapper()
        mapping = mapper.map_finding(["T9999.999"])
        assert len(mapping.techniques) == 0


class TestSigmaEngine:
    """Test Sigma rule loading and matching."""

    def test_engine_loads_rules(self) -> None:
        """SigmaEngine loads rules from the rules directory."""
        from detectors.sigma_detector import SigmaEngine

        engine = SigmaEngine()
        assert len(engine.rules) > 0

    def test_event_log_cleared_match(self) -> None:
        """Event log cleared rule matches EventID 1102."""
        from detectors.sigma_detector import SigmaEngine

        engine = SigmaEngine()
        log_entry = {"EventID": 1102}
        matches = engine.match_log_entry(log_entry, "Security")

        rule_ids = [m.rule.id for m in matches]
        assert "d99b79d6-0b47-4f9d-8cc4-8bf09e76b1fa" in rule_ids

    def test_sigma_match_to_finding(self) -> None:
        """SigmaMatch.to_finding() produces valid finding dict."""
        from detectors.sigma_detector import SigmaEngine

        engine = SigmaEngine()
        log_entry = {"EventID": 1102}
        matches = engine.match_log_entry(log_entry, "Security")

        assert len(matches) > 0
        finding = matches[0].to_finding()
        assert finding["detector"] == "sigma"
        assert finding["severity"] > 0


class TestHoneypotWorkflow:
    """Test honeypot deploy/monitor lifecycle."""

    def test_deploy_and_remove_decoys(self) -> None:
        """Deploy creates files, remove cleans them up."""
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            patches = [
                patch("honeypot.decoy_manager.TESTING_MODE", True),
                patch("honeypot.decoy_manager.SANDBOX_ROOT", sandbox),
                patch("utils.safety.TESTING_MODE", True),
                patch("utils.safety.SANDBOX_ROOT", sandbox),
            ]
            for p in patches:
                p.start()
            try:
                from honeypot.decoy_manager import DecoyManager

                manager = DecoyManager()
                deployed = manager.deploy_decoys()

                assert len(deployed) > 0
                for p in deployed:
                    assert p.exists()

                status = manager.get_status()
                assert status["deployed_count"] > 0
                assert status["active_count"] > 0

                removed = manager.remove_all_decoys()
                assert removed > 0
            finally:
                for p in reversed(patches):
                    p.stop()


class TestDatabasePersistence:
    """Test database save/load round-trips."""

    def test_save_and_retrieve_scan(self) -> None:
        """Scan results survive a database round-trip."""
        from core.database import Database
        from core.models import Finding, RiskLevel, ScanResult, ScanSummary

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db = Database(db_path)

            summary = ScanSummary(
                scan_id="test-001",
                start_time=datetime.now(),
                end_time=datetime.now(),
                target_path=Path("C:/test"),
                total_files=1,
                files_scanned=1,
            )

            result = ScanResult(
                file_path=Path("C:/test/file.exe"),
                risk_level=RiskLevel.HIGH_TARGET,
                risk_score=60,
                file_hash_sha256="abc123",
                file_size=4096,
            )

            db.save_scan(summary)
            db.save_scan_result("test-001", result)

            recent = db.get_recent_scans(limit=1)
            assert len(recent) == 1

            db.close()
        finally:
            os.unlink(db_path)


class TestRiskClassifier:
    """Test risk classification logic."""

    def test_clean_file(self) -> None:
        """File with no findings is classified as CLEAN."""
        from core.models import RiskLevel
        from core.risk_classifier import RiskClassifier

        classifier = RiskClassifier()
        level, score = classifier.classify([], Path("test.txt"))
        assert level == RiskLevel.CLEAN
        assert score == 0

    def test_high_score_is_suspicious(self) -> None:
        """High-scoring findings produce SUSPICIOUS_CODE."""
        from core.models import Finding, RiskLevel
        from core.risk_classifier import RiskClassifier

        findings = [
            Finding(
                detector="yara",
                description="Mimikatz detected",
                severity=95,
                evidence="sekurlsa::logonpasswords",
            ),
        ]

        classifier = RiskClassifier()
        level, score = classifier.classify(findings, Path("evil.exe"))
        assert level in (
            RiskLevel.SUSPICIOUS_CODE, RiskLevel.HIGH_TARGET
        )
        assert score > 0
