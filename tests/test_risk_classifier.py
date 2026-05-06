"""
Tests for core/risk_classifier.py.

Verifies the 4-tier risk classification system.
"""

from pathlib import Path

from core.models import Finding, RiskLevel, ScanResult
from core.risk_classifier import RiskClassifier


class TestRiskClassifier:
    """Tests for the RiskClassifier."""

    def setup_method(self) -> None:
        """Create a classifier for each test."""
        self.classifier = RiskClassifier()

    def test_no_findings_is_clean(self) -> None:
        """No findings should classify as CLEAN."""
        level, score = self.classifier.classify([])
        assert level == RiskLevel.CLEAN
        assert score == 0

    def test_low_score_is_low_risk(self) -> None:
        """Score < 30 should be LOW_RISK."""
        findings = [
            Finding(
                detector="test", description="minor",
                severity=15, evidence="test",
            ),
        ]
        level, _ = self.classifier.classify(findings)
        assert level == RiskLevel.LOW_RISK

    def test_medium_score_is_potential_risk(self) -> None:
        """Score 30-59 should be POTENTIAL_RISK."""
        findings = [
            Finding(
                detector="test", description="medium",
                severity=45, evidence="test",
            ),
        ]
        level, _ = self.classifier.classify(findings)
        assert level == RiskLevel.POTENTIAL_RISK

    def test_high_score_is_high_target(self) -> None:
        """Score 60-79 should be HIGH_TARGET."""
        findings = [
            Finding(
                detector="test", description="high",
                severity=70, evidence="test",
            ),
        ]
        level, _ = self.classifier.classify(findings)
        assert level == RiskLevel.HIGH_TARGET

    def test_critical_score_is_suspicious_code(self) -> None:
        """Score >= 80 should be SUSPICIOUS_CODE."""
        findings = [
            Finding(
                detector="test", description="critical",
                severity=90, evidence="test",
            ),
        ]
        level, _ = self.classifier.classify(findings)
        assert level == RiskLevel.SUSPICIOUS_CODE

    def test_scores_cumulate(self) -> None:
        """Multiple findings should add up."""
        findings = [
            Finding(
                detector="a", description="f1",
                severity=25, evidence="test",
            ),
            Finding(
                detector="b", description="f2",
                severity=40, evidence="test",
            ),
        ]
        score = self.classifier.calculate_score(findings)
        assert score == 65  # HIGH_TARGET range

    def test_score_capped_at_100(self) -> None:
        """Total score should cap at 100."""
        findings = [
            Finding(
                detector="a", description="f1",
                severity=80, evidence="test",
            ),
            Finding(
                detector="b", description="f2",
                severity=80, evidence="test",
            ),
        ]
        score = self.classifier.calculate_score(findings)
        assert score == 100

    def test_classify_results_groups_correctly(self) -> None:
        """classify_results should group by risk level."""
        results = [
            ScanResult(
                file_path=Path("clean.txt"),
                risk_level=RiskLevel.CLEAN,
                risk_score=0,
                findings=[],
            ),
            ScanResult(
                file_path=Path("bad.exe"),
                risk_level=RiskLevel.CLEAN,  # Will be reclassified
                risk_score=0,
                findings=[
                    Finding(
                        detector="test", description="malware",
                        severity=95, evidence="test",
                    ),
                ],
            ),
        ]
        classified = self.classifier.classify_results(results)
        assert len(classified["CLEAN"]) == 1
        assert len(classified["SUSPICIOUS_CODE"]) == 1

    def test_classify_results_preserves_location_modifier(self) -> None:
        """
        Regression: classify_results must reapply the location modifier
        and not clobber the score down to the raw severity sum.
        """
        finding = Finding(
            detector="test", description="medium",
            severity=50, evidence="test",
        )
        result = ScanResult(
            file_path=Path("C:/Users/x/AppData/Local/Temp/evil.exe"),
            risk_level=RiskLevel.CLEAN,
            risk_score=0,
            findings=[finding],
        )

        classified = self.classifier.classify_results([result])

        # Raw severity is 50 (POTENTIAL_RISK); +15 Temp modifier = 65
        # which should bump the file to HIGH_TARGET.
        assert result.risk_score == 65
        assert result.risk_level == RiskLevel.HIGH_TARGET
        assert len(classified["HIGH_TARGET"]) == 1

    def test_location_score_modifier(self) -> None:
        """Temp folder should add location modifier."""
        base_score = 50
        path = Path("C:/Users/test/AppData/Local/Temp/evil.exe")
        new_score = self.classifier.add_location_score(path, base_score)
        assert new_score > base_score  # Should add modifier

    def test_location_score_capped(self) -> None:
        """Location modifier should not exceed 100."""
        new_score = self.classifier.add_location_score(
            Path("C:/Users/x/AppData/Local/Temp/test.exe"), 95
        )
        assert new_score <= 100

    def test_custom_thresholds(self) -> None:
        """Should respect custom threshold configuration."""
        classifier = RiskClassifier(config={
            "critical_threshold": 90,
            "high_threshold": 70,
            "medium_threshold": 40,
        })
        # Score 85 is HIGH_TARGET with custom thresholds (not critical)
        findings = [
            Finding(
                detector="test", description="test",
                severity=85, evidence="test",
            ),
        ]
        level, _ = classifier.classify(findings)
        assert level == RiskLevel.HIGH_TARGET
