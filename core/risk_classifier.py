"""
Risk classification system for FileGuard.

Classifies scan results into four risk tiers based on
cumulative risk scores from all detectors.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.models import Finding, RiskLevel, ScanResult

logger = logging.getLogger(__name__)

# Default thresholds (can be overridden via config)
DEFAULT_CRITICAL_THRESHOLD = 80   # SUSPICIOUS_CODE: score >= 80
DEFAULT_HIGH_THRESHOLD = 60       # HIGH_TARGET: 60-79
DEFAULT_MEDIUM_THRESHOLD = 30     # POTENTIAL_RISK: 30-59
# LOW_RISK: score < 30 (and > 0)


class RiskClassifier:
    """
    Classifies files into risk tiers based on detector findings.

    Scoring factors:
    - Known malware hash match: +100
    - YARA rule match: +50-90 (based on rule severity)
    - High entropy (>7.5): +20
    - Suspicious location: +15
    - Double extension: +25
    - Hidden + executable: +30
    - Unsigned in system dir: +20
    - Recent creation in startup: +25
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize risk classifier.

        Args:
            config: Optional config with threshold overrides.
        """
        self.config = config or {}
        self.critical_threshold = self.config.get(
            "critical_threshold", DEFAULT_CRITICAL_THRESHOLD
        )
        self.high_threshold = self.config.get(
            "high_threshold", DEFAULT_HIGH_THRESHOLD
        )
        self.medium_threshold = self.config.get(
            "medium_threshold", DEFAULT_MEDIUM_THRESHOLD
        )

    def classify(
        self,
        findings: List[Finding],
        file_path: Optional[Path] = None,
    ) -> Tuple[RiskLevel, int]:
        """
        Determine the risk level and final score from findings.

        The risk score is the sum of all finding severities, capped at
        100. If ``file_path`` is provided, a location modifier (e.g.
        Temp, Startup, Recycle.Bin) is applied on top.

        Args:
            findings: List of findings for a single file.
            file_path: Optional file path for location-based scoring.

        Returns:
            Tuple of (RiskLevel, score) where score is 0-100.
        """
        score = self.calculate_score(findings)
        if file_path is not None:
            score = self.add_location_score(file_path, score)
        return self._score_to_level(score), score

    def calculate_score(self, findings: List[Finding]) -> int:
        """
        Calculate cumulative risk score from findings.

        Each finding contributes its severity score. The total
        is capped at 100.

        Args:
            findings: List of findings.

        Returns:
            Risk score between 0 and 100.
        """
        if not findings:
            return 0

        total = sum(f.severity for f in findings)
        return min(total, 100)

    def classify_result(self, result: ScanResult) -> ScanResult:
        """
        Update a ScanResult with the correct risk level and score.

        Reapplies the location modifier so this method is idempotent
        and safe to call after the analyzer has already populated
        ``risk_score``.

        Args:
            result: ScanResult to classify.

        Returns:
            The same ScanResult with updated risk_level and risk_score.
        """
        level, score = self.classify(result.findings, result.file_path)
        result.risk_score = score
        result.risk_level = level
        return result

    def classify_results(
        self, results: List[ScanResult]
    ) -> Dict[str, List[ScanResult]]:
        """
        Classify a list of scan results into risk tiers.

        Args:
            results: List of ScanResult objects.

        Returns:
            Dictionary mapping risk level names to lists of results.
        """
        classified: Dict[str, List[ScanResult]] = {
            "SUSPICIOUS_CODE": [],
            "HIGH_TARGET": [],
            "POTENTIAL_RISK": [],
            "LOW_RISK": [],
            "CLEAN": [],
        }

        for result in results:
            result = self.classify_result(result)
            classified[result.risk_level.name].append(result)

        # Log summary
        for level, items in classified.items():
            if items:
                logger.info("%s: %d files", level, len(items))

        return classified

    def _score_to_level(self, score: int) -> RiskLevel:
        """
        Convert numeric score to risk level.

        Args:
            score: Risk score 0-100.

        Returns:
            Corresponding RiskLevel.
        """
        if score >= self.critical_threshold:
            return RiskLevel.SUSPICIOUS_CODE
        elif score >= self.high_threshold:
            return RiskLevel.HIGH_TARGET
        elif score >= self.medium_threshold:
            return RiskLevel.POTENTIAL_RISK
        elif score > 0:
            return RiskLevel.LOW_RISK
        return RiskLevel.CLEAN

    def add_location_score(
        self, file_path: Path, base_score: int
    ) -> int:
        """
        Add score modifier based on file location.

        Args:
            file_path: Path to the file.
            base_score: Current score before location modifier.

        Returns:
            Updated score with location modifier.
        """
        path_str = str(file_path).lower()

        location_modifiers = {
            "\\appdata\\local\\temp": 15,
            "\\windows\\temp": 20,
            "\\startup": 25,
            "\\start menu\\programs\\startup": 25,
            "\\programdata": 10,
            "\\downloads": 10,
            "\\recycle.bin": 30,
            "\\$recycle.bin": 30,
        }

        modifier = 0
        for location, score_mod in location_modifiers.items():
            if location in path_str:
                modifier = max(modifier, score_mod)

        return min(base_score + modifier, 100)
