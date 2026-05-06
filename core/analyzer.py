"""
File analysis logic for FileGuard.

Orchestrates metadata extraction and builds comprehensive
file analysis results from multiple detectors.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import Finding, RiskLevel, ScanResult
from core.risk_classifier import RiskClassifier
from utils.file_utils import get_file_metadata
from utils.hash_utils import calculate_file_hashes

logger = logging.getLogger(__name__)


class FileAnalyzer:
    """
    Analyzes a single file using all registered detectors.

    Combines metadata extraction, hash calculation, and detector
    results into a comprehensive ScanResult.
    """

    def __init__(
        self,
        detectors: Optional[List[Any]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize file analyzer.

        Args:
            detectors: List of BaseDetector instances to run.
            config: Optional configuration overrides.
        """
        self.detectors = detectors or []
        self.config = config or {}
        self.classifier = RiskClassifier(
            config=self.config.get("risk", {})
        )
        self._max_read_size = (
            self.config.get("max_file_size_mb", 100) * 1024 * 1024
        )

    def analyze(self, file_path: Path) -> ScanResult:
        """
        Perform full analysis of a single file.

        Steps:
        1. Extract metadata (size, timestamps, attributes)
        2. Calculate file hashes (MD5, SHA-256)
        3. Read file content (up to max size)
        4. Run all applicable detectors
        5. Calculate risk score and classify

        Args:
            file_path: Path to the file to analyze.

        Returns:
            ScanResult with all findings and classification.

        Raises:
            FileNotFoundError: If file does not exist.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Initialize result with defaults
        result = ScanResult(
            file_path=file_path,
            risk_level=RiskLevel.CLEAN,
            risk_score=0,
            file_extension=file_path.suffix.lower(),
            scan_time=datetime.now(),
        )

        # Step 1: Extract metadata
        metadata = get_file_metadata(file_path)
        result.file_size = metadata.get("size", 0)
        result.created_time = metadata.get("created")
        result.modified_time = metadata.get("modified")
        result.metadata = metadata

        # Step 2: Calculate hashes
        try:
            hashes = calculate_file_hashes(file_path)
            result.file_hash_md5 = hashes.get("md5", "")
            result.file_hash_sha256 = hashes.get("sha256", "")
        except (PermissionError, OSError) as e:
            logger.warning("Cannot hash %s: %s", file_path, e)

        # Step 3: Read file content for detectors
        file_content: Optional[bytes] = None
        try:
            if result.file_size <= self._max_read_size:
                with open(file_path, "rb") as f:
                    file_content = f.read()
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read %s: %s", file_path, e)

        # Step 4: Run all detectors
        all_findings: List[Finding] = []
        for detector in self.detectors:
            try:
                if detector.is_applicable(file_path):
                    findings = detector.detect(file_path, file_content)
                    all_findings.extend(findings)
            except Exception as e:
                logger.error(
                    "Detector %s failed on %s: %s",
                    detector.name, file_path, e,
                )

        result.findings = all_findings

        # Step 5: Classify (also applies location modifier)
        self.classifier.classify_result(result)

        return result
