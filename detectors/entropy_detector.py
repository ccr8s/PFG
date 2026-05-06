"""
Entropy-based detection module for FileGuard.

Calculates Shannon entropy to identify packed, encrypted,
or obfuscated files.
"""

import logging
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseDetector
from core.models import Finding

logger = logging.getLogger(__name__)

# Entropy thresholds
HIGH_ENTROPY_THRESHOLD = 7.5    # Likely packed/encrypted
SUSPICIOUS_ENTROPY_THRESHOLD = 7.0  # Worth investigating
MAX_READ_SIZE = 10 * 1024 * 1024  # 10 MB max for entropy calc


class EntropyDetector(BaseDetector):
    """
    Detects files with suspicious entropy levels.

    High entropy indicates the file may be packed, encrypted,
    or contains obfuscated content. Values range from 0 (uniform)
    to 8 (perfectly random/encrypted).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize entropy detector.

        Args:
            config: Optional config with threshold overrides.
        """
        super().__init__(config)
        self.high_threshold = self.config.get(
            "high_threshold", HIGH_ENTROPY_THRESHOLD
        )
        self.suspicious_threshold = self.config.get(
            "suspicious_threshold", SUSPICIOUS_ENTROPY_THRESHOLD
        )

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Analyze file entropy and return findings if suspicious.

        Args:
            file_path: Path to the file.
            file_content: Optional pre-read file content.

        Returns:
            List of findings for high-entropy files.
        """
        findings: List[Finding] = []

        try:
            if file_content is None:
                with open(file_path, "rb") as f:
                    file_content = f.read(MAX_READ_SIZE)

            if len(file_content) < 256:
                return findings  # Too small for meaningful entropy

            entropy = calculate_entropy(file_content)

            if entropy >= self.high_threshold:
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Very high entropy ({entropy:.2f}) - "
                        f"file may be packed or encrypted"
                    ),
                    severity=self._score_entropy(entropy),
                    evidence=f"Shannon entropy: {entropy:.4f} / 8.0",
                    remediation=(
                        "Investigate file with hex editor or PE analyzer. "
                        "High entropy may indicate packing (UPX, Themida) "
                        "or encryption."
                    ),
                    attack_techniques=["T1027", "T1027.002"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence=(
                        "high" if entropy >= 7.8 else "medium"
                    ),
                ))
            elif entropy >= self.suspicious_threshold:
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Elevated entropy ({entropy:.2f}) - "
                        f"possible obfuscation"
                    ),
                    severity=self._score_entropy(entropy),
                    evidence=f"Shannon entropy: {entropy:.4f} / 8.0",
                    remediation=(
                        "Review file contents for obfuscation patterns."
                    ),
                    attack_techniques=["T1027"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="low",
                ))

        except PermissionError:
            logger.warning("Permission denied reading %s", file_path)
        except Exception as e:
            logger.error("Entropy analysis failed for %s: %s", file_path, e)

        return findings

    def _score_entropy(self, entropy: float) -> int:
        """
        Convert entropy value to a severity score (0-100).

        Args:
            entropy: Shannon entropy value (0-8).

        Returns:
            Severity score.
        """
        if entropy >= 7.9:
            return 40  # Very high
        elif entropy >= 7.5:
            return 30  # High
        elif entropy >= 7.0:
            return 20  # Suspicious
        return 10  # Mildly elevated


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.

    Args:
        data: Byte sequence to analyze.

    Returns:
        Entropy value between 0.0 and 8.0.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_section_entropy(
    data: bytes, section_size: int = 4096
) -> List[float]:
    """
    Calculate entropy for each section of a file.

    Useful for detecting packed executables where only certain
    sections have high entropy.

    Args:
        data: File content as bytes.
        section_size: Size of each section to analyze.

    Returns:
        List of entropy values for each section.
    """
    sections: List[float] = []
    for i in range(0, len(data), section_size):
        section = data[i:i + section_size]
        if len(section) >= 64:
            sections.append(calculate_entropy(section))
    return sections
