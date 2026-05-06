"""
Pattern-based detection module for FileGuard.

Detects suspicious strings, LOLBins abuse, obfuscated commands,
and known malware tool patterns using the signatures database.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.base import BaseDetector
from core.models import Finding

logger = logging.getLogger(__name__)

# Maximum bytes to read for text pattern analysis
MAX_CONTENT_SIZE = 5 * 1024 * 1024  # 5 MB

# File extensions to scan for text patterns
TEXT_SCANNABLE_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".txt", ".log", ".csv",
    ".py", ".rb", ".pl",
    ".xml", ".html", ".htm",
    ".ini", ".cfg", ".conf",
    ".reg",
}


class PatternDetector(BaseDetector):
    """
    Detects suspicious patterns in file contents.

    Loads patterns from config/signatures.yaml and matches them
    against file contents. Includes LOLBins detection, malware
    tool names, and obfuscated command patterns.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize pattern detector and load signatures.

        Args:
            config: Optional config overrides.
        """
        super().__init__(config)
        self._signatures: Dict[str, Any] = {}
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Load detection signatures from YAML file."""
        signatures_path = self.config.get("signatures_path")

        if signatures_path is None:
            project_root = Path(__file__).resolve().parent.parent
            signatures_path = project_root / "config" / "signatures.yaml"
        else:
            signatures_path = Path(signatures_path)

        if not signatures_path.exists():
            self.logger.warning(
                "Signatures file not found: %s", signatures_path
            )
            return

        try:
            with open(signatures_path, "r", encoding="utf-8") as f:
                self._signatures = yaml.safe_load(f) or {}
            self.logger.info(
                "Loaded signatures from %s", signatures_path
            )
        except Exception as e:
            self.logger.error("Failed to load signatures: %s", e)

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Scan file content for suspicious patterns.

        Args:
            file_path: Path to the file.
            file_content: Optional pre-read content.

        Returns:
            List of findings for matched patterns.
        """
        findings: List[Finding] = []

        try:
            # Read content if not provided
            if file_content is None:
                try:
                    with open(file_path, "rb") as f:
                        file_content = f.read(MAX_CONTENT_SIZE)
                except (PermissionError, OSError) as e:
                    self.logger.debug("Cannot read %s: %s", file_path, e)
                    return findings

            # Decode to text for pattern matching
            try:
                text_content = file_content.decode("utf-8", errors="replace").lower()
            except Exception:
                text_content = file_content.decode("latin-1", errors="replace").lower()

            # Run all pattern checks
            findings.extend(self._check_powershell_patterns(text_content, file_path))
            findings.extend(self._check_cmd_patterns(text_content, file_path))
            findings.extend(self._check_tool_names(text_content, file_path))
            findings.extend(self._check_network_indicators(text_content, file_path))
            findings.extend(self._check_ransomware_indicators(text_content, file_path))
            findings.extend(self._check_double_extension(file_path))
            findings.extend(self._check_suspicious_extension(file_path))

        except Exception as e:
            self.logger.error("Pattern detection failed for %s: %s", file_path, e)

        return findings

    def is_applicable(self, file_path: Path) -> bool:
        """Check if file should be scanned for text patterns."""
        ext = file_path.suffix.lower()
        # Scan text-based files, or any file if small enough
        if ext in TEXT_SCANNABLE_EXTENSIONS:
            return True
        # Also scan small files of any type
        try:
            return file_path.stat().st_size < MAX_CONTENT_SIZE
        except OSError:
            return False

    def _check_powershell_patterns(
        self, content: str, file_path: Path
    ) -> List[Finding]:
        """Check for suspicious PowerShell patterns."""
        findings: List[Finding] = []
        patterns = self._signatures.get("powershell", {}).get("critical", [])

        for entry in patterns:
            pattern = entry.get("pattern", "").lower()
            if pattern and pattern in content:
                findings.append(Finding(
                    detector=self.name,
                    description=entry.get("description", "Suspicious PowerShell pattern"),
                    severity=entry.get("score", 50),
                    evidence=f"Pattern matched: {entry['pattern']}",
                    remediation=(
                        "Suspicious PowerShell activity found. "
                        "Do not run this file. Click here for steps."
                    ),
                    attack_techniques=["T1059.001"],
                    attack_tactics=["Execution"],
                    attack_confidence=(
                        "high" if entry.get("score", 0) >= 80 else "medium"
                    ),
                ))

        return findings

    def _check_cmd_patterns(
        self, content: str, file_path: Path
    ) -> List[Finding]:
        """Check for suspicious CMD/batch patterns."""
        findings: List[Finding] = []
        patterns = self._signatures.get("cmd_batch", {}).get("critical", [])

        for entry in patterns:
            pattern = entry.get("pattern", "").lower()
            if pattern and pattern in content:
                findings.append(Finding(
                    detector=self.name,
                    description=entry.get("description", "Suspicious command pattern"),
                    severity=entry.get("score", 50),
                    evidence=f"Pattern matched: {entry['pattern']}",
                    remediation="Suspicious batch script found. Do not run this file. Click here for steps.",
                    attack_techniques=["T1059.003"],
                    attack_tactics=["Execution"],
                    attack_confidence=(
                        "high" if entry.get("score", 0) >= 80 else "medium"
                    ),
                ))

        return findings

    def _check_tool_names(
        self, content: str, file_path: Path
    ) -> List[Finding]:
        """Check for known malware tool names."""
        findings: List[Finding] = []
        tools = self._signatures.get("tool_names", {}).get("critical", [])

        for entry in tools:
            pattern = entry.get("pattern", "").lower()
            if pattern and pattern in content:
                findings.append(Finding(
                    detector=self.name,
                    description=entry.get("description", "Known malware tool"),
                    severity=entry.get("score", 80),
                    evidence=f"Tool reference found: {entry['pattern']}",
                    remediation=(
                        "Known hacking tool detected. "
                        "Do not open this file. Click here for steps."
                    ),
                    attack_techniques=["T1588.002"],
                    attack_tactics=["Resource Development"],
                    attack_confidence="high",
                ))

        return findings

    def _check_network_indicators(
        self, content: str, file_path: Path
    ) -> List[Finding]:
        """Check for C2/network indicators."""
        findings: List[Finding] = []
        patterns = self._signatures.get("network_indicators", {}).get("patterns", [])

        for entry in patterns:
            pattern = entry.get("pattern", "").lower()
            if pattern and pattern in content:
                findings.append(Finding(
                    detector=self.name,
                    description=entry.get("description", "Network indicator"),
                    severity=entry.get("score", 30),
                    evidence=f"Network pattern: {entry['pattern']}",
                    attack_techniques=["T1071"],
                    attack_tactics=["Command and Control"],
                    attack_confidence=(
                        "high" if entry.get("score", 0) >= 60 else "low"
                    ),
                ))

        return findings

    def _check_ransomware_indicators(
        self, content: str, file_path: Path
    ) -> List[Finding]:
        """Check for ransomware indicators."""
        findings: List[Finding] = []
        patterns = self._signatures.get("ransomware", {}).get("critical", [])

        for entry in patterns:
            pattern = entry.get("pattern", "").lower()
            if pattern and pattern in content:
                findings.append(Finding(
                    detector=self.name,
                    description=entry.get("description", "Ransomware indicator"),
                    severity=entry.get("score", 50),
                    evidence=f"Ransomware pattern: {entry['pattern']}",
                    remediation=(
                        "Possible ransomware detected. "
                        "Disconnect from internet immediately. Click here for steps."
                    ),
                    attack_techniques=["T1486"],
                    attack_tactics=["Impact"],
                    attack_confidence=(
                        "high" if entry.get("score", 0) >= 80 else "low"
                    ),
                ))

        return findings

    def _check_double_extension(self, file_path: Path) -> List[Finding]:
        """Check for deceptive double extensions."""
        findings: List[Finding] = []
        patterns = self._signatures.get("double_extensions", {}).get("patterns", [])
        name_lower = file_path.name.lower()

        for entry in patterns:
            pattern = entry.get("pattern", "").lower()
            if pattern and name_lower.endswith(pattern):
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Deceptive double extension: {file_path.name}"
                    ),
                    severity=entry.get("score", 60),
                    evidence=f"Filename: {file_path.name}",
                    remediation=(
                        "This file is pretending to be something it's not. "
                        "Do not open it. Click here for steps."
                    ),
                    attack_techniques=["T1036.007"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="high",
                ))

        return findings

    def _check_suspicious_extension(self, file_path: Path) -> List[Finding]:
        """Check if the file extension is inherently suspicious."""
        findings: List[Finding] = []
        extensions = self._signatures.get("suspicious_extensions", {}).get("high_risk", [])
        ext = file_path.suffix.lower()

        for entry in extensions:
            if entry.get("ext", "").lower() == ext:
                findings.append(Finding(
                    detector=self.name,
                    description=entry.get("description", "Suspicious file type"),
                    severity=entry.get("score", 25),
                    evidence=f"Extension: {ext}",
                    attack_techniques=["T1204.002"],
                    attack_tactics=["Execution"],
                    attack_confidence="low",
                ))
                break

        return findings
