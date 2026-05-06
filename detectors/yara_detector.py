"""
YARA rule detection module for FileGuard.

Matches files against YARA rules for known malware families,
suspicious patterns, and custom detection rules.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseDetector
from core.models import Finding

logger = logging.getLogger(__name__)


class YaraDetector(BaseDetector):
    """
    Detects threats using YARA rule matching.

    Loads YARA rules from the rules/yara/ directory and matches
    files against them. Rules should include ATT&CK metadata
    in their meta section.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize YARA detector and compile rules.

        Args:
            config: Optional config with rules_path override.
        """
        super().__init__(config)
        self._rules: Optional[Any] = None
        self._yara_available = False
        self._load_rules()

    def _load_rules(self) -> None:
        """Load and compile YARA rules from the rules directory."""
        try:
            import yara
            self._yara_available = True
        except ImportError:
            self.logger.warning(
                "yara-python not installed - YARA detection disabled"
            )
            return

        rules_path = self.config.get("rules_path")
        if rules_path is None:
            project_root = Path(__file__).resolve().parent.parent
            rules_path = project_root / "rules" / "yara"
        else:
            rules_path = Path(rules_path)

        if not rules_path.exists():
            self.logger.warning("YARA rules directory not found: %s", rules_path)
            return

        # Collect all .yar and .yara rule files
        rule_files = {}
        for ext in ("*.yar", "*.yara"):
            for rule_file in rules_path.glob(ext):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)

        if not rule_files:
            self.logger.info("No YARA rules found in %s", rules_path)
            return

        try:
            self._rules = yara.compile(filepaths=rule_files)
            self.logger.info(
                "Compiled %d YARA rule file(s)", len(rule_files)
            )
        except yara.SyntaxError as e:
            self.logger.error("YARA rule syntax error: %s", e)
        except Exception as e:
            self.logger.error("Failed to compile YARA rules: %s", e)

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Match a file against compiled YARA rules.

        Args:
            file_path: Path to the file.
            file_content: Optional pre-read content.

        Returns:
            List of findings for YARA rule matches.
        """
        findings: List[Finding] = []

        if not self._yara_available or self._rules is None:
            return findings

        try:
            timeout = self.config.get("timeout", 60)

            if file_content:
                matches = self._rules.match(data=file_content, timeout=timeout)
            else:
                matches = self._rules.match(str(file_path), timeout=timeout)

            for match in matches:
                finding = self._match_to_finding(match)
                findings.append(finding)

        except Exception as e:
            self.logger.error(
                "YARA scan failed for %s: %s", file_path, e
            )

        return findings

    def _match_to_finding(self, match: Any) -> Finding:
        """
        Convert a YARA match to a Finding object.

        Args:
            match: yara.Match object.

        Returns:
            Finding with ATT&CK mapping from rule metadata.
        """
        meta = match.meta if hasattr(match, "meta") else {}

        # Extract ATT&CK info from rule metadata
        techniques = []
        tactics = []
        if "attack_technique" in meta:
            techniques = [
                t.strip() for t in str(meta["attack_technique"]).split(",")
            ]
        if "attack_tactic" in meta:
            tactics = [
                t.strip() for t in str(meta["attack_tactic"]).split(",")
            ]

        severity = meta.get("severity", 75)
        try:
            severity = int(severity)
        except (ValueError, TypeError):
            severity = 75

        # Build evidence from matched strings
        evidence_parts = [f"Rule: {match.rule}"]
        if hasattr(match, "strings") and match.strings:
            for string_match in match.strings[:5]:  # Limit evidence
                if hasattr(string_match, "instances"):
                    for instance in string_match.instances[:3]:
                        evidence_parts.append(
                            f"  Offset 0x{instance.offset:X}: "
                            f"{instance.matched_data[:50]!r}"
                        )

        return Finding(
            detector=self.name,
            description=(
                meta.get("description", f"YARA rule match: {match.rule}")
            ),
            severity=severity,
            evidence="\n".join(evidence_parts),
            remediation=meta.get(
                "remediation",
                "File matched a YARA detection rule. "
                "Quarantine and investigate.",
            ),
            attack_techniques=techniques or ["T1204"],
            attack_tactics=tactics or ["Execution"],
            attack_confidence=meta.get("confidence", "medium"),
        )

    @property
    def rules_loaded(self) -> bool:
        """Whether YARA rules are loaded and ready."""
        return self._rules is not None
