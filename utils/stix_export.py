"""
STIX 2.1 export module.

Converts FileGuard scan findings into STIX 2.1 objects for
threat intelligence sharing and integration with security tools.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Check if stix2 is available
try:
    from stix2 import (
        AttackPattern,
        Bundle,
        Identity,
        Indicator,
        Malware,
        Relationship,
    )
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False
    logger.debug("stix2 library not installed - STIX export unavailable")

from core.models import Finding, RiskLevel, ScanResult

FILEGUARD_IDENTITY_ID = "identity--f8e1a3c7-5d9b-4e2a-8f6c-3a1b2d4e5f6a"


class StixExporter:
    """
    Exports FileGuard scan results to STIX 2.1 format.

    Creates standardized threat intelligence objects including
    Indicators, Malware, Attack Patterns, and Relationships.
    """

    def __init__(self, organization_name: str = "FileGuard") -> None:
        """
        Initialize STIX exporter.

        Args:
            organization_name: Name for the identity object.
        """
        if not STIX_AVAILABLE:
            raise ImportError(
                "stix2 library required for STIX export. "
                "Install with: pip install stix2"
            )

        self.organization_name = organization_name
        self.identity = self._create_identity()
        self.objects: List[Any] = [self.identity]
        self.created_ids: Dict[str, str] = {}

    def _create_identity(self) -> Any:
        """Create the FileGuard identity object."""
        return Identity(
            id=FILEGUARD_IDENTITY_ID,
            name=self.organization_name,
            identity_class="tool",
            description=(
                "FileGuard Security Scanner - "
                "Automated threat detection tool"
            ),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
        )

    @staticmethod
    def _generate_id(object_type: str, unique_string: str) -> str:
        """Generate deterministic STIX ID from content."""
        hash_input = f"{object_type}:{unique_string}"
        h = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
        return (
            f"{object_type}--{h[:8]}-{h[8:12]}-{h[12:16]}-"
            f"{h[16:20]}-{h[20:32]}"
        )

    def add_scan_result(self, result: ScanResult) -> None:
        """
        Convert a ScanResult to STIX objects.

        Args:
            result: FileGuard scan result to convert.
        """
        # Create indicator if suspicious
        if result.risk_level in (
            RiskLevel.SUSPICIOUS_CODE, RiskLevel.HIGH_TARGET
        ):
            indicator = self._create_indicator(result)
            self.objects.append(indicator)

            if result.risk_level == RiskLevel.SUSPICIOUS_CODE:
                malware = self._create_malware(result)
                self.objects.append(malware)

                rel = Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware.id,
                    created_by_ref=self.identity.id,
                )
                self.objects.append(rel)

        # Create attack patterns from ATT&CK mappings
        for finding in result.findings:
            if finding.attack_techniques:
                for tech_id in finding.attack_techniques:
                    ap = self._create_attack_pattern(tech_id, finding)
                    if ap:
                        self.objects.append(ap)

    def _create_indicator(self, result: ScanResult) -> Any:
        """Create STIX Indicator from scan result."""
        if result.file_hash_sha256:
            pattern = (
                f"[file:hashes.'SHA-256' = "
                f"'{result.file_hash_sha256}']"
            )
        elif result.file_hash_md5:
            pattern = f"[file:hashes.MD5 = '{result.file_hash_md5}']"
        else:
            pattern = f"[file:name = '{result.file_path.name}']"

        indicator_types = ["malicious-activity"]
        if any(
            "ransomware" in f.description.lower()
            for f in result.findings
        ):
            indicator_types.append("attribution")

        return Indicator(
            id=self._generate_id(
                "indicator",
                result.file_hash_sha256 or str(result.file_path),
            ),
            name=f"FileGuard Detection: {result.file_path.name}",
            description=self._build_description(result),
            indicator_types=indicator_types,
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            created_by_ref=self.identity.id,
            labels=self._get_labels(result),
            confidence=self._calculate_confidence(result),
        )

    def _create_malware(self, result: ScanResult) -> Any:
        """Create STIX Malware object from scan result."""
        desc_lower = " ".join(
            f.description.lower() for f in result.findings
        )

        malware_types = ["unknown"]
        for keyword, mtype in [
            ("ransomware", "ransomware"),
            ("trojan", "trojan"),
            ("keylog", "keylogger"),
            ("backdoor", "backdoor"),
            ("rootkit", "rootkit"),
            ("worm", "worm"),
        ]:
            if keyword in desc_lower:
                malware_types = [mtype]
                break

        return Malware(
            id=self._generate_id(
                "malware",
                result.file_hash_sha256 or str(result.file_path),
            ),
            name=f"Detected Malware: {result.file_path.name}",
            description=self._build_description(result),
            malware_types=malware_types,
            is_family=False,
            created_by_ref=self.identity.id,
            confidence=self._calculate_confidence(result),
        )

    def _create_attack_pattern(
        self, technique_id: str, finding: Finding
    ) -> Optional[Any]:
        """Create STIX Attack Pattern from ATT&CK technique."""
        cache_key = f"attack-pattern:{technique_id}"
        if cache_key in self.created_ids:
            return None

        ap = AttackPattern(
            id=self._generate_id("attack-pattern", technique_id),
            name=technique_id,
            description=finding.description,
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": (
                        "https://attack.mitre.org/techniques/"
                        f"{technique_id.replace('.', '/')}/"
                    ),
                }
            ],
            created_by_ref=self.identity.id,
        )

        self.created_ids[cache_key] = ap.id
        return ap

    @staticmethod
    def _build_description(result: ScanResult) -> str:
        """Build description from findings."""
        lines = [
            f"Risk Level: {result.risk_level.name}",
            f"Risk Score: {result.risk_score}",
            f"File: {result.file_path}",
            "",
            "Findings:",
        ]
        for finding in result.findings:
            lines.append(
                f"- [{finding.detector}] {finding.description}"
            )
        return "\n".join(lines)

    @staticmethod
    def _get_labels(result: ScanResult) -> List[str]:
        """Get labels from findings."""
        labels = [result.risk_level.name.lower().replace("_", "-")]
        detectors = set(f.detector for f in result.findings)
        labels.extend(detectors)
        for finding in result.findings:
            labels.extend(finding.attack_tactics)
        return list(set(labels))

    @staticmethod
    def _calculate_confidence(result: ScanResult) -> int:
        """Calculate confidence score (0-100)."""
        if result.risk_level == RiskLevel.SUSPICIOUS_CODE:
            return min(95, result.risk_score)
        elif result.risk_level == RiskLevel.HIGH_TARGET:
            return min(75, result.risk_score)
        return min(50, result.risk_score)

    def export_bundle(self) -> Any:
        """Export all objects as STIX Bundle."""
        return Bundle(objects=self.objects)

    def export_to_file(self, output_path: Path) -> None:
        """
        Export STIX bundle to JSON file.

        Args:
            output_path: Path to output file.
        """
        bundle = self.export_bundle()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(bundle.serialize(pretty=True))
        logger.info(
            "Exported %d STIX objects to %s",
            len(self.objects),
            output_path,
        )

    def export_to_dict(self) -> Dict[str, Any]:
        """Export as dictionary (for JSON API responses)."""
        bundle = self.export_bundle()
        return {
            "type": "bundle",
            "id": bundle.id,
            "objects": [
                json.loads(obj.serialize()) for obj in self.objects
            ],
        }


def export_scan_results_to_stix(
    results: List[ScanResult],
    output_path: Path,
    organization_name: str = "FileGuard",
) -> None:
    """
    Convenience function to export scan results to STIX file.

    Args:
        results: List of scan results to export.
        output_path: Path to output STIX JSON file.
        organization_name: Name for the identity object.
    """
    exporter = StixExporter(organization_name)

    for result in results:
        if result.risk_level != RiskLevel.CLEAN:
            exporter.add_scan_result(result)

    exporter.export_to_file(output_path)
