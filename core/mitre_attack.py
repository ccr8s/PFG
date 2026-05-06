"""
MITRE ATT&CK Framework integration module.

Provides mapping between detections and ATT&CK techniques,
tactics, and procedures for standardized threat intelligence.
"""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class Tactic(Enum):
    """MITRE ATT&CK Tactics (Enterprise)."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    COMMAND_AND_CONTROL = "TA0011"
    IMPACT = "TA0040"


@dataclass
class AttackTechnique:
    """Represents a MITRE ATT&CK technique."""
    technique_id: str
    name: str
    tactic: Tactic
    description: str
    url: str = ""
    subtechnique_of: Optional[str] = None

    @property
    def mitre_url(self) -> str:
        """Generate MITRE ATT&CK URL for this technique."""
        clean_id = self.technique_id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{clean_id}/"


@dataclass
class AttackMapping:
    """Maps a detection to ATT&CK techniques."""
    techniques: List[AttackTechnique]
    confidence: str  # "high", "medium", "low"

    def get_tactics(self) -> Set[Tactic]:
        """Get all tactics associated with mapped techniques."""
        return {t.tactic for t in self.techniques}

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "techniques": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic.value,
                    "url": t.mitre_url,
                }
                for t in self.techniques
            ],
            "confidence": self.confidence,
        }


class MitreAttackMapper:
    """
    Maps detections to MITRE ATT&CK framework.

    Loads technique definitions from data/mitre_attack.json and
    provides lookup functionality for mapping findings to techniques.
    """

    def __init__(self, data_path: Optional[Path] = None) -> None:
        """
        Initialize the ATT&CK mapper.

        Args:
            data_path: Path to mitre_attack.json.
        """
        self.data_path = (
            data_path
            or Path(__file__).resolve().parent.parent / "data" / "mitre_attack.json"
        )
        self.techniques: Dict[str, AttackTechnique] = {}
        self._load_techniques()

    def _load_techniques(self) -> None:
        """Load ATT&CK techniques from JSON file."""
        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for tech_data in data.get("techniques", []):
                technique = AttackTechnique(
                    technique_id=tech_data["id"],
                    name=tech_data["name"],
                    tactic=Tactic(tech_data["tactic"]),
                    description=tech_data["description"],
                    url=tech_data.get("url", ""),
                    subtechnique_of=tech_data.get("subtechnique_of"),
                )
                self.techniques[technique.technique_id] = technique

            logger.info("Loaded %d ATT&CK techniques", len(self.techniques))
        except FileNotFoundError:
            logger.warning("ATT&CK data file not found: %s", self.data_path)
        except Exception as e:
            logger.error("Failed to load ATT&CK data: %s", e)

    def get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        """Get technique by ID."""
        return self.techniques.get(technique_id)

    def map_finding(
        self,
        technique_ids: List[str],
        confidence: str = "medium",
    ) -> AttackMapping:
        """
        Create an ATT&CK mapping for a finding.

        Args:
            technique_ids: List of ATT&CK technique IDs.
            confidence: Confidence level.

        Returns:
            AttackMapping object.
        """
        techniques = []
        for tid in technique_ids:
            if tech := self.get_technique(tid):
                techniques.append(tech)
            else:
                logger.warning("Unknown ATT&CK technique: %s", tid)

        return AttackMapping(techniques=techniques, confidence=confidence)

    def get_techniques_by_tactic(
        self, tactic: Tactic
    ) -> List[AttackTechnique]:
        """Get all techniques for a specific tactic."""
        return [
            t for t in self.techniques.values() if t.tactic == tactic
        ]

    def generate_navigator_layer(
        self,
        findings_with_mappings: List[AttackMapping],
        layer_name: str = "FileGuard Scan Results",
    ) -> Dict:
        """
        Generate ATT&CK Navigator layer JSON.

        This can be imported into MITRE ATT&CK Navigator for visualization.

        Args:
            findings_with_mappings: AttackMapping objects from scan.
            layer_name: Name for the Navigator layer.

        Returns:
            Dictionary in ATT&CK Navigator layer format.
        """
        technique_scores: Dict[str, int] = {}

        for mapping in findings_with_mappings:
            for tech in mapping.techniques:
                technique_scores[tech.technique_id] = (
                    technique_scores.get(tech.technique_id, 0) + 1
                )

        techniques_layer = [
            {
                "techniqueID": tid,
                "score": count,
                "color": self._score_to_color(count),
            }
            for tid, count in technique_scores.items()
        ]

        return {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": (
                "FileGuard security scan results mapped to ATT&CK"
            ),
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": (
                    max(technique_scores.values())
                    if technique_scores
                    else 10
                ),
            },
        }

    @staticmethod
    def _score_to_color(count: int) -> str:
        """Map finding count to color intensity."""
        if count >= 5:
            return "#ff0000"
        elif count >= 3:
            return "#ff6600"
        elif count >= 2:
            return "#ffcc00"
        return "#ffff00"


# Detection pattern -> ATT&CK technique mapping
PATTERN_TO_ATTACK: Dict[str, List[str]] = {
    "invoke-expression": ["T1059.001"],
    "downloadstring": ["T1059.001", "T1105"],
    "invoke-webrequest": ["T1059.001", "T1105"],
    "frombase64string": ["T1059.001", "T1140"],
    "-enc": ["T1059.001", "T1027"],
    "invoke-mimikatz": ["T1059.001", "T1003.001"],
    "invoke-shellcode": ["T1059.001", "T1055"],
    "certutil -decode": ["T1140"],
    "certutil -urlcache": ["T1105"],
    "bitsadmin /transfer": ["T1105", "T1197"],
    "mshta vbscript": ["T1218.005"],
    "regsvr32 /s /n /u": ["T1218.010"],
    "rundll32 javascript": ["T1218.011"],
    "wmic process call create": ["T1047"],
    "schtasks /create": ["T1053.005"],
    "vssadmin delete shadows": ["T1490"],
    "mimikatz": ["T1003.001"],
    "lazagne": ["T1555"],
    "bloodhound": ["T1087.002"],
    "rubeus": ["T1558"],
    "psexec": ["T1569.002", "T1021.002"],
    "procdump": ["T1003.001"],
    "registry run key": ["T1547.001"],
    "scheduled task": ["T1053.005"],
    "startup folder": ["T1547.001"],
    "winlogon": ["T1547.004"],
    "timestomp": ["T1070.006"],
    "event log clear": ["T1070.001"],
    "hidden file": ["T1564.001"],
    "alternate data stream": ["T1564.004"],
    "file encryption": ["T1486"],
    "shadow copy deletion": ["T1490"],
}
