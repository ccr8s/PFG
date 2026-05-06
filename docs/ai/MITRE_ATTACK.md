# TASK: Implement MITRE ATT&CK Mapping

## Phase: Integration Enhancement
## Task Name: MITRE ATT&CK Framework Integration
## Description:
Add MITRE ATT&CK technique mapping to all detections, enabling threat intelligence correlation and standardized reporting.

---

## Specific Requirements:

1. Create a MITRE ATT&CK mapping module at `core/mitre_attack.py`
2. Create ATT&CK technique database at `data/mitre_attack.json`
3. Extend the `Finding` dataclass to include ATT&CK metadata
4. Add ATT&CK technique IDs to all detection patterns in `config/signatures.yaml`
5. Create a threat report generator that groups findings by ATT&CK tactic

---

## Expected Output Files:

### File 1: `core/mitre_attack.py`

```python
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
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class AttackTechnique:
    """Represents a MITRE ATT&CK technique."""
    technique_id: str           # e.g., "T1059.001"
    name: str                   # e.g., "PowerShell"
    tactic: Tactic
    description: str
    url: str                    # Link to ATT&CK page
    subtechnique_of: Optional[str] = None  # Parent technique if sub-technique
    
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
                    "url": t.mitre_url
                }
                for t in self.techniques
            ],
            "confidence": self.confidence
        }


class MitreAttackMapper:
    """
    Maps detections to MITRE ATT&CK framework.
    
    Loads technique definitions from data/mitre_attack.json and provides
    lookup functionality for mapping findings to ATT&CK techniques.
    """
    
    def __init__(self, data_path: Optional[Path] = None):
        """
        Initialize the ATT&CK mapper.
        
        Args:
            data_path: Path to mitre_attack.json. Defaults to data/mitre_attack.json
        """
        self.data_path = data_path or Path(__file__).parent.parent / "data" / "mitre_attack.json"
        self.techniques: Dict[str, AttackTechnique] = {}
        self._load_techniques()
    
    def _load_techniques(self) -> None:
        """Load ATT&CK techniques from JSON file."""
        try:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for tech_data in data.get("techniques", []):
                technique = AttackTechnique(
                    technique_id=tech_data["id"],
                    name=tech_data["name"],
                    tactic=Tactic(tech_data["tactic"]),
                    description=tech_data["description"],
                    url=tech_data.get("url", ""),
                    subtechnique_of=tech_data.get("subtechnique_of")
                )
                self.techniques[technique.technique_id] = technique
            
            logger.info(f"Loaded {len(self.techniques)} ATT&CK techniques")
        except FileNotFoundError:
            logger.warning(f"ATT&CK data file not found: {self.data_path}")
        except Exception as e:
            logger.error(f"Failed to load ATT&CK data: {e}")
    
    def get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        """
        Get technique by ID.
        
        Args:
            technique_id: ATT&CK technique ID (e.g., "T1059.001")
            
        Returns:
            AttackTechnique if found, None otherwise
        """
        return self.techniques.get(technique_id)
    
    def map_finding(
        self,
        technique_ids: List[str],
        confidence: str = "medium"
    ) -> AttackMapping:
        """
        Create an ATT&CK mapping for a finding.
        
        Args:
            technique_ids: List of ATT&CK technique IDs
            confidence: Confidence level ("high", "medium", "low")
            
        Returns:
            AttackMapping object
        """
        techniques = []
        for tid in technique_ids:
            if tech := self.get_technique(tid):
                techniques.append(tech)
            else:
                logger.warning(f"Unknown ATT&CK technique: {tid}")
        
        return AttackMapping(techniques=techniques, confidence=confidence)
    
    def get_techniques_by_tactic(self, tactic: Tactic) -> List[AttackTechnique]:
        """Get all techniques for a specific tactic."""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def generate_navigator_layer(
        self,
        findings_with_mappings: List[AttackMapping],
        layer_name: str = "FileGuard Scan Results"
    ) -> Dict:
        """
        Generate ATT&CK Navigator layer JSON.
        
        This can be imported into MITRE ATT&CK Navigator for visualization.
        
        Args:
            findings_with_mappings: List of AttackMapping objects from scan
            layer_name: Name for the Navigator layer
            
        Returns:
            Dictionary in ATT&CK Navigator layer format
        """
        technique_scores: Dict[str, int] = {}
        
        for mapping in findings_with_mappings:
            for tech in mapping.techniques:
                if tech.technique_id in technique_scores:
                    technique_scores[tech.technique_id] += 1
                else:
                    technique_scores[tech.technique_id] = 1
        
        techniques_layer = [
            {
                "techniqueID": tid,
                "score": count,
                "color": self._score_to_color(count)
            }
            for tid, count in technique_scores.items()
        ]
        
        return {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": "FileGuard security scan results mapped to ATT&CK",
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": max(technique_scores.values()) if technique_scores else 10
            }
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
        else:
            return "#ffff00"


# Mapping of detection patterns to ATT&CK technique IDs
PATTERN_TO_ATTACK: Dict[str, List[str]] = {
    # PowerShell patterns
    "invoke-expression": ["T1059.001"],
    "downloadstring": ["T1059.001", "T1105"],
    "invoke-webrequest": ["T1059.001", "T1105"],
    "frombase64string": ["T1059.001", "T1140"],
    "-enc": ["T1059.001", "T1027"],
    "invoke-mimikatz": ["T1059.001", "T1003.001"],
    "invoke-shellcode": ["T1059.001", "T1055"],
    
    # CMD patterns
    "certutil -decode": ["T1140"],
    "certutil -urlcache": ["T1105"],
    "bitsadmin /transfer": ["T1105", "T1197"],
    "mshta vbscript": ["T1218.005"],
    "regsvr32 /s /n /u": ["T1218.010"],
    "rundll32 javascript": ["T1218.011"],
    "wmic process call create": ["T1047"],
    "schtasks /create": ["T1053.005"],
    "vssadmin delete shadows": ["T1490"],
    
    # Tools
    "mimikatz": ["T1003.001"],
    "lazagne": ["T1555"],
    "bloodhound": ["T1087.002"],
    "rubeus": ["T1558"],
    "psexec": ["T1569.002", "T1021.002"],
    "procdump": ["T1003.001"],
    
    # Persistence
    "registry run key": ["T1547.001"],
    "scheduled task": ["T1053.005"],
    "startup folder": ["T1547.001"],
    "winlogon": ["T1547.004"],
    
    # Defense evasion
    "timestomp": ["T1070.006"],
    "event log clear": ["T1070.001"],
    "hidden file": ["T1564.001"],
    "alternate data stream": ["T1564.004"],
    
    # Ransomware
    "file encryption": ["T1486"],
    "shadow copy deletion": ["T1490"],
}
```

---

### File 2: `data/mitre_attack.json`

```json
{
  "version": "14.0",
  "last_updated": "2024-01-15",
  "techniques": [
    {
      "id": "T1059",
      "name": "Command and Scripting Interpreter",
      "tactic": "TA0002",
      "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."
    },
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "TA0002",
      "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
      "subtechnique_of": "T1059"
    },
    {
      "id": "T1059.003",
      "name": "Windows Command Shell",
      "tactic": "TA0002",
      "description": "Adversaries may abuse the Windows command shell for execution.",
      "subtechnique_of": "T1059"
    },
    {
      "id": "T1105",
      "name": "Ingress Tool Transfer",
      "tactic": "TA0011",
      "description": "Adversaries may transfer tools or other files from an external system into a compromised environment."
    },
    {
      "id": "T1140",
      "name": "Deobfuscate/Decode Files or Information",
      "tactic": "TA0005",
      "description": "Adversaries may use obfuscated files or information to hide artifacts of an intrusion."
    },
    {
      "id": "T1027",
      "name": "Obfuscated Files or Information",
      "tactic": "TA0005",
      "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze."
    },
    {
      "id": "T1003",
      "name": "OS Credential Dumping",
      "tactic": "TA0006",
      "description": "Adversaries may attempt to dump credentials to obtain account login information."
    },
    {
      "id": "T1003.001",
      "name": "LSASS Memory",
      "tactic": "TA0006",
      "description": "Adversaries may attempt to access credential material stored in LSASS process memory.",
      "subtechnique_of": "T1003"
    },
    {
      "id": "T1055",
      "name": "Process Injection",
      "tactic": "TA0005",
      "description": "Adversaries may inject code into processes to evade defenses and elevate privileges."
    },
    {
      "id": "T1197",
      "name": "BITS Jobs",
      "tactic": "TA0005",
      "description": "Adversaries may abuse BITS jobs to download, execute, and clean up after malicious code."
    },
    {
      "id": "T1218.005",
      "name": "Mshta",
      "tactic": "TA0005",
      "description": "Adversaries may abuse mshta.exe to proxy execution of malicious code.",
      "subtechnique_of": "T1218"
    },
    {
      "id": "T1218.010",
      "name": "Regsvr32",
      "tactic": "TA0005",
      "description": "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code.",
      "subtechnique_of": "T1218"
    },
    {
      "id": "T1218.011",
      "name": "Rundll32",
      "tactic": "TA0005",
      "description": "Adversaries may abuse rundll32.exe to proxy execution of malicious code.",
      "subtechnique_of": "T1218"
    },
    {
      "id": "T1047",
      "name": "Windows Management Instrumentation",
      "tactic": "TA0002",
      "description": "Adversaries may abuse WMI to execute malicious commands and payloads."
    },
    {
      "id": "T1053.005",
      "name": "Scheduled Task",
      "tactic": "TA0003",
      "description": "Adversaries may abuse Windows Task Scheduler to perform task scheduling for execution.",
      "subtechnique_of": "T1053"
    },
    {
      "id": "T1490",
      "name": "Inhibit System Recovery",
      "tactic": "TA0040",
      "description": "Adversaries may delete or remove built-in OS data designed to aid in recovery."
    },
    {
      "id": "T1555",
      "name": "Credentials from Password Stores",
      "tactic": "TA0006",
      "description": "Adversaries may search for common password storage locations."
    },
    {
      "id": "T1087.002",
      "name": "Domain Account",
      "tactic": "TA0007",
      "description": "Adversaries may attempt to get a listing of domain accounts.",
      "subtechnique_of": "T1087"
    },
    {
      "id": "T1558",
      "name": "Steal or Forge Kerberos Tickets",
      "tactic": "TA0006",
      "description": "Adversaries may attempt to subvert Kerberos authentication."
    },
    {
      "id": "T1569.002",
      "name": "Service Execution",
      "tactic": "TA0002",
      "description": "Adversaries may abuse Windows service control manager to execute malicious commands.",
      "subtechnique_of": "T1569"
    },
    {
      "id": "T1021.002",
      "name": "SMB/Windows Admin Shares",
      "tactic": "TA0008",
      "description": "Adversaries may use SMB to interact with network shares for lateral movement.",
      "subtechnique_of": "T1021"
    },
    {
      "id": "T1547.001",
      "name": "Registry Run Keys / Startup Folder",
      "tactic": "TA0003",
      "description": "Adversaries may achieve persistence by adding a program to startup folder or registry run key.",
      "subtechnique_of": "T1547"
    },
    {
      "id": "T1547.004",
      "name": "Winlogon Helper DLL",
      "tactic": "TA0003",
      "description": "Adversaries may abuse Winlogon features to execute DLLs during logon.",
      "subtechnique_of": "T1547"
    },
    {
      "id": "T1070.001",
      "name": "Clear Windows Event Logs",
      "tactic": "TA0005",
      "description": "Adversaries may clear Windows Event Logs to hide activity.",
      "subtechnique_of": "T1070"
    },
    {
      "id": "T1070.006",
      "name": "Timestomp",
      "tactic": "TA0005",
      "description": "Adversaries may modify file timestamps to hide malware or tools.",
      "subtechnique_of": "T1070"
    },
    {
      "id": "T1564.001",
      "name": "Hidden Files and Directories",
      "tactic": "TA0005",
      "description": "Adversaries may hide files by setting the hidden attribute.",
      "subtechnique_of": "T1564"
    },
    {
      "id": "T1564.004",
      "name": "NTFS File Attributes",
      "tactic": "TA0005",
      "description": "Adversaries may use NTFS file attributes to hide malicious data.",
      "subtechnique_of": "T1564"
    },
    {
      "id": "T1486",
      "name": "Data Encrypted for Impact",
      "tactic": "TA0040",
      "description": "Adversaries may encrypt data on target systems to interrupt availability."
    }
  ]
}
```

---

### File 3: Update `core/models.py` - Add to Finding dataclass:

```python
# Add these imports at the top
from typing import List, Optional, Dict, Any

# Update the Finding dataclass to include ATT&CK mapping
@dataclass
class Finding:
    """Represents a single security finding."""
    detector: str
    description: str
    severity: int  # 0-100
    evidence: str
    line_number: Optional[int] = None
    remediation: Optional[str] = None
    
    # NEW: MITRE ATT&CK fields
    attack_techniques: List[str] = field(default_factory=list)  # e.g., ["T1059.001", "T1105"]
    attack_tactics: List[str] = field(default_factory=list)     # e.g., ["TA0002", "TA0011"]
    attack_confidence: str = "medium"  # "high", "medium", "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "detector": self.detector,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "line_number": self.line_number,
            "remediation": self.remediation,
            "mitre_attack": {
                "techniques": self.attack_techniques,
                "tactics": self.attack_tactics,
                "confidence": self.attack_confidence
            }
        }
```

---

### File 4: Update `config/signatures.yaml` - Add ATT&CK IDs to patterns:

```yaml
# Example of updated pattern format with ATT&CK mapping
powershell:
  critical:
    - pattern: "invoke-expression"
      description: "Dynamic code execution"
      score: 45
      attack_techniques: ["T1059.001"]
      attack_tactics: ["TA0002"]
      
    - pattern: "downloadstring"
      description: "Remote code download"
      score: 50
      attack_techniques: ["T1059.001", "T1105"]
      attack_tactics: ["TA0002", "TA0011"]
      
    - pattern: "invoke-mimikatz"
      description: "Mimikatz execution"
      score: 95
      attack_techniques: ["T1059.001", "T1003.001"]
      attack_tactics: ["TA0002", "TA0006"]
```

---

## Acceptance Criteria:
- [ ] MitreAttackMapper class loads technique database correctly
- [ ] All existing detection patterns have ATT&CK technique IDs assigned
- [ ] Finding objects include ATT&CK metadata
- [ ] Navigator layer export produces valid JSON importable into ATT&CK Navigator
- [ ] Unit tests cover mapping and export functionality
- [ ] Documentation includes ATT&CK mapping coverage statistics