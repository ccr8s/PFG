"""
FileGuard data models.

All scan results, findings, and related data structures are defined here.
Every detection MUST include MITRE ATT&CK mapping fields.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class RiskLevel(Enum):
    """Risk classification levels."""
    SUSPICIOUS_CODE = 4    # Critical - Likely malware
    HIGH_TARGET = 3        # High - Popular attack targets
    POTENTIAL_RISK = 2     # Medium - Needs review
    LOW_RISK = 1           # Low - Minor anomalies
    CLEAN = 0              # No issues

    @property
    def label(self) -> str:
        """Human-readable label."""
        labels = {
            4: "Suspicious Code",
            3: "High Target",
            2: "Potential Risk",
            1: "Low Risk",
            0: "Clean",
        }
        return labels[self.value]

    @property
    def color(self) -> str:
        """GUI color code."""
        colors = {
            4: "#ff0000",
            3: "#ff6600",
            2: "#ffcc00",
            1: "#00cc66",
            0: "#888888",
        }
        return colors[self.value]


@dataclass
class Finding:
    """
    Represents a single security finding.

    Every finding MUST include MITRE ATT&CK technique and tactic fields.
    """
    detector: str
    description: str
    severity: int  # 0-100
    evidence: str
    line_number: Optional[int] = None
    remediation: Optional[str] = None

    # MITRE ATT&CK fields (REQUIRED)
    attack_techniques: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    attack_confidence: str = "medium"

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
                "confidence": self.attack_confidence,
            },
        }


@dataclass
class ScanResult:
    """Complete scan result for a single file."""
    file_path: Path
    risk_level: RiskLevel
    risk_score: int
    findings: List[Finding] = field(default_factory=list)
    file_hash_md5: str = ""
    file_hash_sha256: str = ""
    file_size: int = 0
    file_extension: str = ""
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    scan_time: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "file_path": str(self.file_path),
            "risk_level": self.risk_level.name,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "file_hash_md5": self.file_hash_md5,
            "file_hash_sha256": self.file_hash_sha256,
            "file_size": self.file_size,
            "file_extension": self.file_extension,
            "created_time": (
                self.created_time.isoformat() if self.created_time else None
            ),
            "modified_time": (
                self.modified_time.isoformat() if self.modified_time else None
            ),
            "scan_time": self.scan_time.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ScanSummary:
    """Summary of a complete scan session."""
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    target_path: Optional[Path] = None
    total_files: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_error: int = 0
    results: List[ScanResult] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Return scan duration in seconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def risk_counts(self) -> Dict[str, int]:
        """Count results by risk level."""
        counts: Dict[str, int] = {}
        for result in self.results:
            key = result.risk_level.name
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan summary to dictionary."""
        return {
            "scan_id": self.scan_id,
            "start_time": self.start_time.isoformat(),
            "end_time": (
                self.end_time.isoformat() if self.end_time else None
            ),
            "target_path": (
                str(self.target_path) if self.target_path else None
            ),
            "total_files": self.total_files,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_error": self.files_error,
            "duration_seconds": self.duration_seconds,
            "risk_counts": self.risk_counts,
        }


@dataclass
class ForensicFinding:
    """Represents a forensic artifact finding."""
    source: str  # e.g., "event_log", "registry", "timestomp"
    description: str
    severity: int  # 0-100
    evidence: str
    timestamp: Optional[datetime] = None
    artifact_path: Optional[str] = None

    # MITRE ATT&CK fields (REQUIRED)
    attack_techniques: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    attack_confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        """Convert forensic finding to dictionary."""
        return {
            "source": self.source,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "timestamp": (
                self.timestamp.isoformat() if self.timestamp else None
            ),
            "artifact_path": self.artifact_path,
            "mitre_attack": {
                "techniques": self.attack_techniques,
                "tactics": self.attack_tactics,
                "confidence": self.attack_confidence,
            },
        }


@dataclass
class HoneypotAlert:
    """Represents a honeypot access alert."""
    decoy_path: Path
    access_type: str  # "read", "write", "delete", "rename"
    timestamp: datetime
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    user: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert honeypot alert to dictionary."""
        return {
            "decoy_path": str(self.decoy_path),
            "access_type": self.access_type,
            "timestamp": self.timestamp.isoformat(),
            "process_name": self.process_name,
            "process_id": self.process_id,
            "user": self.user,
        }
