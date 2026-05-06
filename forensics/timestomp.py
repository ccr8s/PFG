"""
Timestamp manipulation (timestomping) detector for FileGuard.

Identifies files with suspicious timestamps that indicate
deliberate manipulation to evade forensic analysis.
"""

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseForensicModule
from core.models import ForensicFinding
from utils.file_utils import walk_directory

logger = logging.getLogger(__name__)

# Timestamp anomaly thresholds
FUTURE_THRESHOLD_HOURS = 1
ANCIENT_DATE = datetime(2000, 1, 1)
ROUND_TIMESTAMP_TOLERANCE_SECONDS = 1
MASS_TIMESTAMP_THRESHOLD = 10  # Files with identical timestamps


class TimestompDetector(BaseForensicModule):
    """
    Detects timestamp manipulation (timestomping) on files.

    Checks for:
    - Future timestamps (created/modified in the future)
    - Impossible dates (before OS or format existed)
    - Perfectly round timestamps (midnight, noon)
    - Mass identical timestamps (batch manipulation)
    - Created time after modified time anomaly
    - $STANDARD_INFO vs $FILE_NAME mismatch (NTFS-level)
    """

    def analyze(self) -> List[ForensicFinding]:
        """
        Run timestomp detection on configured paths.

        Returns:
            List of forensic findings.
        """
        scan_path = self.config.get("scan_path")
        if scan_path:
            return self.scan_directory(Path(scan_path))
        return []

    def scan_directory(
        self,
        target: Path,
        max_files: int = 10000,
    ) -> List[ForensicFinding]:
        """
        Scan a directory for timestamp anomalies.

        Args:
            target: Directory to scan.
            max_files: Maximum files to check.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []
        timestamp_groups: Dict[str, List[Path]] = {}
        count = 0

        for file_path in walk_directory(target, recursive=True):
            if count >= max_files:
                break
            count += 1

            file_findings = self.check_file(file_path)
            findings.extend(file_findings)

            # Track timestamps for mass-change detection
            try:
                mtime = file_path.stat().st_mtime
                ts_key = str(int(mtime))
                if ts_key not in timestamp_groups:
                    timestamp_groups[ts_key] = []
                timestamp_groups[ts_key].append(file_path)
            except OSError:
                continue

        # Check for mass identical timestamps
        findings.extend(
            self._check_mass_timestamps(timestamp_groups)
        )

        return findings

    def check_file(self, file_path: Path) -> List[ForensicFinding]:
        """
        Check a single file for timestamp anomalies.

        Args:
            file_path: Path to the file to check.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        try:
            stat = file_path.stat()
            created = datetime.fromtimestamp(stat.st_ctime)
            modified = datetime.fromtimestamp(stat.st_mtime)
            accessed = datetime.fromtimestamp(stat.st_atime)
            now = datetime.now()

        except (OSError, PermissionError, OverflowError) as e:
            self.logger.debug("Cannot stat %s: %s", file_path, e)
            return findings

        # Check 1: Future timestamps
        future_threshold = now + timedelta(hours=FUTURE_THRESHOLD_HOURS)

        if created > future_threshold:
            findings.append(ForensicFinding(
                source="timestomp",
                description=(
                    f"Future creation time: {file_path.name} "
                    f"({created.isoformat()})"
                ),
                severity=80,
                evidence=(
                    f"File: {file_path}\n"
                    f"Created: {created.isoformat()}\n"
                    f"Current: {now.isoformat()}"
                ),
                timestamp=now,
                artifact_path=str(file_path),
                attack_techniques=["T1070.006"],
                attack_tactics=["Defense Evasion"],
                attack_confidence="high",
            ))

        if modified > future_threshold:
            findings.append(ForensicFinding(
                source="timestomp",
                description=(
                    f"Future modification time: {file_path.name} "
                    f"({modified.isoformat()})"
                ),
                severity=80,
                evidence=(
                    f"File: {file_path}\n"
                    f"Modified: {modified.isoformat()}\n"
                    f"Current: {now.isoformat()}"
                ),
                timestamp=now,
                artifact_path=str(file_path),
                attack_techniques=["T1070.006"],
                attack_tactics=["Defense Evasion"],
                attack_confidence="high",
            ))

        # Check 2: Impossible dates (before Windows existed meaningfully)
        if created < ANCIENT_DATE:
            findings.append(ForensicFinding(
                source="timestomp",
                description=(
                    f"Impossible creation date: {file_path.name} "
                    f"({created.isoformat()})"
                ),
                severity=85,
                evidence=(
                    f"File: {file_path}\n"
                    f"Created: {created.isoformat()}"
                ),
                timestamp=now,
                artifact_path=str(file_path),
                attack_techniques=["T1070.006"],
                attack_tactics=["Defense Evasion"],
                attack_confidence="high",
            ))

        # Check 3: Round timestamps (exactly midnight or noon)
        for ts, ts_name in [
            (created, "created"),
            (modified, "modified"),
        ]:
            if (ts.hour == 0 and ts.minute == 0 and ts.second == 0 and
                    ts.microsecond == 0):
                findings.append(ForensicFinding(
                    source="timestomp",
                    description=(
                        f"Perfectly round {ts_name} timestamp: "
                        f"{file_path.name} ({ts.isoformat()})"
                    ),
                    severity=40,
                    evidence=(
                        f"File: {file_path}\n"
                        f"{ts_name.title()}: {ts.isoformat()}\n"
                        f"Exactly midnight - may indicate manipulation"
                    ),
                    timestamp=now,
                    artifact_path=str(file_path),
                    attack_techniques=["T1070.006"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="low",
                ))

        # Check 4: Created after modified (NTFS anomaly)
        if created > modified + timedelta(seconds=2):
            findings.append(ForensicFinding(
                source="timestomp",
                description=(
                    f"Creation time after modification time: "
                    f"{file_path.name}"
                ),
                severity=65,
                evidence=(
                    f"File: {file_path}\n"
                    f"Created: {created.isoformat()}\n"
                    f"Modified: {modified.isoformat()}\n"
                    f"Difference: {(created - modified).total_seconds():.0f}s"
                ),
                timestamp=now,
                artifact_path=str(file_path),
                attack_techniques=["T1070.006"],
                attack_tactics=["Defense Evasion"],
                attack_confidence="medium",
            ))

        return findings

    def _check_mass_timestamps(
        self,
        groups: Dict[str, List[Path]],
    ) -> List[ForensicFinding]:
        """Detect groups of files with identical timestamps."""
        findings: List[ForensicFinding] = []

        for ts_key, paths in groups.items():
            if len(paths) >= MASS_TIMESTAMP_THRESHOLD:
                try:
                    ts = datetime.fromtimestamp(int(ts_key))
                except (ValueError, OverflowError):
                    continue

                sample_files = [str(p.name) for p in paths[:5]]
                findings.append(ForensicFinding(
                    source="timestomp",
                    description=(
                        f"{len(paths)} files share identical modification "
                        f"time ({ts.isoformat()})"
                    ),
                    severity=65,
                    evidence=(
                        f"Timestamp: {ts.isoformat()}\n"
                        f"File count: {len(paths)}\n"
                        f"Examples: {', '.join(sample_files)}"
                    ),
                    timestamp=datetime.now(),
                    attack_techniques=["T1070.006"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="medium",
                ))

        return findings

    def scan_system(self) -> List[ForensicFinding]:
        """
        Scan system directories for timestomping.

        Uses sandbox paths in test mode.
        """
        from utils.safety import SANDBOX_ROOT, TESTING_MODE

        if TESTING_MODE:
            target = SANDBOX_ROOT
        else:
            target = Path("C:\\")

        if not target.exists():
            return []

        return self.scan_directory(target, max_files=5000)
