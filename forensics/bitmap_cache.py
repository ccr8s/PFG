"""
RDP Bitmap Cache parser for FileGuard.

Analyzes Remote Desktop Protocol bitmap cache files to identify
evidence of RDP sessions, which may indicate lateral movement.
"""

import logging
import struct
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseForensicModule
from core.models import ForensicFinding

logger = logging.getLogger(__name__)

# Default BMC cache locations (relative to user profile)
BMC_RELATIVE_PATHS = [
    r"AppData\Local\Microsoft\Terminal Server Client\Cache",
]

# BMC file signatures
BMC_FILE_PATTERN = "bcache*.bmc"
CACHE_BIN_PATTERN = "Cache*.bin"


class BitmapCacheParser(BaseForensicModule):
    """
    Parses RDP Bitmap Cache files for forensic evidence.

    BMC files (bcache*.bmc and Cache*.bin) store cached bitmap
    tiles from RDP sessions, providing evidence of remote
    connections and what was displayed on screen.

    Finding BMC files indicates RDP was used, which in an attack
    scenario suggests lateral movement.
    """

    def analyze(self) -> List[ForensicFinding]:
        """
        Scan for and analyze RDP bitmap cache files.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        from utils.safety import SANDBOX_ROOT, TESTING_MODE

        if TESTING_MODE:
            search_roots = [SANDBOX_ROOT / "Users"]
        else:
            search_roots = [Path("C:/Users")]

        for root in search_roots:
            if root.exists():
                findings.extend(self._scan_for_bmc(root))

        return findings

    def _scan_for_bmc(self, users_dir: Path) -> List[ForensicFinding]:
        """
        Scan user profiles for BMC cache files.

        Args:
            users_dir: Path to Users directory.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        try:
            for user_dir in users_dir.iterdir():
                if not user_dir.is_dir():
                    continue

                for rel_path in BMC_RELATIVE_PATHS:
                    cache_dir = user_dir / rel_path

                    if not cache_dir.exists():
                        continue

                    # Find BMC files
                    bmc_files = (
                        list(cache_dir.glob(BMC_FILE_PATTERN))
                        + list(cache_dir.glob(CACHE_BIN_PATTERN))
                    )

                    if bmc_files:
                        findings.extend(
                            self._analyze_cache_directory(
                                cache_dir, bmc_files, user_dir.name
                            )
                        )

        except PermissionError:
            self.logger.debug("Permission denied scanning %s", users_dir)
        except Exception as e:
            self.logger.error("BMC scan failed: %s", e)

        return findings

    def _analyze_cache_directory(
        self,
        cache_dir: Path,
        bmc_files: List[Path],
        username: str,
    ) -> List[ForensicFinding]:
        """
        Analyze a cache directory with BMC files.

        Args:
            cache_dir: Path to the cache directory.
            bmc_files: List of BMC file paths.
            username: Username who owns the profile.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        total_size = sum(f.stat().st_size for f in bmc_files if f.exists())
        newest = max(
            (f.stat().st_mtime for f in bmc_files if f.exists()),
            default=0,
        )
        oldest = min(
            (f.stat().st_mtime for f in bmc_files if f.exists()),
            default=0,
        )

        file_list = ", ".join(f.name for f in bmc_files[:5])
        if len(bmc_files) > 5:
            file_list += f" ... and {len(bmc_files) - 5} more"

        findings.append(ForensicFinding(
            source="bitmap_cache",
            description=(
                f"RDP bitmap cache found for user '{username}': "
                f"{len(bmc_files)} cache file(s), "
                f"{total_size // 1024}KB total"
            ),
            severity=40,
            evidence=(
                f"User: {username}\n"
                f"Cache dir: {cache_dir}\n"
                f"Files: {file_list}\n"
                f"Total size: {total_size // 1024}KB\n"
                f"Oldest: {datetime.fromtimestamp(oldest).isoformat() if oldest else 'N/A'}\n"
                f"Newest: {datetime.fromtimestamp(newest).isoformat() if newest else 'N/A'}"
            ),
            timestamp=datetime.fromtimestamp(newest) if newest else None,
            artifact_path=str(cache_dir),
            attack_techniques=["T1021.001"],
            attack_tactics=["Lateral Movement"],
            attack_confidence="medium",
        ))

        # Analyze individual BMC files for size anomalies
        for bmc_file in bmc_files:
            try:
                file_findings = self._analyze_bmc_file(bmc_file, username)
                findings.extend(file_findings)
            except Exception as e:
                self.logger.debug(
                    "BMC file analysis failed for %s: %s",
                    bmc_file.name, e,
                )

        return findings

    def _analyze_bmc_file(
        self,
        bmc_path: Path,
        username: str,
    ) -> List[ForensicFinding]:
        """
        Analyze a single BMC file.

        Args:
            bmc_path: Path to the BMC file.
            username: Owning username.

        Returns:
            List of findings for anomalies.
        """
        findings: List[ForensicFinding] = []

        try:
            file_size = bmc_path.stat().st_size
            modified = datetime.fromtimestamp(bmc_path.stat().st_mtime)

            # Very large cache files suggest extended RDP sessions
            if file_size > 50 * 1024 * 1024:  # > 50 MB
                findings.append(ForensicFinding(
                    source="bitmap_cache",
                    description=(
                        f"Large RDP cache file: {bmc_path.name} "
                        f"({file_size // (1024 * 1024)}MB) - "
                        f"extended RDP session"
                    ),
                    severity=50,
                    evidence=(
                        f"File: {bmc_path}\n"
                        f"Size: {file_size // (1024 * 1024)}MB\n"
                        f"Modified: {modified.isoformat()}\n"
                        f"User: {username}"
                    ),
                    timestamp=modified,
                    artifact_path=str(bmc_path),
                    attack_techniques=["T1021.001"],
                    attack_tactics=["Lateral Movement"],
                    attack_confidence="medium",
                ))

            # Recently modified cache suggests recent RDP activity
            now = datetime.now()
            if (now - modified).days < 1:
                findings.append(ForensicFinding(
                    source="bitmap_cache",
                    description=(
                        f"Recent RDP activity: {bmc_path.name} "
                        f"modified {modified.isoformat()}"
                    ),
                    severity=35,
                    evidence=(
                        f"File: {bmc_path}\n"
                        f"Modified: {modified.isoformat()}\n"
                        f"User: {username}"
                    ),
                    timestamp=modified,
                    artifact_path=str(bmc_path),
                    attack_techniques=["T1021.001"],
                    attack_tactics=["Lateral Movement"],
                    attack_confidence="low",
                ))

        except (OSError, PermissionError) as e:
            self.logger.debug("Cannot analyze %s: %s", bmc_path, e)

        return findings
