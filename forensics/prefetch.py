"""
Windows Prefetch file parser for FileGuard.

Analyzes Prefetch files to determine program execution history,
identifying suspicious executables that have run on the system.
"""

import logging
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseForensicModule
from core.models import ForensicFinding

logger = logging.getLogger(__name__)

# Default Prefetch directory
PREFETCH_DIR = Path("C:/Windows/Prefetch")

# Suspicious executable names in prefetch
SUSPICIOUS_EXECUTABLES = {
    "mimikatz": {"severity": 95, "technique": "T1003.001", "desc": "Credential dumping tool"},
    "psexec": {"severity": 70, "technique": "T1569.002", "desc": "Remote execution tool"},
    "procdump": {"severity": 60, "technique": "T1003.001", "desc": "Process dumper"},
    "lazagne": {"severity": 85, "technique": "T1555", "desc": "Password recovery tool"},
    "bloodhound": {"severity": 75, "technique": "T1087.002", "desc": "AD recon tool"},
    "sharphound": {"severity": 75, "technique": "T1087.002", "desc": "AD data collector"},
    "rubeus": {"severity": 90, "technique": "T1558", "desc": "Kerberos attack tool"},
    "certutil": {"severity": 30, "technique": "T1140", "desc": "Certificate utility (LOLBin)"},
    "mshta": {"severity": 40, "technique": "T1218.005", "desc": "MSHTA (LOLBin)"},
    "regsvr32": {"severity": 30, "technique": "T1218.010", "desc": "Regsvr32 (LOLBin)"},
    "powershell_ise": {"severity": 20, "technique": "T1059.001", "desc": "PowerShell ISE"},
    "wmic": {"severity": 25, "technique": "T1047", "desc": "WMI command-line"},
    "netcat": {"severity": 70, "technique": "T1095", "desc": "Network utility"},
    "ncat": {"severity": 70, "technique": "T1095", "desc": "Network utility"},
    "nc": {"severity": 60, "technique": "T1095", "desc": "Netcat variant"},
    "whoami": {"severity": 15, "technique": "T1033", "desc": "System owner discovery"},
    "net": {"severity": 15, "technique": "T1087", "desc": "Net command"},
    "nltest": {"severity": 40, "technique": "T1482", "desc": "Domain trust discovery"},
    "crackmapexec": {"severity": 85, "technique": "T1110", "desc": "Network attack tool"},
}

# Prefetch file signature
PREFETCH_SIGNATURES = {
    0x1A: "Windows XP/2003",
    0x17: "Windows Vista/7",
    0x1E: "Windows 8/8.1",
    0x1E + 0x12: "Windows 10/11",  # Compressed
}


class PrefetchParser(BaseForensicModule):
    """
    Parses Windows Prefetch files for execution history.

    Prefetch files (*.pf) record information about programs
    that have been executed, including execution count and
    last run time. Suspicious programs in prefetch indicate
    they were run on the system.
    """

    def analyze(self) -> List[ForensicFinding]:
        """
        Analyze prefetch files for suspicious executables.

        Returns:
            List of forensic findings.
        """
        from utils.safety import SANDBOX_ROOT, TESTING_MODE

        if TESTING_MODE:
            prefetch_dir = SANDBOX_ROOT / "Windows" / "Prefetch"
        else:
            prefetch_dir = Path(
                self.config.get("prefetch_dir", str(PREFETCH_DIR))
            )

        return self.scan_prefetch_directory(prefetch_dir)

    def scan_prefetch_directory(
        self, prefetch_dir: Path
    ) -> List[ForensicFinding]:
        """
        Scan a prefetch directory for execution artifacts.

        Args:
            prefetch_dir: Path to the Prefetch directory.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        if not prefetch_dir.exists():
            self.logger.debug("Prefetch directory not found: %s", prefetch_dir)
            return findings

        pf_files = list(prefetch_dir.glob("*.pf"))
        self.logger.info("Found %d prefetch files", len(pf_files))

        for pf_file in pf_files:
            try:
                pf_findings = self._analyze_prefetch_file(pf_file)
                findings.extend(pf_findings)
            except Exception as e:
                self.logger.debug(
                    "Failed to parse %s: %s", pf_file.name, e
                )

        return findings

    def _analyze_prefetch_file(
        self, pf_path: Path
    ) -> List[ForensicFinding]:
        """
        Analyze a single prefetch file.

        Args:
            pf_path: Path to the .pf file.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        # Extract executable name from prefetch filename
        # Format: EXECUTABLE-HASH.pf
        pf_name = pf_path.stem.upper()
        parts = pf_name.rsplit("-", 1)
        exe_name = parts[0].lower() if parts else pf_name.lower()

        # Check against suspicious executables
        for pattern, info in SUSPICIOUS_EXECUTABLES.items():
            if pattern in exe_name:
                # Try to read basic prefetch metadata
                metadata = self._read_prefetch_metadata(pf_path)

                findings.append(ForensicFinding(
                    source="prefetch",
                    description=(
                        f"Suspicious executable in prefetch: "
                        f"{exe_name} - {info['desc']}"
                    ),
                    severity=info["severity"],
                    evidence=(
                        f"Prefetch file: {pf_path.name}\n"
                        f"Executable: {exe_name}\n"
                        f"Run count: {metadata.get('run_count', 'unknown')}\n"
                        f"Last run: {metadata.get('last_run', 'unknown')}\n"
                        f"PF Modified: {datetime.fromtimestamp(pf_path.stat().st_mtime).isoformat()}"
                    ),
                    timestamp=datetime.fromtimestamp(
                        pf_path.stat().st_mtime
                    ),
                    artifact_path=str(pf_path),
                    attack_techniques=[info["technique"]],
                    attack_tactics=["Execution"],
                    attack_confidence="high",
                ))
                break  # Only report first match per file

        return findings

    def _read_prefetch_metadata(
        self, pf_path: Path
    ) -> Dict[str, Any]:
        """
        Read basic metadata from a prefetch file.

        Args:
            pf_path: Path to the .pf file.

        Returns:
            Dictionary with run_count and last_run.
        """
        metadata: Dict[str, Any] = {}

        try:
            with open(pf_path, "rb") as f:
                header = f.read(84)

            if len(header) < 84:
                return metadata

            # Check for MAM signature (compressed, Win10+)
            if header[:4] == b"MAM\x04":
                # Compressed prefetch - skip decompression for now
                metadata["compressed"] = True
                return metadata

            # Uncompressed prefetch header
            version = struct.unpack_from("<I", header, 0)[0]

            if version in (0x17, 0x1A):
                # XP/Vista/7 format
                run_count = struct.unpack_from("<I", header, 60)[0]
                metadata["run_count"] = run_count
            elif version == 0x1E:
                # Win8+ format
                run_count = struct.unpack_from("<I", header, 60)[0]
                metadata["run_count"] = run_count

        except Exception as e:
            logger.debug("Prefetch metadata read failed: %s", e)

        return metadata
