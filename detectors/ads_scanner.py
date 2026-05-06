"""
Alternate Data Stream (ADS) scanner for FileGuard.

Detects NTFS Alternate Data Streams that can hide malicious
payloads alongside legitimate files.
"""

import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseDetector
from core.models import Finding

logger = logging.getLogger(__name__)

# Known benign ADS names that Windows uses
KNOWN_BENIGN_ADS = {
    "Zone.Identifier",         # Mark of the Web
    "SummaryInformation",      # Office metadata
    "DocumentSummaryInformation",
    "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",  # Thumbnail
    "encryptable",
    "WofCompressedData",       # Windows Overlay Filter
}

# Suspicious ADS content signatures
SUSPICIOUS_ADS_CONTENT = [
    b"MZ",                     # PE executable
    b"#!/",                    # Script shebang
    b"<script",                # HTML script
    b"powershell",             # PowerShell reference
    b"cmd /c",                 # Command execution
]


class ADSScanner(BaseDetector):
    """
    Detects and analyzes NTFS Alternate Data Streams.

    ADS can be used to hide executable payloads, scripts, or
    other malicious content alongside legitimate files without
    changing the file's apparent size.

    ATT&CK Technique: T1564.004 (NTFS File Attributes)
    """

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Scan a file for Alternate Data Streams.

        Args:
            file_path: Path to the file to scan.
            file_content: Unused (ADS requires filesystem access).

        Returns:
            List of findings for suspicious ADS.
        """
        findings: List[Finding] = []

        if not _is_ntfs_path(file_path):
            return findings

        try:
            streams = self._enumerate_streams(file_path)

            for stream_name, stream_size in streams:
                # Skip the main data stream
                if stream_name == "" or stream_name == "$DATA":
                    continue

                # Skip known benign streams
                clean_name = stream_name.strip(":")
                if clean_name in KNOWN_BENIGN_ADS:
                    continue

                severity = self._assess_stream_severity(
                    file_path, stream_name, stream_size
                )

                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Alternate Data Stream found: "
                        f"{file_path.name}:{clean_name} "
                        f"({stream_size} bytes)"
                    ),
                    severity=severity,
                    evidence=(
                        f"ADS: {file_path}:{clean_name}\n"
                        f"Size: {stream_size} bytes"
                    ),
                    remediation=(
                        "Inspect the Alternate Data Stream content. "
                        "ADS can hide executable payloads. Use: "
                        f"more < \"{file_path}:{clean_name}\" "
                        "to view contents."
                    ),
                    attack_techniques=["T1564.004"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence=(
                        "high" if severity >= 50 else "medium"
                    ),
                ))

        except PermissionError:
            self.logger.debug("Permission denied scanning ADS: %s", file_path)
        except Exception as e:
            self.logger.debug("ADS scan failed for %s: %s", file_path, e)

        return findings

    def _enumerate_streams(
        self, file_path: Path
    ) -> List[tuple]:
        """
        Enumerate all data streams on a file.

        Uses the Windows dir /r command to find ADS, or falls back
        to the Python ctypes approach.

        Args:
            file_path: Path to check.

        Returns:
            List of (stream_name, stream_size) tuples.
        """
        streams: List[tuple] = []

        try:
            # Use dir /r to enumerate streams
            result = subprocess.run(
                ["cmd", "/c", "dir", "/r", str(file_path)],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    # ADS lines look like: "  123 filename.txt:stream_name:$DATA"
                    if ":$DATA" in line and file_path.name in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                size = int(parts[0].replace(",", ""))
                                name_part = parts[-1]
                                # Extract stream name between colons
                                stream_parts = name_part.split(":")
                                if len(stream_parts) >= 2:
                                    stream_name = stream_parts[1]
                                    streams.append((stream_name, size))
                            except (ValueError, IndexError):
                                continue

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.debug("dir /r failed: %s", e)

        # Fallback: try using ctypes FindFirstStreamW
        if not streams:
            streams = self._enumerate_streams_ctypes(file_path)

        return streams

    def _enumerate_streams_ctypes(
        self, file_path: Path
    ) -> List[tuple]:
        """
        Enumerate streams using Windows API via ctypes.

        Args:
            file_path: Path to check.

        Returns:
            List of (stream_name, stream_size) tuples.
        """
        streams: List[tuple] = []

        try:
            import ctypes
            import ctypes.wintypes

            kernel32 = ctypes.windll.kernel32

            class WIN32_FIND_STREAM_DATA(ctypes.Structure):
                _fields_ = [
                    ("StreamSize", ctypes.c_longlong),
                    ("cStreamName", ctypes.c_wchar * 296),
                ]

            find_data = WIN32_FIND_STREAM_DATA()
            handle = kernel32.FindFirstStreamW(
                str(file_path),
                0,  # FindStreamInfoStandard
                ctypes.byref(find_data),
                0,
            )

            INVALID_HANDLE = ctypes.c_void_p(-1).value
            if handle == INVALID_HANDLE:
                return streams

            try:
                while True:
                    name = find_data.cStreamName
                    size = find_data.StreamSize

                    # Skip main ::$DATA stream
                    if name != "::$DATA" and ":$DATA" in name:
                        clean = name.replace(":$DATA", "").strip(":")
                        if clean:
                            streams.append((clean, size))

                    if not kernel32.FindNextStreamW(
                        handle, ctypes.byref(find_data)
                    ):
                        break
            finally:
                kernel32.FindClose(handle)

        except (ImportError, AttributeError, OSError) as e:
            self.logger.debug("ctypes stream enumeration failed: %s", e)

        return streams

    def _assess_stream_severity(
        self,
        file_path: Path,
        stream_name: str,
        stream_size: int,
    ) -> int:
        """
        Assess severity of an ADS based on name, size, and content.

        Args:
            file_path: Host file path.
            stream_name: Name of the ADS.
            stream_size: Size in bytes.

        Returns:
            Severity score 0-100.
        """
        severity = 25  # Base severity for any non-benign ADS

        # Large ADS is more suspicious
        if stream_size > 1024 * 1024:  # > 1 MB
            severity += 20
        elif stream_size > 10240:  # > 10 KB
            severity += 10

        # Try to read ADS content for inspection
        try:
            ads_path = f"{file_path}:{stream_name.strip(':')}"
            with open(ads_path, "rb") as f:
                header = f.read(256)

            for sig in SUSPICIOUS_ADS_CONTENT:
                if sig.lower() in header.lower():
                    severity += 30
                    break

        except (OSError, PermissionError):
            pass

        return min(severity, 100)


def _is_ntfs_path(path: Path) -> bool:
    """Check if a path is on an NTFS filesystem."""
    try:
        import ctypes
        vol_name = ctypes.create_unicode_buffer(256)
        fs_name = ctypes.create_unicode_buffer(256)

        drive = str(path.resolve().anchor)
        result = ctypes.windll.kernel32.GetVolumeInformationW(
            drive,
            vol_name, 256,
            None, None, None,
            fs_name, 256,
        )
        return result != 0 and "NTFS" in fs_name.value
    except (ImportError, AttributeError, OSError):
        # If we can't check, assume NTFS on Windows
        import os
        return os.name == "nt"
