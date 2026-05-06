"""
Amcache and Shimcache parser for FileGuard.

Analyzes Windows Amcache.hve and Shimcache (AppCompatCache)
registry entries to identify program execution history.
"""

import logging
import struct
from pathlib import Path
from typing import Any, Dict, List

from core.base import BaseForensicModule
from core.models import ForensicFinding

logger = logging.getLogger(__name__)

# Default Amcache location
AMCACHE_PATH = Path(
    r"C:\Windows\appcompat\Programs\Amcache.hve"
)

# Shimcache registry key
SHIMCACHE_KEY = (
    r"SYSTEM\CurrentControlSet\Control\Session Manager"
    r"\AppCompatCache"
)

# Suspicious paths in execution history
SUSPICIOUS_PATHS = [
    {"pattern": "\\temp\\", "severity": 30, "desc": "Execution from Temp"},
    {"pattern": "\\downloads\\", "severity": 25, "desc": "Execution from Downloads"},
    {"pattern": "\\appdata\\local\\temp", "severity": 35, "desc": "Execution from user Temp"},
    {"pattern": "\\recycle.bin\\", "severity": 50, "desc": "Execution from Recycle Bin"},
    {"pattern": "\\$recycle.bin\\", "severity": 50, "desc": "Execution from Recycle Bin"},
    {"pattern": "\\programdata\\", "severity": 20, "desc": "Execution from ProgramData"},
    {"pattern": "\\public\\", "severity": 20, "desc": "Execution from Public folder"},
]

# Suspicious executable names
SUSPICIOUS_NAMES = {
    "mimikatz": 95,
    "psexec": 60,
    "procdump": 55,
    "lazagne": 85,
    "bloodhound": 70,
    "sharphound": 70,
    "rubeus": 90,
    "covenant": 90,
    "beacon": 80,
    "meterpreter": 95,
    "nc.exe": 60,
    "ncat.exe": 60,
    "netcat": 60,
    "crackmapexec": 85,
    "secretsdump": 90,
    "nanodump": 90,
    "powercat": 65,
}


class AmcacheParser(BaseForensicModule):
    """
    Parses Amcache.hve and Shimcache for execution artifacts.

    The Amcache tracks application compatibility data including
    file paths, sizes, hashes, and timestamps of executables.
    Shimcache (AppCompatCache) similarly records execution data.
    Both provide forensic evidence of what programs have run.
    """

    def analyze(self) -> List[ForensicFinding]:
        """
        Analyze Amcache and Shimcache for suspicious executables.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []

        # Analyze Amcache
        findings.extend(self._analyze_amcache())

        # Analyze Shimcache
        findings.extend(self._analyze_shimcache())

        return findings

    def _analyze_amcache(self) -> List[ForensicFinding]:
        """Analyze Amcache.hve registry hive."""
        findings: List[ForensicFinding] = []

        from utils.safety import SANDBOX_ROOT, TESTING_MODE

        if TESTING_MODE:
            amcache_path = SANDBOX_ROOT / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
        else:
            amcache_path = Path(
                self.config.get("amcache_path", str(AMCACHE_PATH))
            )

        if not amcache_path.exists():
            self.logger.debug("Amcache not found: %s", amcache_path)
            return findings

        try:
            from regipy.plugins.amcache import AmCachePlugin
            from regipy.registry import RegistryHive

            hive = RegistryHive(str(amcache_path))

            # Try to get amcache entries
            try:
                plugin = AmCachePlugin(hive, as_json=True)
                plugin.run()

                for entry in plugin.entries or []:
                    entry_findings = self._assess_amcache_entry(entry)
                    findings.extend(entry_findings)
            except Exception as e:
                self.logger.debug("Amcache plugin failed: %s", e)
                # Fall back to manual parsing
                findings.extend(self._parse_amcache_manual(hive))

        except ImportError:
            self.logger.debug("regipy not available for Amcache analysis")
        except Exception as e:
            self.logger.error("Amcache analysis failed: %s", e)

        return findings

    def _parse_amcache_manual(self, hive: Any) -> List[ForensicFinding]:
        """Manually parse Amcache hive for execution entries."""
        findings: List[ForensicFinding] = []

        try:
            # Amcache stores entries under Root\InventoryApplicationFile
            inv_key = hive.get_key("Root\\InventoryApplicationFile")
            if inv_key and inv_key.subkeys:
                for subkey in inv_key.subkeys:
                    try:
                        values = {
                            v.name: v.value for v in (subkey.values or [])
                        }
                        file_path = values.get("LowerCaseLongPath", "")
                        name = values.get("Name", "")

                        if file_path or name:
                            entry = {
                                "path": str(file_path),
                                "name": str(name),
                            }
                            findings.extend(
                                self._assess_amcache_entry(entry)
                            )
                    except Exception:
                        continue
        except Exception as e:
            self.logger.debug("Manual amcache parse failed: %s", e)

        return findings

    def _analyze_shimcache(self) -> List[ForensicFinding]:
        """Analyze Shimcache from registry."""
        findings: List[ForensicFinding] = []

        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                SHIMCACHE_KEY,
                0,
                winreg.KEY_READ,
            )

            try:
                data, regtype = winreg.QueryValueEx(
                    key, "AppCompatCache"
                )
                if data:
                    entries = self._parse_shimcache_data(data)
                    for entry in entries:
                        findings.extend(
                            self._assess_shimcache_entry(entry)
                        )
            finally:
                winreg.CloseKey(key)

        except ImportError:
            self.logger.debug("winreg not available for Shimcache")
        except FileNotFoundError:
            self.logger.debug("Shimcache registry key not found")
        except PermissionError:
            self.logger.debug("Permission denied reading Shimcache")
        except Exception as e:
            self.logger.debug("Shimcache analysis failed: %s", e)

        return findings

    def _parse_shimcache_data(
        self, data: bytes
    ) -> List[Dict[str, Any]]:
        """
        Parse raw Shimcache binary data.

        Args:
            data: Raw AppCompatCache registry value.

        Returns:
            List of entry dictionaries with path and metadata.
        """
        entries: List[Dict[str, Any]] = []

        if len(data) < 4:
            return entries

        # Detect format by header signature
        sig = struct.unpack_from("<I", data, 0)[0]

        try:
            if sig == 0x30:
                # Windows 10 format
                entries = self._parse_shimcache_win10(data)
            elif sig == 0x80:
                # Windows 8.x format
                entries = self._parse_shimcache_win8(data)
        except Exception as e:
            self.logger.debug("Shimcache parse error: %s", e)

        return entries

    def _parse_shimcache_win10(
        self, data: bytes
    ) -> List[Dict[str, Any]]:
        """Parse Windows 10/11 Shimcache format."""
        entries: List[Dict[str, Any]] = []
        offset = 0x30  # Skip header

        while offset < len(data) - 12:
            try:
                # Check for "10ts" signature
                sig = data[offset:offset + 4]
                if sig != b"10ts":
                    break

                # Read entry
                entry_size = struct.unpack_from("<I", data, offset + 8)[0]
                path_size = struct.unpack_from("<H", data, offset + 12)[0]

                if path_size > 0 and offset + 14 + path_size <= len(data):
                    path = data[
                        offset + 14:offset + 14 + path_size
                    ].decode("utf-16-le", errors="replace").strip("\x00")

                    entries.append({"path": path})

                offset += entry_size + 12
                if entry_size == 0:
                    break

            except Exception:
                break

        return entries

    def _parse_shimcache_win8(
        self, data: bytes
    ) -> List[Dict[str, Any]]:
        """Parse Windows 8.x Shimcache format."""
        entries: List[Dict[str, Any]] = []
        offset = 0x80

        while offset < len(data) - 8:
            try:
                path_size = struct.unpack_from("<I", data, offset)[0]
                if path_size == 0 or path_size > 2048:
                    break

                path = data[
                    offset + 4:offset + 4 + path_size
                ].decode("utf-16-le", errors="replace").strip("\x00")

                entries.append({"path": path})
                offset += path_size + 16  # Skip path + metadata

            except Exception:
                break

        return entries

    def _assess_amcache_entry(
        self, entry: Dict[str, Any]
    ) -> List[ForensicFinding]:
        """Assess an Amcache entry for suspiciousness."""
        findings: List[ForensicFinding] = []
        path = str(entry.get("path", entry.get("LowerCaseLongPath", ""))).lower()
        name = str(entry.get("name", entry.get("Name", ""))).lower()

        if not path and not name:
            return findings

        combined = f"{path} {name}"

        # Check suspicious names
        for susp_name, severity in SUSPICIOUS_NAMES.items():
            if susp_name in combined:
                findings.append(ForensicFinding(
                    source="amcache",
                    description=(
                        f"Suspicious program in Amcache: {susp_name}"
                    ),
                    severity=severity,
                    evidence=f"Path: {path}\nName: {name}",
                    attack_techniques=["T1059"],
                    attack_tactics=["Execution"],
                    attack_confidence="high",
                ))
                break

        # Check suspicious paths
        for susp_path in SUSPICIOUS_PATHS:
            if susp_path["pattern"] in path:
                findings.append(ForensicFinding(
                    source="amcache",
                    description=(
                        f"{susp_path['desc']}: {Path(path).name if path else name}"
                    ),
                    severity=susp_path["severity"],
                    evidence=f"Path: {path}",
                    attack_techniques=["T1204"],
                    attack_tactics=["Execution"],
                    attack_confidence="low",
                ))
                break

        return findings

    def _assess_shimcache_entry(
        self, entry: Dict[str, Any]
    ) -> List[ForensicFinding]:
        """Assess a Shimcache entry (same logic as Amcache)."""
        return self._assess_amcache_entry(entry)
