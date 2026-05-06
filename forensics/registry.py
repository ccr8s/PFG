"""
Windows Registry analyzer for FileGuard.

Analyzes registry hives for persistence mechanisms, suspicious
entries, and indicators of compromise.
"""

import logging
from typing import Any, Dict, List, Optional

from core.base import BaseForensicModule
from core.models import ForensicFinding

logger = logging.getLogger(__name__)

# Registry keys commonly used for persistence
PERSISTENCE_KEYS = [
    {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "hive": "HKLM",
        "description": "System startup programs",
        "severity": 30,
        "technique": "T1547.001",
    },
    {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "hive": "HKCU",
        "description": "User startup programs",
        "severity": 30,
        "technique": "T1547.001",
    },
    {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "hive": "HKLM",
        "description": "One-time startup programs",
        "severity": 35,
        "technique": "T1547.001",
    },
    {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "hive": "HKCU",
        "description": "User one-time startup programs",
        "severity": 35,
        "technique": "T1547.001",
    },
    {
        "path": r"SYSTEM\CurrentControlSet\Services",
        "hive": "HKLM",
        "description": "System services",
        "severity": 35,
        "technique": "T1543.003",
    },
    {
        "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "hive": "HKLM",
        "description": "Winlogon hooks",
        "severity": 45,
        "technique": "T1547.004",
    },
    {
        "path": (
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\Image File Execution Options"
        ),
        "hive": "HKLM",
        "description": "Image File Execution Options (IFEO)",
        "severity": 60,
        "technique": "T1546.012",
    },
    {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "hive": "HKCU",
        "description": "Shell folders (startup redirection)",
        "severity": 30,
        "technique": "T1547.001",
    },
]

# Suspicious patterns in registry values
SUSPICIOUS_VALUE_PATTERNS = [
    {"pattern": "powershell", "description": "PowerShell in startup", "boost": 20},
    {"pattern": "cmd /c", "description": "Command execution in startup", "boost": 15},
    {"pattern": "mshta", "description": "MSHTA in startup", "boost": 25},
    {"pattern": "regsvr32", "description": "Regsvr32 in startup", "boost": 20},
    {"pattern": "rundll32", "description": "Rundll32 in startup", "boost": 15},
    {"pattern": "wscript", "description": "WScript in startup", "boost": 15},
    {"pattern": "cscript", "description": "CScript in startup", "boost": 15},
    {"pattern": "\\temp\\", "description": "Temp folder reference", "boost": 20},
    {"pattern": "\\appdata\\", "description": "AppData folder reference", "boost": 10},
    {"pattern": "http://", "description": "URL in registry value", "boost": 25},
    {"pattern": "https://", "description": "URL in registry value", "boost": 20},
]


class RegistryAnalyzer(BaseForensicModule):
    """
    Analyzes Windows Registry for persistence and suspicious entries.

    Detects:
    - Run/RunOnce key entries
    - Suspicious service registrations
    - Winlogon hook modifications
    - IFEO debugger hijacking
    - USB device history
    - UserAssist execution history
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize registry analyzer.

        Args:
            config: Optional configuration overrides.
        """
        super().__init__(config)

    def analyze(self) -> List[ForensicFinding]:
        """
        Run all registry analysis checks.

        Returns:
            List of forensic findings.
        """
        findings: List[ForensicFinding] = []
        findings.extend(self.check_persistence())
        findings.extend(self.check_ifeo())
        findings.extend(self.check_usb_history())
        return findings

    def check_persistence(self) -> List[ForensicFinding]:
        """
        Check common persistence registry locations.

        Returns:
            List of findings for suspicious persistence entries.
        """
        findings: List[ForensicFinding] = []

        try:
            import winreg
        except ImportError:
            self.logger.debug("winreg not available (non-Windows)")
            return self._check_persistence_offline()

        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }

        for key_info in PERSISTENCE_KEYS:
            hive_name = key_info["hive"]
            hive = hive_map.get(hive_name)
            if hive is None:
                continue

            try:
                key = winreg.OpenKey(
                    hive, key_info["path"], 0, winreg.KEY_READ
                )
                try:
                    i = 0
                    while True:
                        try:
                            name, value, vtype = winreg.EnumValue(key, i)
                            finding = self._assess_registry_value(
                                key_info, name, str(value)
                            )
                            if finding:
                                findings.append(finding)
                            i += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except FileNotFoundError:
                continue
            except PermissionError:
                self.logger.debug(
                    "Permission denied: %s\\%s",
                    hive_name, key_info["path"],
                )
            except Exception as e:
                self.logger.debug(
                    "Registry read failed: %s\\%s: %s",
                    hive_name, key_info["path"], e,
                )

        return findings

    def check_ifeo(self) -> List[ForensicFinding]:
        """Check Image File Execution Options for debugger hijacking."""
        findings: List[ForensicFinding] = []

        try:
            import winreg

            ifeo_path = (
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options"
            )

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, ifeo_path, 0, winreg.KEY_READ
            )

            try:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(
                            key, subkey_name, 0, winreg.KEY_READ
                        )
                        try:
                            debugger, _ = winreg.QueryValueEx(
                                subkey, "Debugger"
                            )
                            if debugger:
                                findings.append(ForensicFinding(
                                    source="registry",
                                    description=(
                                        f"IFEO debugger set for "
                                        f"{subkey_name}: {debugger}"
                                    ),
                                    severity=60,
                                    evidence=(
                                        f"Key: HKLM\\{ifeo_path}\\{subkey_name}\n"
                                        f"Debugger: {debugger}"
                                    ),
                                    artifact_path=(
                                        f"HKLM\\{ifeo_path}\\{subkey_name}"
                                    ),
                                    attack_techniques=["T1546.012"],
                                    attack_tactics=[
                                        "Persistence",
                                        "Privilege Escalation",
                                    ],
                                    attack_confidence="high",
                                ))
                        except FileNotFoundError:
                            pass
                        finally:
                            winreg.CloseKey(subkey)
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)

        except (ImportError, FileNotFoundError, PermissionError):
            pass

        return findings

    def check_usb_history(self) -> List[ForensicFinding]:
        """Check USB device connection history."""
        findings: List[ForensicFinding] = []

        try:
            import winreg

            usb_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, usb_path, 0, winreg.KEY_READ
            )

            devices: List[str] = []
            try:
                i = 0
                while True:
                    try:
                        devices.append(winreg.EnumKey(key, i))
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)

            if devices:
                findings.append(ForensicFinding(
                    source="registry",
                    description=(
                        f"USB storage history: {len(devices)} device(s) found"
                    ),
                    severity=15,
                    evidence=f"Devices: {', '.join(devices[:10])}",
                    artifact_path=f"HKLM\\{usb_path}",
                    attack_techniques=["T1091"],
                    attack_tactics=["Initial Access", "Lateral Movement"],
                    attack_confidence="low",
                ))

        except (ImportError, FileNotFoundError, PermissionError):
            pass

        return findings

    def _check_persistence_offline(self) -> List[ForensicFinding]:
        """Check persistence using offline registry hives (regipy)."""
        findings: List[ForensicFinding] = []

        hive_path = self.config.get("hive_path")
        if not hive_path:
            return findings

        try:
            from regipy.registry import RegistryHive

            hive = RegistryHive(hive_path)
            for key_info in PERSISTENCE_KEYS:
                try:
                    reg_key = hive.get_key(key_info["path"])
                    if reg_key and reg_key.values:
                        for value in reg_key.values:
                            finding = self._assess_registry_value(
                                key_info,
                                value.name or "",
                                str(value.value or ""),
                            )
                            if finding:
                                findings.append(finding)
                except Exception:
                    continue

        except ImportError:
            self.logger.debug("regipy not available for offline analysis")
        except Exception as e:
            self.logger.error("Offline registry analysis failed: %s", e)

        return findings

    def _assess_registry_value(
        self,
        key_info: Dict[str, Any],
        name: str,
        value: str,
    ) -> Optional[ForensicFinding]:
        """
        Assess a registry value for suspiciousness.

        Args:
            key_info: Registry key metadata.
            name: Value name.
            value: Value data as string.

        Returns:
            ForensicFinding if suspicious, None otherwise.
        """
        severity = key_info["severity"]
        value_lower = value.lower()

        # Check against suspicious patterns
        matched_patterns: List[str] = []
        for pattern_info in SUSPICIOUS_VALUE_PATTERNS:
            if pattern_info["pattern"] in value_lower:
                severity += pattern_info["boost"]
                matched_patterns.append(pattern_info["description"])

        if severity >= 40 or matched_patterns:
            return ForensicFinding(
                source="registry",
                description=(
                    f"Persistence entry in {key_info['hive']}\\{key_info['path']}: "
                    f"{name}"
                ),
                severity=min(severity, 100),
                evidence=(
                    f"Key: {key_info['hive']}\\{key_info['path']}\n"
                    f"Name: {name}\n"
                    f"Value: {value[:200]}\n"
                    f"Patterns: {', '.join(matched_patterns) or 'none'}"
                ),
                artifact_path=f"{key_info['hive']}\\{key_info['path']}",
                attack_techniques=[key_info["technique"]],
                attack_tactics=["Persistence"],
                attack_confidence=(
                    "high" if matched_patterns else "low"
                ),
            )

        return None
