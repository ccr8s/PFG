"""
PE (Portable Executable) file analyzer for FileGuard.

Analyzes Windows executables for anomalies, suspicious imports,
packing indicators, and structural issues.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.base import BaseDetector
from core.models import Finding
from detectors.entropy_detector import calculate_entropy

logger = logging.getLogger(__name__)

# PE magic bytes
PE_MAGIC = b"MZ"

# Suspicious section names that indicate packing
SUSPICIOUS_SECTIONS: Set[str] = {
    "UPX0", "UPX1", "UPX2", "UPX!",
    ".nsp0", ".nsp1", ".nsp2",
    ".aspack", ".adata",
    ".Themida", ".vmp0", ".vmp1",
    ".petite", ".perplex",
    ".sforce", ".svkp",
    ".packed", ".RLPack",
}

# Suspicious imports that indicate malicious behavior
SUSPICIOUS_IMPORTS: Dict[str, str] = {
    "VirtualAllocEx": "Remote memory allocation (code injection)",
    "WriteProcessMemory": "Process memory writing (code injection)",
    "CreateRemoteThread": "Remote thread creation (code injection)",
    "NtCreateThreadEx": "Native remote thread (code injection)",
    "SetWindowsHookEx": "Keyboard/mouse hooking",
    "GetAsyncKeyState": "Keylogger behavior",
    "OpenProcess": "Process handle acquisition",
    "AdjustTokenPrivileges": "Privilege escalation",
    "LookupPrivilegeValue": "Privilege lookup",
    "IsDebuggerPresent": "Anti-debugging check",
    "CheckRemoteDebuggerPresent": "Anti-debugging check",
    "NtQueryInformationProcess": "Anti-debugging/sandbox detection",
    "InternetOpen": "Network communication",
    "URLDownloadToFile": "File download from URL",
    "WinExec": "Command execution",
    "ShellExecute": "Shell command execution",
    "RegSetValueEx": "Registry modification",
    "CryptEncrypt": "Encryption operation",
    "CryptDecrypt": "Decryption operation",
}


class PEAnalyzer(BaseDetector):
    """
    Analyzes PE files for structural anomalies and suspicious characteristics.

    Checks for:
    - Packing indicators (section names, entropy)
    - Suspicious imports (injection, keylogging, anti-debug)
    - Structural anomalies (entry point, checksum, sections)
    - Missing or malformed headers
    """

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Analyze a PE file and return findings.

        Args:
            file_path: Path to the PE file.
            file_content: Optional pre-read content.

        Returns:
            List of findings for PE anomalies.
        """
        findings: List[Finding] = []

        if not self.is_applicable(file_path):
            return findings

        try:
            import pefile
        except ImportError:
            logger.warning(
                "pefile not installed - PE analysis skipped for %s",
                file_path,
            )
            return findings

        try:
            if file_content:
                pe = pefile.PE(data=file_content)
            else:
                pe = pefile.PE(str(file_path))
        except pefile.PEFormatError:
            # Malformed PE - that's itself a finding
            findings.append(Finding(
                detector=self.name,
                description="Malformed PE file - invalid headers",
                severity=50,
                evidence="pefile.PEFormatError during parsing",
                remediation=(
                    "File has corrupted or deliberately malformed PE headers. "
                    "This may indicate a packed or obfuscated executable."
                ),
                attack_techniques=["T1027.002"],
                attack_tactics=["Defense Evasion"],
                attack_confidence="medium",
            ))
            return findings
        except Exception as e:
            logger.error("PE analysis failed for %s: %s", file_path, e)
            return findings

        try:
            # Check sections for packing indicators
            findings.extend(self._check_sections(pe))

            # Check for suspicious imports
            findings.extend(self._check_imports(pe))

            # Check entry point
            findings.extend(self._check_entry_point(pe))

            # Check PE checksum
            findings.extend(self._check_checksum(pe))

            # Check for no imports (suspicious for executable)
            findings.extend(self._check_no_imports(pe))

        finally:
            pe.close()

        return findings

    def is_applicable(self, file_path: Path) -> bool:
        """Only analyze PE file extensions."""
        pe_extensions = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl"}
        return file_path.suffix.lower() in pe_extensions

    def _check_sections(self, pe: Any) -> List[Finding]:
        """Check PE sections for packing indicators."""
        findings: List[Finding] = []
        executable_section_count = 0

        for section in pe.sections:
            try:
                section_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                section_name = "<invalid>"

            # Check for known packer section names
            if section_name in SUSPICIOUS_SECTIONS:
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Suspicious section name: {section_name} "
                        f"(indicates packing)"
                    ),
                    severity=35,
                    evidence=f"Section: {section_name}",
                    remediation=(
                        "File appears to be packed. Unpack before analysis."
                    ),
                    attack_techniques=["T1027.002"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="medium",
                ))

            # Check section entropy
            section_data = section.get_data()
            if len(section_data) >= 256:
                entropy = calculate_entropy(section_data)
                if entropy > 7.5:
                    findings.append(Finding(
                        detector=self.name,
                        description=(
                            f"High entropy section: {section_name} "
                            f"({entropy:.2f})"
                        ),
                        severity=40,
                        evidence=(
                            f"Section {section_name} entropy: "
                            f"{entropy:.4f} / 8.0"
                        ),
                        attack_techniques=["T1027"],
                        attack_tactics=["Defense Evasion"],
                        attack_confidence="medium",
                    ))

            # Count executable sections
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                executable_section_count += 1

        # Too many executable sections
        if executable_section_count > 2:
            findings.append(Finding(
                detector=self.name,
                description=(
                    f"{executable_section_count} executable sections "
                    f"(unusual)"
                ),
                severity=30,
                evidence=(
                    f"Found {executable_section_count} sections with "
                    f"execute permission"
                ),
                attack_techniques=["T1027.002"],
                attack_tactics=["Defense Evasion"],
                attack_confidence="low",
            ))

        return findings

    def _check_imports(self, pe: Any) -> List[Finding]:
        """Check for suspicious API imports."""
        findings: List[Finding] = []

        try:
            if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                return findings

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    func_name = imp.name.decode("utf-8", errors="replace")

                    if func_name in SUSPICIOUS_IMPORTS:
                        desc = SUSPICIOUS_IMPORTS[func_name]
                        findings.append(Finding(
                            detector=self.name,
                            description=(
                                f"Suspicious import: {func_name} - {desc}"
                            ),
                            severity=self._import_severity(func_name),
                            evidence=f"Import: {func_name} from {entry.dll.decode('utf-8', errors='replace')}",
                            attack_techniques=self._import_techniques(func_name),
                            attack_tactics=self._import_tactics(func_name),
                            attack_confidence="medium",
                        ))
        except Exception as e:
            logger.debug("Import check failed: %s", e)

        return findings

    def _check_entry_point(self, pe: Any) -> List[Finding]:
        """Check if entry point is outside any section."""
        findings: List[Finding] = []

        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_in_section = False

            for section in pe.sections:
                sec_start = section.VirtualAddress
                sec_end = sec_start + section.Misc_VirtualSize
                if sec_start <= ep < sec_end:
                    ep_in_section = True
                    break

            if not ep_in_section and ep != 0:
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        "Entry point outside any section "
                        "(overlay or injection indicator)"
                    ),
                    severity=60,
                    evidence=f"Entry point RVA: 0x{ep:08X}",
                    remediation=(
                        "Entry point is not within any section. "
                        "May indicate code injection or overlay payload."
                    ),
                    attack_techniques=["T1055"],
                    attack_tactics=["Defense Evasion", "Privilege Escalation"],
                    attack_confidence="medium",
                ))
        except Exception as e:
            logger.debug("Entry point check failed: %s", e)

        return findings

    def _check_checksum(self, pe: Any) -> List[Finding]:
        """Check PE checksum validity."""
        findings: List[Finding] = []

        try:
            claimed = pe.OPTIONAL_HEADER.CheckSum
            actual = pe.generate_checksum()

            if claimed != 0 and claimed != actual:
                findings.append(Finding(
                    detector=self.name,
                    description="PE checksum mismatch (file modified)",
                    severity=25,
                    evidence=(
                        f"Claimed: 0x{claimed:08X}, "
                        f"Actual: 0x{actual:08X}"
                    ),
                    attack_techniques=["T1036"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="low",
                ))
        except Exception as e:
            logger.debug("Checksum check failed: %s", e)

        return findings

    def _check_no_imports(self, pe: Any) -> List[Finding]:
        """Check if PE has no imports at all (suspicious)."""
        findings: List[Finding] = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            findings.append(Finding(
                detector=self.name,
                description=(
                    "PE file has no import table "
                    "(statically linked or packed)"
                ),
                severity=45,
                evidence="No DIRECTORY_ENTRY_IMPORT",
                remediation=(
                    "A PE file with no imports is unusual. "
                    "May be statically linked, packed, or shellcode."
                ),
                attack_techniques=["T1027.002"],
                attack_tactics=["Defense Evasion"],
                attack_confidence="medium",
            ))

        return findings

    @staticmethod
    def _import_severity(func_name: str) -> int:
        """Map import function to severity score."""
        high_severity = {
            "VirtualAllocEx", "WriteProcessMemory",
            "CreateRemoteThread", "NtCreateThreadEx",
        }
        medium_severity = {
            "SetWindowsHookEx", "GetAsyncKeyState",
            "AdjustTokenPrivileges", "URLDownloadToFile",
        }
        if func_name in high_severity:
            return 50
        if func_name in medium_severity:
            return 35
        return 20

    @staticmethod
    def _import_techniques(func_name: str) -> List[str]:
        """Map import function to ATT&CK techniques."""
        mapping: Dict[str, List[str]] = {
            "VirtualAllocEx": ["T1055"],
            "WriteProcessMemory": ["T1055"],
            "CreateRemoteThread": ["T1055"],
            "SetWindowsHookEx": ["T1056.001"],
            "GetAsyncKeyState": ["T1056.001"],
            "AdjustTokenPrivileges": ["T1134"],
            "URLDownloadToFile": ["T1105"],
            "IsDebuggerPresent": ["T1497"],
            "CheckRemoteDebuggerPresent": ["T1497"],
            "RegSetValueEx": ["T1547.001"],
        }
        return mapping.get(func_name, ["T1106"])

    @staticmethod
    def _import_tactics(func_name: str) -> List[str]:
        """Map import function to ATT&CK tactics."""
        mapping: Dict[str, List[str]] = {
            "VirtualAllocEx": ["Defense Evasion", "Privilege Escalation"],
            "WriteProcessMemory": ["Defense Evasion"],
            "CreateRemoteThread": ["Defense Evasion"],
            "SetWindowsHookEx": ["Collection", "Credential Access"],
            "GetAsyncKeyState": ["Collection"],
            "AdjustTokenPrivileges": ["Privilege Escalation"],
            "URLDownloadToFile": ["Command and Control"],
            "IsDebuggerPresent": ["Defense Evasion"],
            "RegSetValueEx": ["Persistence"],
        }
        return mapping.get(func_name, ["Execution"])
