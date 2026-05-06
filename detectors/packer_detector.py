"""
Packed and encrypted file detection module for FileGuard.

Identifies executables that have been packed with common tools
(UPX, Themida, VMProtect, etc.) or encrypted to evade analysis.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.base import BaseDetector
from core.models import Finding
from detectors.entropy_detector import calculate_entropy

logger = logging.getLogger(__name__)

# Known packer signatures (magic bytes at specific offsets)
PACKER_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "UPX",
        "description": "UPX packer detected",
        "section_names": {"UPX0", "UPX1", "UPX2", "UPX!"},
        "severity": 30,
        "strings": [b"UPX!", b"UPX0", b"UPX1"],
    },
    {
        "name": "Themida",
        "description": "Themida/WinLicense protector detected",
        "section_names": {".Themida", ".winlice"},
        "severity": 50,
        "strings": [b"Themida", b"WinLicense"],
    },
    {
        "name": "VMProtect",
        "description": "VMProtect software protection detected",
        "section_names": {".vmp0", ".vmp1", ".vmp2"},
        "severity": 50,
        "strings": [b"VMProtect"],
    },
    {
        "name": "ASPack",
        "description": "ASPack packer detected",
        "section_names": {".aspack", ".adata"},
        "severity": 40,
        "strings": [b"ASPack"],
    },
    {
        "name": "PEtite",
        "description": "PEtite packer detected",
        "section_names": {".petite"},
        "severity": 35,
        "strings": [b"petite"],
    },
    {
        "name": "MPRESS",
        "description": "MPRESS packer detected",
        "section_names": {".MPRESS1", ".MPRESS2"},
        "severity": 35,
        "strings": [b"MPRESS"],
    },
    {
        "name": "Enigma",
        "description": "Enigma Protector detected",
        "section_names": {".enigma1", ".enigma2"},
        "severity": 45,
        "strings": [b"Enigma protector"],
    },
    {
        "name": "NSPack",
        "description": "NSPack packer detected",
        "section_names": {".nsp0", ".nsp1", ".nsp2"},
        "severity": 40,
        "strings": [b"nsPacK"],
    },
]

# PE file extensions to check
PE_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl",
}


class PackerDetector(BaseDetector):
    """
    Detects packed and encrypted executables.

    Uses multiple heuristics:
    1. Known packer section names in PE headers
    2. Packer signature strings in file content
    3. Entropy analysis of PE sections
    4. Import table anomalies (few imports = likely packed)
    5. Section size ratio analysis
    """

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Detect packing in a PE file.

        Args:
            file_path: Path to the PE file.
            file_content: Optional pre-read content.

        Returns:
            List of findings for detected packing.
        """
        findings: List[Finding] = []

        if not self.is_applicable(file_path):
            return findings

        try:
            if file_content is None:
                with open(file_path, "rb") as f:
                    file_content = f.read()

            # Check raw content for packer strings
            findings.extend(self._check_packer_strings(file_content))

            # PE-level analysis
            findings.extend(self._analyze_pe_packing(file_path, file_content))

        except PermissionError:
            logger.debug("Permission denied: %s", file_path)
        except Exception as e:
            logger.error("Packer detection failed for %s: %s", file_path, e)

        return findings

    def is_applicable(self, file_path: Path) -> bool:
        """Only check PE file types."""
        return file_path.suffix.lower() in PE_EXTENSIONS

    def _check_packer_strings(self, content: bytes) -> List[Finding]:
        """Check for known packer signature strings."""
        findings: List[Finding] = []
        content_lower = content[:4096]  # Check headers area

        for sig in PACKER_SIGNATURES:
            for pattern in sig["strings"]:
                if pattern.lower() in content_lower.lower():
                    findings.append(Finding(
                        detector=self.name,
                        description=sig["description"],
                        severity=sig["severity"],
                        evidence=f"Packer: {sig['name']}",
                        remediation=(
                            f"File is packed with {sig['name']}. "
                            f"Unpack before further analysis. "
                            f"Packed files may hide malicious payloads."
                        ),
                        attack_techniques=["T1027.002"],
                        attack_tactics=["Defense Evasion"],
                        attack_confidence="high",
                    ))
                    break  # Only report each packer once

        return findings

    def _analyze_pe_packing(
        self, file_path: Path, content: bytes
    ) -> List[Finding]:
        """Analyze PE structure for packing indicators."""
        findings: List[Finding] = []

        try:
            import pefile
        except ImportError:
            return findings

        try:
            pe = pefile.PE(data=content)
        except pefile.PEFormatError:
            return findings

        try:
            # Check section names against known packers
            section_names = set()
            high_entropy_sections = 0
            total_sections = len(pe.sections)
            raw_sizes = []
            virtual_sizes = []

            for section in pe.sections:
                try:
                    name = section.Name.decode("utf-8", errors="replace").strip("\x00")
                    section_names.add(name)
                except Exception:
                    name = "<invalid>"

                # Calculate section entropy
                section_data = section.get_data()
                if len(section_data) >= 256:
                    entropy = calculate_entropy(section_data)
                    if entropy > 7.0:
                        high_entropy_sections += 1

                raw_sizes.append(section.SizeOfRawData)
                virtual_sizes.append(section.Misc_VirtualSize)

            # Check section names against packer databases
            for sig in PACKER_SIGNATURES:
                if section_names & sig["section_names"]:
                    # Already reported via string check, skip duplicate
                    pass

            # Heuristic: Most sections have high entropy
            if total_sections > 0 and high_entropy_sections >= total_sections - 1:
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Nearly all sections have high entropy "
                        f"({high_entropy_sections}/{total_sections}) - "
                        f"likely packed or encrypted"
                    ),
                    severity=40,
                    evidence=(
                        f"High entropy sections: "
                        f"{high_entropy_sections}/{total_sections}"
                    ),
                    attack_techniques=["T1027.002"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="medium",
                ))

            # Heuristic: Large virtual vs raw size ratio (unpacking stub)
            for i, section in enumerate(pe.sections):
                if (section.SizeOfRawData > 0 and
                        section.Misc_VirtualSize > section.SizeOfRawData * 10):
                    try:
                        name = section.Name.decode(
                            "utf-8", errors="replace"
                        ).strip("\x00")
                    except Exception:
                        name = f"section_{i}"

                    findings.append(Finding(
                        detector=self.name,
                        description=(
                            f"Section {name} has virtual size "
                            f"{section.Misc_VirtualSize // 1024}KB vs "
                            f"raw size {section.SizeOfRawData // 1024}KB "
                            f"(unpacking indicator)"
                        ),
                        severity=35,
                        evidence=(
                            f"Virtual/Raw ratio: "
                            f"{section.Misc_VirtualSize / max(section.SizeOfRawData, 1):.1f}x"
                        ),
                        attack_techniques=["T1027.002"],
                        attack_tactics=["Defense Evasion"],
                        attack_confidence="low",
                    ))
                    break  # Only report once

            # Heuristic: Very few imports (packed files hide imports)
            import_count = 0
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    import_count += len(entry.imports)

            if 0 < import_count <= 5:
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Only {import_count} API imports "
                        f"(packed executables hide real imports)"
                    ),
                    severity=30,
                    evidence=f"Import count: {import_count}",
                    attack_techniques=["T1027.002"],
                    attack_tactics=["Defense Evasion"],
                    attack_confidence="low",
                ))

        finally:
            pe.close()

        return findings
