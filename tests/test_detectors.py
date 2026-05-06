"""
Tests for detector modules.

Verifies that each detector correctly identifies known patterns
and produces proper Finding objects with ATT&CK mappings.
"""

import tempfile
from pathlib import Path

import pytest

from core.models import Finding
from detectors.entropy_detector import EntropyDetector, calculate_entropy
from detectors.pattern_detector import PatternDetector


class TestEntropyCalculation:
    """Tests for entropy calculation."""

    def test_zero_entropy_for_uniform_data(self) -> None:
        """Uniform data (all same byte) should have zero entropy."""
        data = b"\x00" * 1024
        entropy = calculate_entropy(data)
        assert entropy == 0.0

    def test_high_entropy_for_random_data(self) -> None:
        """Random-looking data should have high entropy."""
        import os
        data = os.urandom(10000)
        entropy = calculate_entropy(data)
        assert entropy > 7.0

    def test_moderate_entropy_for_text(self) -> None:
        """English text should have moderate entropy (3-5)."""
        text = b"The quick brown fox jumps over the lazy dog " * 100
        entropy = calculate_entropy(text)
        assert 3.0 < entropy < 6.0

    def test_empty_data_returns_zero(self) -> None:
        """Empty data should return zero entropy."""
        assert calculate_entropy(b"") == 0.0


class TestEntropyDetector:
    """Tests for the EntropyDetector class."""

    def test_high_entropy_file_detected(self) -> None:
        """High entropy files should produce findings."""
        import os
        detector = EntropyDetector()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(os.urandom(10000))
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            assert len(findings) > 0
            assert any("entropy" in f.description.lower() for f in findings)
        finally:
            temp_path.unlink()

    def test_clean_text_file_no_findings(self) -> None:
        """Normal text files should not trigger entropy alerts."""
        detector = EntropyDetector()

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".txt", mode="w"
        ) as f:
            f.write("Hello world. " * 1000)
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            assert len(findings) == 0
        finally:
            temp_path.unlink()

    def test_small_file_skipped(self) -> None:
        """Files smaller than 256 bytes should be skipped."""
        detector = EntropyDetector()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 100)
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            assert len(findings) == 0
        finally:
            temp_path.unlink()


class TestPatternDetector:
    """Tests for the PatternDetector class."""

    def test_detects_powershell_mimikatz(self) -> None:
        """Should detect Invoke-Mimikatz in PowerShell script."""
        detector = PatternDetector()

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".ps1", mode="w"
        ) as f:
            f.write("Import-Module .\\Invoke-Mimikatz.ps1\n")
            f.write("Invoke-Mimikatz -DumpCreds\n")
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            assert len(findings) > 0
            assert any(f.severity >= 80 for f in findings)
        finally:
            temp_path.unlink()

    def test_detects_ransomware_commands(self) -> None:
        """Should detect shadow copy deletion."""
        detector = PatternDetector()

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".bat", mode="w"
        ) as f:
            f.write("vssadmin delete shadows /all /quiet\n")
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            assert len(findings) > 0
            assert any("shadow" in f.description.lower() or
                        "ransomware" in f.description.lower()
                        for f in findings)
        finally:
            temp_path.unlink()

    def test_detects_double_extension(self) -> None:
        """Should detect deceptive double extensions."""
        detector = PatternDetector()

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".pdf.exe"
        ) as f:
            f.write(b"MZ" + b"\x00" * 50)
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            double_ext_findings = [
                f for f in findings
                if "double extension" in f.description.lower()
            ]
            assert len(double_ext_findings) > 0
        finally:
            temp_path.unlink()

    def test_clean_file_minimal_findings(self) -> None:
        """Clean text file should have minimal or no findings."""
        detector = PatternDetector()

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".txt", mode="w"
        ) as f:
            f.write("This is a perfectly safe text file with no issues.\n")
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            # May have extension finding but severity should be low
            for finding in findings:
                assert finding.severity < 50
        finally:
            temp_path.unlink()

    def test_findings_have_attack_mapping(self) -> None:
        """All findings should include ATT&CK techniques."""
        detector = PatternDetector()

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".ps1", mode="w"
        ) as f:
            f.write("Invoke-Mimikatz\n")
            temp_path = Path(f.name)

        try:
            findings = detector.detect(temp_path)
            for finding in findings:
                assert isinstance(finding.attack_techniques, list)
                assert isinstance(finding.attack_tactics, list)
        finally:
            temp_path.unlink()
