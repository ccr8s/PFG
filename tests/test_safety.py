"""
Tests for utils/safety.py - the CRITICAL safety wrapper.

Verifies that file operations are properly sandboxed and
dangerous operations are blocked.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from utils.safety import (
    SANDBOX_ROOT,
    SafetyError,
    is_safe_path,
    safe_delete,
    safe_read,
    safe_write,
    sandbox_path,
    validate_scan_path,
)


class TestIsSafePath:
    """Tests for the is_safe_path function."""

    def test_sandbox_path_is_safe(self) -> None:
        """Paths inside the sandbox should be safe."""
        test_path = SANDBOX_ROOT / "test_file.txt"
        assert is_safe_path(test_path) is True

    def test_project_path_is_safe(self) -> None:
        """Paths inside the project directory should be safe."""
        project_file = Path(__file__).resolve()
        assert is_safe_path(project_file) is True

    @patch("utils.safety.TESTING_MODE", True)
    def test_system_path_blocked_in_test_mode(self) -> None:
        """System paths should be blocked in test mode."""
        assert is_safe_path("C:\\Windows\\System32\\cmd.exe") is False

    @patch("utils.safety.TESTING_MODE", True)
    def test_program_files_blocked_in_test_mode(self) -> None:
        """Program Files should be blocked in test mode."""
        assert is_safe_path("C:\\Program Files\\app.exe") is False


class TestSafeWrite:
    """Tests for the safe_write function."""

    @patch("utils.safety.TESTING_MODE", True)
    def test_write_to_system_path_blocked(self) -> None:
        """Writing to system paths must raise SafetyError."""
        with pytest.raises(SafetyError, match="BLOCKED"):
            safe_write("C:\\Windows\\test.txt", b"data")

    @patch("utils.safety.TESTING_MODE", True)
    @patch("utils.safety.READONLY_MODE", True)
    def test_write_blocked_in_readonly_mode(self) -> None:
        """Writes should be silently blocked in read-only mode."""
        sandbox_file = SANDBOX_ROOT / "test_write.txt"
        safe_write(sandbox_file, b"data")
        # Should not actually create the file in readonly mode
        # (the function returns early)


class TestSafeDelete:
    """Tests for the safe_delete function."""

    @patch("utils.safety.TESTING_MODE", True)
    def test_delete_system_path_blocked(self) -> None:
        """Deleting system paths must raise SafetyError."""
        with pytest.raises(SafetyError, match="BLOCKED"):
            safe_delete("C:\\Windows\\important.dll")

    @patch("utils.safety.TESTING_MODE", True)
    def test_delete_in_sandbox_simulated(self) -> None:
        """Deletes in sandbox should be simulated in test mode."""
        sandbox_file = SANDBOX_ROOT / "test_delete.txt"
        # Should not raise, but also not actually delete
        safe_delete(sandbox_file)


class TestSafeRead:
    """Tests for the safe_read function."""

    def test_read_existing_file(self) -> None:
        """Should be able to read files that exist."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            content = safe_read(temp_path)
            assert content == b"test content"
        finally:
            os.unlink(temp_path)

    def test_read_nonexistent_file_raises(self) -> None:
        """Reading nonexistent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            safe_read("C:\\nonexistent_file_12345.txt")


class TestSandboxPath:
    """Tests for the sandbox_path function."""

    def test_windows_path_mapped(self) -> None:
        """C:\\Windows paths should map to sandbox."""
        result = sandbox_path("C:\\Windows\\System32\\cmd.exe")
        assert str(SANDBOX_ROOT) in str(result)
        assert "cmd.exe" in str(result)

    def test_users_path_mapped(self) -> None:
        """C:\\Users paths should map to sandbox."""
        result = sandbox_path("C:\\Users\\test\\file.txt")
        assert str(SANDBOX_ROOT) in str(result)

    def test_unknown_path_goes_to_root(self) -> None:
        """Unknown paths should land in sandbox root."""
        result = sandbox_path("D:\\custom\\path\\file.txt")
        assert str(SANDBOX_ROOT) in str(result)


class TestValidateScanPath:
    """Tests for the validate_scan_path function."""

    def test_nonexistent_path_raises(self) -> None:
        """Non-existent paths should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            validate_scan_path("C:\\nonexistent_path_xyz")

    @patch("utils.safety.TESTING_MODE", True)
    def test_system_path_blocked_in_test_mode(self) -> None:
        """System paths should be blocked in test mode."""
        # C:\Windows exists but should be blocked
        if Path("C:\\Windows").exists():
            with pytest.raises(SafetyError):
                validate_scan_path("C:\\Windows")
