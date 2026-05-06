"""
Tests for utils/hash_utils.py.

Verifies hash calculation accuracy for known test data.
"""

import tempfile
from pathlib import Path

import pytest

from utils.hash_utils import (
    calculate_file_hashes,
    calculate_md5,
    calculate_sha256,
    hash_bytes,
)


class TestHashCalculation:
    """Tests for file hash functions."""

    def test_md5_known_value(self) -> None:
        """MD5 of known content should match expected value."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Hello, World!")
            temp_path = Path(f.name)

        try:
            md5 = calculate_md5(temp_path)
            assert md5 == "65a8e27d8879283831b664bd8b7f0ad4"
        finally:
            temp_path.unlink()

    def test_sha256_known_value(self) -> None:
        """SHA-256 of known content should match expected value."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Hello, World!")
            temp_path = Path(f.name)

        try:
            sha256 = calculate_sha256(temp_path)
            assert sha256 == (
                "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362"
                "182986f"
            )
        finally:
            temp_path.unlink()

    def test_calculate_both_hashes(self) -> None:
        """Should calculate both MD5 and SHA-256 in one pass."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            temp_path = Path(f.name)

        try:
            hashes = calculate_file_hashes(temp_path)
            assert "md5" in hashes
            assert "sha256" in hashes
            assert len(hashes["md5"]) == 32
            assert len(hashes["sha256"]) == 64
        finally:
            temp_path.unlink()

    def test_empty_file_hashes(self) -> None:
        """Empty file should return valid (empty-content) hashes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)

        try:
            hashes = calculate_file_hashes(temp_path)
            # MD5 of empty string
            assert hashes["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
        finally:
            temp_path.unlink()

    def test_nonexistent_file_raises(self) -> None:
        """Hashing nonexistent file should raise."""
        with pytest.raises(FileNotFoundError):
            calculate_file_hashes(Path("nonexistent_xyz.bin"))

    def test_hash_bytes(self) -> None:
        """hash_bytes should hash in-memory data."""
        result = hash_bytes(b"test", "md5")
        assert result == "098f6bcd4621d373cade4e832627b4f6"

    def test_custom_algorithms(self) -> None:
        """Should support custom algorithm selection."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            hashes = calculate_file_hashes(temp_path, ("sha1",))
            assert "sha1" in hashes
            assert "md5" not in hashes
        finally:
            temp_path.unlink()
