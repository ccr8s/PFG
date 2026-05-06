"""
Hash utility functions for FileGuard.

Provides MD5 and SHA-256 hash calculation for files,
with streaming support for large files.
"""

import hashlib
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Read files in 64KB chunks for memory efficiency
HASH_CHUNK_SIZE = 65536


def calculate_file_hashes(
    file_path: Path,
    algorithms: Optional[Tuple[str, ...]] = None,
) -> Dict[str, str]:
    """
    Calculate one or more hash digests for a file.

    Uses streaming reads to handle large files efficiently.

    Args:
        file_path: Path to the file to hash.
        algorithms: Tuple of algorithm names (default: md5, sha256).

    Returns:
        Dictionary mapping algorithm name to hex digest string.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    if algorithms is None:
        algorithms = ("md5", "sha256")

    hashers = {alg: hashlib.new(alg) for alg in algorithms}

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)

        return {alg: h.hexdigest() for alg, h in hashers.items()}

    except FileNotFoundError:
        logger.error("File not found for hashing: %s", file_path)
        raise
    except PermissionError:
        logger.warning("Permission denied hashing: %s", file_path)
        raise
    except Exception as e:
        logger.error("Hash calculation failed for %s: %s", file_path, e)
        return {}


def calculate_md5(file_path: Path) -> str:
    """
    Calculate MD5 hash of a file.

    Args:
        file_path: Path to the file.

    Returns:
        MD5 hex digest string.
    """
    hashes = calculate_file_hashes(file_path, ("md5",))
    return hashes.get("md5", "")


def calculate_sha256(file_path: Path) -> str:
    """
    Calculate SHA-256 hash of a file.

    Args:
        file_path: Path to the file.

    Returns:
        SHA-256 hex digest string.
    """
    hashes = calculate_file_hashes(file_path, ("sha256",))
    return hashes.get("sha256", "")


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """
    Calculate hash of in-memory bytes.

    Args:
        data: Bytes to hash.
        algorithm: Hash algorithm name.

    Returns:
        Hex digest string.
    """
    return hashlib.new(algorithm, data).hexdigest()


def is_eicar_test_file(file_path: Path) -> bool:
    """
    Check if a file is the EICAR anti-malware test file.

    The EICAR test file has a well-known SHA-256 hash and is used
    to verify that antimalware software is working correctly.

    Args:
        file_path: Path to check.

    Returns:
        True if file matches the EICAR test file hash.
    """
    # EICAR test file SHA-256
    eicar_sha256 = (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )
    try:
        file_hash = calculate_sha256(file_path)
        return file_hash == eicar_sha256
    except (FileNotFoundError, PermissionError):
        return False
