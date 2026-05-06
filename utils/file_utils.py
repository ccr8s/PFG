"""
File utility functions for FileGuard.

Provides helper functions for file operations, always respecting
the safety wrapper.
"""

import logging
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set

logger = logging.getLogger(__name__)

# Common executable extensions
EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".sys", ".com", ".scr", ".pif",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi",
    ".jar", ".cpl",
}

# Common document extensions
DOCUMENT_EXTENSIONS: Set[str] = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".rtf", ".odt", ".ods", ".odp",
}


def get_file_metadata(file_path: Path) -> Dict[str, Any]:
    """
    Extract metadata from a file without reading its content.

    Args:
        file_path: Path to the file.

    Returns:
        Dictionary of metadata including size, timestamps, attributes.
    """
    try:
        file_stat = file_path.stat()
        return {
            "size": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime),
            "modified": datetime.fromtimestamp(file_stat.st_mtime),
            "accessed": datetime.fromtimestamp(file_stat.st_atime),
            "extension": file_path.suffix.lower(),
            "is_hidden": _is_hidden(file_path),
            "is_readonly": not os.access(file_path, os.W_OK),
            "is_executable": file_path.suffix.lower() in EXECUTABLE_EXTENSIONS,
        }
    except (OSError, PermissionError) as e:
        logger.warning("Cannot read metadata for %s: %s", file_path, e)
        return {}


def is_double_extension(file_path: Path) -> bool:
    """
    Check if a file has a deceptive double extension.

    Args:
        file_path: Path to check.

    Returns:
        True if file has a double extension like .pdf.exe.
    """
    name = file_path.name.lower()
    parts = name.split(".")

    if len(parts) < 3:
        return False

    final_ext = f".{parts[-1]}"
    return final_ext in EXECUTABLE_EXTENSIONS


def walk_directory(
    root: Path,
    recursive: bool = True,
    follow_symlinks: bool = False,
    exclusions: Optional[List[str]] = None,
    max_file_size_mb: int = 100,
    scan_hidden: bool = True,
) -> Generator[Path, None, None]:
    """
    Walk a directory yielding file paths respecting exclusions.

    Args:
        root: Root directory to walk.
        recursive: Whether to recurse into subdirectories.
        follow_symlinks: Whether to follow symbolic links.
        exclusions: List of glob patterns to exclude.
        max_file_size_mb: Skip files larger than this (in MB).
        scan_hidden: Whether to include hidden files.

    Yields:
        Path objects for each file found.
    """
    exclusions = exclusions or []
    max_bytes = max_file_size_mb * 1024 * 1024

    try:
        iterator = root.rglob("*") if recursive else root.glob("*")

        for entry in iterator:
            if not entry.is_file():
                continue

            # Skip symlinks if configured
            if entry.is_symlink() and not follow_symlinks:
                continue

            # Skip hidden files if configured
            if not scan_hidden and _is_hidden(entry):
                continue

            # Check exclusions
            if _matches_exclusion(entry, exclusions):
                continue

            # Check file size
            try:
                if entry.stat().st_size > max_bytes:
                    logger.debug("Skipping oversized file: %s", entry)
                    continue
            except OSError:
                continue

            yield entry

    except PermissionError as e:
        logger.warning("Permission denied walking %s: %s", root, e)
    except Exception as e:
        logger.error("Error walking %s: %s", root, e)


def _is_hidden(path: Path) -> bool:
    """Check if a file is hidden (Windows attribute or dot-prefix)."""
    try:
        if os.name == "nt":
            attrs = path.stat().st_file_attributes  # type: ignore[attr-defined]
            return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
        return path.name.startswith(".")
    except (OSError, AttributeError):
        return False


def _matches_exclusion(path: Path, exclusions: List[str]) -> bool:
    """Check if a path matches any exclusion pattern."""
    path_str = str(path).lower()
    name = path.name.lower()

    for pattern in exclusions:
        pattern_lower = pattern.lower()
        if pattern_lower.startswith("*"):
            # Extension pattern like *.tmp
            if name.endswith(pattern_lower[1:]):
                return True
        elif pattern_lower in path_str:
            return True

    return False


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable form.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Formatted string like "1.5 MB".
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0  # type: ignore[assignment]
    return f"{size_bytes:.1f} PB"
