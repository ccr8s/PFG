"""
Safety wrapper to prevent accidental system damage during development.

This module MUST be used for ALL file operations in FileGuard.
It enforces sandboxing, path validation, and confirmation for
dangerous operations.

Mode resolution order (highest priority first):
    1. Environment variables (FILEGUARD_TESTING, FILEGUARD_READONLY,
       FILEGUARD_SANDBOX). If set, they always win.
    2. Values supplied via :func:`apply_config_overrides` (e.g. from
       ``config/settings.yaml``).
    3. Built-in defaults (TESTING_MODE off, READONLY_MODE off, sandbox
       at ``C:/FileGuardTest/mock_system``).
"""

import fnmatch
import logging
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_DEFAULT_SANDBOX = "C:/FileGuardTest/mock_system"
_DEFAULT_TESTING = False
# Read-only is on by default so a fresh shell without dev_setup.ps1
# still refuses to write to real paths until explicitly opted out.
_DEFAULT_READONLY = True

# Track which env vars the user explicitly set so config can fill the
# rest without overriding an explicit choice.
_ENV_TESTING = os.environ.get("FILEGUARD_TESTING")
_ENV_READONLY = os.environ.get("FILEGUARD_READONLY")
_ENV_SANDBOX = os.environ.get("FILEGUARD_SANDBOX")


def _parse_bool(value: Any, default: bool) -> bool:
    """Coerce a string/bool/None into a boolean."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Module-level state (mutable; tests/cli may call apply_config_overrides)
# ---------------------------------------------------------------------------
SANDBOX_ROOT = Path(_ENV_SANDBOX or _DEFAULT_SANDBOX)
TESTING_MODE = _parse_bool(_ENV_TESTING, _DEFAULT_TESTING)
READONLY_MODE = _parse_bool(_ENV_READONLY, _DEFAULT_READONLY)

# Paths that should NEVER be written to. Glob-style ``*`` segments are
# supported and matched against individual path components.
PROTECTED_PATHS = [
    "C:\\Windows",
    "C:\\Windows\\*",
    "C:\\Program Files",
    "C:\\Program Files\\*",
    "C:\\Program Files (x86)",
    "C:\\Program Files (x86)\\*",
    "C:\\ProgramData",
    "C:\\ProgramData\\*",
    "C:\\Users\\*\\AppData",
    "C:\\Users\\*\\AppData\\*",
    "C:\\$Recycle.Bin",
    "C:\\$Recycle.Bin\\*",
]

# Operations that require explicit confirmation
DANGEROUS_OPERATIONS = [
    "delete",
    "modify",
    "write",
    "registry_write",
    "service_modify",
]


class SafetyError(Exception):
    """Raised when a dangerous operation is attempted."""


# ---------------------------------------------------------------------------
# Configuration plumbing
# ---------------------------------------------------------------------------
def apply_config_overrides(config: Mapping[str, Any]) -> None:
    """
    Apply ``safety:`` settings from a loaded config mapping.

    Environment variables always take precedence; values here only
    fill in whatever the env vars left unset. Safe to call multiple
    times.
    """
    global SANDBOX_ROOT, TESTING_MODE, READONLY_MODE

    safety_cfg: Dict[str, Any] = dict(config.get("safety", {}) or {})

    if _ENV_SANDBOX is None and "sandbox_root" in safety_cfg:
        SANDBOX_ROOT = Path(str(safety_cfg["sandbox_root"]))

    if _ENV_TESTING is None and "testing_mode" in safety_cfg:
        TESTING_MODE = _parse_bool(safety_cfg["testing_mode"], _DEFAULT_TESTING)

    if _ENV_READONLY is None and "read_only" in safety_cfg:
        READONLY_MODE = _parse_bool(safety_cfg["read_only"], _DEFAULT_READONLY)

    if TESTING_MODE:
        _ensure_sandbox_exists()
        logger.info(
            "SAFETY MODE ACTIVE - Sandbox: %s (read_only=%s)",
            SANDBOX_ROOT,
            READONLY_MODE,
        )


def _ensure_sandbox_exists() -> None:
    """Create the sandbox directory if it does not already exist."""
    try:
        if not SANDBOX_ROOT.exists():
            logger.warning("Creating sandbox directory: %s", SANDBOX_ROOT)
            SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Cannot create sandbox %s: %s", SANDBOX_ROOT, exc)


# ---------------------------------------------------------------------------
# Path checks
# ---------------------------------------------------------------------------
def _norm(path: Union[str, Path]) -> str:
    """Lowercase, resolved string form of a path for comparison."""
    return str(Path(path).resolve()).lower()


def _matches_protected(path_str: str, pattern: str) -> bool:
    """Return True if a pattern from PROTECTED_PATHS covers the path."""
    pattern = pattern.lower().replace("/", "\\")
    path_str = path_str.replace("/", "\\")

    if "*" not in pattern:
        # Exact directory or any file beneath it.
        return path_str == pattern or path_str.startswith(pattern + "\\")

    # fnmatch handles ``*`` per-segment when applied to the whole string.
    # Ensure trailing wildcard also matches the bare directory itself.
    if path_str == pattern.rstrip("\\*").rstrip("\\"):
        return True
    return fnmatch.fnmatchcase(path_str, pattern)


def is_safe_path(path: Union[str, Path]) -> bool:
    """
    Check if a path is safe to operate on.

    A path is safe if it lives inside the sandbox, inside the project
    directory, or (in production) outside any protected location.
    """
    path_str = _norm(path)
    sandbox_str = _norm(SANDBOX_ROOT)
    project_str = _norm(Path(__file__).resolve().parent.parent)

    if path_str == sandbox_str or path_str.startswith(sandbox_str + os.sep.lower()):
        return True
    if path_str == project_str or path_str.startswith(project_str + os.sep.lower()):
        return True

    if TESTING_MODE:
        return False

    for protected in PROTECTED_PATHS:
        if _matches_protected(path_str, protected):
            return False

    return True


def validate_scan_path(path: Union[str, Path]) -> Path:
    """
    Validate a path is suitable for scanning (read-only).

    Args:
        path: Path to validate.

    Returns:
        Resolved Path object.

    Raises:
        SafetyError: If path is not safe for scanning in test mode.
        FileNotFoundError: If path does not exist.
    """
    path = Path(path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Scan target does not exist: {path}")

    if TESTING_MODE and not is_safe_path(path):
        raise SafetyError(
            f"BLOCKED: Scan target outside sandbox in test mode: {path}\n"
            f"Set FILEGUARD_TESTING=false to scan real paths."
        )

    return path


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------
def safe_read(path: Union[str, Path]) -> bytes:
    """
    Safely read a file (always allowed in sandbox).

    Args:
        path: File to read.

    Returns:
        File contents as bytes.

    Raises:
        FileNotFoundError: If file does not exist.
        PermissionError: If file cannot be read.
    """
    path = Path(path)
    logger.debug("Reading: %s", path)

    with open(path, "rb") as f:
        return f.read()


def safe_read_text(path: Union[str, Path], encoding: str = "utf-8") -> str:
    """
    Safely read a text file.

    Args:
        path: File to read.
        encoding: Text encoding.

    Returns:
        File contents as string.
    """
    path = Path(path)
    logger.debug("Reading text: %s", path)

    with open(path, "r", encoding=encoding, errors="replace") as f:
        return f.read()


def safe_write(
    path: Union[str, Path],
    data: bytes,
    *,
    force: bool = False,
) -> None:
    """
    Safely write to a file.

    The path must satisfy :func:`is_safe_path`. By default the call is
    a no-op when ``READONLY_MODE`` is active; pass ``force=True`` for
    intentional writes (e.g. honeypot deployment) that should bypass
    the read-only guard while still respecting path safety.
    """
    path = Path(path)

    if not is_safe_path(path):
        raise SafetyError(
            f"BLOCKED: Attempted write to protected path: {path}\n"
            f"This operation is only allowed in sandbox: {SANDBOX_ROOT}"
        )

    if READONLY_MODE and not force:
        logger.warning("WRITE BLOCKED (read-only mode): %s", path)
        return

    logger.info("Writing: %s", path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as f:
        f.write(data)


def safe_delete(
    path: Union[str, Path],
    *,
    force: bool = False,
) -> None:
    """
    Safely delete a file.

    The path must satisfy :func:`is_safe_path`. In testing or read-only
    mode the call is normally simulated; pass ``force=True`` for
    intentional deletes (e.g. honeypot cleanup) that should still run
    against safe paths.
    """
    path = Path(path)

    if not is_safe_path(path):
        raise SafetyError(
            f"BLOCKED: Attempted delete of protected path: {path}\n"
            f"This operation is only allowed in sandbox: {SANDBOX_ROOT}"
        )

    if TESTING_MODE and not force:
        logger.warning("DELETE (test mode - simulated): %s", path)
        return

    if READONLY_MODE and not force:
        logger.warning("DELETE BLOCKED (read-only mode): %s", path)
        return

    logger.warning("DELETING: %s", path)
    path.unlink()


def require_confirmation(operation: str, target: str) -> bool:
    """
    Require user confirmation for dangerous operations.

    Args:
        operation: The operation being performed.
        target: The target path or resource.

    Returns:
        True if user confirms, False otherwise.
    """
    if TESTING_MODE:
        logger.info("Auto-denied in test mode: %s on %s", operation, target)
        return False

    response = input(f"WARNING: Confirm {operation} on {target}? [yes/NO]: ")
    return response.strip().lower() == "yes"


def sandbox_path(real_path: Union[str, Path]) -> Path:
    """
    Convert a real system path to its sandbox equivalent.

    Example:
        sandbox_path("C:\\\\Windows\\\\System32")
        -> Path("C:\\\\FileGuardTest\\\\mock_system\\\\Windows\\\\System32")

    Args:
        real_path: Real system path to convert.

    Returns:
        Equivalent path inside the sandbox.
    """
    real_path = Path(real_path)

    # Common path mappings
    mappings = {
        "C:\\Windows": SANDBOX_ROOT / "Windows",
        "C:\\Users": SANDBOX_ROOT / "Users",
        "C:\\ProgramData": SANDBOX_ROOT / "ProgramData",
        "C:\\Program Files": SANDBOX_ROOT / "Program Files",
    }

    real_str = str(real_path)
    for real_prefix, sandbox_prefix in mappings.items():
        if real_str.lower().startswith(real_prefix.lower()):
            relative = real_str[len(real_prefix):]
            return sandbox_prefix / relative.lstrip("\\")

    # Default: put in sandbox root
    return SANDBOX_ROOT / real_path.name


def get_project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Safety check on module load
# ---------------------------------------------------------------------------
if TESTING_MODE:
    logger.info("SAFETY MODE ACTIVE - Sandbox: %s", SANDBOX_ROOT)
    _ensure_sandbox_exists()
