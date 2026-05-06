"""
FileGuard utilities module.

Provides safety wrappers, file utilities, hashing, logging,
and export functionality.
"""

from utils.safety import (
    SafetyError,
    is_safe_path,
    safe_delete,
    safe_read,
    safe_read_text,
    safe_write,
    sandbox_path,
)

__all__ = [
    "SafetyError",
    "is_safe_path",
    "safe_delete",
    "safe_read",
    "safe_read_text",
    "safe_write",
    "sandbox_path",
]
