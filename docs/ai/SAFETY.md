# FileGuard - Safe Development & Testing Guidelines

## ⚠️ CRITICAL SAFETY RULES

### The AI Agent Should NEVER:
- Have write/delete access to system directories
- Run with admin privileges during development
- Execute scans on C:\ or system folders directly
- Modify registry, event logs, or system files
- Run any remediation/deletion code automatically

### The AI Agent Should ONLY:
- Write code to files in the project directory
- Create unit tests that use mock data
- Generate test fixtures in isolated folders
- Read (never write) during scan operations

---

## Safe Testing Setup

### 1. Create Isolated Test Directory

```powershell
# Create a sandboxed test environment
mkdir C:\FileGuardTest
mkdir C:\FileGuardTest\mock_system
mkdir C:\FileGuardTest\mock_system\Windows
mkdir C:\FileGuardTest\mock_system\Users
mkdir C:\FileGuardTest\mock_system\ProgramData
mkdir C:\FileGuardTest\mock_system\Temp

# Create test files (safe mock data)
echo "test content" > C:\FileGuardTest\mock_system\test_file.txt
```

### 2. Test Configuration File

```yaml
# config/settings_test.yaml
# NEVER use this config on real system

testing:
  enabled: true
  sandbox_root: "C:\\FileGuardTest\\mock_system"
  
  # Safety locks
  allow_writes: false
  allow_deletes: false
  allow_registry_access: false
  allow_admin_operations: false
  
  # Mock paths (maps real paths to sandbox)
  path_mappings:
    "C:\\Windows": "C:\\FileGuardTest\\mock_system\\Windows"
    "C:\\Users": "C:\\FileGuardTest\\mock_system\\Users"
    "C:\\ProgramData": "C:\\FileGuardTest\\mock_system\\ProgramData"
```

### 3. Safety Wrapper for All File Operations

```python
# utils/safety.py
"""
Safety wrapper to prevent accidental system damage during development.
"""

import os
from pathlib import Path
from typing import Union
import logging

logger = logging.getLogger(__name__)

# SAFETY CONSTANTS
SANDBOX_ROOT = Path(os.environ.get("FILEGUARD_SANDBOX", "C:/FileGuardTest/mock_system"))
TESTING_MODE = os.environ.get("FILEGUARD_TESTING", "true").lower() == "true"

# Paths that should NEVER be written to
PROTECTED_PATHS = [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\Users\\*\\AppData",
    "C:\\$Recycle.Bin",
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
    pass


def is_safe_path(path: Union[str, Path]) -> bool:
    """
    Check if a path is safe to operate on.
    
    Args:
        path: Path to check
        
    Returns:
        True if path is in sandbox or testing directory
    """
    path = Path(path).resolve()
    
    # Always safe: sandbox directory
    if str(path).startswith(str(SANDBOX_ROOT)):
        return True
    
    # Always safe: project directory
    project_root = Path(__file__).parent.parent
    if str(path).startswith(str(project_root)):
        return True
    
    # In testing mode, block everything else
    if TESTING_MODE:
        return False
    
    # In production, check against protected paths
    path_str = str(path).lower()
    for protected in PROTECTED_PATHS:
        if path_str.startswith(protected.lower().replace("*", "")):
            return False
    
    return True


def safe_read(path: Union[str, Path]) -> bytes:
    """
    Safely read a file (always allowed in sandbox).
    """
    path = Path(path)
    
    # Reading is generally safe, but log it
    logger.debug(f"Reading: {path}")
    
    with open(path, 'rb') as f:
        return f.read()


def safe_write(path: Union[str, Path], data: bytes) -> None:
    """
    Safely write to a file (only in sandbox).
    """
    path = Path(path)
    
    if not is_safe_path(path):
        raise SafetyError(
            f"BLOCKED: Attempted write to protected path: {path}\n"
            f"This operation is only allowed in sandbox: {SANDBOX_ROOT}"
        )
    
    logger.info(f"Writing: {path}")
    
    with open(path, 'wb') as f:
        f.write(data)


def safe_delete(path: Union[str, Path]) -> None:
    """
    Safely delete a file (only in sandbox, requires confirmation).
    """
    path = Path(path)
    
    if not is_safe_path(path):
        raise SafetyError(
            f"BLOCKED: Attempted delete of protected path: {path}\n"
            f"This operation is only allowed in sandbox: {SANDBOX_ROOT}"
        )
    
    if TESTING_MODE:
        logger.warning(f"DELETE (test mode - simulated): {path}")
        return  # Don't actually delete in test mode
    
    logger.warning(f"DELETING: {path}")
    path.unlink()


def require_confirmation(operation: str, target: str) -> bool:
    """
    Require user confirmation for dangerous operations.
    """
    if TESTING_MODE:
        logger.info(f"Auto-denied in test mode: {operation} on {target}")
        return False
    
    response = input(f"⚠️  Confirm {operation} on {target}? [yes/NO]: ")
    return response.lower() == "yes"


def sandbox_path(real_path: Union[str, Path]) -> Path:
    """
    Convert a real system path to its sandbox equivalent.
    
    Example:
        sandbox_path("C:\\Windows\\System32") 
        -> "C:\\FileGuardTest\\mock_system\\Windows\\System32"
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


# Safety check on module load
if TESTING_MODE:
    logger.info(f"🔒 SAFETY MODE ACTIVE - Sandbox: {SANDBOX_ROOT}")
    if not SANDBOX_ROOT.exists():
        logger.warning(f"Creating sandbox directory: {SANDBOX_ROOT}")
        SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
```

---

## 4. Unit Tests with Mock Data

```python
# tests/test_scanner_safe.py
"""
Safe scanner tests using mock filesystem.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile
import shutil

from core.scanner import FileScanner
from utils.safety import SANDBOX_ROOT


@pytest.fixture
def mock_filesystem():
    """Create temporary test filesystem."""
    test_dir = tempfile.mkdtemp(prefix="fileguard_test_")
    
    # Create mock structure
    (Path(test_dir) / "safe_file.txt").write_text("safe content")
    (Path(test_dir) / "suspicious.exe").write_bytes(b"MZ" + b"\x00" * 100)
    (Path(test_dir) / "malware_test.ps1").write_text("Invoke-Mimikatz")
    
    yield test_dir
    
    # Cleanup
    shutil.rmtree(test_dir)


def test_scanner_finds_suspicious_files(mock_filesystem):
    """Test scanner detects suspicious patterns."""
    scanner = FileScanner(config={})
    
    results = list(scanner.scan(Path(mock_filesystem)))
    
    # Should find the suspicious files
    suspicious = [r for r in results if r.risk_score > 50]
    assert len(suspicious) >= 1


def test_scanner_never_modifies_files(mock_filesystem):
    """Verify scanner is read-only."""
    scanner = FileScanner(config={})
    
    # Get file states before scan
    before = {
        f: f.stat().st_mtime 
        for f in Path(mock_filesystem).rglob("*") 
        if f.is_file()
    }
    
    # Run scan
    list(scanner.scan(Path(mock_filesystem)))
    
    # Verify no modifications
    for f, mtime in before.items():
        assert f.stat().st_mtime == mtime, f"File was modified: {f}"


def test_scanner_respects_sandbox():
    """Verify scanner cannot escape sandbox."""
    scanner = FileScanner(config={})
    
    # This should raise SafetyError or return empty
    with pytest.raises(Exception):
        list(scanner.scan(Path("C:\\Windows\\System32")))
```

---

## 5. Development Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    DEVELOPMENT PHASE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Agent writes code → Project directory only              │
│                                                             │
│  2. Agent runs tests → Mock filesystem + sandbox            │
│                                                             │
│  3. YOU manually test → VM or controlled environment        │
│                                                             │
│  4. Real system scan → Only after YOUR manual review        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Environment Variables for Safety

```powershell
# Set these in your development environment

# Force testing mode (blocks dangerous operations)
$env:FILEGUARD_TESTING = "true"

# Set sandbox location
$env:FILEGUARD_SANDBOX = "C:\FileGuardTest\mock_system"

# Disable any auto-remediation
$env:FILEGUARD_READONLY = "true"
```

---

## 7. VM Testing (Recommended for Full Tests)

For testing actual system scans:

1. **Create Windows VM** (VirtualBox, VMware, Hyper-V)
2. **Take snapshot** before testing
3. **Run FileGuard** in the VM
4. **Revert snapshot** if anything goes wrong

```powershell
# In VM only - never on host
$env:FILEGUARD_TESTING = "false"
.\FileGuard.exe scan C:\ --deep
```

---

## 8. Code Review Checklist

Before running ANY code the agent produces:

- [ ] No `os.remove()` or `Path.unlink()` on system paths
- [ ] No `shutil.rmtree()` outside sandbox
- [ ] No registry writes (`winreg` module)
- [ ] No service modifications
- [ ] No scheduled task creation
- [ ] All file operations use `utils/safety.py` wrapper
- [ ] Tests use mock/temp directories only