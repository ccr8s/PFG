# FileGuard - Master Prompt for Cursor AI

> **File**: `docs/ai/MASTER_PROMPT.md`
> **Purpose**: Complete coding standards and implementation patterns for AI agent

---

## PROJECT CONTEXT

**Project Name**: FileGuard  
**Purpose**: Windows security scanner that categorizes files by risk level, detects tampering, and provides remediation guidance  
**Target OS**: Windows 10/11  
**Python Version**: 3.11+  
**GUI Framework**: CustomTkinter

---

## ⚠️ CRITICAL SAFETY RULES

### NEVER:
1. Write code that deletes, modifies, or moves files outside the project directory
2. Write code that modifies the Windows registry
3. Write code that creates/modifies Windows services or scheduled tasks
4. Run scans on actual system directories (C:\Windows, C:\Users, etc.)
5. Execute any remediation actions automatically
6. Use `os.remove()`, `shutil.rmtree()`, or `Path.unlink()` on system paths
7. Request or use admin privileges during development

### ALWAYS:
1. Use the `utils/safety.py` wrapper for ALL file operations
2. Write unit tests that use temporary directories or mocks
3. Use the sandbox directory: `C:\FileGuardTest\mock_system`
4. Make scanning operations READ-ONLY by default
5. Require explicit user confirmation for any destructive action
6. Include safety checks that prevent accidental system damage

### Safe File Operation Pattern:
```python
# WRONG - Never do this
os.remove(some_path)
shutil.rmtree(folder)

# CORRECT - Always use safety wrapper
from utils.safety import safe_delete, is_safe_path
if is_safe_path(some_path):
    safe_delete(some_path)  # Will still require confirmation
```

---

## CODING STANDARDS

### File Structure
```
fileguard/
├── main.py                 # Entry point
├── cli.py                  # CLI interface
├── config/
│   ├── settings.yaml       # User configuration
│   └── signatures.yaml     # Detection signatures
├── core/
│   ├── __init__.py
│   ├── scanner.py          # Main scanning engine
│   ├── analyzer.py         # File analysis logic
│   ├── risk_classifier.py  # Risk categorization
│   ├── database.py         # SQLite operations
│   ├── models.py           # Data models
│   └── mitre_attack.py     # ATT&CK mapping
├── detectors/
│   ├── __init__.py
│   ├── yara_detector.py    # YARA rule matching
│   ├── sigma_detector.py   # Sigma rule engine
│   ├── hash_detector.py    # Hash-based detection
│   ├── entropy_detector.py # Entropy analysis
│   ├── pattern_detector.py # Suspicious patterns
│   └── pe_analyzer.py      # PE file analysis
├── forensics/
│   ├── __init__.py
│   ├── event_logs.py       # Event log analysis
│   ├── registry.py         # Registry analysis
│   ├── timestomp.py        # Timestamp analysis
│   ├── prefetch.py         # Prefetch parsing
│   ├── bitmap_cache.py     # RDP cache analysis
│   └── amcache.py          # Amcache parsing
├── honeypot/
│   ├── __init__.py
│   ├── decoy_manager.py    # Honeypot file management
│   └── monitor.py          # Access monitoring
├── gui/
│   ├── __init__.py
│   ├── app.py              # Main GUI application
│   ├── widgets/            # Custom widgets
│   └── styles.py           # Theming
├── utils/
│   ├── __init__.py
│   ├── safety.py           # CRITICAL: Safety wrapper
│   ├── file_utils.py
│   ├── hash_utils.py
│   ├── stix_export.py      # STIX 2.1 export
│   ├── taxii_client.py     # TAXII publishing
│   └── report_generator.py
├── rules/
│   ├── yara/               # YARA rules
│   └── sigma/              # Sigma rules
├── data/
│   ├── known_hashes.db     # Known malware hashes
│   └── mitre_attack.json   # ATT&CK database
├── tests/
│   └── ...
└── requirements.txt
```

### Code Style Rules
1. **PEP 8** compliance strictly enforced
2. **Type hints** on ALL function signatures
3. **Docstrings** for all classes and public methods (Google style)
4. **Maximum line length**: 100 characters
5. **Imports**: Standard library → Third-party → Local (alphabetized within groups)
6. **Constants**: UPPER_SNAKE_CASE at module level
7. **Classes**: PascalCase
8. **Functions/Variables**: snake_case
9. **Private methods**: Single underscore prefix (_method_name)

### Code Quality
1. **Single Responsibility**: Each function does ONE thing
2. **DRY**: Extract repeated code into utilities
3. **Error Handling**: Always use try/except with specific exceptions
4. **Logging**: Use logging module, never print() in production code
5. **Configuration**: No hardcoded values; use config/settings.yaml
6. **Testing**: Write test alongside implementation

---

## EXAMPLE FUNCTION TEMPLATE

```python
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

from core.models import ScanResult

logger = logging.getLogger(__name__)


def analyze_file(
    file_path: Path,
    options: Optional[Dict[str, Any]] = None
) -> ScanResult:
    """
    Analyze a single file for suspicious characteristics.

    Args:
        file_path: Path to the file to analyze.
        options: Optional configuration overrides.

    Returns:
        ScanResult object containing analysis findings.

    Raises:
        FileNotFoundError: If file_path does not exist.
        PermissionError: If file cannot be accessed.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    options = options or {}
    
    try:
        # Implementation here
        result = _perform_analysis(file_path, options)
        logger.info(f"Successfully analyzed: {file_path}")
        return result
    except PermissionError:
        logger.warning(f"Permission denied: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Analysis failed for {file_path}: {e}")
        raise
```

---

## DATA MODELS

```python
# core/models.py
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any


class RiskLevel(Enum):
    """Risk classification levels."""
    SUSPICIOUS_CODE = 4    # Critical - Likely malware
    HIGH_TARGET = 3        # High - Popular attack targets
    POTENTIAL_RISK = 2     # Medium - Needs review
    LOW_RISK = 1           # Low - Minor anomalies
    CLEAN = 0              # No issues


@dataclass
class Finding:
    """Represents a single security finding."""
    detector: str
    description: str
    severity: int  # 0-100
    evidence: str
    line_number: Optional[int] = None
    remediation: Optional[str] = None
    
    # MITRE ATT&CK fields (REQUIRED)
    attack_techniques: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    attack_confidence: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "detector": self.detector,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "line_number": self.line_number,
            "remediation": self.remediation,
            "mitre_attack": {
                "techniques": self.attack_techniques,
                "tactics": self.attack_tactics,
                "confidence": self.attack_confidence
            }
        }


@dataclass
class ScanResult:
    """Complete scan result for a single file."""
    file_path: Path
    risk_level: RiskLevel
    risk_score: int
    findings: List[Finding] = field(default_factory=list)
    file_hash_md5: str = ""
    file_hash_sha256: str = ""
    file_size: int = 0
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    scan_time: datetime = field(default_factory=datetime.now)
```

---

## GUI SPECIFICATIONS

### Theme & Colors
```python
COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_medium": "#16213e", 
    "bg_light": "#0f3460",
    "accent": "#e94560",
    "text": "#eaeaea",
    "text_dim": "#a0a0a0",
    
    # Risk colors
    "critical": "#ff0000",     # Suspicious Code
    "high": "#ff6600",         # High Target
    "medium": "#ffcc00",       # Potential Risk
    "low": "#00cc66",          # Low Risk
    "clean": "#888888",
}
```

### GUI Layout Rules
1. Dark theme mandatory
2. Minimal padding (5-10px)
3. Fixed-width font for file paths and code
4. Scrollbars on all list views
5. Status bar at bottom with scan progress
6. Responsive to window resize
7. Never block UI thread - use threading

---

## THREAT INTELLIGENCE INTEGRATION

### 1. MITRE ATT&CK Framework
- All detections map to ATT&CK technique IDs
- Use `core/mitre_attack.py` for lookups
- Every Finding MUST include `attack_techniques` and `attack_tactics` fields
- Can export ATT&CK Navigator layers for visualization

### 2. Sigma Rules Engine
- Log-based detection using Sigma rules at `rules/sigma/`
- Complements YARA for file-based detection
- Use `detectors/sigma_detector.py` for log analysis
- Rules use standard Sigma YAML format with ATT&CK tags

### 3. STIX/TAXII Export
- Export findings in STIX 2.1 format via `utils/stix_export.py`
- Publish to TAXII servers via `utils/taxii_client.py`
- Enables integration with SIEMs, TIPs, SOARs
- Configure servers in `config/taxii_servers.yaml`

---

## DETECTION PRIORITIES

### Suspicious Code Indicators (Score 80-100)
- Known malware hash match
- YARA rule: malware family match
- Obfuscated PowerShell with download
- Keylogger patterns
- Ransomware patterns
- C2 beacon patterns
- Credential harvesting code

### High Target File Indicators (Score 60-79)
- Executable in user temp folder
- DLL in Downloads folder
- Script in Startup folder
- Unsigned executable in System32
- Recently modified system file
- File with ADS containing executable

### Potential Risk Indicators (Score 30-59)
- High entropy (>7.0)
- Double extension
- Hidden attribute on executable
- Packed executable (UPX, etc.)
- Suspicious import table
- Recently created executable

### Low Risk Indicators (Score 1-29)
- Executable not in standard location
- Old file with no recent access
- Minor anomaly in PE structure

---

## TASK INPUT TEMPLATE

When given a task, use this format:

```
=================================================================
CURRENT TASK
=================================================================

Phase: [NUMBER]
Task Name: [NAME]
Description: [DESCRIPTION]

Specific Requirements:
1. [REQUIREMENT]
2. [REQUIREMENT]
3. [REQUIREMENT]

Expected Output Files:
- [FILE_PATH]
- [FILE_PATH]

Additional Context:
[ANY EXTRA INFO]

=================================================================
```

---

## RESPONSE FORMAT

When completing a task, structure response as:

1. **Understanding**: Brief restatement of the task
2. **Approach**: How you'll implement it
3. **Code**: Complete implementation with all files
4. **Tests**: Unit tests for the implementation
5. **Next Steps**: What should be done next

---

## REMINDERS

- Always check if base classes exist before creating new ones
- Import from existing modules when available
- Keep GUI code separate from business logic
- Use threading for any operation >100ms
- Never block the GUI thread
- Log at appropriate levels (DEBUG, INFO, WARNING, ERROR)
- Handle Windows-specific paths with pathlib
- Run as admin may be required for some forensic functions—detect and warn user
- ATT&CK mappings are REQUIRED for all detections
- STIX export compatibility must be maintained