# TASK: Implement Sigma Rules Integration

## Phase: Integration Enhancement
## Task Name: Sigma Rules Engine for Log-Based Detection
## Description:
Integrate Sigma rules for standardized log-based detection, complementing YARA for file-based detection. This enables detection of suspicious activity in Windows Event Logs, PowerShell logs, and other log sources.

---

## Specific Requirements:

1. Create Sigma rule parser and engine at `detectors/sigma_detector.py`
2. Create Sigma rule converter for Windows Event Logs at `detectors/sigma_backends/`
3. Add default Sigma rules at `rules/sigma/`
4. Integrate with forensics module for log analysis
5. Support custom rule creation

---

## Expected Output Files:

### File 1: `detectors/sigma_detector.py`

```python
"""
Sigma rule detection engine.

Parses and applies Sigma rules against Windows Event Logs
and other log sources for threat detection.
"""

import logging
import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SigmaRule:
    """Represents a parsed Sigma rule."""
    id: str
    title: str
    status: str  # "experimental", "test", "stable"
    level: str   # "informational", "low", "medium", "high", "critical"
    description: str
    author: str
    date: str
    references: List[str]
    tags: List[str]  # ATT&CK tags like "attack.execution"
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    falsepositives: List[str]
    
    # Extracted ATT&CK info from tags
    attack_techniques: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    
    @property
    def severity_score(self) -> int:
        """Convert level to numeric score."""
        level_map = {
            "informational": 10,
            "low": 30,
            "medium": 50,
            "high": 70,
            "critical": 90
        }
        return level_map.get(self.level, 50)
    
    def __post_init__(self):
        """Extract ATT&CK info from tags."""
        for tag in self.tags:
            if tag.startswith("attack.t"):
                # Extract technique ID like "attack.t1059.001" -> "T1059.001"
                tech_id = tag.replace("attack.", "").upper()
                self.attack_techniques.append(tech_id)
            elif tag.startswith("attack."):
                # Tactic like "attack.execution"
                tactic = tag.replace("attack.", "")
                self.attack_tactics.append(tactic)


@dataclass
class SigmaMatch:
    """Represents a Sigma rule match against a log entry."""
    rule: SigmaRule
    log_entry: Dict[str, Any]
    matched_fields: Dict[str, str]
    timestamp: datetime
    source_log: str  # e.g., "Security", "PowerShell"
    
    def to_finding(self) -> Dict[str, Any]:
        """Convert to Finding-compatible dictionary."""
        return {
            "detector": "sigma",
            "description": f"[{self.rule.level.upper()}] {self.rule.title}",
            "severity": self.rule.severity_score,
            "evidence": str(self.matched_fields),
            "remediation": self.rule.description,
            "attack_techniques": self.rule.attack_techniques,
            "attack_tactics": self.rule.attack_tactics,
            "attack_confidence": "high" if self.rule.status == "stable" else "medium"
        }


class SigmaConditionParser:
    """
    Parses Sigma detection conditions.
    
    Supports:
    - Basic conditions: selection, filter
    - Boolean operators: and, or, not
    - Grouping with parentheses
    - Pipe operators: | count, | near
    """
    
    def __init__(self, detection: Dict[str, Any]):
        self.detection = detection
        self.condition = detection.get("condition", "")
        self.selections = {k: v for k, v in detection.items() if k != "condition"}
    
    def parse(self) -> Callable[[Dict], bool]:
        """
        Parse condition into executable matcher function.
        
        Returns:
            Function that takes a log entry dict and returns bool
        """
        return self._build_matcher(self.condition)
    
    def _build_matcher(self, condition: str) -> Callable[[Dict], bool]:
        """Build matcher function from condition string."""
        condition = condition.strip()
        
        # Handle 'not' operator
        if condition.startswith("not "):
            inner = self._build_matcher(condition[4:])
            return lambda log: not inner(log)
        
        # Handle 'and' operator
        if " and " in condition:
            parts = condition.split(" and ")
            matchers = [self._build_matcher(p.strip()) for p in parts]
            return lambda log: all(m(log) for m in matchers)
        
        # Handle 'or' operator
        if " or " in condition:
            parts = condition.split(" or ")
            matchers = [self._build_matcher(p.strip()) for p in parts]
            return lambda log: any(m(log) for m in matchers)
        
        # Handle parentheses
        if condition.startswith("(") and condition.endswith(")"):
            return self._build_matcher(condition[1:-1])
        
        # Handle '1 of selection*' pattern
        if condition.startswith("1 of "):
            pattern = condition[5:].replace("*", ".*")
            matching_selections = [
                k for k in self.selections.keys()
                if re.match(pattern, k)
            ]
            matchers = [
                self._build_selection_matcher(self.selections[s])
                for s in matching_selections
            ]
            return lambda log: any(m(log) for m in matchers)
        
        # Handle 'all of selection*' pattern
        if condition.startswith("all of "):
            pattern = condition[7:].replace("*", ".*")
            matching_selections = [
                k for k in self.selections.keys()
                if re.match(pattern, k)
            ]
            matchers = [
                self._build_selection_matcher(self.selections[s])
                for s in matching_selections
            ]
            return lambda log: all(m(log) for m in matchers)
        
        # Simple selection reference
        if condition in self.selections:
            return self._build_selection_matcher(self.selections[condition])
        
        logger.warning(f"Unknown condition format: {condition}")
        return lambda log: False
    
    def _build_selection_matcher(
        self,
        selection: Union[Dict, List]
    ) -> Callable[[Dict], bool]:
        """Build matcher for a single selection."""
        if isinstance(selection, list):
            # List of conditions (OR)
            matchers = [self._build_selection_matcher(s) for s in selection]
            return lambda log: any(m(log) for m in matchers)
        
        if isinstance(selection, dict):
            # Dictionary of field conditions (AND)
            field_matchers = []
            for field_name, value in selection.items():
                field_matchers.append(
                    self._build_field_matcher(field_name, value)
                )
            return lambda log: all(m(log) for m in field_matchers)
        
        return lambda log: False
    
    def _build_field_matcher(
        self,
        field_name: str,
        value: Any
    ) -> Callable[[Dict], bool]:
        """Build matcher for a single field condition."""
        # Handle field modifiers
        modifiers = []
        if "|" in field_name:
            parts = field_name.split("|")
            field_name = parts[0]
            modifiers = parts[1:]
        
        def match_value(log_value: str, pattern: Any) -> bool:
            if log_value is None:
                return False
            log_value = str(log_value).lower()
            
            if isinstance(pattern, list):
                return any(match_value(log_value, p) for p in pattern)
            
            pattern = str(pattern).lower()
            
            # Apply modifiers
            if "contains" in modifiers:
                return pattern in log_value
            elif "startswith" in modifiers:
                return log_value.startswith(pattern)
            elif "endswith" in modifiers:
                return log_value.endswith(pattern)
            elif "re" in modifiers:
                return bool(re.search(pattern, log_value, re.IGNORECASE))
            else:
                # Default: contains for strings with wildcards, exact otherwise
                if "*" in pattern:
                    regex = pattern.replace("*", ".*")
                    return bool(re.match(regex, log_value, re.IGNORECASE))
                return log_value == pattern
        
        return lambda log: match_value(log.get(field_name), value)


class SigmaEngine:
    """
    Main Sigma detection engine.
    
    Loads rules, validates them, and matches against log entries.
    """
    
    def __init__(self, rules_path: Optional[Path] = None):
        """
        Initialize Sigma engine.
        
        Args:
            rules_path: Path to directory containing .yml Sigma rules
        """
        self.rules_path = rules_path or Path(__file__).parent.parent / "rules" / "sigma"
        self.rules: Dict[str, SigmaRule] = {}
        self.matchers: Dict[str, Callable] = {}
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load all Sigma rules from rules directory."""
        if not self.rules_path.exists():
            logger.warning(f"Sigma rules directory not found: {self.rules_path}")
            self.rules_path.mkdir(parents=True, exist_ok=True)
            return
        
        for rule_file in self.rules_path.glob("**/*.yml"):
            try:
                self._load_rule_file(rule_file)
            except Exception as e:
                logger.error(f"Failed to load Sigma rule {rule_file}: {e}")
        
        logger.info(f"Loaded {len(self.rules)} Sigma rules")
    
    def _load_rule_file(self, path: Path) -> None:
        """Load a single Sigma rule file."""
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return
        
        rule = SigmaRule(
            id=data.get("id", path.stem),
            title=data.get("title", "Unknown"),
            status=data.get("status", "experimental"),
            level=data.get("level", "medium"),
            description=data.get("description", ""),
            author=data.get("author", "Unknown"),
            date=data.get("date", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {}),
            falsepositives=data.get("falsepositives", [])
        )
        
        self.rules[rule.id] = rule
        
        # Pre-compile matcher
        parser = SigmaConditionParser(rule.detection)
        self.matchers[rule.id] = parser.parse()
    
    def match_log_entry(
        self,
        log_entry: Dict[str, Any],
        log_source: str = "Security"
    ) -> List[SigmaMatch]:
        """
        Match a log entry against all applicable rules.
        
        Args:
            log_entry: Dictionary of log entry fields
            log_source: Log source type (e.g., "Security", "PowerShell")
            
        Returns:
            List of SigmaMatch objects for rules that matched
        """
        matches = []
        
        for rule_id, rule in self.rules.items():
            # Check if rule applies to this log source
            if not self._check_logsource(rule, log_source):
                continue
            
            # Check if rule matches
            matcher = self.matchers.get(rule_id)
            if matcher and matcher(log_entry):
                match = SigmaMatch(
                    rule=rule,
                    log_entry=log_entry,
                    matched_fields=self._extract_matched_fields(rule, log_entry),
                    timestamp=datetime.now(),
                    source_log=log_source
                )
                matches.append(match)
        
        return matches
    
    def match_logs(
        self,
        log_entries: List[Dict[str, Any]],
        log_source: str = "Security"
    ) -> List[SigmaMatch]:
        """Match multiple log entries."""
        all_matches = []
        for entry in log_entries:
            all_matches.extend(self.match_log_entry(entry, log_source))
        return all_matches
    
    def _check_logsource(self, rule: SigmaRule, log_source: str) -> bool:
        """Check if rule applies to given log source."""
        rule_product = rule.logsource.get("product", "").lower()
        rule_service = rule.logsource.get("service", "").lower()
        rule_category = rule.logsource.get("category", "").lower()
        
        log_source_lower = log_source.lower()
        
        # Windows-specific checks
        if rule_product == "windows":
            if rule_service == "security" and log_source_lower == "security":
                return True
            if rule_service == "powershell" and "powershell" in log_source_lower:
                return True
            if rule_service == "sysmon" and "sysmon" in log_source_lower:
                return True
            if rule_category == "process_creation":
                return log_source_lower in ["security", "sysmon"]
        
        # Generic match
        return rule_service == log_source_lower or not rule_service
    
    def _extract_matched_fields(
        self,
        rule: SigmaRule,
        log_entry: Dict[str, Any]
    ) -> Dict[str, str]:
        """Extract fields that contributed to the match."""
        matched = {}
        for selection in rule.detection.values():
            if isinstance(selection, dict):
                for field in selection.keys():
                    clean_field = field.split("|")[0]
                    if clean_field in log_entry:
                        matched[clean_field] = str(log_entry[clean_field])[:200]
        return matched
    
    def get_rules_by_tactic(self, tactic: str) -> List[SigmaRule]:
        """Get all rules for a specific ATT&CK tactic."""
        return [
            r for r in self.rules.values()
            if tactic.lower() in [t.lower() for t in r.attack_tactics]
        ]
    
    def get_rules_by_level(self, level: str) -> List[SigmaRule]:
        """Get all rules of a specific severity level."""
        return [r for r in self.rules.values() if r.level == level]
```

---

### File 2: `rules/sigma/windows_powershell_suspicious.yml`

```yaml
title: Suspicious PowerShell Download Commands
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: stable
level: high
description: Detects PowerShell commands commonly used to download and execute malicious payloads
author: FileGuard
date: 2024/01/15
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1105/
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1105
logsource:
    product: windows
    service: powershell
    category: ps_script
detection:
    selection_download:
        ScriptBlockText|contains:
            - 'Invoke-WebRequest'
            - 'wget '
            - 'curl '
            - 'DownloadFile'
            - 'DownloadString'
            - 'DownloadData'
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
    selection_execute:
        ScriptBlockText|contains:
            - 'Invoke-Expression'
            - 'IEX('
            - 'IEX ('
            - '| IEX'
            - 'Invoke-Command'
            - 'ICM '
    condition: selection_download and selection_execute
falsepositives:
    - Legitimate PowerShell scripts that download and execute modules
    - Software deployment scripts
---
title: PowerShell Encoded Command Execution
id: fb843269-508c-4b76-8b8d-88679db22ce7
status: stable
level: high
description: Detects execution of PowerShell with encoded commands, commonly used to obfuscate malicious scripts
author: FileGuard
date: 2024/01/15
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -ec '
        Image|endswith: '\powershell.exe'
    filter:
        CommandLine|contains:
            - 'Get-AppxPackage'
    condition: selection and not filter
falsepositives:
    - Some legitimate software deployment tools use encoded commands
---
title: Mimikatz Command Line Keywords
id: a642964e-bead-4bed-8910-1bb4d63e3b77
status: stable
level: critical
description: Detects Mimikatz command line arguments
author: FileGuard
date: 2024/01/15
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
            - 'crypto::'
            - 'lsadump::'
            - 'privilege::debug'
            - 'token::elevate'
    condition: selection
falsepositives:
    - Legitimate security testing
```

---

### File 3: `rules/sigma/windows_event_log_tampering.yml`

```yaml
title: Security Event Log Cleared
id: d99b79d6-0b47-4f9d-8cc4-8bf09e76b1fa
status: stable
level: critical
description: Detects when the Windows Security Event Log is cleared, potential evidence destruction
author: FileGuard
date: 2024/01/15
tags:
    - attack.defense_evasion
    - attack.t1070.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1102
    condition: selection
falsepositives:
    - Legitimate administrative activity
    - Log rotation policies
---
title: System Event Log Cleared
id: 6e5a38a6-8dde-4edb-8e24-32fe6b53d03b
status: stable
level: high
description: Detects when the Windows System Event Log is cleared
author: FileGuard
date: 2024/01/15
tags:
    - attack.defense_evasion
    - attack.t1070.001
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 104
    condition: selection
falsepositives:
    - Legitimate administrative activity
---
title: Event Log Service Stopped
id: 7fb14104-e7eb-4dbb-a7cd-5a0b2e4a8a2f
status: stable
level: high
description: Detects when Windows Event Log service is stopped
author: FileGuard
date: 2024/01/15
tags:
    - attack.defense_evasion
    - attack.t1070.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1100
    condition: selection
falsepositives:
    - System shutdown
    - Legitimate maintenance
```

---

## Integration with Forensics Module:

### Update `forensics/event_logs.py` to use Sigma:

```python
# Add to imports
from detectors.sigma_detector import SigmaEngine, SigmaMatch

class EventLogAnalyzer:
    """Analyzes Windows Event Logs for suspicious activity."""
    
    def __init__(self, config: dict):
        self.config = config
        self.sigma_engine = SigmaEngine()
        self.logger = logging.getLogger(__name__)
    
    def analyze_logs(
        self,
        log_type: str = "Security",
        max_entries: int = 10000
    ) -> List[SigmaMatch]:
        """
        Analyze event logs using Sigma rules.
        
        Args:
            log_type: Type of event log to analyze
            max_entries: Maximum number of log entries to process
            
        Returns:
            List of Sigma matches found
        """
        entries = self._read_event_log(log_type, max_entries)
        return self.sigma_engine.match_logs(entries, log_type)
```

---

## Acceptance Criteria:
- [ ] SigmaEngine loads and parses .yml rules correctly
- [ ] Condition parser handles and/or/not operators
- [ ] Field modifiers (contains, startswith, endswith, re) work correctly
- [ ] Rules match against sample log entries correctly
- [ ] Integration with EventLogAnalyzer works
- [ ] Default rules cover major threat categories
- [ ] ATT&CK tags extracted from rules automatically
- [ ] Unit tests achieve >90% coverage