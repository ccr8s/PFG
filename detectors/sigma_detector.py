"""
Sigma rule detection engine.

Parses and applies Sigma rules against Windows Event Logs
and other log sources for threat detection.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

import yaml

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
    tags: List[str]
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
            "critical": 90,
        }
        return level_map.get(self.level, 50)

    def __post_init__(self) -> None:
        """Extract ATT&CK info from tags."""
        for tag in self.tags:
            if tag.startswith("attack.t"):
                tech_id = tag.replace("attack.", "").upper()
                self.attack_techniques.append(tech_id)
            elif tag.startswith("attack."):
                tactic = tag.replace("attack.", "")
                self.attack_tactics.append(tactic)


@dataclass
class SigmaMatch:
    """Represents a Sigma rule match against a log entry."""
    rule: SigmaRule
    log_entry: Dict[str, Any]
    matched_fields: Dict[str, str]
    timestamp: datetime
    source_log: str

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
            "attack_confidence": (
                "high" if self.rule.status == "stable" else "medium"
            ),
        }


class SigmaConditionParser:
    """
    Parses Sigma detection conditions.

    Supports basic conditions, boolean operators, 1-of/all-of patterns,
    and field modifiers (contains, startswith, endswith, re).
    """

    def __init__(self, detection: Dict[str, Any]) -> None:
        self.detection = detection
        self.condition = detection.get("condition", "")
        self.selections = {
            k: v for k, v in detection.items() if k != "condition"
        }

    def parse(self) -> Callable[[Dict], bool]:
        """Parse condition into executable matcher function."""
        return self._build_matcher(self.condition)

    def _build_matcher(self, condition: str) -> Callable[[Dict], bool]:
        """Build matcher function from condition string."""
        condition = condition.strip()

        # Handle 'not' prefix
        if condition.startswith("not "):
            inner = self._build_matcher(condition[4:])
            return lambda log, _i=inner: not _i(log)

        # Handle 'X and not Y' pattern
        if " and not " in condition:
            parts = condition.split(" and not ", 1)
            left = self._build_matcher(parts[0].strip())
            right = self._build_matcher(parts[1].strip())
            return lambda log, _l=left, _r=right: _l(log) and not _r(log)

        # Handle 'and' operator
        if " and " in condition:
            parts = condition.split(" and ")
            matchers = [self._build_matcher(p.strip()) for p in parts]
            return lambda log, _m=matchers: all(m(log) for m in _m)

        # Handle 'or' operator
        if " or " in condition:
            parts = condition.split(" or ")
            matchers = [self._build_matcher(p.strip()) for p in parts]
            return lambda log, _m=matchers: any(m(log) for m in _m)

        # Handle parentheses
        if condition.startswith("(") and condition.endswith(")"):
            return self._build_matcher(condition[1:-1])

        # Handle '1 of selection*' pattern
        if condition.startswith("1 of "):
            pattern = condition[5:].replace("*", ".*")
            matching = [
                k for k in self.selections
                if re.match(pattern, k)
            ]
            matchers = [
                self._build_selection_matcher(self.selections[s])
                for s in matching
            ]
            return lambda log, _m=matchers: any(m(log) for m in _m)

        # Handle 'all of selection*' pattern
        if condition.startswith("all of "):
            pattern = condition[7:].replace("*", ".*")
            matching = [
                k for k in self.selections
                if re.match(pattern, k)
            ]
            matchers = [
                self._build_selection_matcher(self.selections[s])
                for s in matching
            ]
            return lambda log, _m=matchers: all(m(log) for m in _m)

        # Simple selection reference
        if condition in self.selections:
            return self._build_selection_matcher(
                self.selections[condition]
            )

        logger.warning("Unknown Sigma condition format: %s", condition)
        return lambda log: False

    def _build_selection_matcher(
        self, selection: Union[Dict, List]
    ) -> Callable[[Dict], bool]:
        """Build matcher for a single selection."""
        if isinstance(selection, list):
            matchers = [
                self._build_selection_matcher(s) for s in selection
            ]
            return lambda log, _m=matchers: any(m(log) for m in _m)

        if isinstance(selection, dict):
            field_matchers = []
            for field_name, value in selection.items():
                field_matchers.append(
                    self._build_field_matcher(field_name, value)
                )
            return lambda log, _m=field_matchers: all(m(log) for m in _m)

        return lambda log: False

    def _build_field_matcher(
        self, field_name: str, value: Any
    ) -> Callable[[Dict], bool]:
        """Build matcher for a single field condition."""
        modifiers: List[str] = []
        if "|" in field_name:
            parts = field_name.split("|")
            field_name = parts[0]
            modifiers = parts[1:]

        def match_value(log_value: Any, pattern: Any) -> bool:
            if log_value is None:
                return False
            log_str = str(log_value).lower()

            if isinstance(pattern, list):
                return any(match_value(log_value, p) for p in pattern)

            pattern_str = str(pattern).lower()

            if "contains" in modifiers:
                return pattern_str in log_str
            elif "startswith" in modifiers:
                return log_str.startswith(pattern_str)
            elif "endswith" in modifiers:
                return log_str.endswith(pattern_str)
            elif "re" in modifiers:
                return bool(
                    re.search(pattern_str, log_str, re.IGNORECASE)
                )
            else:
                if "*" in pattern_str:
                    regex = pattern_str.replace("*", ".*")
                    return bool(
                        re.match(regex, log_str, re.IGNORECASE)
                    )
                return log_str == pattern_str

        return (
            lambda log, _fn=field_name, _v=value:
                match_value(log.get(_fn), _v)
        )


class SigmaEngine:
    """
    Main Sigma detection engine.

    Loads rules, validates them, and matches against log entries.
    """

    def __init__(self, rules_path: Optional[Path] = None) -> None:
        """
        Initialize Sigma engine.

        Args:
            rules_path: Path to directory containing .yml Sigma rules.
        """
        self.rules_path = (
            rules_path
            or Path(__file__).resolve().parent.parent / "rules" / "sigma"
        )
        self.rules: Dict[str, SigmaRule] = {}
        self.matchers: Dict[str, Callable] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all Sigma rules from rules directory."""
        if not self.rules_path.exists():
            logger.warning(
                "Sigma rules directory not found: %s", self.rules_path
            )
            self.rules_path.mkdir(parents=True, exist_ok=True)
            return

        for rule_file in self.rules_path.glob("**/*.yml"):
            try:
                self._load_rule_file(rule_file)
            except Exception as e:
                logger.error(
                    "Failed to load Sigma rule %s: %s", rule_file, e
                )

        logger.info("Loaded %d Sigma rules", len(self.rules))

    def _load_rule_file(self, path: Path) -> None:
        """Load a single Sigma rule file (may contain multiple rules)."""
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Support multi-document YAML
        for doc in yaml.safe_load_all(content):
            if not doc or not isinstance(doc, dict):
                continue

            rule = SigmaRule(
                id=doc.get("id", path.stem),
                title=doc.get("title", "Unknown"),
                status=doc.get("status", "experimental"),
                level=doc.get("level", "medium"),
                description=doc.get("description", ""),
                author=doc.get("author", "Unknown"),
                date=doc.get("date", ""),
                references=doc.get("references", []),
                tags=doc.get("tags", []),
                logsource=doc.get("logsource", {}),
                detection=doc.get("detection", {}),
                falsepositives=doc.get("falsepositives", []),
            )

            self.rules[rule.id] = rule

            # Pre-compile matcher
            parser = SigmaConditionParser(rule.detection)
            self.matchers[rule.id] = parser.parse()

    def match_log_entry(
        self,
        log_entry: Dict[str, Any],
        log_source: str = "Security",
    ) -> List[SigmaMatch]:
        """
        Match a log entry against all applicable rules.

        Args:
            log_entry: Dictionary of log entry fields.
            log_source: Log source type.

        Returns:
            List of SigmaMatch objects for rules that matched.
        """
        matches = []

        for rule_id, rule in self.rules.items():
            if not self._check_logsource(rule, log_source):
                continue

            matcher = self.matchers.get(rule_id)
            if matcher and matcher(log_entry):
                match = SigmaMatch(
                    rule=rule,
                    log_entry=log_entry,
                    matched_fields=self._extract_matched_fields(
                        rule, log_entry
                    ),
                    timestamp=datetime.now(),
                    source_log=log_source,
                )
                matches.append(match)

        return matches

    def match_logs(
        self,
        log_entries: List[Dict[str, Any]],
        log_source: str = "Security",
    ) -> List[SigmaMatch]:
        """Match multiple log entries."""
        all_matches: List[SigmaMatch] = []
        for entry in log_entries:
            all_matches.extend(self.match_log_entry(entry, log_source))
        return all_matches

    def _check_logsource(
        self, rule: SigmaRule, log_source: str
    ) -> bool:
        """Check if rule applies to given log source."""
        rule_product = rule.logsource.get("product", "").lower()
        rule_service = rule.logsource.get("service", "").lower()
        rule_category = rule.logsource.get("category", "").lower()
        ls = log_source.lower()

        if rule_product == "windows":
            if rule_service == "security" and ls == "security":
                return True
            if rule_service == "powershell" and "powershell" in ls:
                return True
            if rule_service == "sysmon" and "sysmon" in ls:
                return True
            if rule_category == "process_creation":
                return ls in ("security", "sysmon")

        return rule_service == ls or not rule_service

    @staticmethod
    def _extract_matched_fields(
        rule: SigmaRule, log_entry: Dict[str, Any]
    ) -> Dict[str, str]:
        """Extract fields that contributed to the match."""
        matched: Dict[str, str] = {}
        for selection in rule.detection.values():
            if isinstance(selection, dict):
                for fld in selection:
                    clean_field = fld.split("|")[0]
                    if clean_field in log_entry:
                        matched[clean_field] = str(
                            log_entry[clean_field]
                        )[:200]
        return matched

    def get_rules_by_tactic(self, tactic: str) -> List[SigmaRule]:
        """Get all rules for a specific ATT&CK tactic."""
        return [
            r
            for r in self.rules.values()
            if tactic.lower() in [t.lower() for t in r.attack_tactics]
        ]

    def get_rules_by_level(self, level: str) -> List[SigmaRule]:
        """Get all rules of a specific severity level."""
        return [r for r in self.rules.values() if r.level == level]
