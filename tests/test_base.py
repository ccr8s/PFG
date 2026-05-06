"""
Tests for core/base.py - Base classes and configuration.
"""

import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

from core.base import (
    BaseAnalyzer,
    BaseDetector,
    BaseForensicModule,
    ConfigManager,
)
from core.models import Finding, ForensicFinding

# ---------------------------------------------------------------------------
# Concrete implementations for testing abstract classes
# ---------------------------------------------------------------------------

class MockDetector(BaseDetector):
    """Concrete detector for testing."""

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        return [
            Finding(
                detector=self.name,
                description="Mock detection",
                severity=50,
                evidence="test",
            )
        ]


class MockAnalyzer(BaseAnalyzer):
    """Concrete analyzer for testing."""

    def analyze(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        return {"analyzed": True, "file": str(file_path)}


class MockForensicModule(BaseForensicModule):
    """Concrete forensic module for testing."""

    def analyze(self) -> List[ForensicFinding]:
        return [
            ForensicFinding(
                source="mock",
                description="Mock forensic finding",
                severity=30,
                evidence="test",
            )
        ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBaseDetector:
    """Tests for the BaseDetector abstract class."""

    def test_detector_has_name(self) -> None:
        """Detector should have a name based on class."""
        detector = MockDetector()
        assert detector.name == "MockDetector"

    def test_detector_detect_returns_findings(self) -> None:
        """detect() should return a list of findings."""
        detector = MockDetector()
        findings = detector.detect(Path("test.exe"))
        assert len(findings) == 1
        assert findings[0].severity == 50

    def test_detector_is_applicable_default_true(self) -> None:
        """is_applicable should default to True."""
        detector = MockDetector()
        assert detector.is_applicable(Path("any_file.txt")) is True

    def test_detector_accepts_config(self) -> None:
        """Detector should accept optional config."""
        detector = MockDetector(config={"threshold": 50})
        assert detector.config["threshold"] == 50


class TestBaseAnalyzer:
    """Tests for the BaseAnalyzer abstract class."""

    def test_analyzer_analyze_returns_dict(self) -> None:
        """analyze() should return a dictionary."""
        analyzer = MockAnalyzer()
        result = analyzer.analyze(Path("test.exe"))
        assert result["analyzed"] is True


class TestBaseForensicModule:
    """Tests for the BaseForensicModule abstract class."""

    def test_forensic_module_analyze(self) -> None:
        """analyze() should return forensic findings."""
        module = MockForensicModule()
        findings = module.analyze()
        assert len(findings) == 1
        assert findings[0].source == "mock"

    def test_forensic_module_is_available_default_true(self) -> None:
        """is_available should default to True."""
        module = MockForensicModule()
        assert module.is_available() is True


class TestConfigManager:
    """Tests for the ConfigManager."""

    def setup_method(self) -> None:
        """Reset singleton before each test."""
        ConfigManager._instance = None
        ConfigManager._config = {}

    def test_singleton_pattern(self) -> None:
        """ConfigManager should be a singleton."""
        a = ConfigManager()
        b = ConfigManager()
        assert a is b

    def test_load_yaml_config(self) -> None:
        """Should load configuration from a YAML file."""
        config_data = {
            "app": {"name": "TestApp", "version": "0.1"},
            "scanner": {"threads": 8},
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(config_data, f)
            config_path = Path(f.name)

        try:
            config = ConfigManager()
            config.load(config_path)
            assert config.get("app.name") == "TestApp"
            assert config.get("scanner.threads") == 8
        finally:
            config_path.unlink()

    def test_get_with_dot_notation(self) -> None:
        """Should retrieve nested values with dot notation."""
        config = ConfigManager()
        config._config = {
            "a": {"b": {"c": 42}}
        }
        assert config.get("a.b.c") == 42

    def test_get_default_for_missing_key(self) -> None:
        """Should return default for missing keys."""
        config = ConfigManager()
        config._config = {}
        assert config.get("nonexistent.key", "default") == "default"

    def test_set_value(self) -> None:
        """Should set nested configuration values."""
        config = ConfigManager()
        config._config = {}
        config.set("new.nested.key", "value")
        assert config.get("new.nested.key") == "value"

    def test_defaults_have_required_keys(self) -> None:
        """Default config should have minimum required keys."""
        defaults = ConfigManager._defaults()
        assert "app" in defaults
        assert "scanner" in defaults
        assert "risk" in defaults
        assert "safety" in defaults
