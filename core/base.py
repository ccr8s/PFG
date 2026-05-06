"""
Base classes and interfaces for FileGuard modules.

All detectors, analyzers, and forensic modules should inherit from
the appropriate base class defined here.
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import Finding, ForensicFinding, ScanResult

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """
    Abstract base class for all detection modules.

    Subclasses must implement the `detect` method which analyzes a single
    file and returns a list of findings.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize detector.

        Args:
            config: Optional configuration overrides.
        """
        self.config = config or {}
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(f"fileguard.detectors.{self.name}")

    @abstractmethod
    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Analyze a file and return findings.

        Args:
            file_path: Path to the file to analyze.
            file_content: Optional pre-read file content.

        Returns:
            List of Finding objects for any detections.
        """

    def is_applicable(self, file_path: Path) -> bool:
        """
        Check if this detector should run on the given file.

        Override in subclasses to limit to specific file types.

        Args:
            file_path: Path to check.

        Returns:
            True if this detector should analyze the file.
        """
        return True

    def __repr__(self) -> str:
        return f"<{self.name}>"


class BaseAnalyzer(ABC):
    """
    Abstract base class for file analyzers.

    Analyzers extract metadata and structural information from files
    (e.g., PE headers, entropy, imports).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize analyzer.

        Args:
            config: Optional configuration overrides.
        """
        self.config = config or {}
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(f"fileguard.analyzers.{self.name}")

    @abstractmethod
    def analyze(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a file and return metadata.

        Args:
            file_path: Path to the file to analyze.
            file_content: Optional pre-read file content.

        Returns:
            Dictionary of analysis results.
        """

    def is_applicable(self, file_path: Path) -> bool:
        """
        Check if this analyzer should run on the given file.

        Args:
            file_path: Path to check.

        Returns:
            True if this analyzer should process the file.
        """
        return True

    def __repr__(self) -> str:
        return f"<{self.name}>"


class BaseForensicModule(ABC):
    """
    Abstract base class for forensic analysis modules.

    Forensic modules analyze system artifacts like event logs,
    registry entries, timestamps, and caches.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize forensic module.

        Args:
            config: Optional configuration overrides.
        """
        self.config = config or {}
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(f"fileguard.forensics.{self.name}")

    @abstractmethod
    def analyze(self) -> List[ForensicFinding]:
        """
        Run forensic analysis and return findings.

        Returns:
            List of ForensicFinding objects.
        """

    def is_available(self) -> bool:
        """
        Check if this forensic module can run on the current system.

        Override in subclasses to check for required system access,
        admin privileges, etc.

        Returns:
            True if the module can execute.
        """
        return True

    def __repr__(self) -> str:
        return f"<{self.name}>"


class ConfigManager:
    """
    Manages FileGuard configuration from YAML files.

    Loads settings from config/settings.yaml with environment
    variable overrides.
    """

    _instance: Optional["ConfigManager"] = None
    _config: Dict[str, Any] = {}

    def __new__(cls) -> "ConfigManager":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load(self, config_path: Optional[Path] = None) -> None:
        """
        Load configuration from YAML file.

        After loading the main config, ``config/secrets.yaml`` (if it
        exists) is merged on top so that user secrets like API keys
        live in an untracked file. ``config/secrets.yaml`` is listed
        in ``.gitignore``.

        Args:
            config_path: Path to config file. Defaults to
                         config/settings.yaml in project root.
        """
        import yaml

        if config_path is None:
            project_root = Path(__file__).resolve().parent.parent
            config_path = project_root / "config" / "settings.yaml"

        if not config_path.exists():
            logger.warning("Config file not found: %s, using defaults", config_path)
            self._config = self._defaults()
        else:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    self._config = yaml.safe_load(f) or {}
                logger.info("Configuration loaded from %s", config_path)
            except Exception as e:
                logger.error("Failed to load config: %s", e)
                self._config = self._defaults()

        # Overlay untracked secrets file if present.
        secrets_path = config_path.with_name("secrets.yaml")
        if secrets_path.exists():
            try:
                with open(secrets_path, "r", encoding="utf-8") as f:
                    secrets = yaml.safe_load(f) or {}
                self._merge(self._config, secrets)
                logger.info("Secrets overlay loaded from %s", secrets_path)
            except Exception as e:
                logger.error("Failed to load secrets file: %s", e)

    @staticmethod
    def _merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> None:
        """Deep-merge ``overlay`` into ``base`` in place."""
        for key, value in overlay.items():
            if (
                key in base
                and isinstance(base[key], dict)
                and isinstance(value, dict)
            ):
                ConfigManager._merge(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.

        Args:
            key: Dot-separated key (e.g., "scanner.threads").
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        keys = key.split(".")
        value: Any = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.

        Args:
            key: Dot-separated key.
            value: Value to set.
        """
        keys = key.split(".")
        config = self._config
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    def save(self, config_path: Optional[Path] = None) -> None:
        """
        Save current configuration to YAML file.

        Args:
            config_path: Path to save to.
        """
        import yaml

        if config_path is None:
            project_root = Path(__file__).resolve().parent.parent
            config_path = project_root / "config" / "settings.yaml"

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(self._config, f, default_flow_style=False)
            logger.info("Configuration saved to %s", config_path)
        except Exception as e:
            logger.error("Failed to save config: %s", e)

    def save_secret(self, key: str, value: Any) -> Path:
        """
        Persist a secret (e.g. API key) to ``config/secrets.yaml``.

        The secrets file is gitignored so credentials do not land in
        the tracked ``settings.yaml``. The in-memory config is also
        updated so the value is immediately available.
        """
        import yaml

        project_root = Path(__file__).resolve().parent.parent
        secrets_path = project_root / "config" / "secrets.yaml"

        existing: Dict[str, Any] = {}
        if secrets_path.exists():
            try:
                with open(secrets_path, "r", encoding="utf-8") as f:
                    existing = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error("Cannot read existing secrets: %s", e)

        # Walk dotted key into the nested dict.
        target = existing
        parts = key.split(".")
        for part in parts[:-1]:
            if part not in target or not isinstance(target[part], dict):
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value

        secrets_path.parent.mkdir(parents=True, exist_ok=True)
        with open(secrets_path, "w", encoding="utf-8") as f:
            yaml.dump(existing, f, default_flow_style=False)

        # Reflect immediately in current in-memory config too.
        self.set(key, value)

        logger.info("Secret saved to %s (key=%s)", secrets_path, key)
        return secrets_path

    @property
    def config(self) -> Dict[str, Any]:
        """Return full configuration dictionary."""
        return self._config

    @staticmethod
    def _defaults() -> Dict[str, Any]:
        """Return default configuration."""
        return {
            "app": {
                "name": "FileGuard",
                "version": "1.0.0",
                "log_level": "INFO",
            },
            "scanner": {
                "threads": 4,
                "max_file_size_mb": 100,
                "recursive": True,
            },
            "risk": {
                "critical_threshold": 80,
                "high_threshold": 60,
                "medium_threshold": 30,
            },
            "database": {
                "path": "data/fileguard.db",
            },
            "safety": {
                "sandbox_root": "C:\\FileGuardTest\\mock_system",
                "testing_mode": True,
                "read_only": True,
            },
        }

    def reset(self) -> None:
        """Reset configuration values to the built-in defaults."""
        self._config = self._defaults()

    @classmethod
    def reset_singleton(cls) -> None:
        """Drop the singleton instance (test helper)."""
        cls._instance = None
        cls._config = {}
