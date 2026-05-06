"""
FileGuard logging configuration.

Provides consistent logging setup across CLI and GUI modes.
"""

import logging
import sys
from pathlib import Path
from typing import List, Optional


# Log format constants
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_FORMAT_DEBUG = (
    "%(asctime)s [%(levelname)s] %(name)s "
    "(%(filename)s:%(lineno)d): %(message)s"
)
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    verbose: bool = False,
) -> None:
    """
    Configure logging for the application.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
        log_file: Optional path to a log file.
        verbose: If True, use DEBUG level regardless of level arg.
    """
    log_level = logging.DEBUG if verbose else getattr(logging, level.upper(), logging.INFO)
    fmt = LOG_FORMAT_DEBUG if verbose else LOG_FORMAT

    handlers: List[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
    ]

    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=LOG_DATE_FORMAT))
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=fmt,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
        force=True,
    )

    # Quiet noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)

    logger = logging.getLogger("fileguard")
    logger.info(
        "Logging initialized (level=%s, file=%s)",
        logging.getLevelName(log_level),
        log_file or "stdout only",
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a namespaced logger for a FileGuard module.

    Args:
        name: Module name (e.g., "core.scanner").

    Returns:
        Logger instance with "fileguard." prefix.
    """
    return logging.getLogger(f"fileguard.{name}")
