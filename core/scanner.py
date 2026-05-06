"""
FileGuard main scanning engine.

Provides the FileScanner class which orchestrates recursive file
scanning with multi-threaded analysis using all registered detectors.
"""

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional

ProgressCallback = Callable[[int, int, Optional[Path]], None]

from core.analyzer import FileAnalyzer
from core.base import ConfigManager
from core.models import ScanResult, ScanSummary
from core.risk_classifier import RiskClassifier
from detectors.ads_scanner import ADSScanner
from detectors.entropy_detector import EntropyDetector
from detectors.hash_detector import HashDetector
from detectors.packer_detector import PackerDetector
from detectors.pattern_detector import PatternDetector
from detectors.pe_analyzer import PEAnalyzer
from detectors.yara_detector import YaraDetector
from utils.file_utils import walk_directory
from utils.safety import validate_scan_path

logger = logging.getLogger(__name__)


class FileScanner:
    """
    Main file scanning engine for FileGuard.

    Walks directories, dispatches file analysis to a thread pool,
    and collects results. Integrates all detection modules.
    """

    def __init__(
        self,
        threads: int = 4,
        max_file_size_mb: int = 100,
        yara_rules_path: Optional[Path] = None,
        exclusions: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the file scanner.

        Args:
            threads: Number of worker threads for analysis.
            max_file_size_mb: Maximum file size to scan (in MB).
            yara_rules_path: Optional path to YARA rules directory.
            exclusions: List of glob patterns/paths to exclude.
            config: Optional full configuration dictionary.
        """
        self.threads = max(1, threads)
        self.max_file_size_mb = max_file_size_mb
        self.exclusions = exclusions or []
        self.config = config or {}

        # Initialize detectors
        detector_config: Dict[str, Any] = {}
        if yara_rules_path:
            detector_config["rules_path"] = str(yara_rules_path)

        self._detectors = [
            PatternDetector(detector_config),
            EntropyDetector(self.config.get("entropy", {})),
            PEAnalyzer(detector_config),
            PackerDetector(detector_config),
            ADSScanner(detector_config),
            HashDetector(self.config.get("hashes", {})),
            YaraDetector(detector_config),
        ]

        self._analyzer = FileAnalyzer(
            detectors=self._detectors,
            config=self.config,
        )

        self._classifier = RiskClassifier(
            config=self.config.get("risk", {}),
        )

        # Scan statistics
        self._files_scanned = 0
        self._files_skipped = 0
        self._files_error = 0

    def scan(
        self,
        target: Path,
        deep: bool = False,
        quick: bool = False,
        progress_callback: Optional[ProgressCallback] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> Generator[ScanResult, None, None]:
        """
        Scan a directory or file and yield results.

        Args:
            target: Path to scan (file or directory).
            deep: If True, scan system files (requires appropriate access).
            quick: If True, only scan high-risk locations.
            progress_callback: Optional callable invoked as
                ``(processed, total, current_path)`` whenever the scanner
                advances. ``total == 0`` means the file list is still
                being enumerated; ``current_path`` may be ``None`` while
                walking. The callback runs on the worker-completion
                thread; UI callers must marshal to their main thread.
            cancel_event: Optional threading.Event. If set, the scan
                stops accepting new work, cancels still-pending workers,
                and returns. Already-running workers finish in the
                background but their results are dropped.

        Yields:
            ScanResult for each analyzed file.

        Raises:
            SafetyError: If target is outside sandbox in test mode.
            FileNotFoundError: If target does not exist.
        """
        target = validate_scan_path(target)

        logger.info("Starting scan of %s (deep=%s, quick=%s)", target, deep, quick)
        self._files_scanned = 0
        self._files_skipped = 0
        self._files_error = 0

        def _cancelled() -> bool:
            return cancel_event is not None and cancel_event.is_set()

        def _emit(processed: int, total: int, current: Optional[Path]) -> None:
            if progress_callback is None:
                return
            try:
                progress_callback(processed, total, current)
            except Exception as cb_err:
                logger.debug("progress_callback raised: %s", cb_err)

        if target.is_file():
            _emit(0, 1, target)
            if _cancelled():
                return
            result = self._analyze_file(target)
            if result:
                self._files_scanned += 1
                _emit(1, 1, target)
                yield result
            else:
                self._files_skipped += 1
                _emit(1, 1, target)
            return

        # Load scanner config
        try:
            config_mgr = ConfigManager()
            config_mgr.load()
            scanner_config = config_mgr.get("scanner", {}) or {}
        except Exception:
            scanner_config = {}

        # Merge exclusions
        all_exclusions = list(self.exclusions)
        default_exclusions = scanner_config.get("default_exclusions", [])
        if isinstance(default_exclusions, list):
            all_exclusions.extend(default_exclusions)

        # Signal "enumerating" before we know the total. Walk lazily so
        # cancel during a giant tree is responsive instead of waiting
        # for rglob to finish materializing.
        _emit(0, 0, None)

        files: List[Path] = []
        for f in walk_directory(
            root=target,
            recursive=True,
            follow_symlinks=False,
            exclusions=all_exclusions,
            max_file_size_mb=self.max_file_size_mb,
            scan_hidden=scanner_config.get("scan_hidden", True),
        ):
            if _cancelled():
                logger.info("Scan cancelled during enumeration")
                return
            files.append(f)

        total = len(files)
        logger.info("Found %d files to scan", total)
        _emit(0, total, None)

        if _cancelled():
            logger.info("Scan cancelled before analysis")
            return

        # Manual executor lifecycle so we can shutdown(cancel_futures=True)
        # without waiting for in-flight workers to finish.
        executor = ThreadPoolExecutor(max_workers=self.threads)
        processed = 0
        try:
            futures = {
                executor.submit(self._analyze_file, f): f
                for f in files
            }

            for future in as_completed(futures):
                if _cancelled():
                    logger.info(
                        "Scan cancelled at %d/%d", processed, total
                    )
                    break

                file_path = futures[future]
                processed += 1
                try:
                    result = future.result()
                    if result:
                        self._files_scanned += 1
                        _emit(processed, total, result.file_path)
                        yield result
                    else:
                        self._files_skipped += 1
                        _emit(processed, total, file_path)
                except Exception as e:
                    self._files_error += 1
                    logger.error("Scan failed for %s: %s", file_path, e)
                    _emit(processed, total, file_path)
        finally:
            # cancel_futures requires Python 3.9+. Don't wait - the
            # caller wants to return control immediately. In-flight
            # workers (up to self.threads) finish in the background;
            # their results are dropped because we've broken out of
            # the as_completed loop.
            executor.shutdown(wait=False, cancel_futures=True)

        logger.info(
            "Scan complete: %d scanned, %d skipped, %d errors%s",
            self._files_scanned,
            self._files_skipped,
            self._files_error,
            " (cancelled)" if _cancelled() else "",
        )

    def scan_full(
        self,
        target: Path,
        deep: bool = False,
    ) -> ScanSummary:
        """
        Perform a complete scan and return a summary.

        Unlike scan() which yields individual results, this method
        collects all results into a ScanSummary.

        Args:
            target: Path to scan.
            deep: If True, scan system files.

        Returns:
            ScanSummary with all results and statistics.
        """
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.now()

        results = list(self.scan(target, deep=deep))

        summary = ScanSummary(
            scan_id=scan_id,
            start_time=start_time,
            end_time=datetime.now(),
            target_path=target,
            total_files=self._files_scanned + self._files_skipped + self._files_error,
            files_scanned=self._files_scanned,
            files_skipped=self._files_skipped,
            files_error=self._files_error,
            results=results,
        )

        return summary

    def _analyze_file(self, file_path: Path) -> Optional[ScanResult]:
        """
        Analyze a single file with error handling.

        Args:
            file_path: Path to the file.

        Returns:
            ScanResult or None if file should be skipped.
        """
        try:
            result = self._analyzer.analyze(file_path)
            return result
        except PermissionError:
            logger.debug("Permission denied: %s", file_path)
            return None
        except FileNotFoundError:
            logger.debug("File disappeared: %s", file_path)
            return None
        except Exception as e:
            logger.error("Analysis failed for %s: %s", file_path, e)
            return None

    @property
    def stats(self) -> Dict[str, int]:
        """Return current scan statistics."""
        return {
            "scanned": self._files_scanned,
            "skipped": self._files_skipped,
            "errors": self._files_error,
        }
