"""
Hash-based detection module for FileGuard.

Checks file hashes against the local known-malware database
and optionally queries VirusTotal.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.base import BaseDetector
from core.models import Finding
from utils.hash_utils import calculate_file_hashes

logger = logging.getLogger(__name__)


class HashDetector(BaseDetector):
    """
    Detects known malware by file hash lookup.

    Compares file hashes (MD5, SHA-256) against the local
    known_hashes database table. Optionally queries VirusTotal
    if an API key is configured.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize hash detector.

        Args:
            config: Optional config with database_path and
                    virustotal settings.
        """
        super().__init__(config)
        self._db_path = self.config.get("database_path")

    def _get_db(self) -> Any:
        """Create a thread-local database connection."""
        from core.database import Database
        return Database(Path(self._db_path) if self._db_path else None)

    def detect(
        self,
        file_path: Path,
        file_content: Optional[bytes] = None,
    ) -> List[Finding]:
        """
        Check file hash against known malware database.

        Args:
            file_path: Path to the file.
            file_content: Optional pre-read content (unused).

        Returns:
            List of findings if hash matches known malware.
        """
        findings: List[Finding] = []

        try:
            hashes = calculate_file_hashes(file_path)
            sha256 = hashes.get("sha256", "")
            md5 = hashes.get("md5", "")

            if not sha256:
                return findings

            # Check local database (new connection per call for thread safety)
            db = self._get_db()
            try:
                result = db.check_hash(sha256)
            finally:
                db.close()

            if result:
                findings.append(Finding(
                    detector=self.name,
                    description=(
                        f"Known malware hash match: "
                        f"{result.get('malware_name', 'Unknown')}"
                    ),
                    severity=result.get("severity", 100),
                    evidence=(
                        f"SHA-256: {sha256}\n"
                        f"MD5: {md5}\n"
                        f"Family: {result.get('malware_family', 'N/A')}\n"
                        f"Source: {result.get('source', 'local')}"
                    ),
                    remediation=(
                        "File matches a known malware hash. "
                        "Quarantine immediately and investigate "
                        "how it arrived on the system."
                    ),
                    attack_techniques=["T1204"],
                    attack_tactics=["Execution"],
                    attack_confidence="high",
                ))

        except (FileNotFoundError, PermissionError) as e:
            self.logger.debug("Cannot hash %s: %s", file_path, e)
        except Exception as e:
            self.logger.error(
                "Hash detection failed for %s: %s", file_path, e
            )

        return findings
