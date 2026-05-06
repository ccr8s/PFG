"""
FileGuard SQLite database operations.

Handles storage and retrieval of scan results, forensic findings,
and honeypot alerts.
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import (
    Finding,
    ForensicFinding,
    HoneypotAlert,
    RiskLevel,
    ScanResult,
    ScanSummary,
)

logger = logging.getLogger(__name__)

# Database schema version for migrations
SCHEMA_VERSION = 1


class Database:
    """
    SQLite database manager for FileGuard.

    Provides methods to store and query scan results, forensic
    findings, and honeypot alerts.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """
        Initialize the database.

        Args:
            db_path: Path to SQLite database file. Defaults to
                     data/fileguard.db in the project root.
        """
        if db_path is None:
            project_root = Path(__file__).resolve().parent.parent
            db_path = project_root / "data" / "fileguard.db"

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection: Optional[sqlite3.Connection] = None
        self._initialize()

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._connection is None:
            self._connection = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
        return self._connection

    def _initialize(self) -> None:
        """Create database tables if they don't exist."""
        conn = self._get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    target_path TEXT,
                    total_files INTEGER DEFAULT 0,
                    files_scanned INTEGER DEFAULT 0,
                    files_skipped INTEGER DEFAULT 0,
                    files_error INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    file_hash_md5 TEXT,
                    file_hash_sha256 TEXT,
                    file_size INTEGER,
                    file_extension TEXT,
                    created_time TEXT,
                    modified_time TEXT,
                    scan_time TEXT NOT NULL,
                    metadata_json TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_result_id INTEGER NOT NULL,
                    detector TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    evidence TEXT,
                    line_number INTEGER,
                    remediation TEXT,
                    attack_techniques TEXT,
                    attack_tactics TEXT,
                    attack_confidence TEXT DEFAULT 'medium',
                    FOREIGN KEY (scan_result_id)
                        REFERENCES scan_results(id)
                );

                CREATE TABLE IF NOT EXISTS forensic_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    evidence TEXT,
                    timestamp TEXT,
                    artifact_path TEXT,
                    attack_techniques TEXT,
                    attack_tactics TEXT,
                    attack_confidence TEXT DEFAULT 'medium',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS honeypot_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decoy_path TEXT NOT NULL,
                    access_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    process_name TEXT,
                    process_id INTEGER,
                    user TEXT
                );

                CREATE TABLE IF NOT EXISTS known_hashes (
                    hash_sha256 TEXT PRIMARY KEY,
                    hash_md5 TEXT,
                    malware_name TEXT,
                    malware_family TEXT,
                    severity INTEGER,
                    source TEXT,
                    added_date TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
                    ON scan_results(scan_id);
                CREATE INDEX IF NOT EXISTS idx_scan_results_risk_level
                    ON scan_results(risk_level);
                CREATE INDEX IF NOT EXISTS idx_scan_results_file_hash
                    ON scan_results(file_hash_sha256);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_result_id
                    ON findings(scan_result_id);
                CREATE INDEX IF NOT EXISTS idx_known_hashes_md5
                    ON known_hashes(hash_md5);
                CREATE INDEX IF NOT EXISTS idx_honeypot_alerts_timestamp
                    ON honeypot_alerts(timestamp);
            """)

            # Set schema version
            conn.execute(
                "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
            conn.commit()
            logger.info("Database initialized: %s", self.db_path)
        except Exception as e:
            logger.error("Database initialization failed: %s", e)
            raise

    # ------------------------------------------------------------------
    # Scan operations
    # ------------------------------------------------------------------

    def save_scan(self, summary: ScanSummary) -> None:
        """
        Save a complete scan session with all results.

        Args:
            summary: ScanSummary with results to store.
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO scans
                   (scan_id, start_time, end_time, target_path,
                    total_files, files_scanned, files_skipped, files_error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    summary.scan_id,
                    summary.start_time.isoformat(),
                    (
                        summary.end_time.isoformat()
                        if summary.end_time else None
                    ),
                    (
                        str(summary.target_path)
                        if summary.target_path else None
                    ),
                    summary.total_files,
                    summary.files_scanned,
                    summary.files_skipped,
                    summary.files_error,
                ),
            )

            for result in summary.results:
                self._save_scan_result(conn, summary.scan_id, result)

            conn.commit()
            logger.info(
                "Saved scan %s with %d results",
                summary.scan_id,
                len(summary.results),
            )
        except Exception as e:
            conn.rollback()
            logger.error("Failed to save scan: %s", e)
            raise

    def save_scan_result(self, scan_id: str, result: ScanResult) -> None:
        """
        Persist a single ScanResult under an existing scan_id.

        The scan row must already exist (created via :meth:`save_scan`).
        """
        conn = self._get_connection()
        try:
            self._save_scan_result(conn, scan_id, result)
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to save scan result: %s", e)
            raise

    def _save_scan_result(
        self,
        conn: sqlite3.Connection,
        scan_id: str,
        result: ScanResult,
    ) -> None:
        """Save a single scan result and its findings."""
        cursor = conn.execute(
            """INSERT INTO scan_results
               (scan_id, file_path, risk_level, risk_score,
                file_hash_md5, file_hash_sha256, file_size,
                file_extension, created_time, modified_time,
                scan_time, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                str(result.file_path),
                result.risk_level.name,
                result.risk_score,
                result.file_hash_md5,
                result.file_hash_sha256,
                result.file_size,
                result.file_extension,
                (
                    result.created_time.isoformat()
                    if result.created_time else None
                ),
                (
                    result.modified_time.isoformat()
                    if result.modified_time else None
                ),
                result.scan_time.isoformat(),
                json.dumps(result.metadata),
            ),
        )
        result_id = cursor.lastrowid

        for finding in result.findings:
            conn.execute(
                """INSERT INTO findings
                   (scan_result_id, detector, description, severity,
                    evidence, line_number, remediation,
                    attack_techniques, attack_tactics,
                    attack_confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result_id,
                    finding.detector,
                    finding.description,
                    finding.severity,
                    finding.evidence,
                    finding.line_number,
                    finding.remediation,
                    json.dumps(finding.attack_techniques),
                    json.dumps(finding.attack_tactics),
                    finding.attack_confidence,
                ),
            )

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan session by ID.

        Args:
            scan_id: The scan identifier.

        Returns:
            Dictionary with scan data, or None if not found.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    def get_scan_results(
        self,
        scan_id: str,
        risk_level: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Get scan results for a scan, optionally filtered by risk level.

        Args:
            scan_id: The scan identifier.
            risk_level: Optional risk level filter.
            limit: Maximum number of results.

        Returns:
            List of result dictionaries.
        """
        conn = self._get_connection()

        if risk_level:
            rows = conn.execute(
                """SELECT * FROM scan_results
                   WHERE scan_id = ? AND risk_level = ?
                   ORDER BY risk_score DESC LIMIT ?""",
                (scan_id, risk_level, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM scan_results
                   WHERE scan_id = ?
                   ORDER BY risk_score DESC LIMIT ?""",
                (scan_id, limit),
            ).fetchall()

        return [dict(r) for r in rows]

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get the most recent scan sessions.

        Args:
            limit: Maximum number of scans to return.

        Returns:
            List of scan dictionaries.
        """
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Forensic operations
    # ------------------------------------------------------------------

    def save_forensic_finding(self, finding: ForensicFinding) -> None:
        """
        Save a forensic finding.

        Args:
            finding: ForensicFinding to store.
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO forensic_findings
                   (source, description, severity, evidence,
                    timestamp, artifact_path, attack_techniques,
                    attack_tactics, attack_confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.source,
                    finding.description,
                    finding.severity,
                    finding.evidence,
                    (
                        finding.timestamp.isoformat()
                        if finding.timestamp else None
                    ),
                    finding.artifact_path,
                    json.dumps(finding.attack_techniques),
                    json.dumps(finding.attack_tactics),
                    finding.attack_confidence,
                ),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to save forensic finding: %s", e)
            raise

    def get_forensic_findings(
        self,
        source: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve forensic findings.

        Args:
            source: Optional filter by source type.
            limit: Maximum results.

        Returns:
            List of finding dictionaries.
        """
        conn = self._get_connection()

        if source:
            rows = conn.execute(
                """SELECT * FROM forensic_findings
                   WHERE source = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (source, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM forensic_findings
                   ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Honeypot operations
    # ------------------------------------------------------------------

    def save_honeypot_alert(self, alert: HoneypotAlert) -> None:
        """
        Save a honeypot alert.

        Args:
            alert: HoneypotAlert to store.
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO honeypot_alerts
                   (decoy_path, access_type, timestamp,
                    process_name, process_id, user)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    str(alert.decoy_path),
                    alert.access_type,
                    alert.timestamp.isoformat(),
                    alert.process_name,
                    alert.process_id,
                    alert.user,
                ),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to save honeypot alert: %s", e)
            raise

    def get_honeypot_alerts(
        self, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Retrieve recent honeypot alerts.

        Args:
            limit: Maximum number of alerts.

        Returns:
            List of alert dictionaries.
        """
        conn = self._get_connection()
        rows = conn.execute(
            """SELECT * FROM honeypot_alerts
               ORDER BY timestamp DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Hash operations
    # ------------------------------------------------------------------

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        """
        Check if a hash exists in the known malware database.

        Args:
            sha256: SHA-256 hash to check.

        Returns:
            Dictionary with malware info, or None.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM known_hashes WHERE hash_sha256 = ?",
            (sha256,),
        ).fetchone()

        return dict(row) if row else None

    def add_known_hash(
        self,
        sha256: str,
        md5: str = "",
        malware_name: str = "",
        malware_family: str = "",
        severity: int = 0,
        source: str = "manual",
    ) -> None:
        """
        Add a known malware hash to the database.

        Args:
            sha256: SHA-256 hash.
            md5: MD5 hash.
            malware_name: Name of the malware.
            malware_family: Malware family.
            severity: Severity score 0-100.
            source: Where this hash came from.
        """
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO known_hashes
                   (hash_sha256, hash_md5, malware_name,
                    malware_family, severity, source)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (sha256, md5, malware_name, malware_family, severity, source),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Failed to add known hash: %s", e)
            raise

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.debug("Database connection closed")

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
