"""
Honeypot decoy file manager for FileGuard.

Creates, deploys, tracks, and removes decoy files designed to
attract attackers. Any access to these files triggers an alert.
"""

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.safety import (
    SANDBOX_ROOT,
    TESTING_MODE,
    SafetyError,
    is_safe_path,
    safe_delete,
    safe_write,
)

logger = logging.getLogger(__name__)

# Default decoy file definitions
DEFAULT_DECOYS = [
    {"name": "passwords.xlsx", "content_type": "xlsx_stub", "desc": "Password file decoy"},
    {"name": "bitcoin_wallet.dat", "content_type": "binary_stub", "desc": "Crypto wallet decoy"},
    {"name": "bank_accounts.docx", "content_type": "docx_stub", "desc": "Banking info decoy"},
    {"name": "SSN_backup.txt", "content_type": "text_stub", "desc": "SSN backup decoy"},
    {"name": "tax_returns_2024.pdf", "content_type": "pdf_stub", "desc": "Tax return decoy"},
    {"name": "credit_cards.csv", "content_type": "csv_stub", "desc": "Credit card decoy"},
    {"name": "master_password.txt", "content_type": "text_stub", "desc": "Master password decoy"},
    {"name": "crypto_seed_phrase.txt", "content_type": "text_stub", "desc": "Crypto seed decoy"},
]

# Default locations (relative to user profile)
DEFAULT_LOCATIONS = ["Desktop", "Documents", "Downloads"]

# Hidden marker to identify FileGuard decoys
DECOY_MARKER = "FILEGUARD_DECOY_v1"
MANIFEST_FILENAME = ".fileguard_decoys.json"


class DecoyManager:
    """
    Manages honeypot decoy file lifecycle.

    Handles deployment, tracking, status reporting, and removal
    of decoy files across configured locations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize decoy manager.

        Args:
            config: Optional configuration overrides.
        """
        self.config = config or {}
        self._manifest: Dict[str, Any] = {}
        self._manifest_path = self._get_manifest_path()
        self._load_manifest()

    def _get_manifest_path(self) -> Path:
        """Get the path to the decoy manifest file."""
        if TESTING_MODE:
            return SANDBOX_ROOT / MANIFEST_FILENAME
        project_root = Path(__file__).resolve().parent.parent
        return project_root / "data" / MANIFEST_FILENAME

    def _load_manifest(self) -> None:
        """Load the deployed decoys manifest."""
        if self._manifest_path.exists():
            try:
                with open(self._manifest_path, "r", encoding="utf-8") as f:
                    self._manifest = json.load(f)
            except Exception as e:
                logger.warning("Failed to load manifest: %s", e)
                self._manifest = {"decoys": [], "deployed_at": None}
        else:
            self._manifest = {"decoys": [], "deployed_at": None}

    def _save_manifest(self) -> None:
        """Save the deployed decoys manifest."""
        try:
            payload = json.dumps(
                self._manifest, indent=2, default=str
            ).encode("utf-8")
            safe_write(self._manifest_path, payload, force=True)
        except SafetyError as e:
            logger.error("Manifest path rejected by safety wrapper: %s", e)
        except Exception as e:
            logger.error("Failed to save manifest: %s", e)

    def deploy_decoys(
        self,
        locations: Optional[List[Path]] = None,
    ) -> List[Path]:
        """
        Deploy decoy files to specified locations.

        Args:
            locations: Custom locations. Defaults to Desktop/Documents/Downloads.

        Returns:
            List of paths where decoys were deployed.
        """
        deployed: List[Path] = []

        if locations:
            target_dirs = [Path(loc) for loc in locations]
        else:
            target_dirs = self._get_default_locations()

        for target_dir in target_dirs:
            if not target_dir.exists():
                logger.debug("Skipping nonexistent location: %s", target_dir)
                continue

            if not is_safe_path(target_dir):
                logger.warning("Skipping unsafe location: %s", target_dir)
                continue

            for decoy_def in DEFAULT_DECOYS:
                decoy_path = target_dir / decoy_def["name"]

                if decoy_path.exists():
                    logger.debug("Decoy already exists: %s", decoy_path)
                    continue

                try:
                    content = self._generate_content(decoy_def)
                    # Honeypot deployment is an explicit action, so we
                    # bypass READONLY_MODE while still requiring the
                    # path to satisfy is_safe_path().
                    safe_write(decoy_path, content, force=True)

                    # Track deployment
                    self._manifest["decoys"].append({
                        "id": str(uuid.uuid4())[:8],
                        "path": str(decoy_path),
                        "name": decoy_def["name"],
                        "description": decoy_def["desc"],
                        "deployed_at": datetime.now().isoformat(),
                        "size": len(content),
                    })

                    deployed.append(decoy_path)
                    logger.info("Deployed decoy: %s", decoy_path)

                except SafetyError as e:
                    logger.warning(
                        "Refusing to deploy decoy to %s: %s",
                        decoy_path, e,
                    )
                except (PermissionError, OSError) as e:
                    logger.warning(
                        "Cannot deploy decoy to %s: %s", decoy_path, e
                    )

        self._manifest["deployed_at"] = datetime.now().isoformat()
        self._save_manifest()

        logger.info("Deployed %d decoy files", len(deployed))
        return deployed

    def remove_all_decoys(self) -> int:
        """
        Remove all deployed decoy files.

        Returns:
            Number of decoys removed.
        """
        removed = 0

        for decoy in self._manifest.get("decoys", []):
            decoy_path = Path(decoy["path"])
            try:
                if decoy_path.exists():
                    # Removal is the user's explicit intent; bypass the
                    # testing/readonly simulation but still gate on
                    # is_safe_path().
                    safe_delete(decoy_path, force=True)
                    removed += 1
                    logger.info("Removed decoy: %s", decoy_path)
            except SafetyError as e:
                logger.warning("Refusing to remove %s: %s", decoy_path, e)
            except (PermissionError, OSError) as e:
                logger.warning("Cannot remove %s: %s", decoy_path, e)

        self._manifest["decoys"] = []
        self._manifest["deployed_at"] = None
        self._save_manifest()

        logger.info("Removed %d decoy files", removed)
        return removed

    def get_status(self) -> Dict[str, Any]:
        """
        Get current honeypot status.

        Returns:
            Dictionary with status information.
        """
        decoys = self._manifest.get("decoys", [])
        active = sum(
            1 for d in decoys if Path(d["path"]).exists()
        )

        return {
            "deployed_count": len(decoys),
            "active_count": active,
            "active_monitors": 0,  # Updated by monitor
            "recent_alerts": 0,    # Updated by monitor
            "deployed_at": self._manifest.get("deployed_at"),
            "last_alert_time": None,
            "decoys": decoys,
        }

    def get_deployed_paths(self) -> List[Path]:
        """Return list of all deployed decoy paths."""
        return [
            Path(d["path"])
            for d in self._manifest.get("decoys", [])
            if Path(d["path"]).exists()
        ]

    def is_decoy(self, file_path: Path) -> bool:
        """Check if a file is a deployed decoy."""
        file_str = str(file_path.resolve())
        for decoy in self._manifest.get("decoys", []):
            if str(Path(decoy["path"]).resolve()) == file_str:
                return True
        return False

    def _get_default_locations(self) -> List[Path]:
        """Get default decoy deployment locations."""
        if TESTING_MODE:
            base = SANDBOX_ROOT / "Users" / "TestUser"
            locations = [base / loc for loc in DEFAULT_LOCATIONS]
            for loc in locations:
                loc.mkdir(parents=True, exist_ok=True)
            return locations

        user_home = Path.home()
        return [user_home / loc for loc in DEFAULT_LOCATIONS]

    @staticmethod
    def _generate_content(decoy_def: Dict[str, Any]) -> bytes:
        """
        Generate realistic-looking decoy file content.

        Args:
            decoy_def: Decoy definition with content_type.

        Returns:
            File content as bytes.
        """
        content_type = decoy_def.get("content_type", "text_stub")

        if content_type == "text_stub":
            text = (
                f"# {DECOY_MARKER}\n"
                f"# This file is monitored by FileGuard honeypot system.\n"
                f"# Any access to this file will trigger a security alert.\n"
                f"\n"
                f"Last updated: {datetime.now().isoformat()}\n"
            )
            return text.encode("utf-8")

        elif content_type == "csv_stub":
            text = (
                f"# {DECOY_MARKER}\n"
                "Card Type,Number,Expiration,CVV,Name\n"
                "Visa,4111-XXXX-XXXX-1111,12/25,XXX,John Doe\n"
                "Mastercard,5500-XXXX-XXXX-0005,06/26,XXX,Jane Smith\n"
            )
            return text.encode("utf-8")

        elif content_type == "binary_stub":
            # Generic binary stub with marker
            marker = DECOY_MARKER.encode("utf-8")
            return b"\x00" * 64 + marker + b"\x00" * 192

        elif content_type == "xlsx_stub":
            # Minimal XLSX-like content (ZIP with marker)
            # Real XLSX is a ZIP file; this is a simplified stub
            marker = DECOY_MARKER.encode("utf-8")
            return b"PK\x03\x04" + b"\x00" * 26 + marker + b"\x00" * 200

        elif content_type == "docx_stub":
            marker = DECOY_MARKER.encode("utf-8")
            return b"PK\x03\x04" + b"\x00" * 26 + marker + b"\x00" * 200

        elif content_type == "pdf_stub":
            text = (
                f"%PDF-1.4\n"
                f"% {DECOY_MARKER}\n"
                f"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                f"%%EOF\n"
            )
            return text.encode("utf-8")

        # Default: text content
        return f"# {DECOY_MARKER}\nDecoy file.\n".encode("utf-8")
