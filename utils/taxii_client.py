"""
TAXII 2.1 client for threat intelligence sharing.

Enables pushing FileGuard findings to TAXII servers for
integration with enterprise security infrastructure.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Check if TAXII library is available
try:
    from taxii2client.v21 import Collection, Server, as_pages
    TAXII_AVAILABLE = True
except ImportError:
    TAXII_AVAILABLE = False
    logger.debug(
        "taxii2-client not installed - TAXII integration unavailable"
    )


@dataclass
class TaxiiConfig:
    """Configuration for TAXII server connection."""
    server_url: str
    collection_id: str
    username: Optional[str] = None
    password: Optional[str] = None
    api_root: Optional[str] = None
    verify_ssl: bool = True


class TaxiiClient:
    """
    TAXII 2.1 client for publishing threat intelligence.

    Supports server discovery, collection listing,
    publishing STIX bundles, and fetching shared intelligence.
    """

    def __init__(self, config: TaxiiConfig) -> None:
        """
        Initialize TAXII client.

        Args:
            config: TAXII server configuration.
        """
        if not TAXII_AVAILABLE:
            raise ImportError(
                "taxii2-client required. "
                "Install with: pip install taxii2-client"
            )

        self.config = config
        self.server: Optional[Any] = None
        self.collection: Optional[Any] = None
        self._connect()

    def _connect(self) -> None:
        """Establish connection to TAXII server."""
        try:
            self.server = Server(
                self.config.server_url,
                user=self.config.username,
                password=self.config.password,
                verify=self.config.verify_ssl,
            )

            api_root = (
                self.server.api_roots[0]
                if self.config.api_root
                else self.server.default
            )

            for collection in api_root.collections:
                if collection.id == self.config.collection_id:
                    self.collection = collection
                    break

            if not self.collection:
                raise ValueError(
                    f"Collection {self.config.collection_id} not found"
                )

            logger.info(
                "Connected to TAXII server: %s", self.config.server_url
            )

        except Exception as e:
            logger.error("Failed to connect to TAXII server: %s", e)
            raise

    def publish_bundle(self, bundle: Any) -> Dict[str, Any]:
        """
        Publish STIX bundle to TAXII collection.

        Args:
            bundle: STIX 2.1 Bundle to publish.

        Returns:
            Server response as dictionary.
        """
        if not self.collection:
            raise RuntimeError("Not connected to TAXII collection")

        if not self.collection.can_write:
            raise PermissionError(
                "Collection does not allow write operations"
            )

        try:
            response = self.collection.add_objects(bundle)
            logger.info(
                "Published %d objects to TAXII server",
                len(bundle.objects),
            )
            return response
        except Exception as e:
            logger.error("Failed to publish to TAXII: %s", e)
            raise

    def publish_stix_file(self, stix_path: Path) -> Dict[str, Any]:
        """
        Publish a STIX JSON file to TAXII collection.

        Args:
            stix_path: Path to STIX JSON file.

        Returns:
            Server response.
        """
        try:
            from stix2 import Bundle
        except ImportError as exc:
            raise ImportError(
                "stix2 library required for file publishing"
            ) from exc

        with open(stix_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        bundle = Bundle(**data)
        return self.publish_bundle(bundle)

    def fetch_indicators(
        self,
        added_after: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Fetch indicators from TAXII collection.

        Args:
            added_after: Only fetch objects added after this timestamp.
            limit: Maximum objects to fetch.

        Returns:
            List of STIX objects.
        """
        if not self.collection:
            raise RuntimeError("Not connected to TAXII collection")

        if not self.collection.can_read:
            raise PermissionError(
                "Collection does not allow read operations"
            )

        objects: List[Dict[str, Any]] = []
        try:
            for envelope in as_pages(
                self.collection.get_objects,
                per_request=limit,
                added_after=added_after,
            ):
                objects.extend(envelope.get("objects", []))
                if len(objects) >= limit:
                    break

            logger.info(
                "Fetched %d objects from TAXII server", len(objects)
            )
            return objects[:limit]

        except Exception as e:
            logger.error("Failed to fetch from TAXII: %s", e)
            raise

    def get_server_info(self) -> Dict[str, Any]:
        """Get information about the TAXII server."""
        if not self.server:
            raise RuntimeError("Not connected to server")

        return {
            "title": self.server.title,
            "description": self.server.description,
            "contact": self.server.contact,
            "api_roots": [str(ar) for ar in self.server.api_roots],
        }

    def list_collections(self) -> List[Dict[str, Any]]:
        """List available collections on the server."""
        if not self.server:
            raise RuntimeError("Not connected to server")

        collections: List[Dict[str, Any]] = []
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                collections.append({
                    "id": collection.id,
                    "title": collection.title,
                    "description": collection.description,
                    "can_read": collection.can_read,
                    "can_write": collection.can_write,
                })
        return collections


class TaxiiIntegration:
    """
    High-level integration between FileGuard and TAXII.

    Handles automatic publishing and fetching of threat intelligence.
    """

    def __init__(
        self, config_path: Optional[Path] = None
    ) -> None:
        """
        Initialize TAXII integration.

        Args:
            config_path: Path to TAXII configuration YAML.
        """
        self.config_path = config_path
        self.clients: Dict[str, TaxiiClient] = {}

    def add_server(self, name: str, config: TaxiiConfig) -> None:
        """Add a TAXII server connection."""
        self.clients[name] = TaxiiClient(config)

    def publish_to_all(self, bundle: Any) -> Dict[str, Any]:
        """Publish bundle to all configured servers."""
        results: Dict[str, Any] = {}
        for name, client in self.clients.items():
            try:
                results[name] = client.publish_bundle(bundle)
            except Exception as e:
                results[name] = {"error": str(e)}
        return results

    def fetch_from_all(self) -> Dict[str, Any]:
        """Fetch indicators from all configured servers."""
        results: Dict[str, Any] = {}
        for name, client in self.clients.items():
            try:
                results[name] = client.fetch_indicators()
            except Exception as e:
                results[name] = {"error": str(e)}
        return results
