# TASK: Implement STIX/TAXII Export

## Phase: Integration Enhancement
## Task Name: STIX 2.1 Export and TAXII Client Integration
## Description:
Add capability to export scan findings in STIX 2.1 format for threat intelligence sharing, and optionally push to TAXII servers. This enables integration with enterprise security tools (SIEMs, TIPs, SOARs).

---

## Specific Requirements:

1. Create STIX 2.1 export module at `utils/stix_export.py`
2. Create TAXII client at `utils/taxii_client.py`
3. Add STIX export option to GUI and CLI
4. Support export of indicators, malware objects, attack patterns, and relationships
5. Add configuration for TAXII server connections

---

## Dependencies to Add to requirements.txt:

```
stix2>=3.0.1
taxii2-client>=2.3.0
```

---

## Expected Output Files:

### File 1: `utils/stix_export.py`

```python
"""
STIX 2.1 export module.

Converts FileGuard scan findings into STIX 2.1 objects for
threat intelligence sharing and integration with security tools.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from stix2 import (
    Bundle,
    Identity,
    Indicator,
    Malware,
    AttackPattern,
    Relationship,
    ObservedData,
    File as StixFile,
    WindowsRegistryKey,
    MemoryExt,
    CustomObject,
    properties,
)
from stix2.v21 import _Observable

from core.models import ScanResult, Finding, RiskLevel

logger = logging.getLogger(__name__)

# FileGuard identity for STIX objects
FILEGUARD_IDENTITY_ID = "identity--f8e1a3c7-5d9b-4e2a-8f6c-3a1b2d4e5f6a"


class StixExporter:
    """
    Exports FileGuard scan results to STIX 2.1 format.
    
    Creates standardized threat intelligence objects including:
    - Indicators (file hashes, patterns)
    - Malware (detected malware samples)
    - Attack Patterns (MITRE ATT&CK mappings)
    - Relationships (connections between objects)
    - Observed Data (raw file observations)
    """
    
    def __init__(self, organization_name: str = "FileGuard"):
        """
        Initialize STIX exporter.
        
        Args:
            organization_name: Name for the identity object
        """
        self.organization_name = organization_name
        self.identity = self._create_identity()
        self.objects: List[Any] = [self.identity]
        self.created_ids: Dict[str, str] = {}
    
    def _create_identity(self) -> Identity:
        """Create the FileGuard identity object."""
        return Identity(
            id=FILEGUARD_IDENTITY_ID,
            name=self.organization_name,
            identity_class="tool",
            description="FileGuard Security Scanner - Automated threat detection tool",
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc)
        )
    
    def _generate_id(self, object_type: str, unique_string: str) -> str:
        """Generate deterministic STIX ID from content."""
        hash_input = f"{object_type}:{unique_string}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:32]
        return f"{object_type}--{hash_value[:8]}-{hash_value[8:12]}-{hash_value[12:16]}-{hash_value[16:20]}-{hash_value[20:32]}"
    
    def add_scan_result(self, result: ScanResult) -> None:
        """
        Convert a ScanResult to STIX objects.
        
        Args:
            result: FileGuard scan result to convert
        """
        # Create file observable
        file_obj = self._create_file_observable(result)
        
        # Create indicator if suspicious
        if result.risk_level in [RiskLevel.SUSPICIOUS_CODE, RiskLevel.HIGH_TARGET]:
            indicator = self._create_indicator(result, file_obj)
            self.objects.append(indicator)
            
            # Create malware object for high-risk findings
            if result.risk_level == RiskLevel.SUSPICIOUS_CODE:
                malware = self._create_malware(result)
                self.objects.append(malware)
                
                # Relationship: indicator indicates malware
                rel = Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware.id,
                    created_by_ref=self.identity.id
                )
                self.objects.append(rel)
        
        # Create attack patterns from ATT&CK mappings
        for finding in result.findings:
            if finding.attack_techniques:
                for tech_id in finding.attack_techniques:
                    attack_pattern = self._create_attack_pattern(tech_id, finding)
                    if attack_pattern:
                        self.objects.append(attack_pattern)
    
    def _create_file_observable(self, result: ScanResult) -> StixFile:
        """Create STIX File observable from scan result."""
        hashes = {}
        if result.file_hash_md5:
            hashes["MD5"] = result.file_hash_md5
        if result.file_hash_sha256:
            hashes["SHA-256"] = result.file_hash_sha256
        
        return StixFile(
            name=result.file_path.name,
            size=result.file_size,
            hashes=hashes if hashes else None,
            ctime=result.created_time.isoformat() if result.created_time else None,
            mtime=result.modified_time.isoformat() if result.modified_time else None
        )
    
    def _create_indicator(
        self,
        result: ScanResult,
        file_obj: StixFile
    ) -> Indicator:
        """Create STIX Indicator from scan result."""
        # Build STIX pattern
        patterns = []
        if result.file_hash_sha256:
            patterns.append(f"[file:hashes.'SHA-256' = '{result.file_hash_sha256}']")
        elif result.file_hash_md5:
            patterns.append(f"[file:hashes.MD5 = '{result.file_hash_md5}']")
        else:
            patterns.append(f"[file:name = '{result.file_path.name}']")
        
        pattern = " OR ".join(patterns)
        
        # Determine indicator type based on findings
        indicator_types = ["malicious-activity"]
        if any("ransomware" in f.description.lower() for f in result.findings):
            indicator_types.append("attribution")
        
        return Indicator(
            id=self._generate_id("indicator", result.file_hash_sha256 or str(result.file_path)),
            name=f"FileGuard Detection: {result.file_path.name}",
            description=self._build_description(result),
            indicator_types=indicator_types,
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            created_by_ref=self.identity.id,
            labels=self._get_labels(result),
            confidence=self._calculate_confidence(result)
        )
    
    def _create_malware(self, result: ScanResult) -> Malware:
        """Create STIX Malware object from scan result."""
        # Determine malware types from findings
        malware_types = ["unknown"]
        description_lower = " ".join(f.description.lower() for f in result.findings)
        
        if "ransomware" in description_lower:
            malware_types = ["ransomware"]
        elif "trojan" in description_lower:
            malware_types = ["trojan"]
        elif "keylog" in description_lower:
            malware_types = ["keylogger"]
        elif "backdoor" in description_lower:
            malware_types = ["backdoor"]
        elif "rootkit" in description_lower:
            malware_types = ["rootkit"]
        elif "worm" in description_lower:
            malware_types = ["worm"]
        
        return Malware(
            id=self._generate_id("malware", result.file_hash_sha256 or str(result.file_path)),
            name=f"Detected Malware: {result.file_path.name}",
            description=self._build_description(result),
            malware_types=malware_types,
            is_family=False,
            created_by_ref=self.identity.id,
            confidence=self._calculate_confidence(result)
        )
    
    def _create_attack_pattern(
        self,
        technique_id: str,
        finding: Finding
    ) -> Optional[AttackPattern]:
        """Create STIX Attack Pattern from ATT&CK technique."""
        # Avoid duplicates
        cache_key = f"attack-pattern:{technique_id}"
        if cache_key in self.created_ids:
            return None
        
        attack_pattern = AttackPattern(
            id=self._generate_id("attack-pattern", technique_id),
            name=technique_id,
            description=finding.description,
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                }
            ],
            created_by_ref=self.identity.id
        )
        
        self.created_ids[cache_key] = attack_pattern.id
        return attack_pattern
    
    def _build_description(self, result: ScanResult) -> str:
        """Build description from findings."""
        lines = [
            f"Risk Level: {result.risk_level.name}",
            f"Risk Score: {result.risk_score}",
            f"File: {result.file_path}",
            "",
            "Findings:"
        ]
        for finding in result.findings:
            lines.append(f"- [{finding.detector}] {finding.description}")
        
        return "\n".join(lines)
    
    def _get_labels(self, result: ScanResult) -> List[str]:
        """Get labels from findings."""
        labels = [result.risk_level.name.lower().replace("_", "-")]
        
        # Add detector names as labels
        detectors = set(f.detector for f in result.findings)
        labels.extend(detectors)
        
        # Add ATT&CK tactics
        for finding in result.findings:
            labels.extend(finding.attack_tactics)
        
        return list(set(labels))
    
    def _calculate_confidence(self, result: ScanResult) -> int:
        """Calculate confidence score (0-100)."""
        if result.risk_level == RiskLevel.SUSPICIOUS_CODE:
            return min(95, result.risk_score)
        elif result.risk_level == RiskLevel.HIGH_TARGET:
            return min(75, result.risk_score)
        else:
            return min(50, result.risk_score)
    
    def export_bundle(self) -> Bundle:
        """
        Export all objects as STIX Bundle.
        
        Returns:
            STIX 2.1 Bundle containing all objects
        """
        return Bundle(objects=self.objects)
    
    def export_to_file(self, output_path: Path) -> None:
        """
        Export STIX bundle to JSON file.
        
        Args:
            output_path: Path to output file
        """
        bundle = self.export_bundle()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(bundle.serialize(pretty=True))
        
        logger.info(f"Exported {len(self.objects)} STIX objects to {output_path}")
    
    def export_to_dict(self) -> Dict[str, Any]:
        """Export as dictionary (for JSON API responses)."""
        bundle = self.export_bundle()
        return {
            "type": "bundle",
            "id": bundle.id,
            "objects": [obj.serialize() for obj in self.objects]
        }


def export_scan_results_to_stix(
    results: List[ScanResult],
    output_path: Path,
    organization_name: str = "FileGuard"
) -> None:
    """
    Convenience function to export scan results to STIX file.
    
    Args:
        results: List of scan results to export
        output_path: Path to output STIX JSON file
        organization_name: Name for the identity object
    """
    exporter = StixExporter(organization_name)
    
    for result in results:
        if result.risk_level != RiskLevel.CLEAN:
            exporter.add_scan_result(result)
    
    exporter.export_to_file(output_path)
```

---

### File 2: `utils/taxii_client.py`

```python
"""
TAXII 2.1 client for threat intelligence sharing.

Enables pushing FileGuard findings to TAXII servers for
integration with enterprise security infrastructure.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from taxii2client.v21 import Server, Collection, as_pages
from stix2 import Bundle

logger = logging.getLogger(__name__)


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
    
    Supports:
    - Server discovery
    - Collection listing
    - Publishing STIX bundles
    - Fetching shared intelligence
    """
    
    def __init__(self, config: TaxiiConfig):
        """
        Initialize TAXII client.
        
        Args:
            config: TAXII server configuration
        """
        self.config = config
        self.server: Optional[Server] = None
        self.collection: Optional[Collection] = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish connection to TAXII server."""
        try:
            self.server = Server(
                self.config.server_url,
                user=self.config.username,
                password=self.config.password,
                verify=self.config.verify_ssl
            )
            
            # Get API root
            if self.config.api_root:
                api_root = self.server.api_roots[0]  # Use first or specified
            else:
                api_root = self.server.default
            
            # Get collection
            for collection in api_root.collections:
                if collection.id == self.config.collection_id:
                    self.collection = collection
                    break
            
            if not self.collection:
                raise ValueError(f"Collection {self.config.collection_id} not found")
            
            logger.info(f"Connected to TAXII server: {self.config.server_url}")
            
        except Exception as e:
            logger.error(f"Failed to connect to TAXII server: {e}")
            raise
    
    def publish_bundle(self, bundle: Bundle) -> Dict[str, Any]:
        """
        Publish STIX bundle to TAXII collection.
        
        Args:
            bundle: STIX 2.1 Bundle to publish
            
        Returns:
            Server response as dictionary
        """
        if not self.collection:
            raise RuntimeError("Not connected to TAXII collection")
        
        if not self.collection.can_write:
            raise PermissionError("Collection does not allow write operations")
        
        try:
            response = self.collection.add_objects(bundle)
            logger.info(f"Published {len(bundle.objects)} objects to TAXII server")
            return response
        except Exception as e:
            logger.error(f"Failed to publish to TAXII: {e}")
            raise
    
    def publish_stix_file(self, stix_path: Path) -> Dict[str, Any]:
        """
        Publish STIX file to TAXII collection.
        
        Args:
            stix_path: Path to STIX JSON file
            
        Returns:
            Server response
        """
        with open(stix_path, 'r', encoding='utf-8') as f:
            import json
            data = json.load(f)
        
        bundle = Bundle(**data)
        return self.publish_bundle(bundle)
    
    def fetch_indicators(
        self,
        added_after: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Fetch indicators from TAXII collection.
        
        Args:
            added_after: Only fetch objects added after this timestamp
            limit: Maximum objects to fetch
            
        Returns:
            List of STIX objects
        """
        if not self.collection:
            raise RuntimeError("Not connected to TAXII collection")
        
        if not self.collection.can_read:
            raise PermissionError("Collection does not allow read operations")
        
        objects = []
        try:
            for envelope in as_pages(
                self.collection.get_objects,
                per_request=limit,
                added_after=added_after
            ):
                objects.extend(envelope.get("objects", []))
                if len(objects) >= limit:
                    break
            
            logger.info(f"Fetched {len(objects)} objects from TAXII server")
            return objects[:limit]
            
        except Exception as e:
            logger.error(f"Failed to fetch from TAXII: {e}")
            raise
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get information about the TAXII server."""
        if not self.server:
            raise RuntimeError("Not connected to server")
        
        return {
            "title": self.server.title,
            "description": self.server.description,
            "contact": self.server.contact,
            "api_roots": [str(ar) for ar in self.server.api_roots]
        }
    
    def list_collections(self) -> List[Dict[str, Any]]:
        """List available collections."""
        if not self.server:
            raise RuntimeError("Not connected to server")
        
        collections = []
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                collections.append({
                    "id": collection.id,
                    "title": collection.title,
                    "description": collection.description,
                    "can_read": collection.can_read,
                    "can_write": collection.can_write
                })
        
        return collections


class TaxiiIntegration:
    """
    High-level integration between FileGuard and TAXII.
    
    Handles automatic publishing and fetching of threat intelligence.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize TAXII integration.
        
        Args:
            config_path: Path to TAXII configuration YAML
        """
        self.config_path = config_path
        self.clients: Dict[str, TaxiiClient] = {}
    
    def add_server(self, name: str, config: TaxiiConfig) -> None:
        """Add a TAXII server connection."""
        self.clients[name] = TaxiiClient(config)
    
    def publish_to_all(self, bundle: Bundle) -> Dict[str, Any]:
        """Publish bundle to all configured servers."""
        results = {}
        for name, client in self.clients.items():
            try:
                results[name] = client.publish_bundle(bundle)
            except Exception as e:
                results[name] = {"error": str(e)}
        return results
    
    def fetch_from_all(self) -> Dict[str, List[Dict]]:
        """Fetch indicators from all configured servers."""
        results = {}
        for name, client in self.clients.items():
            try:
                results[name] = client.fetch_indicators()
            except Exception as e:
                results[name] = {"error": str(e)}
        return results
```

---

### File 3: `config/taxii_servers.yaml` (Template)

```yaml
# TAXII Server Configuration
# Add your TAXII servers here for threat intelligence sharing

servers:
  # Example: Anomali STAXX (free)
  # anomali_staxx:
  #   enabled: false
  #   server_url: "https://staxx.anomali.com/taxii/"
  #   collection_id: "your-collection-id"
  #   username: "your-username"
  #   password: "your-password"
  #   verify_ssl: true
  
  # Example: MISP TAXII
  # misp_taxii:
  #   enabled: false
  #   server_url: "https://your-misp.local/taxii/"
  #   collection_id: "your-collection-id"
  #   api_key: "your-api-key"
  
  # Example: Custom TAXII Server
  # custom_server:
  #   enabled: true
  #   server_url: "https://your-server.com/taxii2/"
  #   collection_id: "collection-uuid"
  #   username: "user"
  #   password: "pass"

# Auto-publish settings
auto_publish:
  enabled: false
  min_risk_level: "SUSPICIOUS_CODE"  # Only publish high-risk findings
  include_attack_mappings: true
  
# Auto-fetch settings (import threat intel)
auto_fetch:
  enabled: false
  interval_hours: 24
  import_indicators: true
```

---

### File 4: Update CLI for STIX Export (`cli.py` additions):

```python
# Add to cli.py argument parser

def setup_export_arguments(parser: argparse.ArgumentParser) -> None:
    """Add export-related arguments."""
    export_group = parser.add_argument_group("Export Options")
    
    export_group.add_argument(
        "--export-stix",
        type=Path,
        metavar="PATH",
        help="Export findings to STIX 2.1 JSON file"
    )
    
    export_group.add_argument(
        "--export-stix-org",
        type=str,
        default="FileGuard",
        help="Organization name for STIX identity (default: FileGuard)"
    )
    
    export_group.add_argument(
        "--taxii-publish",
        action="store_true",
        help="Publish findings to configured TAXII servers"
    )
    
    export_group.add_argument(
        "--taxii-server",
        type=str,
        help="Specific TAXII server name to publish to"
    )


# Add to main scan function
def handle_exports(results: List[ScanResult], args: argparse.Namespace) -> None:
    """Handle export operations after scan."""
    from utils.stix_export import export_scan_results_to_stix, StixExporter
    from utils.taxii_client import TaxiiIntegration, TaxiiConfig
    
    # STIX file export
    if args.export_stix:
        export_scan_results_to_stix(
            results,
            args.export_stix,
            args.export_stix_org
        )
        print(f"[+] Exported STIX bundle to {args.export_stix}")
    
    # TAXII publish
    if args.taxii_publish:
        exporter = StixExporter(args.export_stix_org)
        for result in results:
            if result.risk_level.value >= 3:  # HIGH_TARGET or above
                exporter.add_scan_result(result)
        
        bundle = exporter.export_bundle()
        
        # Load TAXII config and publish
        integration = TaxiiIntegration()
        # ... load config and publish
        print(f"[+] Published to TAXII servers")
```

---

### File 5: GUI Export Button Handler (`gui/app.py` additions):

```python
# Add export menu/buttons to GUI

def _create_export_menu(self) -> None:
    """Create export menu options."""
    export_frame = ctk.CTkFrame(self.toolbar_frame)
    export_frame.pack(side="right", padx=5)
    
    self.export_button = ctk.CTkButton(
        export_frame,
        text="Export",
        command=self._show_export_options,
        width=80
    )
    self.export_button.pack(side="left", padx=2)

def _show_export_options(self) -> None:
    """Show export options dialog."""
    dialog = ExportDialog(self, self.scan_results)
    dialog.mainloop()

class ExportDialog(ctk.CTkToplevel):
    """Export options dialog."""
    
    def __init__(self, parent, results: List[ScanResult]):
        super().__init__(parent)
        self.results = results
        self.title("Export Findings")
        self.geometry("400x300")
        
        # Export format selection
        ctk.CTkLabel(self, text="Export Format:").pack(pady=10)
        
        self.format_var = ctk.StringVar(value="stix")
        formats = [
            ("STIX 2.1 (JSON)", "stix"),
            ("HTML Report", "html"),
            ("CSV", "csv"),
            ("JSON", "json")
        ]
        
        for text, value in formats:
            ctk.CTkRadioButton(
                self,
                text=text,
                variable=self.format_var,
                value=value
            ).pack(anchor="w", padx=20)
        
        # TAXII publish option
        self.taxii_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self,
            text="Also publish to TAXII servers",
            variable=self.taxii_var
        ).pack(pady=10)
        
        # Export button
        ctk.CTkButton(
            self,
            text="Export",
            command=self._do_export
        ).pack(pady=20)
    
    def _do_export(self) -> None:
        """Perform the export."""
        format_type = self.format_var.get()
        
        # Get save path
        from tkinter import filedialog
        
        filetypes = {
            "stix": [("STIX JSON", "*.json")],
            "html": [("HTML", "*.html")],
            "csv": [("CSV", "*.csv")],
            "json": [("JSON", "*.json")]
        }
        
        path = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=filetypes[format_type]
        )
        
        if path:
            if format_type == "stix":
                from utils.stix_export import export_scan_results_to_stix
                export_scan_results_to_stix(self.results, Path(path))
            # ... handle other formats
            
            self.destroy()
```

---

## Acceptance Criteria:
- [ ] StixExporter creates valid STIX 2.1 bundles
- [ ] All risk levels map to appropriate STIX objects
- [ ] ATT&CK techniques link to Attack Pattern objects
- [ ] TaxiiClient connects and authenticates successfully
- [ ] Bundle publishing works with test TAXII server
- [ ] CLI export flags work correctly
- [ ] GUI export dialog functional
- [ ] Unit tests cover export scenarios
- [ ] Documentation includes TAXII setup guide