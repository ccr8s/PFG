# FileGuard - Development Phase Plan

> **File**: `docs/ai/PHASE_PLAN.md`
> **Purpose**: Complete development roadmap with tasks and deliverables

---

## Project Overview

A Python-based security scanner with GUI that categorizes files by risk level, detects tampering, analyzes suspicious patterns, and provides remediation guidance.

---

## Phase 1: Foundation & Project Structure (Week 1)

**Goal**: Establish clean, maintainable codebase architecture

### Tasks:
- [x] Create project directory structure
- [x] Set up virtual environment and requirements.txt
- [x] Implement logging framework
- [x] Create configuration management (YAML-based)
- [x] Build base classes and interfaces
- [x] Set up CLI entry point with argparse
- [x] Create database schema (SQLite)
- [x] Implement `utils/safety.py` (CRITICAL)

### Key Files:
- `main.py` - Entry point
- `cli.py` - CLI interface
- `core/models.py` - Data models
- `core/base.py` - Base classes
- `utils/safety.py` - Safety wrapper
- `config/settings.yaml` - Configuration

---

## Phase 2: Core Scanning Engine (Week 2)

**Goal**: Build the file scanning and analysis backbone

### Tasks:
- [x] Implement recursive file scanner with exclusions
- [x] Build file metadata extractor
- [x] Implement hash calculation (MD5, SHA256)
- [x] Create entropy calculator
- [x] Build PE file analyzer (pefile library)
- [x] Implement YARA rule engine
- [x] Create risk scoring algorithm
- [x] Build 4-tier risk classification system

### Risk Classification Logic:
```
SUSPICIOUS_CODE (Critical):     Score >= 80
HIGH_TARGET_FILES (High):       Score 60-79
POTENTIAL_RISK (Medium):        Score 30-59
LOW_RISK (Low):                 Score < 30
```

### Scoring Factors:
- Known malware hash match: +100
- YARA rule match: +50-90 (based on rule severity)
- High entropy (>7.5): +20
- Suspicious location: +15
- Double extension: +25
- Hidden + executable: +30
- Unsigned in system dir: +20
- Recent creation in startup: +25

---

## Phase 3: Detection Modules (Week 3)

**Goal**: Implement all detection capabilities

### Tasks:
- [x] YARA rule integration with custom rules
- [x] Hash lookup (local DB + VirusTotal API optional)
- [x] Pattern detection for:
  - Obfuscated PowerShell
  - Base64 encoded commands
  - Known malware strings
  - Suspicious function imports
  - LOLBins abuse patterns
- [x] PE anomaly detection
- [x] Alternate Data Stream (ADS) scanner
- [x] Packed/encrypted file detection

---

## Phase 4: Forensics Module (Week 4)

**Goal**: Implement Windows forensic artifact analysis

### Tasks:
- [x] Event Log Parser
  - Security log (4624, 4625, 4688, etc.)
  - Detect cleared logs (Event ID 1102)
  - Detect log service stopped
- [x] Registry Analyzer
  - Run keys
  - Services
  - Scheduled tasks
  - Recent USB devices
  - UserAssist (execution history)
- [x] Timestomp Detection
  - Compare $STANDARD_INFO vs $FILE_NAME
  - Flag impossible timestamps
  - Detect mass timestamp changes
- [x] Prefetch Parser
  - Extract execution times
  - Flag suspicious executables
- [x] Bitmap Cache Parser
  - Parse bcache*.bmc files
  - Extract cached images
- [x] Amcache/Shimcache Parser

### Event Log Tampering Indicators:
- Event ID 1102 (audit log cleared)
- Event ID 104 (system log cleared)
- Gaps in sequential event IDs
- Log file size anomalies
- Missing expected periodic events
- Log files with future timestamps

---

## Phase 5: Honeypot System (Week 5)

**Goal**: Lightweight decoy file monitoring

### Tasks:
- [x] Create decoy file generator
- [x] Implement file access monitoring (watchdog)
- [x] Build alert system
- [x] Create honeypot dashboard in GUI

### Decoy Files:
```
Locations: Desktop, Documents, Downloads, Root of drives

File Names:
- passwords.xlsx
- bitcoin_wallet.dat
- bank_accounts.docx
- SSN_backup.txt
- tax_returns_2024.pdf
- credit_cards.csv
- master_password.txt
- crypto_seed_phrase.txt
```

### Monitoring:
- Use Windows ReadDirectoryChangesW or watchdog library
- Log all access attempts with timestamp, process, user
- Alert on any read/write/delete attempt
- Minimal CPU footprint (~0.1% when idle)

---

## Phase 6: GUI Development (Week 6-7)

**Goal**: Clean, functional GUI matching wireframe

### Framework: CustomTkinter

### Tasks:
- [x] Main window layout
- [x] "Start Scan" button with progress
- [x] 4-column risk category display
- [x] File list with icons and scrollbars
- [x] File detail panel (right side)
- [x] Code highlighting for suspicious sections
- [x] Bottom toolbar (Event Logs, Registry, etc.)
- [x] Information panel (bottom)
- [x] Color-coded risk indicators
- [x] Export menu (STIX, HTML, CSV)

### GUI Layout:
```
┌─────────────────────────────────────────────────────────────┐
│  [Start Scan]  [Stop]  [Export Report]      FileGuard v1.0  │
├─────────────────────────────────────────────────────────────┤
│ ┌──────────┬──────────┬──────────┬──────────┐ ┌───────────┐ │
│ │Suspicious│High Tgt  │Potential │Low Risk  │ │           │ │
│ │Code  (5) │Files (12)│Risk  (34)│    (156) │ │  FILE     │ │
│ ├──────────┼──────────┼──────────┼──────────┤ │  DETAILS  │ │
│ │ 📄 file1 │ 📄 file5 │ 📄 file8 │ 📄 fileX │ │           │ │
│ │ 📄 file2 │ 📄 file6 │ 📄 file9 │ 📄 fileY │ │  Attack:  │ │
│ │ 📄 file3 │ 📄 file7 │ 📄 fileA │ 📄 fileZ │ │  Method   │ │
│ │ 📄 file4 │          │          │          │ │           │ │
│ │ ▼ scroll │ ▼ scroll │ ▼ scroll │ ▼ scroll │ │  Port:    │ │
│ └──────────┴──────────┴──────────┴──────────┘ │  Info     │ │
│                                                │           │ │
│ [Event Logs] [Registry] [Timestamps] [Cache]  │  Response │ │
│                                                │  Steps    │ │
├───────────────────────────────────────────────┤           │ │
│  Information Panel                             └───────────┘ │
│  - Selected file analysis results                           │
│  - Code preview with highlighting                           │
│  - BMC Tool link when relevant                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 7: Integration & Polish (Week 8)

**Goal**: Connect all components, optimize performance

### Tasks:
- [x] Connect GUI to scanning engine
- [x] Implement threading for non-blocking scans
- [x] Add scan progress and ETA
- [x] Implement report export (HTML, JSON, CSV)
- [x] Performance optimization
- [x] Memory management for large scans
- [x] Add update mechanism for YARA rules
- [x] Create installer/packager

---

## Phase 8: Testing & Documentation (Week 9)

**Goal**: Ensure reliability and usability

### Tasks:
- [x] Unit tests for all modules
- [x] Integration tests
- [x] Test with known malware samples (in VM!)
- [x] Performance benchmarking
- [x] Write user documentation
- [x] Create README with setup instructions

---

## Phase 9: Threat Intelligence Integration (Week 10)

**Goal**: Add enterprise-grade threat intelligence capabilities

### Tasks:
- [x] Implement MITRE ATT&CK mapping module
- [x] Create ATT&CK technique database
- [x] Add ATT&CK IDs to all detection patterns
- [x] Implement Sigma rule parser and engine
- [x] Create default Sigma rules for Windows logs
- [x] Integrate Sigma with EventLogAnalyzer
- [x] Implement STIX 2.1 exporter
- [x] Create TAXII client for publishing
- [x] Add ATT&CK Navigator layer export
- [x] Update GUI with export options

---

## Phase 10: Packaging & Distribution (Week 11)

**Goal**: Create standalone Windows executable

### Tasks:
- [x] Configure PyInstaller spec file
- [x] Bundle all dependencies
- [x] Create installer with NSIS (optional)
- [x] Test on clean Windows VM
- [x] Submit to AV vendors for whitelisting
- [x] Code signing (recommended)

### Build Commands:
```bash
python build/build.py --clean
python build/build.py --onefile
```

---

## Dependencies (requirements.txt)

```
# Core
yara-python>=4.3.0
pefile>=2023.2.7
python-magic-bin>=0.4.14
watchdog>=3.0.0
customtkinter>=5.2.0
pillow>=10.0.0
pyyaml>=6.0
requests>=2.31.0
psutil>=5.9.0
python-evtx>=0.7.4
pywin32>=306
regipy>=4.0.0
construct>=2.10.0
rich>=13.0.0
tqdm>=4.66.0

# Threat Intelligence
stix2>=3.0.1
taxii2-client>=2.3.0
```

---

## Success Metrics

- [ ] Scans 100GB in < 30 minutes
- [ ] <5% false positive rate
- [ ] Detects EICAR test file correctly
- [ ] Honeypot alerts within 1 second
- [ ] GUI responsive during scan
- [ ] Memory usage < 500MB during full scan