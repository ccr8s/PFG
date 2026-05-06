# FileGuard

> Windows security scanner, forensic analyzer, and honeypot — in one tool.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-orange)](#)

FileGuard scans for suspicious files, hunts for indicators of compromise in Windows artifacts, and deploys honeypot decoys that alert on touch. Detections are mapped to **MITRE ATT&CK** and exportable as **STIX 2.1** for sharing through TAXII.

---

## Highlights

| Area | What it does |
|---|---|
| **Scan engine** | Multi-threaded recursive scanner with 7 pluggable detectors |
| **Detectors** | YARA, pattern, entropy, PE structure, packer, hash, alternate data streams |
| **Forensics** | Windows Event Logs, Registry persistence, timestomp, Prefetch, Amcache/Shimcache, RDP bitmap cache |
| **Honeypot** | Realistic decoy files in Desktop / Documents / Downloads with watchdog-based real-time alerts |
| **Threat intel** | MITRE ATT&CK mapping, Sigma rule engine, STIX 2.1 export, TAXII 2.1 client |
| **Interfaces** | CLI (Rich-formatted) and GUI (CustomTkinter dark theme) |
| **Reports** | HTML, JSON, CSV, STIX 2.1 |
| **Risk model** | 4 tiers (`SUSPICIOUS_CODE` / `HIGH_TARGET` / `POTENTIAL_RISK` / `LOW_RISK`) with location-based score modifiers |

---

## Requirements

- Python 3.11+
- Windows 10 or 11 (some forensic modules use Windows-specific APIs)

---

## Installation

```powershell
git clone https://github.com/ccr8s/PFG.git fileguard
cd fileguard

python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Optional, for a development session with the safety sandbox enabled:

```powershell
.\dev_setup.ps1
```

This sets `FILEGUARD_TESTING=true`, `FILEGUARD_READONLY=true`, and points the sandbox at `C:\FileGuardTest\mock_system`. See [Safety](#safety) below.

---

## Quick Start

### Scan

```powershell
# Scan a directory
python main.py scan C:\Users\YourName\Downloads

# Deep scan with JSON output
python main.py scan C:\Users\YourName\Documents --deep --output report.json

# Multi-format export
python main.py scan . --export-html report.html --export-stix findings.json
```

### Forensics

```powershell
# Run every forensic module
python main.py forensics --all

# Pick specific checks
python main.py forensics --event-logs --registry --timestomps
```

### Honeypot

```powershell
python main.py honeypot --deploy     # drop decoys in user folders
python main.py honeypot --monitor    # watch for access (Ctrl+C to stop)
python main.py honeypot --status     # show current state
python main.py honeypot --remove     # clean up
```

### GUI

```powershell
python main.py --gui
```

The bottom panel hosts a tabbed view: an `Activity` log, one tab per forensic tool (Event Logs, Registry, Timestamps, Prefetch, Amcache, Bitmap Cache), a `Honeypot` tab (tutorial + Deploy / Remove / Choose-decoys / **Start monitoring** controls), and a separate `Honeypot Alerts` tab. The alerts tab carries an unread counter in its title and pulses when new alerts arrive while you're on another tab; switching to it clears the indicator. Each forensic tab carries its own `Run` button, so output from one tool no longer overwrites another's. All clickable buttons show the pointer-finger cursor on hover.

#### Honeypot monitoring caveat

The Honeypot tab uses [`watchdog`](https://pypi.org/project/watchdog/) under the hood, which on Windows is implemented over `ReadDirectoryChangesW`. That API only fires for **modify / create / delete / rename** events - simply opening a decoy to read it is invisible at this layer (you'd need ETW or a kernel mini-filter for read detection). In practice this is fine: ransomware encrypts (modify), wipers delete, and infostealers usually copy then delete - all of which fire alerts. A user double-clicking and just closing without saving will not.

### Configuration

```powershell
python main.py config --show
python main.py config --set scanner.threads 8
python main.py config --set-virustotal-key <KEY>     # written to gitignored secrets file
```

---

## Safety

This tool reads sensitive areas of the filesystem and can deploy real decoys. Every write goes through `utils/safety.py`, which enforces three layers:

1. **Path safety** — writes are rejected for protected paths (`C:\Windows`, `C:\Program Files`, AppData, etc.).
2. **Testing mode** — when on, scans are restricted to the sandbox (`C:\FileGuardTest\mock_system`) and the project directory.
3. **Read-only mode** — when on, `safe_write` / `safe_delete` are silent no-ops. Reads are always allowed; honeypot deploy/remove opts in explicitly via `force=True`, so it still works.

### Defaults

| Setting | Default | What it does |
|---|---|---|
| `testing_mode` | `false` | Real-path scanning works out of the box. Set `true` to hard-restrict scans to the sandbox/project dir during development. |
| `read_only` | `true` | Belt-and-suspenders against accidental writes. Does **not** block scanning. Honeypot deploy still works because it passes `force=True`. |

Resolution order (highest priority first):

```
ENV vars  →  config/settings.yaml  →  built-in defaults
```

Relevant env vars: `FILEGUARD_TESTING`, `FILEGUARD_READONLY`, `FILEGUARD_SANDBOX`.

### Reverting to sandbox-only mode

If you want to hard-restrict scans to `C:\FileGuardTest\mock_system` and the project directory (e.g. for development on this codebase):

```powershell
$env:FILEGUARD_TESTING="true"
python main.py --gui
```

Or flip `safety.testing_mode: true` in `config/settings.yaml` to make it the persistent default.

---

## Reviewing flagged files safely

When the GUI flags a file, **don't** just open it. Even a "harmless" double-click can trigger Explorer preview handlers that parse the file with the same buggy code that made it suspicious in the first place. FileGuard ships three built-in alternatives:

### Preview (safe) — always available

The detail panel's **Preview (safe)** button opens a read-only window with three tabs:

- **Hex** — first 4 KB rendered as a classic offset/hex/ASCII dump.
- **Strings** — extracted printable runs (ASCII + UTF-16 LE), deduplicated.
- **PE Headers** — only shown for PE files; lists machine, sections (with entropy), and imports, with notable Windows API calls highlighted.

This view never invokes a Windows shell handler, never spawns a subprocess on the file, and never decodes the bytes into objects with side effects. The worst it can do is render garbled text.

### Open in hex editor — for deeper byte-level inspection

The blue **Open in hex editor** button hands the file off to a real hex editor running as a separate process. Opening a file in a hex editor is safe because hex editors only read bytes — they don't execute the file, run macros, or render scripts. Caveat: the editor opens the file with write permissions, so the file stays unchanged on disk *unless you click Save in the editor.*

FileGuard tries to find an editor in this order:

1. `FILEGUARD_HEX_EDITOR` environment variable
2. `data/user_prefs.json` (saved when you click *Browse for .exe...* in the picker)
3. `tools.hex_editor_path` in `config/settings.yaml`
4. Auto-detect [HxD](https://mh-nexus.de/en/hxd/), [ImHex](https://imhex.werwolv.net/), or [010 Editor](https://www.sweetscape.com/010editor/) at common install paths or on `PATH`

If none is found, a picker dialog offers Download buttons for each option plus a *Browse for .exe...* button so you can point at any other hex editor you already use.

### Detonate in Sandbox — Pro / Enterprise / Education only

The red **Detonate in Sandbox** button is for when you actually need to *run* the file to see what it does. It uses [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview), Microsoft's built-in disposable VM:

1. Copies the file into `data/sandbox_staging/<uuid>/` (gitignored).
2. Generates an `isolated.wsb` config that mounts the staging dir **read-only**, with networking, GPU, clipboard, printer, audio, and video redirection all **disabled**.
3. Launches `WindowsSandbox.exe` with **only** the `.wsb` path on the command line — the suspicious file is never passed as a process argument.

The sample lives on the host the whole time; the sandbox just gets a read-only view of the staging directory.

**Automatic cleanup** — staged copies don't accumulate on disk:

- While a detonation is active, the **Detonate in Sandbox** button changes to an amber **Close Sandbox** button. Clicking it force-terminates the sandbox VM and immediately deletes the staging dir.
- Closing the sandbox window with X is detected by a background watcher (polls `WindowsSandboxClient.exe` every 5 s); the staging dir is deleted automatically when the VM exits.
- Closing FileGuard itself with X (or Alt+F4) terminates any running sandbox and wipes every staging dir from this session before exiting.
- On startup FileGuard sweeps any staging dir older than 24 h, so a previous crash doesn't leave litter behind.

If the **Detonate** button is greyed out, Windows Sandbox isn't enabled. Turn it on via *Turn Windows features on or off → Windows Sandbox → reboot*. It requires Windows 10/11 Pro / Enterprise / Education with hardware virtualization enabled in BIOS/UEFI.

---

## Project Layout

```
fileguard/
├── main.py                    # entry point
├── cli.py                     # CLI (argparse + rich)
├── config/
│   ├── settings.yaml          # tracked, no secrets
│   ├── signatures.yaml        # detection patterns
│   ├── taxii_servers.yaml     # TAXII endpoints (no creds in this file)
│   └── secrets.yaml           # gitignored; created on first --set-*
├── core/                      # scanner, analyzer, classifier, models, db, ATT&CK mapper
├── detectors/                 # pattern / entropy / PE / packer / ADS / hash / YARA / sigma
├── forensics/                 # event_logs / registry / timestomp / prefetch / amcache / bitmap_cache
├── honeypot/                  # decoy_manager + monitor (watchdog)
├── gui/                       # CustomTkinter app + widgets
├── utils/                     # safety wrapper, file/hash utils, report generator, STIX, TAXII
├── rules/
│   ├── yara/
│   └── sigma/
├── data/
│   └── mitre_attack.json      # ATT&CK technique database
├── tests/                     # pytest suite (pytest + coverage)
├── build/                     # PyInstaller scripts
└── docs/                      # design + AI-pairing notes
```

---

## Detection Capabilities

| Engine | Method | Targets |
|---|---|---|
| YARA | Rule-based pattern matching | Malware signatures, tool artifacts |
| Pattern | Text/regex scanning | PowerShell, CMD, LOLBins, ransomware notes |
| Entropy | Statistical analysis | Packed / encrypted / obfuscated payloads |
| PE Analyzer | Header & import inspection | PE anomalies, suspicious IAT entries |
| Packer | Signature + heuristic | UPX, Themida, custom packers |
| ADS Scanner | NTFS alternate streams | Hidden payloads in `:streamname` |
| Hash | Local DB + optional VirusTotal | Previously identified malware |
| Sigma | Log-based rule matching | Event log tampering, suspicious process trees |

---

## Risk Scoring

Each finding contributes a severity (0–100). A file's score is the sum of its findings, capped at 100, plus a location modifier:

| Location pattern | Modifier |
|---|---|
| `\AppData\Local\Temp` | +15 |
| `\Windows\Temp` | +20 |
| `\Startup` / `\Start Menu\Programs\Startup` | +25 |
| `\ProgramData` | +10 |
| `\Downloads` | +10 |
| `\$Recycle.Bin` | +30 |

Score → tier:

| Score | Tier |
|---|---|
| ≥ 80 | `SUSPICIOUS_CODE` |
| 60 – 79 | `HIGH_TARGET` |
| 30 – 59 | `POTENTIAL_RISK` |
| 1 – 29 | `LOW_RISK` |
| 0 | `CLEAN` |

Thresholds are configurable under `risk:` in `settings.yaml`.

---

## Building a Standalone Executable

```powershell
pip install -r build/requirements-build.txt
python build/build.py --skip-tests          # dev build
python build/build.py --clean --onefile     # single-file release build
```

---

## Testing

```powershell
python -m pytest tests/ -v
python -m pytest tests/ --cov=. --cov-report=html
```

---

## Attribution

This project includes a subset of the MITRE ATT&CK framework in `data/mitre_attack.json`.

> ATT&CK&reg; is &copy; The MITRE Corporation. Used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

---

## License

[MIT](LICENSE) &mdash; do whatever you want with it. No warranty, no liability. Use at your own risk; you are responsible for ensuring you have authorization to scan whatever systems you point this at.
