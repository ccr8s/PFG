# TASK: Package FileGuard as Windows Executable

## Phase: 10 (Final)
## Task Name: Create Standalone Windows Executable
## Description:
Package FileGuard as a standalone .exe using PyInstaller. Creates both CLI and GUI executables that run without Python installed.

---

## Prerequisites:
- All features complete and tested
- Virtual environment with all dependencies
- Windows machine for building (or cross-compile setup)

---

## File 1: `build/fileguard.spec` (PyInstaller Spec)

```python
# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for FileGuard.

Build commands:
    pyinstaller build/fileguard.spec --clean
    
Output:
    dist/FileGuard/FileGuard.exe (GUI + CLI)
"""

import sys
from pathlib import Path

block_cipher = None

# Project root
ROOT = Path(SPECPATH).parent

# Collect data files
datas = [
    # Configuration files
    (str(ROOT / 'config'), 'config'),
    
    # YARA rules
    (str(ROOT / 'rules'), 'rules'),
    
    # Data files (hashes, MITRE ATT&CK)
    (str(ROOT / 'data'), 'data'),
    
    # GUI assets if any
    # (str(ROOT / 'gui' / 'assets'), 'gui/assets'),
]

# Hidden imports that PyInstaller might miss
hiddenimports = [
    'yara',
    'pefile',
    'watchdog',
    'watchdog.observers',
    'watchdog.events',
    'customtkinter',
    'stix2',
    'taxii2client',
    'win32api',
    'win32con',
    'win32evtlog',
    'win32security',
    'pywintypes',
    'Evtx',
    'regipy',
    'PIL',
    'PIL._tkinter_finder',
]

# Binaries (DLLs) to include
binaries = []

# Analysis
a = Analysis(
    [str(ROOT / 'main.py')],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'jupyter',
        'notebook',
        'pytest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Filter out unnecessary files to reduce size
a.datas = [d for d in a.datas if not d[0].startswith('tcl')]
a.datas = [d for d in a.datas if 'test' not in d[0].lower()]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='FileGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # Compress with UPX
    console=True,  # Set False for GUI-only
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'assets' / 'icon.ico') if (ROOT / 'assets' / 'icon.ico').exists() else None,
    version=str(ROOT / 'build' / 'version_info.txt') if (ROOT / 'build' / 'version_info.txt').exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='FileGuard',
)
```

---

## File 2: `build/version_info.txt` (Windows Version Info)

```
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'FileGuard'),
            StringStruct(u'FileDescription', u'FileGuard Security Scanner'),
            StringStruct(u'FileVersion', u'1.0.0.0'),
            StringStruct(u'InternalName', u'FileGuard'),
            StringStruct(u'LegalCopyright', u'Copyright (c) 2024'),
            StringStruct(u'OriginalFilename', u'FileGuard.exe'),
            StringStruct(u'ProductName', u'FileGuard Security Scanner'),
            StringStruct(u'ProductVersion', u'1.0.0.0')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
```

---

## File 3: `build/build.py` (Build Script)

```python
#!/usr/bin/env python3
"""
FileGuard Build Script

Usage:
    python build/build.py [--clean] [--onefile] [--gui-only]
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
BUILD_DIR = ROOT / "build"
DIST_DIR = ROOT / "dist"


def clean():
    """Clean build artifacts."""
    print("Cleaning build artifacts...")
    
    dirs_to_clean = [
        ROOT / "build" / "FileGuard",
        ROOT / "dist",
        ROOT / "__pycache__",
    ]
    
    for d in dirs_to_clean:
        if d.exists():
            shutil.rmtree(d)
            print(f"  Removed: {d}")
    
    # Remove .pyc files
    for pyc in ROOT.rglob("*.pyc"):
        pyc.unlink()
    
    print("Clean complete.\n")


def run_tests():
    """Run test suite before building."""
    print("Running tests...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        cwd=ROOT
    )
    if result.returncode != 0:
        print("Tests failed! Fix issues before building.")
        sys.exit(1)
    print("Tests passed.\n")


def build_exe(onefile: bool = False, gui_only: bool = False):
    """Build the executable."""
    print("Building FileGuard executable...")
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
    ]
    
    if onefile:
        cmd.append("--onefile")
        cmd.append("--name=FileGuard")
        cmd.append(str(ROOT / "main.py"))
        
        # Add data files for onefile
        cmd.extend(["--add-data", f"{ROOT / 'config'};config"])
        cmd.extend(["--add-data", f"{ROOT / 'rules'};rules"])
        cmd.extend(["--add-data", f"{ROOT / 'data'};data"])
    else:
        cmd.append(str(BUILD_DIR / "fileguard.spec"))
    
    if gui_only:
        cmd.append("--noconsole")
    
    # Add icon if exists
    icon_path = ROOT / "assets" / "icon.ico"
    if icon_path.exists():
        cmd.extend(["--icon", str(icon_path)])
    
    print(f"Running: {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, cwd=ROOT)
    
    if result.returncode != 0:
        print("Build failed!")
        sys.exit(1)
    
    print("\nBuild complete!")
    print(f"Executable location: {DIST_DIR / 'FileGuard'}")


def create_installer():
    """Create installer using NSIS (optional)."""
    nsis_script = BUILD_DIR / "installer.nsi"
    if not nsis_script.exists():
        print("NSIS script not found, skipping installer creation.")
        return
    
    print("Creating installer...")
    result = subprocess.run(["makensis", str(nsis_script)])
    
    if result.returncode == 0:
        print("Installer created successfully!")


def main():
    parser = argparse.ArgumentParser(description="Build FileGuard executable")
    parser.add_argument("--clean", action="store_true", help="Clean before build")
    parser.add_argument("--onefile", action="store_true", help="Create single file executable")
    parser.add_argument("--gui-only", action="store_true", help="GUI mode only (no console)")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--installer", action="store_true", help="Create installer after build")
    
    args = parser.parse_args()
    
    if args.clean:
        clean()
    
    if not args.skip_tests:
        run_tests()
    
    build_exe(onefile=args.onefile, gui_only=args.gui_only)
    
    if args.installer:
        create_installer()
    
    print("\n" + "="*50)
    print("BUILD SUCCESSFUL")
    print("="*50)
    print(f"\nTo run: {DIST_DIR / 'FileGuard' / 'FileGuard.exe'}")
    print("\nDistribution checklist:")
    print("  [ ] Test on clean Windows machine")
    print("  [ ] Verify all features work")
    print("  [ ] Check antivirus false positives")
    print("  [ ] Sign executable (recommended)")


if __name__ == "__main__":
    main()
```

---

## File 4: `build/requirements-build.txt`

```
# Build dependencies
pyinstaller>=6.0.0
pywin32>=306
pillow>=10.0.0

# Optional: For creating installers
# nsis (install separately)

# Optional: Code signing
# signtool (Windows SDK)
```

---

## Build Commands

```bash
# Install build dependencies
pip install -r build/requirements-build.txt

# Development build (folder with all files)
python build/build.py

# Clean build
python build/build.py --clean

# Single file executable (slower to start but easier to distribute)
python build/build.py --onefile

# GUI-only build (no console window)
python build/build.py --gui-only

# Full release build
python build/build.py --clean --onefile --installer
```

---

## Running the Built Executable

```powershell
# After building, the exe is in dist/FileGuard/

# Run scan from command line
.\dist\FileGuard\FileGuard.exe scan C:\Users\YourName\Downloads

# Launch GUI
.\dist\FileGuard\FileGuard.exe --gui

# Full system scan
.\dist\FileGuard\FileGuard.exe scan C:\ --deep

# Run forensics
.\dist\FileGuard\FileGuard.exe forensics --all
```

---

## Distribution Checklist

Before distributing:

- [ ] Test on clean Windows 10/11 VM without Python
- [ ] Verify all scan features work
- [ ] Verify GUI launches correctly
- [ ] Check YARA rules are bundled
- [ ] Check config files are bundled
- [ ] Test with Windows Defender (may flag as suspicious)
- [ ] Submit to VirusTotal to check false positives
- [ ] Consider code signing certificate ($100-400/year)
- [ ] Create SHA256 hash of final exe for verification

---

## Common Issues & Fixes

**Issue: Missing DLL errors**
```python
# Add to hiddenimports in spec file
hiddenimports += ['win32timezone']
```

**Issue: YARA rules not found**
```python
# Ensure data files are copied
datas += [(str(ROOT / 'rules'), 'rules')]
```

**Issue: Antivirus false positive**
- Submit to AV vendors for whitelisting
- Consider signing the executable
- Use `--onefile` which sometimes helps

**Issue: Large executable size**
```bash
# Use UPX compression (enabled by default in spec)
# Exclude unnecessary packages in spec file
```

---

## File Structure After Build

```
dist/
└── FileGuard/
    ├── FileGuard.exe          # Main executable
    ├── python311.dll          # Python runtime
    ├── config/                # Configuration files
    │   ├── settings.yaml
    │   ├── signatures.yaml
    │   └── taxii_servers.yaml
    ├── rules/                 # Detection rules
    │   ├── yara/
    │   └── sigma/
    ├── data/                  # Data files
    │   ├── mitre_attack.json
    │   └── known_hashes.db
    └── [various .dll files]
```