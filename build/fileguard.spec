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
    upx=True,
    console=True,
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
