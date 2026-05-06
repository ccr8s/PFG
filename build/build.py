#!/usr/bin/env python3
"""
FileGuard Build Script.

Usage:
    python build/build.py [--clean] [--onefile] [--gui-only]
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = ROOT / "build"
DIST_DIR = ROOT / "dist"


def clean() -> None:
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

    for pyc in ROOT.rglob("*.pyc"):
        pyc.unlink()

    print("Clean complete.\n")


def run_tests() -> None:
    """Run test suite before building."""
    print("Running tests...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        cwd=ROOT,
    )
    if result.returncode != 0:
        print("Tests failed! Fix issues before building.")
        sys.exit(1)
    print("Tests passed.\n")


def build_exe(
    onefile: bool = False,
    gui_only: bool = False,
) -> None:
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


def create_installer() -> None:
    """Create installer using NSIS (optional)."""
    nsis_script = BUILD_DIR / "installer.nsi"
    if not nsis_script.exists():
        print("NSIS script not found, skipping installer creation.")
        return

    print("Creating installer...")
    result = subprocess.run(["makensis", str(nsis_script)])

    if result.returncode == 0:
        print("Installer created successfully!")


def main() -> None:
    """Build entry point."""
    parser = argparse.ArgumentParser(
        description="Build FileGuard executable"
    )
    parser.add_argument(
        "--clean", action="store_true", help="Clean before build"
    )
    parser.add_argument(
        "--onefile", action="store_true",
        help="Create single file executable",
    )
    parser.add_argument(
        "--gui-only", action="store_true",
        help="GUI mode only (no console)",
    )
    parser.add_argument(
        "--skip-tests", action="store_true",
        help="Skip running tests",
    )
    parser.add_argument(
        "--installer", action="store_true",
        help="Create installer after build",
    )

    args = parser.parse_args()

    if args.clean:
        clean()

    if not args.skip_tests:
        run_tests()

    build_exe(onefile=args.onefile, gui_only=args.gui_only)

    if args.installer:
        create_installer()

    print("\n" + "=" * 50)
    print("BUILD SUCCESSFUL")
    print("=" * 50)
    print(f"\nTo run: {DIST_DIR / 'FileGuard' / 'FileGuard.exe'}")
    print("\nDistribution checklist:")
    print("  [ ] Test on clean Windows machine")
    print("  [ ] Verify all features work")
    print("  [ ] Check antivirus false positives")
    print("  [ ] Sign executable (recommended)")


if __name__ == "__main__":
    main()
