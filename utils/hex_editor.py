"""External hex-editor integration.

Resolves which hex editor to launch using a priority chain:

    1. Environment variable ``FILEGUARD_HEX_EDITOR``
    2. ``data/user_prefs.json`` -> ``hex_editor_path``
    3. ``config/settings.yaml`` -> ``tools.hex_editor_path``
    4. Auto-detect a known editor (HxD, ImHex, 010 Editor) by checking
       common install paths and the system ``PATH``.

Opening a file in a hex editor is safe on the host: the editor reads
bytes; it does not execute the file, render scripts, or run macros.
We launch the editor with ``subprocess.Popen`` using a list argv (no
shell) so paths with spaces or quotes can't be misinterpreted.

This module is Windows-first because the bundled editor list is
Windows-centric, but ``open_in_hex_editor`` works on any platform once
an editor path is configured.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_USER_PREFS_PATH = _PROJECT_ROOT / "data" / "user_prefs.json"
_USER_PREFS_KEY = "hex_editor_path"
_ENV_VAR = "FILEGUARD_HEX_EDITOR"


@dataclass(frozen=True)
class EditorSpec:
    """Static descriptor for a known hex editor."""

    name: str
    exe_names: Tuple[str, ...]
    install_globs: Tuple[str, ...]
    download_url: str
    blurb: str


def _expand_program_files() -> List[Path]:
    """Common roots where editors may be installed.

    Covers system-wide installs (``ProgramFiles*``) and per-user
    installs done without admin (``%LOCALAPPDATA%\\Programs``,
    ``%LOCALAPPDATA%`` directly). HxD in particular can end up in
    any of these depending on installer mode.
    """
    candidates: List[Path] = []
    for env_var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        value = os.environ.get(env_var)
        if value:
            candidates.append(Path(value))
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        local = Path(local_appdata)
        candidates.append(local / "Programs")
        candidates.append(local)
    return candidates


KNOWN_EDITORS: Tuple[EditorSpec, ...] = (
    EditorSpec(
        name="HxD",
        exe_names=("HxD.exe", "HxD32.exe"),
        install_globs=("HxD/HxD.exe", "HxD Hex Editor/HxD.exe"),
        download_url="https://mh-nexus.de/en/hxd/",
        blurb="Free, fast, and the most popular Windows hex editor.",
    ),
    EditorSpec(
        name="ImHex",
        exe_names=("imhex.exe", "imhex-gui.exe", "imhex"),
        install_globs=("ImHex/imhex.exe",),
        download_url="https://imhex.werwolv.net/",
        blurb="Free and open-source, cross-platform, with a pattern language.",
    ),
    EditorSpec(
        name="010 Editor",
        exe_names=("010Editor.exe",),
        install_globs=("010 Editor/010Editor.exe",),
        download_url="https://www.sweetscape.com/010editor/",
        blurb="Paid, commercial-grade, with binary templates and scripting.",
    ),
)


# ---------------------------------------------------------------------------
# User-prefs persistence
# ---------------------------------------------------------------------------
def _load_user_prefs() -> Dict[str, Any]:
    if not _USER_PREFS_PATH.exists():
        return {}
    try:
        with open(_USER_PREFS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read %s: %s", _USER_PREFS_PATH, exc)
        return {}


def _write_user_prefs(prefs: Dict[str, Any]) -> None:
    _USER_PREFS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_USER_PREFS_PATH, "w", encoding="utf-8") as f:
        json.dump(prefs, f, indent=2, sort_keys=True)


def load_user_editor_path() -> Optional[Path]:
    """Return the user-pinned editor path, if any."""
    raw = _load_user_prefs().get(_USER_PREFS_KEY)
    if not raw:
        return None
    path = Path(str(raw))
    return path if path.exists() else None


def save_user_editor_path(path: Path) -> None:
    """Persist a custom editor path to ``data/user_prefs.json``."""
    prefs = _load_user_prefs()
    prefs[_USER_PREFS_KEY] = str(path)
    _write_user_prefs(prefs)
    logger.info("Saved hex editor preference: %s", path)


# ---------------------------------------------------------------------------
# Resolution chain
# ---------------------------------------------------------------------------
def _from_env() -> Optional[Path]:
    raw = os.environ.get(_ENV_VAR)
    if not raw:
        return None
    path = Path(raw)
    if not path.exists():
        logger.warning("%s points to non-existent path: %s", _ENV_VAR, raw)
        return None
    return path


def _from_yaml() -> Optional[Path]:
    try:
        from core.base import ConfigManager
        cfg = ConfigManager()
        raw = cfg.get("tools.hex_editor_path", "")
    except Exception:
        return None
    if not raw:
        return None
    path = Path(str(raw))
    return path if path.exists() else None


def _autodetect(spec: EditorSpec) -> Optional[Path]:
    """Locate one editor via known install paths or PATH."""
    for root in _expand_program_files():
        for rel in spec.install_globs:
            candidate = root / rel
            if candidate.exists():
                return candidate
    for exe in spec.exe_names:
        located = shutil.which(exe)
        if located:
            return Path(located)
    return None


def _autodetect_any() -> Optional[Path]:
    for spec in KNOWN_EDITORS:
        found = _autodetect(spec)
        if found is not None:
            return found
    return None


def find_editor() -> Optional[Path]:
    """Resolve which hex editor to use.

    Order: env var, user prefs, settings.yaml, autodetect. Returns the
    first existing path or ``None`` if nothing was configured or found.
    """
    for resolver, label in (
        (_from_env, "env"),
        (load_user_editor_path, "user_prefs"),
        (_from_yaml, "settings.yaml"),
        (_autodetect_any, "autodetect"),
    ):
        path = resolver()
        if path is not None:
            logger.debug("Hex editor resolved via %s: %s", label, path)
            return path
    return None


def available_editors() -> List[Dict[str, Any]]:
    """Return one record per known editor for the picker dialog.

    Each record contains: ``name``, ``path`` (Optional[Path]),
    ``download_url``, and ``blurb``. ``path`` is set when the editor
    was located on the system, otherwise ``None``.
    """
    return [
        {
            "name": spec.name,
            "path": _autodetect(spec),
            "download_url": spec.download_url,
            "blurb": spec.blurb,
        }
        for spec in KNOWN_EDITORS
    ]


# ---------------------------------------------------------------------------
# Launching
# ---------------------------------------------------------------------------
def open_in_hex_editor(
    file_path: Path, editor: Optional[Path] = None
) -> Tuple[bool, str]:
    """Launch a hex editor on ``file_path``.

    The editor process is spawned via ``subprocess.Popen`` with a list
    argv (no shell), so spaces and special characters in the path are
    handled correctly and command injection is impossible.

    Args:
        file_path: file to open.
        editor: optional explicit editor path. If ``None``,
            :func:`find_editor` is used.

    Returns:
        Tuple of ``(ok, message)``. ``ok`` is True only if the editor
        process was successfully spawned. The message is human-readable
        and safe to surface in the GUI.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return False, f"File does not exist: {file_path}"
    if not file_path.is_file():
        return False, f"Not a regular file: {file_path}"

    if editor is None:
        editor = find_editor()
    if editor is None:
        return (
            False,
            "No hex editor configured. Install one of HxD, ImHex, or "
            "010 Editor, or pick a custom executable.",
        )
    editor = Path(editor)
    if not editor.exists():
        return False, f"Editor not found at: {editor}"

    try:
        resolved_file = file_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return False, f"Could not resolve file path: {exc}"

    try:
        subprocess.Popen(
            [str(editor), str(resolved_file)],
            shell=False,
            close_fds=True,
        )
    except OSError as exc:
        logger.exception("Failed to launch hex editor")
        return False, f"Could not launch editor: {exc}"

    logger.info("Opened %s in %s", resolved_file, editor)
    return True, f"Opened in {editor.name}"


__all__ = [
    "EditorSpec",
    "KNOWN_EDITORS",
    "available_editors",
    "find_editor",
    "load_user_editor_path",
    "open_in_hex_editor",
    "save_user_editor_path",
]
