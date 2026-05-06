"""Tests for utils.hex_editor.

Covers the resolution priority chain (env > user_prefs > yaml >
autodetect), launching via subprocess.Popen with a list argv (no
shell), file-path validation, and persistence of the user's editor
choice through ``data/user_prefs.json``.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from utils import hex_editor


@pytest.fixture
def tmp_prefs(tmp_path, monkeypatch):
    """Redirect user_prefs.json into tmp_path."""
    fake = tmp_path / "user_prefs.json"
    monkeypatch.setattr(hex_editor, "_USER_PREFS_PATH", fake)
    return fake


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    monkeypatch.delenv(hex_editor._ENV_VAR, raising=False)


# ---------------------------------------------------------------------------
# user_prefs round-trip
# ---------------------------------------------------------------------------
def test_save_and_load_user_editor_path(tmp_prefs, tmp_path):
    fake_exe = tmp_path / "MyHex.exe"
    fake_exe.write_bytes(b"MZ")
    hex_editor.save_user_editor_path(fake_exe)

    assert tmp_prefs.exists()
    payload = json.loads(tmp_prefs.read_text())
    assert payload["hex_editor_path"] == str(fake_exe)

    loaded = hex_editor.load_user_editor_path()
    assert loaded == fake_exe


def test_load_user_editor_path_returns_none_for_missing_file(
    tmp_prefs, tmp_path
):
    """A pinned path that no longer exists must not be returned."""
    tmp_prefs.write_text(
        json.dumps({"hex_editor_path": str(tmp_path / "ghost.exe")})
    )
    assert hex_editor.load_user_editor_path() is None


def test_save_preserves_other_keys(tmp_prefs, tmp_path):
    """Writing the editor path must not nuke unrelated user settings."""
    tmp_prefs.write_text(json.dumps({"unrelated": "keep me"}))
    fake = tmp_path / "ed.exe"
    fake.write_bytes(b"MZ")
    hex_editor.save_user_editor_path(fake)
    payload = json.loads(tmp_prefs.read_text())
    assert payload["unrelated"] == "keep me"
    assert payload["hex_editor_path"] == str(fake)


# ---------------------------------------------------------------------------
# Resolution priority
# ---------------------------------------------------------------------------
def test_find_editor_prefers_env_var(tmp_prefs, tmp_path, monkeypatch):
    env_exe = tmp_path / "env.exe"
    env_exe.write_bytes(b"MZ")
    pref_exe = tmp_path / "pref.exe"
    pref_exe.write_bytes(b"MZ")

    monkeypatch.setenv(hex_editor._ENV_VAR, str(env_exe))
    hex_editor.save_user_editor_path(pref_exe)

    with patch.object(hex_editor, "_from_yaml", return_value=None), \
         patch.object(hex_editor, "_autodetect_any", return_value=None):
        assert hex_editor.find_editor() == env_exe


def test_find_editor_falls_through_to_user_prefs(tmp_prefs, tmp_path):
    pref_exe = tmp_path / "pref.exe"
    pref_exe.write_bytes(b"MZ")
    hex_editor.save_user_editor_path(pref_exe)

    with patch.object(hex_editor, "_from_yaml", return_value=None), \
         patch.object(hex_editor, "_autodetect_any", return_value=None):
        assert hex_editor.find_editor() == pref_exe


def test_find_editor_falls_through_to_yaml(tmp_prefs, tmp_path):
    yaml_exe = tmp_path / "yaml.exe"
    yaml_exe.write_bytes(b"MZ")

    with patch.object(hex_editor, "_from_yaml", return_value=yaml_exe), \
         patch.object(hex_editor, "_autodetect_any", return_value=None):
        assert hex_editor.find_editor() == yaml_exe


def test_find_editor_falls_through_to_autodetect(tmp_prefs, tmp_path):
    detected = tmp_path / "detected.exe"
    detected.write_bytes(b"MZ")

    with patch.object(hex_editor, "_from_yaml", return_value=None), \
         patch.object(hex_editor, "_autodetect_any", return_value=detected):
        assert hex_editor.find_editor() == detected


def test_find_editor_returns_none_when_nothing_available(tmp_prefs):
    with patch.object(hex_editor, "_from_yaml", return_value=None), \
         patch.object(hex_editor, "_autodetect_any", return_value=None):
        assert hex_editor.find_editor() is None


def test_env_var_pointing_to_missing_file_is_ignored(
    tmp_prefs, tmp_path, monkeypatch
):
    monkeypatch.setenv(hex_editor._ENV_VAR, str(tmp_path / "nope.exe"))
    with patch.object(hex_editor, "_from_yaml", return_value=None), \
         patch.object(hex_editor, "_autodetect_any", return_value=None):
        assert hex_editor.find_editor() is None


# ---------------------------------------------------------------------------
# open_in_hex_editor: subprocess invocation
# ---------------------------------------------------------------------------
def test_open_in_hex_editor_uses_list_argv_no_shell(tmp_path):
    """Critical security guarantee: never shell=True, always list argv."""
    target = tmp_path / "suspicious.bin"
    target.write_bytes(b"\x00\x01\x02")
    editor = tmp_path / "ed.exe"
    editor.write_bytes(b"MZ")

    with patch("utils.hex_editor.subprocess.Popen") as popen:
        ok, msg = hex_editor.open_in_hex_editor(target, editor=editor)

    assert ok is True
    popen.assert_called_once()
    args, kwargs = popen.call_args
    argv = args[0]
    assert isinstance(argv, list)
    assert argv[0] == str(editor)
    assert argv[1] == str(target.resolve())
    assert kwargs.get("shell", False) is False


def test_open_rejects_missing_file(tmp_path):
    editor = tmp_path / "ed.exe"
    editor.write_bytes(b"MZ")
    ok, msg = hex_editor.open_in_hex_editor(
        tmp_path / "ghost.bin", editor=editor
    )
    assert ok is False
    assert "does not exist" in msg


def test_open_rejects_directory(tmp_path):
    editor = tmp_path / "ed.exe"
    editor.write_bytes(b"MZ")
    ok, msg = hex_editor.open_in_hex_editor(tmp_path, editor=editor)
    assert ok is False
    assert "Not a regular file" in msg


def test_open_rejects_missing_editor(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    ok, msg = hex_editor.open_in_hex_editor(
        target, editor=tmp_path / "ghost.exe"
    )
    assert ok is False
    assert "Editor not found" in msg


def test_open_returns_friendly_error_when_no_editor_at_all(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    with patch.object(hex_editor, "find_editor", return_value=None):
        ok, msg = hex_editor.open_in_hex_editor(target)
    assert ok is False
    assert "No hex editor configured" in msg


def test_open_handles_popen_oserror(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"x")
    editor = tmp_path / "ed.exe"
    editor.write_bytes(b"MZ")
    with patch(
        "utils.hex_editor.subprocess.Popen",
        side_effect=OSError("blocked by AV"),
    ):
        ok, msg = hex_editor.open_in_hex_editor(target, editor=editor)
    assert ok is False
    assert "blocked by AV" in msg


# ---------------------------------------------------------------------------
# Autodetect
# ---------------------------------------------------------------------------
def test_available_editors_returns_one_record_per_known(tmp_prefs):
    """Independent of what's installed, the list length matches registry."""
    records = hex_editor.available_editors()
    assert len(records) == len(hex_editor.KNOWN_EDITORS)
    names = {r["name"] for r in records}
    assert {"HxD", "ImHex", "010 Editor"} <= names
    for r in records:
        assert "download_url" in r
        assert "blurb" in r
        assert "path" in r  # may be None if not installed


def test_autodetect_uses_program_files_glob(tmp_path, monkeypatch):
    """Editor under %ProgramFiles%/HxD/HxD.exe should be detected."""
    pf = tmp_path / "Program Files"
    (pf / "HxD").mkdir(parents=True)
    fake = pf / "HxD" / "HxD.exe"
    fake.write_bytes(b"MZ")

    monkeypatch.setenv("ProgramFiles", str(pf))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.delenv("ProgramW6432", raising=False)
    with patch("utils.hex_editor.shutil.which", return_value=None):
        spec = next(s for s in hex_editor.KNOWN_EDITORS if s.name == "HxD")
        assert hex_editor._autodetect(spec) == fake


def test_autodetect_falls_back_to_path(tmp_path, monkeypatch):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.delenv("ProgramW6432", raising=False)
    fake_path_exe = tmp_path / "HxD.exe"
    fake_path_exe.write_bytes(b"MZ")
    with patch(
        "utils.hex_editor.shutil.which",
        side_effect=lambda name: (
            str(fake_path_exe) if name == "HxD.exe" else None
        ),
    ):
        spec = next(s for s in hex_editor.KNOWN_EDITORS if s.name == "HxD")
        assert hex_editor._autodetect(spec) == fake_path_exe
