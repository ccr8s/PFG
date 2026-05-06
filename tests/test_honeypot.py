"""Tests for honeypot.decoy_manager.DecoyManager.

Focus areas:
    * deploy_decoys actually writes files to disk under read-only
      mode (force=True is wired through safe_write).
    * deploy_decoys(decoys=[...]) only creates the requested files.
    * remove_all_decoys actually deletes files under read-only mode.
    * Manifest persistence round-trips correctly.

We point :data:`utils.safety` at the test's tmp_path via monkeypatch
so nothing leaves the test sandbox.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from unittest import mock

import pytest

from honeypot import decoy_manager
from utils import safety


@pytest.fixture(autouse=True)
def _isolated_safety(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Re-point safety to ``tmp_path`` and force read-only on.

    This proves honeypot deploy/remove work even when read-only mode
    is the active default - which is what the GUI ships with.
    """
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    monkeypatch.setattr(safety, "SANDBOX_ROOT", sandbox)
    monkeypatch.setattr(safety, "TESTING_MODE", True)
    monkeypatch.setattr(safety, "READONLY_MODE", True)
    # decoy_manager bound the names at import time; refresh.
    monkeypatch.setattr(decoy_manager, "SANDBOX_ROOT", sandbox)
    monkeypatch.setattr(decoy_manager, "TESTING_MODE", True)
    return sandbox


def _location(sandbox: Path) -> Path:
    """Create a target directory inside the sandbox and return it."""
    loc = sandbox / "Users" / "TestUser" / "Desktop"
    loc.mkdir(parents=True, exist_ok=True)
    return loc


class TestDeployDecoys:
    def test_default_decoys_actually_write_under_readonly(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()

        deployed: List[Path] = manager.deploy_decoys(locations=[loc])

        assert len(deployed) == len(decoy_manager.DEFAULT_DECOYS)
        for path in deployed:
            assert path.exists(), (
                f"{path} should be on disk - read-only mode must not "
                "block honeypot deployment"
            )
            assert path.stat().st_size > 0
            assert decoy_manager.DECOY_MARKER.encode() in path.read_bytes()

    def test_custom_decoy_list_overrides_defaults(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        custom = [
            {
                "name": "totally_legit_secrets.txt",
                "content_type": "text_stub",
                "desc": "Custom",
            },
            {
                "name": "wallet_backup.dat",
                "content_type": "binary_stub",
                "desc": "Custom",
            },
        ]

        manager = decoy_manager.DecoyManager()
        deployed = manager.deploy_decoys(locations=[loc], decoys=custom)

        names = sorted(p.name for p in deployed)
        assert names == [
            "totally_legit_secrets.txt",
            "wallet_backup.dat",
        ]
        # Default-set names must NOT be created when a custom list is
        # supplied.
        for default in decoy_manager.DEFAULT_DECOYS:
            assert not (loc / default["name"]).exists()

    def test_empty_custom_list_falls_back_to_defaults(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()
        deployed = manager.deploy_decoys(locations=[loc], decoys=[])
        assert len(deployed) == len(decoy_manager.DEFAULT_DECOYS)

    def test_existing_files_are_not_overwritten(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        existing = loc / decoy_manager.DEFAULT_DECOYS[0]["name"]
        existing.write_bytes(b"USER FILE - DO NOT TOUCH")

        manager = decoy_manager.DecoyManager()
        manager.deploy_decoys(locations=[loc])

        assert existing.read_bytes() == b"USER FILE - DO NOT TOUCH"

    def test_skips_unsafe_locations(
        self, _isolated_safety: Path
    ) -> None:
        # In TESTING_MODE, anything outside the sandbox/project dir is
        # rejected by is_safe_path.
        evil = Path("C:/Windows/System32")
        manager = decoy_manager.DecoyManager()

        deployed = manager.deploy_decoys(locations=[evil])
        assert deployed == []


class TestRemoveDecoys:
    def test_remove_all_actually_deletes(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()
        deployed = manager.deploy_decoys(locations=[loc])
        assert all(p.exists() for p in deployed)

        count = manager.remove_all_decoys()

        assert count == len(deployed)
        for p in deployed:
            assert not p.exists(), (
                f"{p} should be gone - read-only mode must not block "
                "honeypot removal"
            )

    def test_remove_when_none_deployed(
        self, _isolated_safety: Path
    ) -> None:
        manager = decoy_manager.DecoyManager()
        assert manager.remove_all_decoys() == 0

    def test_remove_swallows_already_missing(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()
        deployed = manager.deploy_decoys(locations=[loc])
        # User deleted one manually before our remove
        deployed[0].unlink()

        count = manager.remove_all_decoys()
        assert count == len(deployed) - 1


class TestStatus:
    def test_status_after_deploy(self, _isolated_safety: Path) -> None:
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()
        manager.deploy_decoys(locations=[loc])

        status = manager.get_status()
        assert status["deployed_count"] == len(decoy_manager.DEFAULT_DECOYS)
        assert status["active_count"] == status["deployed_count"]
        assert status["deployed_at"] is not None

    def test_is_decoy_recognises_deployed_files(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()
        deployed = manager.deploy_decoys(locations=[loc])

        for path in deployed:
            assert manager.is_decoy(path) is True

    def test_is_decoy_rejects_unrelated_files(
        self, _isolated_safety: Path
    ) -> None:
        unrelated = _isolated_safety / "innocent.txt"
        unrelated.write_bytes(b"hello")
        manager = decoy_manager.DecoyManager()
        assert manager.is_decoy(unrelated) is False


class TestManifestPersistence:
    def test_manifest_round_trip(self, _isolated_safety: Path) -> None:
        loc = _location(_isolated_safety)
        m1 = decoy_manager.DecoyManager()
        deployed = m1.deploy_decoys(locations=[loc])

        m2 = decoy_manager.DecoyManager()
        paths = m2.get_deployed_paths()
        assert sorted(str(p) for p in paths) == sorted(str(p) for p in deployed)


class TestSafetyWrapperRespected:
    def test_deploy_calls_safe_write_with_force_true(
        self, _isolated_safety: Path
    ) -> None:
        """Sanity-check the actual call into safe_write uses force=True."""
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()

        with mock.patch.object(
            decoy_manager, "safe_write",
            wraps=decoy_manager.safe_write,
        ) as wrapped:
            manager.deploy_decoys(locations=[loc])

        assert wrapped.call_count >= len(decoy_manager.DEFAULT_DECOYS)
        for call in wrapped.call_args_list:
            assert call.kwargs.get("force") is True, (
                "deploy_decoys must pass force=True or "
                "READONLY_MODE will silently no-op the write"
            )

    def test_remove_calls_safe_delete_with_force_true(
        self, _isolated_safety: Path
    ) -> None:
        loc = _location(_isolated_safety)
        manager = decoy_manager.DecoyManager()
        manager.deploy_decoys(locations=[loc])

        with mock.patch.object(
            decoy_manager, "safe_delete",
            wraps=decoy_manager.safe_delete,
        ) as wrapped:
            manager.remove_all_decoys()

        assert wrapped.call_count >= 1
        for call in wrapped.call_args_list:
            assert call.kwargs.get("force") is True
