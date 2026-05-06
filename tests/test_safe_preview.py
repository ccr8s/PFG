"""Tests for safe preview utilities and sandbox launcher.

Covers:
    * hex_dump rendering and truncation
    * extract_strings on ASCII / UTF-16 LE input, dedup, min_len, limit
    * summarize_pe optional behavior with a real test asset (skipped
      when pefile is missing or no asset is available)
    * is_sandbox_available branches via patched ``Path.is_file``
    * detonate writes a valid .wsb, copies the file, calls Popen
      with [exe, wsb_path]; raises cleanly when unavailable
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from unittest import mock

import pytest

from utils import safe_preview, sandbox_launcher


@pytest.fixture(autouse=True)
def _sandbox_test_env(monkeypatch: pytest.MonkeyPatch):
    """Common neutralizers for sandbox_launcher tests.

    * Replaces the polling watcher with a no-op so spawned daemons
      exit immediately and never call ``tasklist``.
    * Default-mocks the platform/edition to a supported configuration
      so tests aren't sensitive to the CI runner's actual SKU. Tests
      that exercise edition gating just override these.
    """
    monkeypatch.setattr(sandbox_launcher, "_watch", lambda det: None)
    monkeypatch.setattr(
        sandbox_launcher.platform, "system", lambda: "Windows"
    )
    monkeypatch.setattr(
        sandbox_launcher, "windows_edition", lambda: "Professional"
    )
    yield
    with sandbox_launcher._active_lock:
        sandbox_launcher._active.clear()


# ---------------------------------------------------------------------------
# hex_dump
# ---------------------------------------------------------------------------
class TestHexDump:
    def test_empty_returns_marker(self) -> None:
        assert safe_preview.hex_dump(b"") == "(empty file)"

    def test_basic_layout(self) -> None:
        out = safe_preview.hex_dump(b"Hello!", width=16)
        assert "00000000" in out
        assert "48 65 6c 6c 6f 21" in out
        assert "|Hello!|" in out

    def test_truncation_marker_appears(self) -> None:
        data = b"A" * 5000
        out = safe_preview.hex_dump(data, max_bytes=4096)
        assert "more bytes not shown" in out
        assert "904" in out  # 5000 - 4096

    def test_no_truncation_when_under_limit(self) -> None:
        out = safe_preview.hex_dump(b"abc", max_bytes=4096)
        assert "more bytes not shown" not in out

    def test_non_printable_renders_as_dot(self) -> None:
        out = safe_preview.hex_dump(b"\x00\x01\x02A")
        # ASCII gutter should contain three dots and an A
        assert "|...A|" in out


# ---------------------------------------------------------------------------
# extract_strings
# ---------------------------------------------------------------------------
class TestExtractStrings:
    def test_ascii_run_found(self) -> None:
        data = b"\x00\x00HelloWorld\x00\x00ShortX\x00\x00"
        result = safe_preview.extract_strings(data, min_len=6)
        assert "HelloWorld" in result
        assert "ShortX" in result

    def test_min_len_filters(self) -> None:
        data = b"\x00abc\x00abcdef\x00"
        result = safe_preview.extract_strings(data, min_len=6)
        assert "abc" not in result
        assert "abcdef" in result

    def test_utf16_le_run_found(self) -> None:
        # "Secret" in UTF-16 LE
        utf16 = "Secret".encode("utf-16-le")
        data = b"\xff\xff" + utf16 + b"\xff\xff"
        result = safe_preview.extract_strings(data, min_len=6)
        assert "Secret" in result

    def test_dedupe_preserves_order(self) -> None:
        data = b"\x00alpha1\x00\x00bravo2\x00\x00alpha1\x00"
        result = safe_preview.extract_strings(data, min_len=6)
        assert result == ["alpha1", "bravo2"]

    def test_limit_caps_results(self) -> None:
        parts: List[bytes] = [
            f"value{i:04d}".encode("ascii") + b"\x00" for i in range(50)
        ]
        data = b"".join(parts)
        result = safe_preview.extract_strings(data, min_len=6, limit=10)
        assert len(result) == 10
        assert result[0] == "value0000"


# ---------------------------------------------------------------------------
# summarize_pe
# ---------------------------------------------------------------------------
class TestSummarizePe:
    def test_returns_none_for_non_pe(self, tmp_path: Path) -> None:
        f = tmp_path / "plain.txt"
        f.write_bytes(b"not a pe file")
        assert safe_preview.summarize_pe(f) is None

    def test_returns_dict_for_real_pe(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        # Reuse cmd.exe as a known-good PE on Windows test runners.
        windir = Path("C:/Windows/System32/cmd.exe")
        if not windir.is_file():
            pytest.skip("No PE asset available on this host")
        info = safe_preview.summarize_pe(windir)
        assert info is not None
        assert "machine" in info
        assert "sections" in info
        assert isinstance(info["sections"], list)
        assert info["sections"], "expected at least one section"


# ---------------------------------------------------------------------------
# is_sandbox_available / sandbox_unavailable_reason / windows_edition
# ---------------------------------------------------------------------------
class TestIsSandboxAvailable:
    def test_true_when_exe_present_and_pro(self) -> None:
        with mock.patch.object(Path, "is_file", return_value=True):
            assert sandbox_launcher.is_sandbox_available() is True
            assert sandbox_launcher.sandbox_unavailable_reason() is None

    def test_false_when_exe_missing(self) -> None:
        with mock.patch.object(Path, "is_file", return_value=False):
            assert sandbox_launcher.is_sandbox_available() is False
            reason = sandbox_launcher.sandbox_unavailable_reason()
            assert reason is not None
            assert "feature isn't enabled" in reason

    def test_false_on_oserror(self) -> None:
        with mock.patch.object(Path, "is_file", side_effect=OSError):
            assert sandbox_launcher.is_sandbox_available() is False


class TestEditionGate:
    """Ensure the Windows edition acts as a hard fail-safe."""

    def test_home_edition_rejected_even_if_exe_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            sandbox_launcher, "windows_edition", lambda: "Core"
        )
        # Even if some bizarre setup put WindowsSandbox.exe on a Home
        # box, the edition gate must still refuse.
        with mock.patch.object(Path, "is_file", return_value=True):
            reason = sandbox_launcher.sandbox_unavailable_reason()
            assert reason is not None
            assert "Home" in reason
            assert sandbox_launcher.is_sandbox_available() is False

    def test_unknown_edition_is_permissive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Unknown edition string -> fall through to file existence check
        monkeypatch.setattr(
            sandbox_launcher, "windows_edition", lambda: ""
        )
        with mock.patch.object(Path, "is_file", return_value=True):
            assert sandbox_launcher.is_sandbox_available() is True

    def test_non_windows_platform_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            sandbox_launcher.platform, "system", lambda: "Linux"
        )
        reason = sandbox_launcher.sandbox_unavailable_reason()
        assert reason is not None
        assert "only available on Windows" in reason

    @pytest.mark.parametrize(
        "edition",
        [
            "Professional",
            "ProfessionalWorkstation",
            "Enterprise",
            "EnterpriseS",
            "Education",
        ],
    )
    def test_supported_editions_accepted(
        self, monkeypatch: pytest.MonkeyPatch, edition: str
    ) -> None:
        monkeypatch.setattr(
            sandbox_launcher, "windows_edition", lambda: edition
        )
        with mock.patch.object(Path, "is_file", return_value=True):
            assert sandbox_launcher.is_sandbox_available() is True

    def test_detonate_raises_with_friendly_reason_on_home(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sample = tmp_path / "x.bin"
        sample.write_bytes(b"x")
        monkeypatch.setattr(
            sandbox_launcher, "windows_edition", lambda: "Core"
        )
        with mock.patch.object(
            sandbox_launcher.subprocess, "Popen"
        ) as popen:
            with pytest.raises(
                sandbox_launcher.SandboxUnavailableError,
                match="Home",
            ):
                sandbox_launcher.detonate(sample)
            popen.assert_not_called()


# ---------------------------------------------------------------------------
# detonate
# ---------------------------------------------------------------------------
class TestDetonate:
    def test_raises_when_unavailable(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"AAAA")

        with mock.patch.object(
            sandbox_launcher, "is_sandbox_available", return_value=False
        ), mock.patch.object(sandbox_launcher.subprocess, "Popen") as popen:
            with pytest.raises(sandbox_launcher.SandboxUnavailableError):
                sandbox_launcher.detonate(sample)
            popen.assert_not_called()

    def test_raises_for_missing_file(self, tmp_path: Path) -> None:
        ghost = tmp_path / "nope.bin"
        with mock.patch.object(sandbox_launcher.subprocess, "Popen") as popen:
            with pytest.raises(FileNotFoundError):
                sandbox_launcher.detonate(ghost)
            popen.assert_not_called()

    def test_writes_wsb_and_copies_file_and_launches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "evil.exe"
        sample.write_bytes(b"MZ\x90\x00sample-bytes")

        staging_root = tmp_path / "stage"
        monkeypatch.setattr(
            sandbox_launcher, "_staging_root", lambda: staging_root
        )
        fake_exe = tmp_path / "fakebin" / "WindowsSandbox.exe"
        fake_exe.parent.mkdir()
        fake_exe.write_bytes(b"\x00")
        monkeypatch.setattr(
            sandbox_launcher, "_wsb_executable", lambda: fake_exe
        )

        with mock.patch.object(sandbox_launcher.subprocess, "Popen") as popen:
            det = sandbox_launcher.detonate(sample)

        assert isinstance(det, sandbox_launcher.Detonation)
        wsb_path = det.wsb_path
        assert wsb_path.exists()
        assert wsb_path.suffix == ".wsb"
        xml = wsb_path.read_text(encoding="utf-8")
        assert "<Networking>Disable</Networking>" in xml
        assert "<ReadOnly>true</ReadOnly>" in xml
        assert str(wsb_path.parent) in xml

        # Sample copied into staging dir under same filename
        assert (wsb_path.parent / "evil.exe").read_bytes().startswith(b"MZ")

        popen.assert_called_once()
        args, _ = popen.call_args
        assert args[0] == [str(fake_exe), str(wsb_path)]
        # CRITICAL: the sample path must NEVER appear in the argv
        assert str(sample) not in args[0]

        # Newly-detonated handle should be tracked as active.
        assert det in sandbox_launcher.active_detonations()

    def test_strip_zone_identifier_is_best_effort(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "x.bin"
        target.write_bytes(b"x")
        # Should swallow FileNotFoundError from os.remove silently
        sandbox_launcher._strip_zone_identifier(target)


# ---------------------------------------------------------------------------
# is_sandbox_running
# ---------------------------------------------------------------------------
class TestIsSandboxRunning:
    def test_true_when_tasklist_lists_process(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = mock.Mock(stdout='"WindowsSandboxClient.exe","1234"\n')
        monkeypatch.setattr(
            sandbox_launcher.subprocess, "run", lambda *a, **kw: fake
        )
        assert sandbox_launcher.is_sandbox_running() is True

    def test_false_on_empty_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = mock.Mock(stdout="")
        monkeypatch.setattr(
            sandbox_launcher.subprocess, "run", lambda *a, **kw: fake
        )
        assert sandbox_launcher.is_sandbox_running() is False

    def test_false_on_oserror(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_a, **_kw):
            raise OSError("boom")
        monkeypatch.setattr(sandbox_launcher.subprocess, "run", boom)
        assert sandbox_launcher.is_sandbox_running() is False


# ---------------------------------------------------------------------------
# Detonation.cleanup / auto-cleanup
# ---------------------------------------------------------------------------
class TestDetonationCleanup:
    def test_cleanup_removes_staging_and_unregisters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "evil.bin"
        sample.write_bytes(b"x")
        staging_root = tmp_path / "stage"
        monkeypatch.setattr(
            sandbox_launcher, "_staging_root", lambda: staging_root
        )
        fake_exe = tmp_path / "WindowsSandbox.exe"
        fake_exe.write_bytes(b"\x00")
        monkeypatch.setattr(
            sandbox_launcher, "_wsb_executable", lambda: fake_exe
        )

        with mock.patch.object(sandbox_launcher.subprocess, "Popen"):
            det = sandbox_launcher.detonate(sample)

        assert det.staging_dir.exists()
        assert det in sandbox_launcher.active_detonations()

        det.cleanup()

        assert not det.staging_dir.exists()
        assert det not in sandbox_launcher.active_detonations()

    def test_cleanup_is_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "x"
        sample.write_bytes(b"x")
        monkeypatch.setattr(
            sandbox_launcher, "_staging_root", lambda: tmp_path / "stage"
        )
        fake_exe = tmp_path / "WindowsSandbox.exe"
        fake_exe.write_bytes(b"\x00")
        monkeypatch.setattr(
            sandbox_launcher, "_wsb_executable", lambda: fake_exe
        )
        with mock.patch.object(sandbox_launcher.subprocess, "Popen"):
            det = sandbox_launcher.detonate(sample)

        det.cleanup()
        det.cleanup()  # must not raise


# ---------------------------------------------------------------------------
# force_close_sandbox / terminate_all
# ---------------------------------------------------------------------------
class TestForceCloseAndTerminateAll:
    def test_force_close_invokes_taskkill(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = mock.Mock(stdout="SUCCESS: ...\nSUCCESS: ...\n", stderr="")
        run = mock.Mock(return_value=fake)
        monkeypatch.setattr(sandbox_launcher.subprocess, "run", run)

        count = sandbox_launcher.force_close_sandbox()

        run.assert_called_once()
        argv = run.call_args[0][0]
        assert argv[0] == "taskkill"
        assert "WindowsSandboxClient.exe" in argv
        assert count == 2

    def test_force_close_swallows_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_a, **_kw):
            raise OSError("nope")
        monkeypatch.setattr(sandbox_launcher.subprocess, "run", boom)
        assert sandbox_launcher.force_close_sandbox() == 0

    def test_terminate_all_kills_and_cleans(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "x"
        sample.write_bytes(b"x")
        staging_root = tmp_path / "stage"
        monkeypatch.setattr(
            sandbox_launcher, "_staging_root", lambda: staging_root
        )
        fake_exe = tmp_path / "WindowsSandbox.exe"
        fake_exe.write_bytes(b"\x00")
        monkeypatch.setattr(
            sandbox_launcher, "_wsb_executable", lambda: fake_exe
        )
        with mock.patch.object(sandbox_launcher.subprocess, "Popen"):
            det = sandbox_launcher.detonate(sample)

        kill = mock.Mock()
        monkeypatch.setattr(sandbox_launcher, "force_close_sandbox", kill)

        cleaned = sandbox_launcher.terminate_all()

        assert cleaned == 1
        kill.assert_called_once()
        assert not det.staging_dir.exists()
        assert sandbox_launcher.active_detonations() == []


# ---------------------------------------------------------------------------
# cleanup_staging
# ---------------------------------------------------------------------------
class TestCleanupStaging:
    def test_removes_all_when_no_age_filter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "stage"
        root.mkdir()
        (root / "a").mkdir()
        (root / "b").mkdir()
        monkeypatch.setattr(sandbox_launcher, "_staging_root", lambda: root)

        removed = sandbox_launcher.cleanup_staging()
        assert removed == 2
        assert list(root.iterdir()) == []

    def test_no_op_when_root_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "missing"
        monkeypatch.setattr(sandbox_launcher, "_staging_root", lambda: root)
        assert sandbox_launcher.cleanup_staging() == 0
