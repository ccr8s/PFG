"""Windows Sandbox detonation helper with automatic cleanup.

When the host has the optional "Windows Sandbox" feature installed
(Win 10/11 Pro / Enterprise / Education), this module can stage a
flagged file into a per-detonation directory and launch a fully
isolated VM that mounts that directory **read-only** and has
networking disabled.

Lifecycle and cleanup
---------------------
Each call to :func:`detonate` returns a :class:`Detonation` handle
and registers it in the module-level active set. A daemon watcher
thread polls ``tasklist`` for ``WindowsSandboxClient.exe``; when
that process exits the staging directory is removed automatically
and the optional ``on_closed`` callback fires on the watcher thread.

Use :func:`terminate_all` on app shutdown to force-kill any sandbox
that's still running and wipe every staging dir from this session.

Safety properties
-----------------
* The suspicious file is **never** passed as a command-line argument
  to ``WindowsSandbox.exe``. Only the generated ``.wsb`` path is.
* The host folder mapping is read-only, so even a successful exploit
  inside the sandbox cannot modify the staged copy.
* Networking, GPU, clipboard, printer, audio, and video redirection
  are all disabled in the generated config.
* If Windows Sandbox is not installed, ``detonate`` raises
  :class:`SandboxUnavailableError` *before* doing any I/O - no
  partial side effects.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from utils.safety import get_project_root

logger = logging.getLogger(__name__)


class SandboxUnavailableError(RuntimeError):
    """Raised when Windows Sandbox isn't installed or reachable."""


_WSB_TEMPLATE = """<Configuration>
  <Networking>Disable</Networking>
  <VGpu>Disable</VGpu>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{host_folder}</HostFolder>
      <SandboxFolder>C:\\sample</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>explorer.exe C:\\sample</Command>
  </LogonCommand>
</Configuration>
"""

# Polling cadence for the sandbox watcher thread. Each tasklist call
# costs ~0.5-1 second on a modern Windows host, so 5s is the sweet
# spot between responsiveness and CPU.
_POLL_INTERVAL = 5.0
# How long to wait for WindowsSandboxClient.exe to *appear* before we
# give up and assume the sandbox failed to launch.
_BOOT_TIMEOUT = 60.0
# Process name of the actual sandbox VM host (not the launcher).
_SANDBOX_PROC = "WindowsSandboxClient.exe"

# Extra Popen flag on Windows so polling subprocesses don't flash
# console windows. ``CREATE_NO_WINDOW`` exists only on Windows.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ---------------------------------------------------------------------------
# Process / availability helpers
# ---------------------------------------------------------------------------
def _windir() -> Path:
    return Path(os.environ.get("WINDIR", r"C:\Windows"))


def _wsb_executable() -> Path:
    return _windir() / "System32" / "WindowsSandbox.exe"


# Editions that can install the Windows Sandbox optional feature.
# Values come from ``platform.win32_edition()`` which wraps the
# Win32 ``GetProductInfo`` API. Notably absent: ``Core`` (Home),
# ``CoreSingleLanguage``, ``CoreCountrySpecific``, server SKUs.
_SANDBOX_SUPPORTED_EDITIONS = frozenset({
    "Professional",
    "ProfessionalN",
    "ProfessionalE",
    "ProfessionalWorkstation",
    "ProfessionalWorkstationN",
    "ProfessionalEducation",
    "ProfessionalEducationN",
    "Enterprise",
    "EnterpriseN",
    "EnterpriseS",
    "EnterpriseSN",
    "EnterpriseG",
    "Education",
    "EducationN",
})


def windows_edition() -> str:
    """Return the Windows edition string (e.g. ``"Professional"``).

    Empty string if the platform isn't Windows or the API is
    unavailable. Wraps :func:`platform.win32_edition` (Python 3.8+).
    """
    try:
        edition = platform.win32_edition()
    except (AttributeError, OSError):
        return ""
    return edition or ""


def _edition_supports_sandbox(edition: str) -> bool:
    """Return True if ``edition`` is known to permit Windows Sandbox.

    Unknown / empty edition strings are treated as permissive - we'd
    rather let the file-existence check be the final gate than
    falsely reject a user on a SKU we don't recognise.
    """
    if not edition:
        return True
    return edition in _SANDBOX_SUPPORTED_EDITIONS


def sandbox_unavailable_reason() -> Optional[str]:
    """Return a human-readable reason why sandbox can't run, or None.

    Combines edition detection and binary-existence checks into a
    single message suitable for tooltips and error dialogs. Returns
    ``None`` when sandboxing is available.
    """
    if platform.system() != "Windows":
        return (
            "Windows Sandbox detonation is only available on Windows. "
            f"Detected platform: {platform.system() or 'unknown'}."
        )

    edition = windows_edition()
    if edition and not _edition_supports_sandbox(edition):
        friendly = "Home" if edition.startswith("Core") else edition
        return (
            f"Windows Sandbox isn't available on Windows {friendly}.\n\n"
            "It requires Windows 10/11 Pro, Enterprise, or Education "
            "edition. To upgrade your edition, search Windows for "
            "'Activation' and select 'Change product key'.\n\n"
            "(Detected edition tag: " + edition + ")"
        )

    try:
        exe_present = _wsb_executable().is_file()
    except OSError:
        exe_present = False

    if not exe_present:
        return (
            "Windows Sandbox is supported on this edition but the "
            "feature isn't enabled yet.\n\n"
            "To enable it:\n"
            "  1. Press Start and type 'Turn Windows features on or off'\n"
            "  2. Tick 'Windows Sandbox' and click OK\n"
            "  3. Reboot when prompted\n\n"
            "Hardware virtualization must also be enabled in your "
            "BIOS/UEFI (usually labelled VT-x, AMD-V, or SVM)."
        )

    return None


def is_sandbox_available() -> bool:
    """Return True iff Windows Sandbox can actually be launched.

    Backed by :func:`sandbox_unavailable_reason` so the file-presence
    check, edition gate, and platform gate stay in lock-step.
    """
    return sandbox_unavailable_reason() is None


def _staging_root() -> Path:
    return get_project_root() / "data" / "sandbox_staging"


def is_sandbox_running() -> bool:
    """Return True if any ``WindowsSandboxClient.exe`` is currently running.

    Uses ``tasklist`` so we don't take a hard dep on ``psutil``.
    """
    try:
        result = subprocess.run(
            [
                "tasklist",
                "/FI",
                f"IMAGENAME eq {_SANDBOX_PROC}",
                "/NH",
                "/FO",
                "CSV",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("tasklist failed: %s", exc)
        return False

    out = (result.stdout or "").strip()
    if not out:
        return False
    # When no matches, tasklist /NH /FO CSV prints nothing on stdout
    # but emits an INFO line on stderr. When matches exist, each line
    # starts with "WindowsSandboxClient.exe".
    return _SANDBOX_PROC.lower() in out.lower()


# ---------------------------------------------------------------------------
# Active detonation tracking
# ---------------------------------------------------------------------------
@dataclass
class Detonation:
    """Handle for a single in-flight sandbox detonation."""

    staging_dir: Path
    wsb_path: Path
    popen: subprocess.Popen
    on_closed: Optional[Callable[[], None]] = None
    _watcher: Optional[threading.Thread] = field(default=None, repr=False)
    _stop_watcher: threading.Event = field(
        default_factory=threading.Event, repr=False
    )
    _cleaned: bool = field(default=False, repr=False)

    def is_running(self) -> bool:
        """Best-effort check whether the sandbox VM is still alive."""
        return is_sandbox_running()

    def cleanup(self) -> None:
        """Remove the staging dir and stop the watcher.

        Idempotent; safe to call from app shutdown even if the watcher
        already cleaned up.
        """
        if self._cleaned:
            return
        self._cleaned = True
        self._stop_watcher.set()
        try:
            shutil.rmtree(self.staging_dir, ignore_errors=True)
        except OSError as exc:
            logger.debug("Failed to rmtree %s: %s", self.staging_dir, exc)
        _unregister(self)


_active: List[Detonation] = []
_active_lock = threading.Lock()


def _register(det: Detonation) -> None:
    with _active_lock:
        _active.append(det)


def _unregister(det: Detonation) -> None:
    with _active_lock:
        try:
            _active.remove(det)
        except ValueError:
            pass


def active_detonations() -> List[Detonation]:
    """Snapshot of currently tracked detonations."""
    with _active_lock:
        return list(_active)


# ---------------------------------------------------------------------------
# Watcher thread
# ---------------------------------------------------------------------------
def _watch(det: Detonation) -> None:
    """Wait for the sandbox VM to exit, then clean up.

    The launcher Popen exits before the VM is ready, so we instead
    poll for ``WindowsSandboxClient.exe``: wait for it to appear
    (boot), then wait for it to disappear (close). If it never
    appears within ``_BOOT_TIMEOUT`` we assume the launch failed
    and clean up anyway so we don't leak the staging dir.
    """
    boot_deadline = time.monotonic() + _BOOT_TIMEOUT

    # Phase 1: wait for the sandbox VM to start.
    while time.monotonic() < boot_deadline:
        if det._stop_watcher.is_set():
            break
        if is_sandbox_running():
            break
        time.sleep(_POLL_INTERVAL)
    else:
        logger.warning(
            "Sandbox failed to start within %.0fs - cleaning %s",
            _BOOT_TIMEOUT,
            det.staging_dir,
        )

    # Phase 2: wait for the VM to stop.
    while not det._stop_watcher.is_set():
        if not is_sandbox_running():
            break
        time.sleep(_POLL_INTERVAL)

    # Cleanup, then notify.
    det.cleanup()
    if det.on_closed is not None:
        try:
            det.on_closed()
        except Exception:
            logger.exception("Sandbox on_closed callback raised")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def _strip_zone_identifier(staged_file: Path) -> None:
    """Best-effort removal of the ``:Zone.Identifier`` ADS."""
    ads_path = f"{staged_file}:Zone.Identifier"
    try:
        os.remove(ads_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug("Could not strip Zone.Identifier on %s: %s", staged_file, exc)


def detonate(
    file_path: Path,
    on_closed: Optional[Callable[[], None]] = None,
) -> Detonation:
    """Stage ``file_path`` and launch Windows Sandbox on it.

    Returns a :class:`Detonation` handle. A daemon watcher thread is
    started immediately; when the sandbox VM closes the staging
    directory is deleted and ``on_closed`` (if provided) is called
    on that thread.

    Raises:
        FileNotFoundError: if ``file_path`` does not exist.
        SandboxUnavailableError: if Windows Sandbox isn't installed.
    """
    src = Path(file_path).resolve()
    if not src.is_file():
        raise FileNotFoundError(f"Cannot detonate missing file: {src}")

    # Bottom-of-stack fail-safe: re-check edition + binary every time
    # so a stale ``self._sandbox_available`` flag in the GUI can't
    # cause us to launch on a host that doesn't support it.
    reason = sandbox_unavailable_reason()
    if reason is not None:
        raise SandboxUnavailableError(reason)

    staging = _staging_root() / uuid.uuid4().hex
    staging.mkdir(parents=True, exist_ok=False)

    staged_file = staging / src.name
    shutil.copy2(src, staged_file)
    _strip_zone_identifier(staged_file)

    wsb_path = staging / "isolated.wsb"
    wsb_path.write_text(
        _WSB_TEMPLATE.format(host_folder=str(staging)),
        encoding="utf-8",
    )

    wsb_exe = _wsb_executable()
    logger.info(
        "Launching Windows Sandbox: exe=%s wsb=%s", wsb_exe, wsb_path
    )
    popen = subprocess.Popen(
        [str(wsb_exe), str(wsb_path)],
        close_fds=True,
        creationflags=_NO_WINDOW,
    )

    det = Detonation(
        staging_dir=staging,
        wsb_path=wsb_path,
        popen=popen,
        on_closed=on_closed,
    )
    _register(det)

    watcher = threading.Thread(
        target=_watch, args=(det,), daemon=True, name="sandbox-watcher"
    )
    det._watcher = watcher
    watcher.start()
    return det


def force_close_sandbox() -> int:
    """Force-terminate every running ``WindowsSandboxClient.exe``.

    Returns the number of processes signalled. Used by the GUI's
    "Close Sandbox" button and by the app-shutdown path. Failure
    here is logged but not raised.
    """
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/IM", _SANDBOX_PROC, "/T"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("taskkill failed: %s", exc)
        return 0

    out = (result.stdout or "") + (result.stderr or "")
    # taskkill prints "SUCCESS:" once per process killed.
    return out.upper().count("SUCCESS:")


def terminate_all() -> int:
    """Kill any running sandboxes and clean up every tracked staging.

    Intended for app shutdown. Synchronous: blocks until all known
    staging dirs have been removed (or have failed loudly). Returns
    the number of staging dirs cleaned.
    """
    snapshot = active_detonations()
    if snapshot or is_sandbox_running():
        force_close_sandbox()

    cleaned = 0
    for det in snapshot:
        det.cleanup()
        cleaned += 1

    # Belt and braces: nuke any staging dirs that survived.
    cleanup_staging()
    return cleaned


def cleanup_staging(older_than_hours: Optional[float] = None) -> int:
    """Remove staged sandbox directories.

    Args:
        older_than_hours: If provided, only delete directories whose
            mtime is older than this many hours. ``None`` means delete
            everything under the staging root.

    Returns:
        Number of directories removed.
    """
    root = _staging_root()
    if not root.exists():
        return 0

    cutoff = (
        time.time() - older_than_hours * 3600
        if older_than_hours is not None
        else None
    )
    removed = 0
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if cutoff is not None:
            try:
                if child.stat().st_mtime > cutoff:
                    continue
            except OSError:
                continue
        try:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
        except OSError as exc:
            logger.debug("Could not remove %s: %s", child, exc)
    return removed


__all__ = [
    "Detonation",
    "SandboxUnavailableError",
    "active_detonations",
    "cleanup_staging",
    "detonate",
    "force_close_sandbox",
    "is_sandbox_available",
    "is_sandbox_running",
    "sandbox_unavailable_reason",
    "terminate_all",
    "windows_edition",
]
