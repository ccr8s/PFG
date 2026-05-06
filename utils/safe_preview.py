"""
Safe in-process preview helpers for FileGuard.

These functions read file *bytes* and render them in non-executable form
so an analyst can inspect a flagged file without ever invoking a Windows
shell handler. None of these functions:

    * call ``os.startfile``
    * call ``webbrowser.open``
    * launch a subprocess with the file path as argv
    * decode bytes into Python objects that could trigger side-effects

The worst that can happen is mis-rendered text, which is fine.

Usage::

    from utils.safe_preview import hex_dump, extract_strings, summarize_pe
    data = safe_read(path)
    print(hex_dump(data))
    for s in extract_strings(data):
        print(s)
    info = summarize_pe(path)  # None if the file isn't a PE
"""

from __future__ import annotations

import logging
import string
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hex dump
# ---------------------------------------------------------------------------

_PRINTABLE_BYTES = set(bytes(string.printable, "ascii")) - set(b"\t\n\r\x0b\x0c")


def hex_dump(
    data: bytes,
    width: int = 16,
    max_bytes: int = 4096,
) -> str:
    """
    Render bytes as a classic ``offset  hex  ascii`` dump.

    Args:
        data: The bytes to render.
        width: Bytes per line.
        max_bytes: Don't render more than this many bytes; appends a
            truncation marker if exceeded.

    Returns:
        A multi-line string suitable for a monospace text widget.
    """
    if not data:
        return "(empty file)"

    truncated = len(data) > max_bytes
    view = data[:max_bytes]
    lines: List[str] = []

    for offset in range(0, len(view), width):
        chunk = view[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad short final line so the ASCII gutter aligns
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(
            chr(b) if b in _PRINTABLE_BYTES else "."
            for b in chunk
        )
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")

    if truncated:
        lines.append(
            f"... ({len(data) - max_bytes:,} more bytes not shown)"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Strings extraction
# ---------------------------------------------------------------------------

_ASCII_PRINTABLE = bytes(range(0x20, 0x7F))


def extract_strings(
    data: bytes,
    min_len: int = 6,
    limit: int = 500,
) -> List[str]:
    """
    Extract printable runs from ``data``.

    Looks for both ASCII (single-byte) and UTF-16 little-endian runs.
    Order is preserved and duplicates removed - the first occurrence
    wins. The returned list is capped at ``limit``.

    Args:
        data: Raw file contents.
        min_len: Minimum run length in characters before we keep it.
        limit: Cap on the number of strings returned.

    Returns:
        Deduplicated list of extracted strings, in discovery order.
    """
    seen: Dict[str, None] = {}
    printable = set(_ASCII_PRINTABLE)

    def _maybe_add(value: str) -> bool:
        if len(value) < min_len:
            return True
        if value in seen:
            return True
        seen[value] = None
        return len(seen) < limit

    # ASCII pass
    run = bytearray()
    for byte in data:
        if byte in printable:
            run.append(byte)
        else:
            if run:
                if not _maybe_add(run.decode("ascii", errors="replace")):
                    return list(seen)
                run.clear()
    if run:
        _maybe_add(run.decode("ascii", errors="replace"))
        if len(seen) >= limit:
            return list(seen)

    # UTF-16 LE pass: pairs of (printable_byte, 0x00)
    run.clear()
    i = 0
    n = len(data) - 1
    while i < n:
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and lo in printable:
            run.append(lo)
            i += 2
            continue
        if run:
            if not _maybe_add(run.decode("ascii", errors="replace")):
                return list(seen)
            run.clear()
        i += 1
    if run:
        _maybe_add(run.decode("ascii", errors="replace"))

    return list(seen)


# ---------------------------------------------------------------------------
# PE summary
# ---------------------------------------------------------------------------

# Imports that often signal "this binary does interesting things" and are
# worth surfacing in the preview - mirrors the spirit of pe_analyzer.
_NOTABLE_IMPORTS = {
    b"VirtualAlloc",
    b"VirtualAllocEx",
    b"VirtualProtect",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"NtCreateThreadEx",
    b"CreateProcessA",
    b"CreateProcessW",
    b"ShellExecuteA",
    b"ShellExecuteW",
    b"WinExec",
    b"LoadLibraryA",
    b"LoadLibraryW",
    b"GetProcAddress",
    b"InternetOpenA",
    b"InternetOpenW",
    b"WSAStartup",
    b"socket",
    b"connect",
    b"URLDownloadToFileA",
    b"URLDownloadToFileW",
    b"CryptEncrypt",
    b"CryptDecrypt",
    b"SetWindowsHookExA",
    b"SetWindowsHookExW",
    b"GetAsyncKeyState",
}


def summarize_pe(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Build a small dict describing a PE file's headers.

    Returns ``None`` if ``pefile`` is unavailable or the file isn't a
    valid PE - never raises for either of those cases. The dict has
    the shape::

        {
            "machine": "AMD64",
            "timestamp": "2026-01-01T00:00:00",
            "is_dll": False,
            "subsystem": "WINDOWS_GUI",
            "sections": [
                {"name": ".text", "vsize": 0x1234, "rsize": 0x1200,
                 "entropy": 6.2, "characteristics": "RX"},
                ...
            ],
            "imports": [
                {"dll": "kernel32.dll", "functions": ["VirtualAlloc", ...]},
                ...
            ],
            "notable_imports": ["VirtualAlloc", "WriteProcessMemory", ...],
        }
    """
    try:
        import pefile
    except ImportError:
        logger.debug("pefile not installed; skipping PE summary")
        return None

    try:
        pe = pefile.PE(str(file_path), fast_load=False)
    except pefile.PEFormatError:
        return None
    except Exception as e:
        logger.debug("Failed to parse PE %s: %s", file_path, e)
        return None

    try:
        machine = pefile.MACHINE_TYPE.get(
            pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04x}"
        )
        if isinstance(machine, str) and machine.startswith("IMAGE_FILE_MACHINE_"):
            machine = machine[len("IMAGE_FILE_MACHINE_"):]

        subsystem = pefile.SUBSYSTEM_TYPE.get(
            pe.OPTIONAL_HEADER.Subsystem,
            f"0x{pe.OPTIONAL_HEADER.Subsystem:04x}",
        )
        if isinstance(subsystem, str) and subsystem.startswith(
            "IMAGE_SUBSYSTEM_"
        ):
            subsystem = subsystem[len("IMAGE_SUBSYSTEM_"):]

        from datetime import datetime, timezone
        try:
            timestamp = datetime.fromtimestamp(
                pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc
            ).isoformat()
        except (OSError, ValueError, OverflowError):
            timestamp = f"0x{pe.FILE_HEADER.TimeDateStamp:08x}"

        sections = []
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            try:
                entropy = section.get_entropy()
            except Exception:
                entropy = 0.0
            chars = []
            ch = section.Characteristics
            if ch & 0x20000000:
                chars.append("X")
            if ch & 0x40000000:
                chars.append("R")
            if ch & 0x80000000:
                chars.append("W")
            sections.append({
                "name": name,
                "vsize": section.Misc_VirtualSize,
                "rsize": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "characteristics": "".join(chars) or "-",
            })

        imports: List[Dict[str, Any]] = []
        notable: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = (entry.dll or b"").decode("ascii", errors="replace")
                funcs: List[str] = []
                for imp in entry.imports:
                    fname = imp.name
                    if not fname:
                        funcs.append(f"ord_{imp.ordinal}")
                        continue
                    if fname in _NOTABLE_IMPORTS and (
                        fname.decode("ascii", errors="replace")
                        not in notable
                    ):
                        notable.append(fname.decode("ascii", errors="replace"))
                    funcs.append(fname.decode("ascii", errors="replace"))
                imports.append({"dll": dll, "functions": funcs})

        return {
            "machine": machine,
            "timestamp": timestamp,
            "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "subsystem": subsystem,
            "sections": sections,
            "imports": imports,
            "notable_imports": notable,
        }
    finally:
        try:
            pe.close()
        except Exception:
            pass
