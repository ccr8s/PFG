# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-in-hex-editor button on the file detail panel. The blue
  `Open in hex editor` button hands the selected file to a real
  hex editor running as a separate process (safe: hex editors
  read bytes, don't execute). New `utils/hex_editor.py` resolves
  the editor in priority order: `FILEGUARD_HEX_EDITOR` env var,
  `data/user_prefs.json` (`hex_editor_path`), `config/settings.yaml`
  (`tools.hex_editor_path`), then auto-detection of HxD, ImHex, or
  010 Editor in common Program Files paths and on `PATH`. If none
  is found, a new `HexEditorPickerDialog` lists detected editors,
  offers download buttons for missing ones, and includes a
  `Browse for .exe...` picker that pins a custom editor for future
  sessions. Launches via `subprocess.Popen([editor, file])` -
  list argv, never `shell=True`. New tests in
  `tests/test_hex_editor.py` cover the resolution chain, list-argv
  invocation, file-path validation, and prefs round-trip.

- Dedicated `Honeypot Alerts` tab next to the `Honeypot` tab.
  Alerts now stream into their own screen instead of squeezing
  beneath the tutorial. The tab title includes an unread counter
  (e.g. `Honeypot Alerts (3)`) and pulses between filled / empty
  bullet markers (`\u25cf` / `\u25cb`) every 700ms while there are
  unread alerts and the tab is not active. Switching to the tab
  marks alerts viewed and stops the animation. A `Clear log`
  button on the tab wipes the panel without affecting the monitor.
  Alert lines are color-coded by access type (delete / rename = red,
  modify / create = amber, other = blue). Implemented in
  `gui/widgets/honeypot_alerts_tab.py`; `HoneypotTab` now routes
  alerts via injected `on_alert` / `on_monitor_state` callbacks
  the app wires up in `_on_honeypot_alert` and
  `_on_tool_tab_changed`.

- Pointer-finger (`hand2`) cursor on every clickable button:
  toolbar (Start Scan, Stop, Export), detail panel (Preview,
  Detonate), per-file risk-column entries, all Honeypot controls,
  the decoy chooser modal, and the `Clear log` button. New
  `gui.widgets.use_hand_cursor` helper handles both `tk.Button` and
  `customtkinter.CTkButton` (the latter via its `_canvas` attribute,
  since CTkButton 5.2.x does not accept `cursor` as a constructor
  kwarg).

- Honeypot real-time monitoring wired into the GUI. The `Honeypot`
  tab now has a `Start monitoring` / `Stop monitoring` toggle and a
  live alerts panel below the status box. Alerts come from
  `honeypot.monitor.HoneypotMonitor` (watchdog-based) and are
  marshalled onto the Tk main thread via an `alert_callback`. The
  monitor is auto-stopped from `FileGuardApp._on_close_window` so
  watchdog observers don't leak on app exit. Tutorial text updated
  to explain that Windows file-system events cover modify / create
  / delete / rename but not pure reads. Tests in
  `tests/test_honeypot_tab.py` cover toggle, abort-when-no-decoys,
  alert rendering, and failed-start state reset.

- Per-tool `Run` buttons. The shared forensic-tool button bar at
  the top of the GUI was removed; each `ToolTab` (Event Logs,
  Registry, Timestamps, Prefetch, Amcache, Bitmap Cache) now owns
  its own green `Run <tool>` button in an action bar, so the start
  control sits next to the output it produces. `_run_forensic`
  was refactored to take an explicit tool name and look the tab up
  by key.

- Per-tool tabs in the bottom panel. Each forensic tool (Event Logs,
  Registry, Timestamps, Prefetch, Amcache, Bitmap Cache) now writes
  into its own dedicated tab inside a `ttk.Notebook`, so output from
  one tool no longer overwrites another's. The legacy `_info_write`
  sink (scan progress, sandbox-close logs, startup messages) lives
  in the new `Activity` tab. Implemented via new `gui/widgets/tool_tab.py`.
- New `Honeypot` tab and forensic-bar button. Beginner-friendly
  tutorial in plain English explains what a honeypot is and how it
  helps, followed by `Deploy decoys`, `Remove all decoys`, and
  `Choose decoy files...` buttons. The chooser opens a checkbox
  modal pre-filled with the eight default templates plus a custom-
  filename entry, so users can scatter only the decoys they want.
  Status pane lists each deployed path with `*`/`x`/`+` markers for
  active / missing / just-deployed. Implemented in
  `gui/widgets/honeypot_tab.py`.
- `DecoyManager.deploy_decoys(decoys=...)` parameter for custom
  decoy lists. When supplied, only the listed decoys are created;
  empty list falls back to `DEFAULT_DECOYS`. Backwards-compatible.

### Changed
- Default `safety.testing_mode` flipped from `true` to `false` in
  `config/settings.yaml`. Real-path scanning works out of the box
  now; sandbox-only mode is opt-in via `FILEGUARD_TESTING=true` or
  the YAML override. `read_only` stays `true` as defense in depth -
  it doesn't block scanning, and honeypot deploy/remove explicitly
  pass `force=True` so they keep working.

### Fixed
- ADS scanner ctypes access violation on 64-bit Windows. `FindFirstStreamW`,
  `FindNextStreamW`, and `FindClose` now declare `argtypes`/`restype` so the
  returned `HANDLE` is no longer truncated to 32 bits before being passed
  back into the Windows API. The ctypes path is also only used when the
  `dir /r` subprocess fallback actually fails, instead of running on every
  clean file.
- CLI now prints a friendly red `Safety error:` message and exits with code 2
  when `SafetyError` is raised, instead of dumping a Python traceback.
  `KeyboardInterrupt` (Ctrl+C) returns exit code 130.
- `Database.save_scan` no longer fails when a `ScanResult.metadata` dict
  contains `datetime` values; `json.dumps` is now invoked with
  `default=str`.

### Changed
- GUI now streams flagged files into their risk columns in real time
  as the scan finds them, instead of dumping everything at the end.
  Side-benefit: when you hit Stop mid-scan, the partial results
  already populated stay put for review - no end-of-scan dump that
  could fail to deliver them.

### Added
- GUI Stop button now actually halts a running scan. Implemented via
  a `threading.Event` plumbed through `FileScanner.scan(cancel_event=)`.
  When set, the scanner stops accepting new work, calls
  `executor.shutdown(wait=False, cancel_futures=True)` to drop pending
  futures, and returns. In-flight workers (up to `threads`) finish in
  the background, so CPU subsides within a few seconds instead of
  running to completion. Also responsive during the directory walk
  on huge trees.
- Real-time scan progress in both CLI and GUI. `FileScanner.scan` now
  accepts a `progress_callback(processed, total, current_path)`. The
  CLI shows `Scanning <name>  N/M  XX% <elapsed>`; the GUI shows
  `Scanning N/M: <name>` with the bar filling proportionally. While
  the file list is still being walked, both surface
  `Enumerating files...` so the user can tell scanning hasn't frozen.
- Scan results persisted to the SQLite database (`data/fileguard.db`) by
  default. Pass `--no-save` to skip persistence. The pre-existing
  `core/database.py` schema is finally wired up to the CLI.
- GitHub Actions CI workflow at `.github/workflows/ci.yml` running ruff +
  pytest on `windows-latest` for Python 3.11 and 3.12.
- Minimal `.ruff.toml` with the `E`, `F`, `W`, `I` rule sets and per-file
  ignores for optional-dependency availability probes.
- `CHANGELOG.md` (this file).
- Safe in-process file preview. New **Preview (safe)** button on the
  detail panel opens a modal with three tabs: a hex+ASCII dump of the
  first 4 KB, extracted ASCII / UTF-16 LE strings, and (for PE files) a
  parsed header summary including sections, entropy, and a list of
  notable Windows API imports. Reads bytes through `utils.safety.safe_read`
  - no `os.startfile`, no `webbrowser.open`, no subprocess on the file.
  Implemented in `utils/safe_preview.py` and `gui/widgets/preview_window.py`.
- Windows Sandbox detonation. New **Detonate in Sandbox** button stages
  the flagged file into `data/sandbox_staging/<uuid>/`, generates an
  `isolated.wsb` config (networking / GPU / clipboard / printer / audio /
  video redirection all disabled, host folder mounted read-only), and
  launches `WindowsSandbox.exe` with **only** the `.wsb` path on argv.
  Greys out automatically when Windows Sandbox isn't installed.
  Implemented in `utils/sandbox_launcher.py`. Requires Windows 10/11 Pro /
  Enterprise / Education.
- Windows edition fail-safe for sandbox detonation. New
  `sandbox_unavailable_reason()` and `windows_edition()` helpers in
  `utils/sandbox_launcher.py` use `platform.win32_edition()` to
  reject Home / non-Pro SKUs explicitly with a beginner-friendly
  message ("Windows Sandbox isn't available on Windows Home..."),
  rather than the previous vague "WindowsSandbox.exe not found".
  The check runs at app start (tooltip) **and** at click time
  inside `detonate()` itself, so a stale GUI state can't slip past
  it. Non-Windows platforms are also rejected up front.
- Automatic sandbox cleanup. Per-detonation watcher thread polls for
  `WindowsSandboxClient.exe` and deletes the staging dir as soon as the
  sandbox VM exits. The Detonate button flips to an amber **Close Sandbox**
  button while a sandbox is active; clicking it force-terminates the VM
  via `taskkill` and cleans up immediately. Closing the FileGuard main
  window (`WM_DELETE_WINDOW`) tears down all active sandboxes and wipes
  every staging dir from the session. Stale staging dirs older than 24 h
  are also swept on app start.
- `data/sandbox_staging/` added to `.gitignore` so per-detonation copies
  of suspicious files never end up in the repo.

### Changed
- `gui/app.py` (33 KB) split into per-widget modules under `gui/widgets/`:
  `risk_column.py`, `detail_panel.py`, `info_popup.py`, `tooltip.py`. The
  classes are now public (`RiskColumn`, `DetailPanel`, `InfoPopup`,
  `ToolTip`) and re-exported from `gui.widgets`.
- Documented the CLI exit-code convention (`0`, `1`, `2`, `130`) in the
  `cli.py` module docstring.

[Unreleased]: https://github.com/ccr8s/PFG/compare/HEAD...HEAD
