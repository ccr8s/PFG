"""
FileGuard - Security Scanner CLI Interface.

Usage:
    python main.py <command> [options]

Commands:
    scan        Scan files and directories for threats
    forensics   Analyze system artifacts (logs, registry, timestamps)
    honeypot    Manage honeypot decoy files
    config      Manage configuration

Examples:
    python main.py scan C:\\Users --deep
    python main.py scan . --export-stix findings.json
    python main.py forensics --event-logs --registry
    python main.py --gui

Exit codes:
    0   success / no critical findings
    1   usage error or unimplemented feature
    2   critical findings or SafetyError
    130 interrupted (Ctrl+C)
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Dict

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.base import ConfigManager
from utils.logging_config import setup_logging
from utils.safety import SafetyError, apply_config_overrides

console = Console()
logger = logging.getLogger(__name__)


# =============================================================================
# ARGUMENT PARSER
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="fileguard",
        description=(
            "FileGuard Security Scanner - "
            "Detect threats and analyze system artifacts"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fileguard scan C:\\Users\\John\\Downloads
  fileguard scan C:\\ --deep --threads 8
  fileguard scan . --export-stix report.json --export-html report.html
  fileguard forensics --event-logs --registry --timestomps
  fileguard honeypot --deploy
  fileguard --gui
        """,
    )

    # Global options
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch graphical user interface",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Write logs to file",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="FileGuard v1.0.0",
    )

    # Subcommands
    subparsers = parser.add_subparsers(
        dest="command", help="Available commands"
    )

    # ----- SCAN COMMAND -----
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan files and directories for threats",
    )
    scan_parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=Path("."),
        help="Path to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep scan including system files (requires admin)",
    )
    scan_parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan of high-risk locations only",
    )
    scan_parser.add_argument(
        "-t", "--threads",
        type=int,
        default=4,
        help="Number of scanner threads (default: 4)",
    )
    scan_parser.add_argument(
        "--exclude",
        type=str,
        nargs="+",
        help="Paths or patterns to exclude",
    )
    scan_parser.add_argument(
        "--max-size",
        type=int,
        default=100,
        help="Max file size to scan in MB (default: 100)",
    )
    scan_parser.add_argument(
        "--yara-rules",
        type=Path,
        help="Path to custom YARA rules directory",
    )
    scan_parser.add_argument(
        "--check-hashes",
        action="store_true",
        help="Check file hashes against known malware databases",
    )
    scan_parser.add_argument(
        "--virustotal",
        action="store_true",
        help="Query VirusTotal for unknown hashes (requires API key)",
    )

    # Scan output options
    scan_output = scan_parser.add_argument_group("Output Options")
    scan_output.add_argument(
        "-o", "--output",
        type=Path,
        help="Save scan results to JSON file",
    )
    scan_output.add_argument(
        "--export-stix",
        type=Path,
        help="Export findings to STIX 2.1 JSON",
    )
    scan_output.add_argument(
        "--export-html",
        type=Path,
        help="Export findings to HTML report",
    )
    scan_output.add_argument(
        "--export-csv",
        type=Path,
        help="Export findings to CSV",
    )
    scan_output.add_argument(
        "--taxii-publish",
        action="store_true",
        help="Publish findings to configured TAXII servers",
    )
    scan_output.add_argument(
        "--no-save",
        action="store_true",
        help="Do not persist results to the SQLite database",
    )

    # ----- FORENSICS COMMAND -----
    forensics_parser = subparsers.add_parser(
        "forensics",
        help="Analyze system artifacts for signs of compromise",
    )
    forensics_parser.add_argument(
        "--event-logs",
        action="store_true",
        help="Analyze Windows Event Logs for tampering",
    )
    forensics_parser.add_argument(
        "--registry",
        action="store_true",
        help="Check registry for persistence mechanisms",
    )
    forensics_parser.add_argument(
        "--timestomps",
        action="store_true",
        help="Detect timestamp manipulation",
    )
    forensics_parser.add_argument(
        "--prefetch",
        action="store_true",
        help="Analyze prefetch files for execution history",
    )
    forensics_parser.add_argument(
        "--amcache",
        action="store_true",
        help="Analyze Amcache for execution artifacts",
    )
    forensics_parser.add_argument(
        "--bitmap-cache",
        action="store_true",
        help="Analyze RDP bitmap cache",
    )
    forensics_parser.add_argument(
        "--all",
        action="store_true",
        help="Run all forensic checks",
    )
    forensics_parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Save forensics results to JSON file",
    )

    # ----- HONEYPOT COMMAND -----
    honeypot_parser = subparsers.add_parser(
        "honeypot",
        help="Manage honeypot decoy files",
    )
    honeypot_parser.add_argument(
        "--deploy",
        action="store_true",
        help="Deploy decoy files to monitored locations",
    )
    honeypot_parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove all deployed decoy files",
    )
    honeypot_parser.add_argument(
        "--status",
        action="store_true",
        help="Show honeypot status and recent alerts",
    )
    honeypot_parser.add_argument(
        "--monitor",
        action="store_true",
        help="Start real-time honeypot monitoring",
    )
    honeypot_parser.add_argument(
        "--locations",
        type=Path,
        nargs="+",
        help="Custom locations for decoy files",
    )

    # ----- CONFIG COMMAND -----
    config_parser = subparsers.add_parser(
        "config",
        help="Manage FileGuard configuration",
    )
    config_parser.add_argument(
        "--show",
        action="store_true",
        help="Show current configuration",
    )
    config_parser.add_argument(
        "--set",
        nargs=2,
        metavar=("KEY", "VALUE"),
        help="Set a configuration value",
    )
    config_parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset to default configuration",
    )
    config_parser.add_argument(
        "--set-virustotal-key",
        type=str,
        help="Set VirusTotal API key",
    )

    return parser


# =============================================================================
# COMMAND HANDLERS
# =============================================================================

def handle_scan(args: argparse.Namespace) -> int:
    """Handle the scan command."""
    import uuid
    from datetime import datetime

    console.print(Panel.fit(
        "[bold blue]FileGuard Security Scanner[/bold blue]\n"
        f"Target: {args.path.absolute()}",
        border_style="blue",
    ))

    # Validate path
    if not args.path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {args.path}")
        return 1

    # Lazy imports for scan modules (not yet implemented)
    try:
        from core.models import ScanSummary
        from core.risk_classifier import RiskClassifier
        from core.scanner import FileScanner
    except ImportError:
        console.print(
            "[yellow]Warning:[/yellow] Scan engine not yet implemented. "
            "This is a Phase 2 feature."
        )
        return 1

    # Initialize scanner with the loaded application config so that
    # detector-specific settings (entropy thresholds, hash db, etc.)
    # actually take effect.
    scanner = FileScanner(
        threads=args.threads,
        max_file_size_mb=args.max_size,
        yara_rules_path=args.yara_rules,
        exclusions=args.exclude or [],
        config=ConfigManager().config,
    )

    # Stream scan results so the progress bar still updates per file,
    # then assemble a ScanSummary for persistence and exports.
    scan_id = str(uuid.uuid4())[:8]
    start_time = datetime.now()
    results = []
    from rich.progress import MofNCompleteColumn, TimeElapsedColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Enumerating files...", total=None)

        def on_progress(processed, total, current):
            if total > 0:
                progress.update(task, total=total, completed=processed)
            name = current.name if current else "..."
            if len(name) > 40:
                name = name[:37] + "..."
            label = (
                f"Scanning {name}" if total > 0
                else "Enumerating files..."
            )
            progress.update(task, description=label)

        for result in scanner.scan(
            args.path, deep=args.deep, progress_callback=on_progress
        ):
            results.append(result)

    summary = ScanSummary(
        scan_id=scan_id,
        start_time=start_time,
        end_time=datetime.now(),
        target_path=args.path,
        total_files=(
            scanner.stats["scanned"]
            + scanner.stats["skipped"]
            + scanner.stats["errors"]
        ),
        files_scanned=scanner.stats["scanned"],
        files_skipped=scanner.stats["skipped"],
        files_error=scanner.stats["errors"],
        results=results,
    )

    # Classify results
    classifier = RiskClassifier()
    classified = classifier.classify_results(results)

    # Display results table
    display_results_table(classified)

    # Persist to SQLite by default. Failures here should not abort
    # the rest of the scan output.
    if not args.no_save:
        try:
            from core.database import Database
            with Database() as db:
                db.save_scan(summary)
            console.print(
                f"[green]OK[/green] Saved to DB "
                f"(scan_id={summary.scan_id})"
            )
        except Exception as e:
            console.print(
                f"[yellow]Warning:[/yellow] Failed to persist scan: {e}"
            )

    # Handle exports
    if args.output:
        _save_results_json(results, args.output)
        console.print(f"[green]OK[/green] Results saved to {args.output}")

    if args.export_stix:
        try:
            from utils.stix_export import export_scan_results_to_stix
            export_scan_results_to_stix(results, args.export_stix)
            console.print(
                f"[green]OK[/green] STIX bundle exported to {args.export_stix}"
            )
        except ImportError:
            console.print(
                "[yellow]Warning:[/yellow] stix2 library not installed."
            )

    if args.export_html:
        from utils.report_generator import ReportGenerator
        gen = ReportGenerator(results)
        gen.export_html(args.export_html)
        console.print(
            f"[green]OK[/green] HTML report exported to {args.export_html}"
        )

    if args.export_csv:
        from utils.report_generator import ReportGenerator
        gen = ReportGenerator(results)
        gen.export_csv(args.export_csv)
        console.print(
            f"[green]OK[/green] CSV report exported to {args.export_csv}"
        )

    # Return code based on findings
    critical_count = len(classified.get("SUSPICIOUS_CODE", []))
    return 2 if critical_count > 0 else 0


def handle_forensics(args: argparse.Namespace) -> int:
    """Handle the forensics command."""
    from forensics.amcache import AmcacheParser
    from forensics.bitmap_cache import BitmapCacheParser
    from forensics.event_logs import EventLogAnalyzer
    from forensics.prefetch import PrefetchParser
    from forensics.registry import RegistryAnalyzer
    from forensics.timestomp import TimestompDetector

    console.print(Panel.fit(
        "[bold yellow]FileGuard Forensics Analysis[/bold yellow]",
        border_style="yellow",
    ))

    if not any([
        args.event_logs, args.registry, args.timestomps,
        args.prefetch, args.amcache, args.bitmap_cache, args.all,
    ]):
        console.print(
            "[yellow]No forensic checks selected.[/yellow] "
            "Use --all or specify checks."
        )
        return 1

    findings: list = []

    if args.event_logs or args.all:
        console.print("\n[bold]Analyzing Event Logs...[/bold]")
        analyzer = EventLogAnalyzer({})
        log_findings = analyzer.analyze()
        findings.extend(log_findings)
        console.print(f"  Found {len(log_findings)} suspicious entries")

    if args.registry or args.all:
        console.print("\n[bold]Checking Registry...[/bold]")
        analyzer = RegistryAnalyzer({})
        reg_findings = analyzer.analyze()
        findings.extend(reg_findings)
        console.print(f"  Found {len(reg_findings)} persistence mechanisms")

    if args.timestomps or args.all:
        console.print("\n[bold]Detecting Timestomps...[/bold]")
        detector = TimestompDetector({})
        ts_findings = detector.scan_system()
        findings.extend(ts_findings)
        console.print(f"  Found {len(ts_findings)} potential timestomps")

    if args.prefetch or args.all:
        console.print("\n[bold]Analyzing Prefetch...[/bold]")
        parser = PrefetchParser({})
        pf_findings = parser.analyze()
        findings.extend(pf_findings)
        console.print(f"  Found {len(pf_findings)} execution artifacts")

    if args.amcache or args.all:
        console.print("\n[bold]Analyzing Amcache/Shimcache...[/bold]")
        parser = AmcacheParser({})
        am_findings = parser.analyze()
        findings.extend(am_findings)
        console.print(f"  Found {len(am_findings)} execution artifacts")

    if args.bitmap_cache or args.all:
        console.print("\n[bold]Analyzing RDP Bitmap Cache...[/bold]")
        parser = BitmapCacheParser({})
        bmc_findings = parser.analyze()
        findings.extend(bmc_findings)
        console.print(f"  Found {len(bmc_findings)} RDP artifacts")

    # Display findings
    if findings:
        display_forensics_findings(findings)
    else:
        console.print("\n[green]No suspicious artifacts found.[/green]")

    # Save output if requested
    if args.output:
        data = [f.to_dict() for f in findings]
        import json as json_mod
        with open(args.output, "w", encoding="utf-8") as fout:
            json_mod.dump(data, fout, indent=2, default=str)
        console.print(f"[green]OK[/green] Results saved to {args.output}")

    return 0


def handle_honeypot(args: argparse.Namespace) -> int:
    """Handle the honeypot command."""
    from honeypot.decoy_manager import DecoyManager
    from honeypot.monitor import HoneypotMonitor

    if not any([args.deploy, args.remove, args.status, args.monitor]):
        console.print(
            "[yellow]No honeypot action specified.[/yellow] "
            "Use --deploy, --remove, --status, or --monitor."
        )
        return 1

    console.print(Panel.fit(
        "[bold magenta]FileGuard Honeypot System[/bold magenta]",
        border_style="magenta",
    ))

    manager = DecoyManager()

    if args.deploy:
        console.print("\n[bold]Deploying decoy files...[/bold]")
        locations = [Path(loc) for loc in args.locations] if args.locations else None
        deployed = manager.deploy_decoys(locations=locations)
        for p in deployed:
            console.print(f"  [green]+[/green] {p}")
        console.print(f"\n[green]Deployed {len(deployed)} decoy files[/green]")

    if args.remove:
        console.print("\n[bold]Removing all decoy files...[/bold]")
        removed = manager.remove_all_decoys()
        console.print(f"[green]Removed {removed} decoy files[/green]")

    if args.status:
        status = manager.get_status()
        table = Table(title="Honeypot Status")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        table.add_row("Deployed Decoys", str(status["deployed_count"]))
        table.add_row("Active Decoys", str(status["active_count"]))
        table.add_row("Deployed At", str(status["deployed_at"] or "Never"))
        console.print(table)

        if status["decoys"]:
            console.print("\n[bold]Deployed files:[/bold]")
            for d in status["decoys"]:
                exists = Path(d["path"]).exists()
                icon = "[green]\u2714[/green]" if exists else "[red]\u2718[/red]"
                console.print(f"  {icon} {d['path']}")

    if args.monitor:
        console.print("\n[bold]Starting honeypot monitor...[/bold]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        def on_alert(alert):
            console.print(
                f"[red bold]ALERT[/red bold] "
                f"{alert.access_type.upper()} on {alert.decoy_path.name} "
                f"by {alert.process_name or 'unknown'} "
                f"(PID {alert.process_id or '?'})"
            )

        monitor = HoneypotMonitor(manager, alert_callback=on_alert)
        monitor.start()

        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()
            console.print(
                f"\n[yellow]Monitor stopped.[/yellow] "
                f"Total alerts: {monitor.alert_count}"
            )

    return 0


def handle_config(args: argparse.Namespace) -> int:
    """Handle the config command."""
    # main() has already loaded the configuration; the singleton means
    # we just re-fetch the same instance here.
    config = ConfigManager()

    if args.show:
        import yaml
        console.print(Panel.fit(
            yaml.dump(config.config, default_flow_style=False),
            title="Current Configuration",
            border_style="cyan",
        ))
    elif args.set:
        key, value = args.set
        config.set(key, value)
        config.save()
        console.print(f"[green]OK[/green] Set {key} = {value}")
    elif args.reset:
        config.reset()
        config.save()
        console.print("[green]OK[/green] Configuration reset to defaults")
    elif args.set_virustotal_key:
        secrets_path = config.save_secret(
            "hashes.virustotal_api_key", args.set_virustotal_key
        )
        console.print(
            f"[green]OK[/green] VirusTotal API key saved to {secrets_path}\n"
            "[dim]This file is gitignored; do not commit it.[/dim]"
        )
    else:
        console.print(
            "[yellow]No config action specified.[/yellow] "
            "Use --show, --set, or --reset."
        )

    return 0


def handle_gui(args: argparse.Namespace) -> int:
    """Launch the GUI."""
    console.print("[bold]Launching FileGuard GUI...[/bold]")
    try:
        from gui.app import launch_gui
        launch_gui()
        return 0
    except ImportError as e:
        console.print(
            f"[red]Error:[/red] Could not launch GUI: {e}\n"
            "Ensure customtkinter is installed: pip install customtkinter"
        )
        return 1


# =============================================================================
# DISPLAY HELPERS
# =============================================================================

def display_results_table(classified: Dict[str, list]) -> None:
    """Display scan results in a formatted table."""
    table = Table(title="Scan Results Summary")

    table.add_column("Risk Level", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Description")

    risk_styles = {
        "SUSPICIOUS_CODE": ("red", "Critical - Likely malware"),
        "HIGH_TARGET": ("orange1", "High - Popular attack targets"),
        "POTENTIAL_RISK": ("yellow", "Medium - Needs review"),
        "LOW_RISK": ("green", "Low - Minor anomalies"),
    }

    for level, (style, desc) in risk_styles.items():
        count = len(classified.get(level, []))
        if count > 0:
            table.add_row(
                f"[{style}]{level}[/{style}]", str(count), desc
            )

    console.print(table)


def display_forensics_findings(findings: list) -> None:
    """Display forensic analysis findings."""
    table = Table(title="Forensics Findings")

    table.add_column("Source", style="cyan")
    table.add_column("Description")
    table.add_column("Severity", justify="center")
    table.add_column("ATT&CK", style="dim")

    for finding in findings[:30]:
        sev = finding.severity
        severity_style = (
            "red" if sev > 70 else "yellow" if sev > 40 else "green"
        )
        table.add_row(
            finding.source,
            finding.description[:60],
            f"[{severity_style}]{sev}[/{severity_style}]",
            ", ".join(finding.attack_techniques[:2]),
        )

    console.print(table)

    if len(findings) > 30:
        console.print(
            f"[dim]... and {len(findings) - 30} more findings[/dim]"
        )


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def _save_results_json(results: list, output_path: Path) -> None:
    """Save scan results to a JSON file."""
    data = [r.to_dict() for r in results]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(
        verbose=args.verbose,
        log_file=args.log_file,
    )

    # Load configuration once and let the safety wrapper pick up any
    # `safety:` overrides from settings.yaml. Env vars still win.
    config_mgr = ConfigManager()
    config_mgr.load(args.config)
    apply_config_overrides(config_mgr.config)

    try:
        if args.gui:
            return handle_gui(args)

        if args.command == "scan":
            return handle_scan(args)
        elif args.command == "forensics":
            return handle_forensics(args)
        elif args.command == "honeypot":
            return handle_honeypot(args)
        elif args.command == "config":
            return handle_config(args)
        else:
            parser.print_help()
            return 0
    except SafetyError as e:
        console.print(f"[bold red]Safety error:[/bold red] {e}")
        if args.verbose:
            console.print_exception()
        return 2
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130
