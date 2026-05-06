#!/usr/bin/env python3
"""
FileGuard - Security Scanner CLI Entry Point

Usage:
    python -m fileguard <command> [options]
    
Commands:
    scan        Scan files and directories for threats
    forensics   Analyze system artifacts (logs, registry, timestamps)
    honeypot    Manage honeypot decoy files
    export      Export previous scan results
    config      Manage configuration
    
Examples:
    python -m fileguard scan C:\\Users --deep
    python -m fileguard scan . --export-stix findings.json
    python -m fileguard forensics --event-logs --registry
    python -m fileguard --gui
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import Optional, List
from datetime import datetime

# Rich for beautiful CLI output
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import print as rprint

console = Console()

# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> None:
    """Configure logging for CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    
    handlers: List[logging.Handler] = [
        logging.StreamHandler(sys.stdout)
    ]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers
    )


# =============================================================================
# ARGUMENT PARSER
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="fileguard",
        description="FileGuard Security Scanner - Detect threats and analyze system artifacts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fileguard scan C:\\Users\\John\\Downloads
  fileguard scan C:\\ --deep --threads 8
  fileguard scan . --export-stix report.json --export-html report.html
  fileguard forensics --event-logs --registry --timestomps
  fileguard honeypot --deploy
  fileguard --gui
        """
    )
    
    # Global options
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch graphical user interface"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Write logs to file"
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="FileGuard v1.0.0"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # ----- SCAN COMMAND -----
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan files and directories for threats"
    )
    scan_parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=Path("."),
        help="Path to scan (default: current directory)"
    )
    scan_parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep scan including system files (requires admin)"
    )
    scan_parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan of high-risk locations only"
    )
    scan_parser.add_argument(
        "-t", "--threads",
        type=int,
        default=4,
        help="Number of scanner threads (default: 4)"
    )
    scan_parser.add_argument(
        "--exclude",
        type=str,
        nargs="+",
        help="Paths or patterns to exclude"
    )
    scan_parser.add_argument(
        "--max-size",
        type=int,
        default=100,
        help="Max file size to scan in MB (default: 100)"
    )
    scan_parser.add_argument(
        "--yara-rules",
        type=Path,
        help="Path to custom YARA rules directory"
    )
    scan_parser.add_argument(
        "--check-hashes",
        action="store_true",
        help="Check file hashes against known malware databases"
    )
    scan_parser.add_argument(
        "--virustotal",
        action="store_true",
        help="Query VirusTotal for unknown hashes (requires API key)"
    )
    
    # Scan output options
    scan_output = scan_parser.add_argument_group("Output Options")
    scan_output.add_argument(
        "-o", "--output",
        type=Path,
        help="Save scan results to JSON file"
    )
    scan_output.add_argument(
        "--export-stix",
        type=Path,
        help="Export findings to STIX 2.1 JSON"
    )
    scan_output.add_argument(
        "--export-html",
        type=Path,
        help="Export findings to HTML report"
    )
    scan_output.add_argument(
        "--export-csv",
        type=Path,
        help="Export findings to CSV"
    )
    scan_output.add_argument(
        "--taxii-publish",
        action="store_true",
        help="Publish findings to configured TAXII servers"
    )
    
    # ----- FORENSICS COMMAND -----
    forensics_parser = subparsers.add_parser(
        "forensics",
        help="Analyze system artifacts for signs of compromise"
    )
    forensics_parser.add_argument(
        "--event-logs",
        action="store_true",
        help="Analyze Windows Event Logs for tampering"
    )
    forensics_parser.add_argument(
        "--registry",
        action="store_true",
        help="Check registry for persistence mechanisms"
    )
    forensics_parser.add_argument(
        "--timestomps",
        action="store_true",
        help="Detect timestamp manipulation"
    )
    forensics_parser.add_argument(
        "--prefetch",
        action="store_true",
        help="Analyze prefetch files for execution history"
    )
    forensics_parser.add_argument(
        "--amcache",
        action="store_true",
        help="Analyze Amcache for execution artifacts"
    )
    forensics_parser.add_argument(
        "--bitmap-cache",
        action="store_true",
        help="Analyze RDP bitmap cache"
    )
    forensics_parser.add_argument(
        "--all",
        action="store_true",
        help="Run all forensic checks"
    )
    forensics_parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Save forensics results to JSON file"
    )
    
    # ----- HONEYPOT COMMAND -----
    honeypot_parser = subparsers.add_parser(
        "honeypot",
        help="Manage honeypot decoy files"
    )
    honeypot_parser.add_argument(
        "--deploy",
        action="store_true",
        help="Deploy decoy files to monitored locations"
    )
    honeypot_parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove all deployed decoy files"
    )
    honeypot_parser.add_argument(
        "--status",
        action="store_true",
        help="Show honeypot status and recent alerts"
    )
    honeypot_parser.add_argument(
        "--monitor",
        action="store_true",
        help="Start real-time honeypot monitoring"
    )
    honeypot_parser.add_argument(
        "--locations",
        type=Path,
        nargs="+",
        help="Custom locations for decoy files"
    )
    
    # ----- CONFIG COMMAND -----
    config_parser = subparsers.add_parser(
        "config",
        help="Manage FileGuard configuration"
    )
    config_parser.add_argument(
        "--show",
        action="store_true",
        help="Show current configuration"
    )
    config_parser.add_argument(
        "--set",
        nargs=2,
        metavar=("KEY", "VALUE"),
        help="Set a configuration value"
    )
    config_parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset to default configuration"
    )
    config_parser.add_argument(
        "--set-virustotal-key",
        type=str,
        help="Set VirusTotal API key"
    )
    
    return parser


# =============================================================================
# COMMAND HANDLERS
# =============================================================================

def handle_scan(args: argparse.Namespace) -> int:
    """Handle the scan command."""
    from core.scanner import FileScanner
    from core.risk_classifier import RiskClassifier
    from utils.stix_export import export_scan_results_to_stix
    
    console.print(Panel.fit(
        "[bold blue]FileGuard Security Scanner[/bold blue]\n"
        f"Target: {args.path.absolute()}",
        border_style="blue"
    ))
    
    # Validate path
    if not args.path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {args.path}")
        return 1
    
    # Initialize scanner
    scanner = FileScanner(
        threads=args.threads,
        max_file_size_mb=args.max_size,
        yara_rules_path=args.yara_rules,
        exclusions=args.exclude or []
    )
    
    # Run scan with progress
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning files...", total=None)
        
        for result in scanner.scan(args.path, deep=args.deep):
            results.append(result)
            progress.update(task, description=f"Scanning: {result.file_path.name[:40]}")
    
    # Classify results
    classifier = RiskClassifier()
    classified = classifier.classify_results(results)
    
    # Display results table
    display_results_table(classified)
    
    # Handle exports
    if args.output:
        save_results_json(results, args.output)
        console.print(f"[green]✓[/green] Results saved to {args.output}")
    
    if args.export_stix:
        export_scan_results_to_stix(results, args.export_stix)
        console.print(f"[green]✓[/green] STIX bundle exported to {args.export_stix}")
    
    if args.export_html:
        export_html_report(results, args.export_html)
        console.print(f"[green]✓[/green] HTML report exported to {args.export_html}")
    
    # Return code based on findings
    critical_count = len(classified.get("SUSPICIOUS_CODE", []))
    return 2 if critical_count > 0 else 0


def handle_forensics(args: argparse.Namespace) -> int:
    """Handle the forensics command."""
    from forensics.event_logs import EventLogAnalyzer
    from forensics.registry import RegistryAnalyzer
    from forensics.timestomp import TimestompDetector
    
    console.print(Panel.fit(
        "[bold yellow]FileGuard Forensics Analysis[/bold yellow]",
        border_style="yellow"
    ))
    
    findings = []
    
    if args.event_logs or args.all:
        console.print("\n[bold]Analyzing Event Logs...[/bold]")
        analyzer = EventLogAnalyzer({})
        log_findings = analyzer.analyze_logs()
        findings.extend(log_findings)
        console.print(f"  Found {len(log_findings)} suspicious entries")
    
    if args.registry or args.all:
        console.print("\n[bold]Checking Registry...[/bold]")
        analyzer = RegistryAnalyzer({})
        reg_findings = analyzer.check_persistence()
        findings.extend(reg_findings)
        console.print(f"  Found {len(reg_findings)} persistence mechanisms")
    
    if args.timestomps or args.all:
        console.print("\n[bold]Detecting Timestomps...[/bold]")
        detector = TimestompDetector({})
        ts_findings = detector.scan_system()
        findings.extend(ts_findings)
        console.print(f"  Found {len(ts_findings)} potential timestomps")
    
    # Display findings
    if findings:
        display_forensics_table(findings)
    else:
        console.print("\n[green]No suspicious artifacts found.[/green]")
    
    return 0


def handle_honeypot(args: argparse.Namespace) -> int:
    """Handle the honeypot command."""
    from honeypot.decoy_manager import DecoyManager
    from honeypot.monitor import HoneypotMonitor
    
    manager = DecoyManager()
    
    if args.deploy:
        console.print("[bold]Deploying honeypot decoys...[/bold]")
        deployed = manager.deploy_decoys(args.locations)
        console.print(f"[green]✓[/green] Deployed {len(deployed)} decoy files")
        for path in deployed:
            console.print(f"  • {path}")
    
    elif args.remove:
        console.print("[bold]Removing honeypot decoys...[/bold]")
        removed = manager.remove_all_decoys()
        console.print(f"[green]✓[/green] Removed {removed} decoy files")
    
    elif args.status:
        status = manager.get_status()
        display_honeypot_status(status)
    
    elif args.monitor:
        console.print("[bold]Starting honeypot monitor...[/bold]")
        console.print("Press Ctrl+C to stop\n")
        monitor = HoneypotMonitor(manager)
        try:
            monitor.start()
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()
            console.print("\n[yellow]Monitor stopped.[/yellow]")
    
    return 0


def handle_gui(args: argparse.Namespace) -> int:
    """Launch the GUI."""
    console.print("[bold]Launching FileGuard GUI...[/bold]")
    from gui.app import FileGuardApp
    app = FileGuardApp()
    app.mainloop()
    return 0


# =============================================================================
# DISPLAY HELPERS
# =============================================================================

def display_results_table(classified: dict) -> None:
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
            table.add_row(f"[{style}]{level}[/{style}]", str(count), desc)
    
    console.print(table)


def display_forensics_table(findings: list) -> None:
    """Display forensics findings."""
    table = Table(title="Forensics Findings")
    
    table.add_column("Type", style="cyan")
    table.add_column("Description")
    table.add_column("Severity", justify="center")
    table.add_column("ATT&CK", style="dim")
    
    for finding in findings[:20]:  # Limit display
        severity_style = "red" if finding.severity > 70 else "yellow" if finding.severity > 40 else "green"
        table.add_row(
            finding.detector,
            finding.description[:60],
            f"[{severity_style}]{finding.severity}[/{severity_style}]",
            ", ".join(finding.attack_techniques[:2])
        )
    
    console.print(table)
    
    if len(findings) > 20:
        console.print(f"[dim]... and {len(findings) - 20} more findings[/dim]")


def display_honeypot_status(status: dict) -> None:
    """Display honeypot status."""
    console.print(Panel.fit(
        f"[bold]Honeypot Status[/bold]\n\n"
        f"Deployed decoys: {status['deployed_count']}\n"
        f"Active monitors: {status['active_monitors']}\n"
        f"Recent alerts: {status['recent_alerts']}\n"
        f"Last alert: {status.get('last_alert_time', 'None')}",
        border_style="cyan"
    ))


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.log_file)
    
    # Handle GUI launch
    if args.gui:
        return handle_gui(args)
    
    # Handle subcommands
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


if __name__ == "__main__":
    sys.exit(main())