"""
Report generation for FileGuard.

Exports scan results to HTML, JSON, and CSV formats with
rich formatting and summary statistics.
"""

import csv
import json
import logging
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import RiskLevel, ScanResult, ScanSummary

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates scan reports in multiple formats.

    Supports HTML (styled), JSON, and CSV exports.
    """

    def __init__(
        self,
        results: List[ScanResult],
        summary: Optional[ScanSummary] = None,
    ) -> None:
        """
        Initialize report generator.

        Args:
            results: Scan results to include.
            summary: Optional scan summary with timing/counts.
        """
        self.results = results
        self.summary = summary

    def export_html(self, output_path: Path) -> None:
        """
        Export scan results as a styled HTML report.

        Args:
            output_path: Path to write the HTML file.
        """
        risk_counts = self._count_risks()
        total = len(self.results)

        rows = ""
        for r in sorted(
            self.results, key=lambda x: x.risk_score, reverse=True
        ):
            findings_html = "<br>".join(
                f"<span class='finding'>[{escape(f.detector)}] "
                f"{escape(f.description)}</span>"
                for f in r.findings
            )
            attack_html = "<br>".join(
                escape(", ".join(f.attack_techniques))
                for f in r.findings
                if f.attack_techniques
            )
            risk_class = r.risk_level.name.lower()
            rows += (
                f"<tr class='{risk_class}'>"
                f"<td>{escape(str(r.file_path))}</td>"
                f"<td>{r.risk_level.label}</td>"
                f"<td>{r.risk_score}</td>"
                f"<td>{r.file_size:,}</td>"
                f"<td>{findings_html or '—'}</td>"
                f"<td>{attack_html or '—'}</td>"
                f"</tr>\n"
            )

        duration_str = ""
        if self.summary:
            duration_str = f" in {self.summary.duration_seconds:.1f}s"

        html = _HTML_TEMPLATE.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=total,
            duration=duration_str,
            suspicious=risk_counts.get("SUSPICIOUS_CODE", 0),
            high=risk_counts.get("HIGH_TARGET", 0),
            potential=risk_counts.get("POTENTIAL_RISK", 0),
            low=risk_counts.get("LOW_RISK", 0),
            clean=risk_counts.get("CLEAN", 0),
            rows=rows,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        logger.info("HTML report saved to %s", output_path)

    def export_json(self, output_path: Path) -> None:
        """
        Export scan results as JSON.

        Args:
            output_path: Path to write the JSON file.
        """
        data: Dict[str, Any] = {
            "report_time": datetime.now().isoformat(),
            "total_files": len(self.results),
            "risk_counts": self._count_risks(),
            "results": [r.to_dict() for r in self.results],
        }

        if self.summary:
            data["summary"] = self.summary.to_dict()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("JSON report saved to %s", output_path)

    def export_csv(self, output_path: Path) -> None:
        """
        Export scan results as CSV.

        Args:
            output_path: Path to write the CSV file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "File Path",
                "Risk Level",
                "Risk Score",
                "File Size",
                "MD5",
                "SHA-256",
                "Finding Count",
                "Detectors",
                "ATT&CK Techniques",
            ])

            for r in sorted(
                self.results, key=lambda x: x.risk_score, reverse=True
            ):
                detectors = "; ".join(set(f.detector for f in r.findings))
                techniques = "; ".join(
                    t
                    for f in r.findings
                    for t in f.attack_techniques
                )
                writer.writerow([
                    str(r.file_path),
                    r.risk_level.label,
                    r.risk_score,
                    r.file_size,
                    r.file_hash_md5,
                    r.file_hash_sha256,
                    len(r.findings),
                    detectors,
                    techniques,
                ])

        logger.info("CSV report saved to %s", output_path)

    def _count_risks(self) -> Dict[str, int]:
        """Count results by risk level."""
        counts: Dict[str, int] = {}
        for r in self.results:
            key = r.risk_level.name
            counts[key] = counts.get(key, 0) + 1
        return counts


# ── HTML Template ──────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FileGuard Scan Report</title>
<style>
  :root {{
    --bg: #1a1a2e; --card: #1e2a45; --text: #e8e8e8;
    --accent: #00adb5; --red: #e74c3c; --orange: #e67e22;
    --yellow: #f1c40f; --green: #2ecc71; --gray: #95a5a6;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: var(--bg); color: var(--text); padding: 20px;
  }}
  h1 {{ color: var(--accent); margin-bottom: 6px; }}
  .meta {{ color: var(--gray); margin-bottom: 20px; font-size: 0.9em; }}
  .cards {{
    display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap;
  }}
  .card {{
    background: var(--card); border-radius: 8px; padding: 16px 20px;
    flex: 1; min-width: 140px; text-align: center;
    border-left: 4px solid var(--accent);
  }}
  .card .num {{ font-size: 2em; font-weight: bold; }}
  .card .label {{ font-size: 0.85em; color: var(--gray); margin-top: 4px; }}
  .card.crit {{ border-color: var(--red); }}
  .card.crit .num {{ color: var(--red); }}
  .card.high {{ border-color: var(--orange); }}
  .card.high .num {{ color: var(--orange); }}
  .card.med  {{ border-color: var(--yellow); }}
  .card.med .num  {{ color: var(--yellow); }}
  .card.low  {{ border-color: var(--green); }}
  .card.low .num  {{ color: var(--green); }}
  .card.clean {{ border-color: var(--gray); }}
  .card.clean .num {{ color: var(--gray); }}
  table {{
    width: 100%; border-collapse: collapse; background: var(--card);
    border-radius: 8px; overflow: hidden;
  }}
  th {{
    background: #0f3460; padding: 10px 12px; text-align: left;
    font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em;
  }}
  td {{
    padding: 8px 12px; border-top: 1px solid #2c3e50;
    font-size: 0.9em; vertical-align: top;
  }}
  tr.suspicious_code td:nth-child(2) {{ color: var(--red); font-weight:bold; }}
  tr.high_target td:nth-child(2) {{ color: var(--orange); font-weight:bold; }}
  tr.potential_risk td:nth-child(2) {{ color: var(--yellow); }}
  tr.low_risk td:nth-child(2) {{ color: var(--green); }}
  .finding {{ display: block; margin: 2px 0; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>FileGuard Scan Report</h1>
<p class="meta">Generated {timestamp} &mdash; {total} files scanned{duration}</p>

<div class="cards">
  <div class="card crit"><div class="num">{suspicious}</div><div class="label">Suspicious Code</div></div>
  <div class="card high"><div class="num">{high}</div><div class="label">High Target</div></div>
  <div class="card med"><div class="num">{potential}</div><div class="label">Potential Risk</div></div>
  <div class="card low"><div class="num">{low}</div><div class="label">Low Risk</div></div>
  <div class="card clean"><div class="num">{clean}</div><div class="label">Clean</div></div>
</div>

<table>
<thead>
<tr>
  <th>File Path</th><th>Risk Level</th><th>Score</th>
  <th>Size</th><th>Findings</th><th>ATT&amp;CK</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""
