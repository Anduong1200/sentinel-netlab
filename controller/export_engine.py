#!/usr/bin/env python3
"""
Sentinel NetLab - Report Export Engine
Generates HTML and PDF reports from security data.

Supports:
- Security Assessment Reports
- Incident Reports
- Audit Reports
- Executive Summaries
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from string import Template
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportFormat(str, Enum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"


class ReportType(str, Enum):
    SECURITY_ASSESSMENT = "security_assessment"
    INCIDENT = "incident"
    AUDIT = "audit"
    EXECUTIVE = "executive"


@dataclass
class ReportSection:
    """A section within a report"""
    title: str
    content: str
    order: int = 0
    subsections: list['ReportSection'] = field(default_factory=list)


@dataclass
class ReportData:
    """Data container for report generation"""
    report_type: ReportType
    title: str
    generated_at: str
    date_range_start: Optional[str] = None
    date_range_end: Optional[str] = None

    # Summary statistics
    total_networks: int = 0
    critical_risks: int = 0
    high_risks: int = 0
    medium_risks: int = 0
    low_risks: int = 0
    total_alerts: int = 0
    sensors_active: int = 0

    # Detail data
    networks: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    # Metadata
    author: str = "Sentinel NetLab"
    organization: str = ""
    confidentiality: str = "CONFIDENTIAL"


# =============================================================================
# HTML TEMPLATES
# =============================================================================

HTML_BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        :root {
            --primary: #2563eb;
            --danger: #dc2626;
            --warning: #f59e0b;
            --success: #10b981;
            --muted: #6b7280;
            --bg: #f9fafb;
            --card-bg: #ffffff;
            --border: #e5e7eb;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: var(--bg);
            padding: 2rem;
        }

        .container { max-width: 900px; margin: 0 auto; }

        .header {
            background: linear-gradient(135deg, var(--primary), #1d4ed8);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }

        .header h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
        .header .meta { opacity: 0.9; font-size: 0.9rem; }

        .confidential {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-top: 0.5rem;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }

        .stat-card .value {
            font-size: 2rem;
            font-weight: 700;
        }

        .stat-card .label {
            color: var(--muted);
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .stat-card.critical .value { color: var(--danger); }
        .stat-card.high .value { color: #ea580c; }
        .stat-card.medium .value { color: var(--warning); }
        .stat-card.success .value { color: var(--success); }

        .section {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .section h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--primary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: var(--bg);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-critical { background: #fef2f2; color: var(--danger); }
        .badge-high { background: #fff7ed; color: #ea580c; }
        .badge-medium { background: #fffbeb; color: #b45309; }
        .badge-low { background: #f0fdf4; color: var(--success); }

        .finding {
            border-left: 4px solid var(--primary);
            padding: 1rem;
            margin: 1rem 0;
            background: var(--bg);
            border-radius: 0 8px 8px 0;
        }

        .finding.critical { border-left-color: var(--danger); }
        .finding.high { border-left-color: #ea580c; }

        .finding h4 { margin-bottom: 0.5rem; }
        .finding p { color: var(--muted); font-size: 0.9rem; }

        .recommendations ul {
            list-style: none;
            padding: 0;
        }

        .recommendations li {
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border);
            padding-left: 1.5rem;
            position: relative;
        }

        .recommendations li::before {
            content: "→";
            position: absolute;
            left: 0;
            color: var(--primary);
            font-weight: bold;
        }

        .footer {
            text-align: center;
            color: var(--muted);
            font-size: 0.85rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }

        @media print {
            body { background: white; padding: 0; }
            .section { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        ${content}
        <div class="footer">
            Generated by Sentinel NetLab • ${generated_at}
        </div>
    </div>
</body>
</html>
"""

SECURITY_ASSESSMENT_TEMPLATE = """
<div class="header">
    <h1>🛡️ ${title}</h1>
    <div class="meta">
        <div>Period: ${date_range_start} to ${date_range_end}</div>
        <div>Generated: ${generated_at}</div>
    </div>
    <span class="confidential">${confidentiality}</span>
</div>

<div class="summary-grid">
    <div class="stat-card">
        <div class="value">${total_networks}</div>
        <div class="label">Networks</div>
    </div>
    <div class="stat-card critical">
        <div class="value">${critical_risks}</div>
        <div class="label">Critical</div>
    </div>
    <div class="stat-card high">
        <div class="value">${high_risks}</div>
        <div class="label">High Risk</div>
    </div>
    <div class="stat-card medium">
        <div class="value">${medium_risks}</div>
        <div class="label">Medium</div>
    </div>
    <div class="stat-card success">
        <div class="value">${sensors_active}</div>
        <div class="label">Sensors</div>
    </div>
</div>

<div class="section">
    <h2>Executive Summary</h2>
    <p>
        During the assessment period, <strong>${total_networks}</strong> wireless networks
        were analyzed across <strong>${sensors_active}</strong> sensors.
        The analysis identified <strong>${critical_risks}</strong> critical and
        <strong>${high_risks}</strong> high-risk networks requiring immediate attention.
    </p>
</div>

<div class="section">
    <h2>Risk Distribution</h2>
    <table>
        <thead>
            <tr>
                <th>BSSID</th>
                <th>SSID</th>
                <th>Channel</th>
                <th>Security</th>
                <th>Risk</th>
            </tr>
        </thead>
        <tbody>
            ${networks_table}
        </tbody>
    </table>
</div>

<div class="section">
    <h2>Key Findings</h2>
    ${findings_html}
</div>

<div class="section recommendations">
    <h2>Recommendations</h2>
    <ul>
        ${recommendations_html}
    </ul>
</div>
"""


class ReportEngine:
    """Generate reports in various formats"""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("./reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, data: ReportData, format: ReportFormat) -> Path:
        """Generate report in specified format"""
        if format == ReportFormat.HTML:
            return self._generate_html(data)
        elif format == ReportFormat.PDF:
            return self._generate_pdf(data)
        elif format == ReportFormat.JSON:
            return self._generate_json(data)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_html(self, data: ReportData) -> Path:
        """Generate HTML report"""
        # Build networks table
        networks_rows = []
        for net in data.networks[:50]:  # Limit to 50 for readability
            risk_class = net.get('risk_level', 'low').lower()
            networks_rows.append(f"""
                <tr>
                    <td><code>{net.get('bssid', 'N/A')}</code></td>
                    <td>{net.get('ssid', '[Hidden]') or '[Hidden]'}</td>
                    <td>{net.get('channel', 'N/A')}</td>
                    <td>{net.get('security', 'Unknown')}</td>
                    <td><span class="badge badge-{risk_class}">{risk_class.upper()}</span></td>
                </tr>
            """)

        # Build findings HTML
        findings_html = []
        for finding in data.findings[:10]:
            severity = finding.get('severity', 'medium').lower()
            findings_html.append(f"""
                <div class="finding {severity}">
                    <h4>{finding.get('title', 'Finding')}</h4>
                    <p>{finding.get('description', '')}</p>
                </div>
            """)

        # Build recommendations HTML
        recommendations_html = "\n".join(
            f"<li>{rec}</li>" for rec in data.recommendations
        )

        # Fill content template
        content = Template(SECURITY_ASSESSMENT_TEMPLATE).safe_substitute(
            title=data.title,
            date_range_start=data.date_range_start or "N/A",
            date_range_end=data.date_range_end or "N/A",
            generated_at=data.generated_at,
            confidentiality=data.confidentiality,
            total_networks=data.total_networks,
            critical_risks=data.critical_risks,
            high_risks=data.high_risks,
            medium_risks=data.medium_risks,
            sensors_active=data.sensors_active,
            networks_table="\n".join(networks_rows),
            findings_html="\n".join(findings_html) or "<p>No critical findings.</p>",
            recommendations_html=recommendations_html or "<li>No recommendations at this time.</li>"
        )

        # Fill base template
        html = Template(HTML_BASE_TEMPLATE).safe_substitute(
            title=data.title,
            generated_at=data.generated_at,
            content=content
        )

        # Write file
        filename = f"report_{data.report_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = self.output_dir / filename
        output_path.write_text(html, encoding='utf-8')

        logger.info(f"Generated HTML report: {output_path}")
        return output_path

    def _generate_pdf(self, data: ReportData) -> Path:
        """Generate PDF report using weasyprint"""
        # First generate HTML
        html_path = self._generate_html(data)
        pdf_path = html_path.with_suffix('.pdf')

        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"Generated PDF report: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning("weasyprint not installed. Install with: pip install weasyprint")
            logger.info("Returning HTML report instead")
            return html_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return html_path

    def _generate_json(self, data: ReportData) -> Path:
        """Generate JSON report"""
        output = {
            'report_type': data.report_type.value,
            'title': data.title,
            'generated_at': data.generated_at,
            'date_range': {
                'start': data.date_range_start,
                'end': data.date_range_end
            },
            'summary': {
                'total_networks': data.total_networks,
                'critical_risks': data.critical_risks,
                'high_risks': data.high_risks,
                'medium_risks': data.medium_risks,
                'low_risks': data.low_risks,
                'total_alerts': data.total_alerts,
                'sensors_active': data.sensors_active
            },
            'networks': data.networks,
            'alerts': data.alerts,
            'findings': data.findings,
            'recommendations': data.recommendations,
            'metadata': {
                'author': data.author,
                'organization': data.organization,
                'confidentiality': data.confidentiality
            }
        }

        filename = f"report_{data.report_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path = self.output_dir / filename
        output_path.write_text(json.dumps(output, indent=2), encoding='utf-8')

        logger.info(f"Generated JSON report: {output_path}")
        return output_path


def main():
    """CLI for report generation"""
    import argparse

    parser = argparse.ArgumentParser(description='Generate security reports')
    parser.add_argument('--type', choices=['security_assessment', 'incident', 'audit', 'executive'],
                       default='security_assessment', help='Report type')
    parser.add_argument('--format', choices=['html', 'pdf', 'json'], default='html', help='Output format')
    parser.add_argument('--output-dir', default='./reports', help='Output directory')
    parser.add_argument('--demo', action='store_true', help='Generate demo report with sample data')

    args = parser.parse_args()

    if args.demo:
        # Generate demo report with sample data
        data = ReportData(
            report_type=ReportType(args.type),
            title="Wireless Security Assessment Report",
            generated_at=datetime.now(timezone.utc).isoformat(),
            date_range_start="2026-01-01",
            date_range_end="2026-01-28",
            total_networks=47,
            critical_risks=2,
            high_risks=5,
            medium_risks=12,
            low_risks=28,
            total_alerts=23,
            sensors_active=3,
            networks=[
                {'bssid': 'AA:BB:CC:11:22:33', 'ssid': 'OpenCafe', 'channel': 6, 'security': 'Open', 'risk_level': 'critical'},
                {'bssid': 'AA:BB:CC:44:55:66', 'ssid': 'OldRouter', 'channel': 1, 'security': 'WEP', 'risk_level': 'critical'},
                {'bssid': 'AA:BB:CC:77:88:99', 'ssid': 'GuestWiFi', 'channel': 11, 'security': 'WPA2', 'risk_level': 'high'},
            ],
            findings=[
                {'title': 'Open Network Detected', 'description': 'Network "OpenCafe" has no encryption enabled.', 'severity': 'critical'},
                {'title': 'WEP Encryption', 'description': 'Network "OldRouter" uses deprecated WEP encryption.', 'severity': 'critical'},
            ],
            recommendations=[
                'Disable or encrypt open guest networks',
                'Upgrade WEP networks to WPA2 or WPA3',
                'Enable 802.11w (PMF) where supported',
                'Implement network segmentation for IoT devices',
                'Review and update access point firmware'
            ]
        )

        engine = ReportEngine(Path(args.output_dir))
        output = engine.generate(data, ReportFormat(args.format))
        print(f"Demo report generated: {output}")


if __name__ == '__main__':
    main()
