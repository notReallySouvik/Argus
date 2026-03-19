from pathlib import Path

from jinja2 import Template

from argus.config import HTML_REPORT_NAME
from argus.models.scan import ScanResult


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Argus Report - {{ result.target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 2rem;
            line-height: 1.5;
            color: #222;
        }
        h1, h2 {
            margin-bottom: 0.5rem;
        }
        .summary {
            margin-bottom: 2rem;
            padding: 1rem;
            background: #f5f5f5;
            border-radius: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 0.75rem;
            text-align: left;
            vertical-align: top;
        }
        th {
            background: #f0f0f0;
        }
        .severity-high { color: #b00020; font-weight: bold; }
        .severity-medium { color: #9c6500; font-weight: bold; }
        .severity-info { color: #005a9c; font-weight: bold; }
        .severity-low { color: #0a7a2f; font-weight: bold; }
        ul {
            margin: 0;
            padding-left: 1.2rem;
        }
        .muted {
            color: #666;
        }
        .pill {
            display: inline-block;
            padding: 0.15rem 0.45rem;
            margin: 0.1rem 0.2rem 0.1rem 0;
            background: #eef2f7;
            border-radius: 999px;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <h1>Argus Attack Surface Report</h1>
    <p><strong>Target:</strong> {{ result.target }}</p>

    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Candidate hosts:</strong> {{ result.summary.candidate_hosts }}</p>
        <p><strong>Resolved hosts:</strong> {{ result.summary.resolved_hosts }}</p>
        <p><strong>Live web assets:</strong> {{ result.summary.live_web_assets }}</p>
        <p><strong>Exposed services:</strong> {{ result.summary.exposed_services }}</p>
        <p><strong>Assets with signals:</strong> {{ result.summary.assets_with_signals }}</p>
        <p><strong>Total findings:</strong> {{ result.findings | length }}</p>
    </div>

    <h2>Assets</h2>
    <table>
        <thead>
            <tr>
                <th>Host</th>
                <th>Live</th>
                <th>Confidence</th>
                <th>Discovery Sources</th>
                <th>IPs</th>
                <th>Services</th>
                <th>Title</th>
                <th>Status</th>
                <th>Server</th>
                <th>Technologies</th>
                <th>Signals</th>
            </tr>
        </thead>
        <tbody>
            {% for asset in result.assets %}
            <tr>
                <td>{{ asset.host }}</td>
                <td>{{ "yes" if asset.live else "no" }}</td>
                <td>{{ asset.confidence }}</td>
                <td>
                    {% if asset.discovery_sources %}
                        {% for source in asset.discovery_sources %}
                            <span class="pill">{{ source.name }}</span>
                        {% endfor %}
                    {% else %}
                        <span class="muted">-</span>
                    {% endif %}
                </td>
                <td>{{ ", ".join(asset.ip_addresses) if asset.ip_addresses else "-" }}</td>
                <td>
                    {% if asset.services %}
                        <ul>
                        {% for svc in asset.services %}
                            <li>{{ svc.service_name or "unknown" }}:{{ svc.port }}{% if svc.classification %} <span class="muted">({{ svc.classification }})</span>{% endif %}</li>
                        {% endfor %}
                        </ul>
                    {% else %}
                        -
                    {% endif %}
                </td>
                <td>{{ asset.web.title if asset.web and asset.web.title else "-" }}</td>
                <td>{{ asset.web.status_code if asset.web and asset.web.status_code else "-" }}</td>
                <td>{{ asset.web.server if asset.web and asset.web.server else "-" }}</td>
                <td>
                    {% if asset.web and asset.web.technologies %}
                        {% for tech in asset.web.technologies %}
                            <span class="pill">{{ tech }}</span>
                        {% endfor %}
                    {% else %}
                        -
                    {% endif %}
                </td>
                <td>
                    {% if asset.risk_signals %}
                        {% for signal in asset.risk_signals %}
                            <span class="pill">{{ signal }}</span>
                        {% endfor %}
                    {% else %}
                        -
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

        <h2>Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Asset</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Meaning / Likely Cause</th>
                <th>Potential Impact</th>
                <th>Recommended Review</th>
            </tr>
        </thead>
        <tbody>
            {% for finding in result.findings %}
            <tr>
                <td>{{ finding.asset }}</td>
                <td>{{ finding.title }}</td>
                <td class="severity-{{ finding.severity }}">{{ finding.severity }}</td>
                <td>{{ finding.description }}</td>
                <td>{{ finding.impact if finding.impact else "-" }}</td>
                <td>{{ finding.recommendation if finding.recommendation else "-" }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""


def write_html_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / HTML_REPORT_NAME

    template = Template(HTML_TEMPLATE)
    rendered = template.render(result=result)

    out_file.write_text(rendered, encoding="utf-8")
    return out_file