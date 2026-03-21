from pathlib import Path

from jinja2 import Template

from argus.config import HTML_REPORT_NAME
from argus.core.findings import is_correlated_finding
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
        h1, h2, h3 {
            margin-bottom: 0.5rem;
        }
        .summary {
            margin-bottom: 2rem;
            padding: 1rem;
            background: #f5f5f5;
            border-radius: 8px;
        }
        .asset-card {
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1.25rem;
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
        .muted { color: #666; }
        .pill {
            display: inline-block;
            padding: 0.15rem 0.45rem;
            margin: 0.1rem 0.2rem 0.1rem 0;
            background: #eef2f7;
            border-radius: 999px;
            font-size: 0.9rem;
        }
        ul {
            margin: 0.25rem 0 0.5rem 1rem;
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

    <h2>Asset Context Overview</h2>
    {% for asset in result.assets %}
    <div class="asset-card">
        <h3>{{ asset.host }}</h3>
        <p><strong>Live:</strong> {{ "yes" if asset.live else "no" }}</p>
        <p><strong>Confidence:</strong> {{ asset.confidence }}</p>
        <p><strong>Exposure Summary:</strong> {{ asset.exposure_summary if asset.exposure_summary else "-" }}</p>

        <p><strong>Context Tags:</strong>
            {% if asset.context_tags %}
                {% for tag in asset.context_tags %}
                    <span class="pill">{{ tag }}</span>
                {% endfor %}
            {% else %}
                <span class="muted">-</span>
            {% endif %}
        </p>

        <p><strong>Discovery Sources:</strong>
            {% if asset.discovery_sources %}
                {% for source in asset.discovery_sources %}
                    <span class="pill">{{ source.name }}</span>
                {% endfor %}
            {% else %}
                <span class="muted">-</span>
            {% endif %}
        </p>

        <p><strong>IP Addresses:</strong> {{ ", ".join(asset.ip_addresses) if asset.ip_addresses else "-" }}</p>

        <p><strong>Services:</strong></p>
        {% if asset.services %}
        <ul>
            {% for svc in asset.services %}
            <li>{{ svc.service_name or "unknown" }}:{{ svc.port }}{% if svc.classification %} <span class="muted">({{ svc.classification }})</span>{% endif %}</li>
            {% endfor %}
        </ul>
        {% else %}
        <p class="muted">-</p>
        {% endif %}

        <p><strong>Technologies:</strong>
            {% if asset.web and asset.web.technologies %}
                {% for tech in asset.web.technologies %}
                    <span class="pill">{{ tech }}</span>
                {% endfor %}
            {% else %}
                <span class="muted">-</span>
            {% endif %}
        </p>

        <p><strong>Signals:</strong>
            {% if asset.risk_signals %}
                {% for signal in asset.risk_signals %}
                    <span class="pill">{{ signal }}</span>
                {% endfor %}
            {% else %}
                <span class="muted">-</span>
            {% endif %}
        </p>

        <p><strong>Relationships:</strong></p>
        {% if asset.relationships %}
        <ul>
            {% for rel in asset.relationships %}
            <li>{{ rel.relationship_type }} → {{ rel.target }}</li>
            {% endfor %}
        </ul>
        {% else %}
        <p class="muted">-</p>
        {% endif %}
    </div>
    {% endfor %}

    <h2>Correlated Findings</h2>
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
                {% if is_correlated_finding(finding.signal) %}
                <tr>
                    <td>{{ finding.asset }}</td>
                    <td>{{ finding.title }}</td>
                    <td class="severity-{{ finding.severity }}">{{ finding.severity }}</td>
                    <td>{{ finding.description }}</td>
                    <td>{{ finding.impact if finding.impact else "-" }}</td>
                    <td>{{ finding.recommendation if finding.recommendation else "-" }}</td>
                </tr>
                {% endif %}
            {% endfor %}
        </tbody>
    </table>

    <h2>Base Findings</h2>
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
                {% if not is_correlated_finding(finding.signal) %}
                <tr>
                    <td>{{ finding.asset }}</td>
                    <td>{{ finding.title }}</td>
                    <td class="severity-{{ finding.severity }}">{{ finding.severity }}</td>
                    <td>{{ finding.description }}</td>
                    <td>{{ finding.impact if finding.impact else "-" }}</td>
                    <td>{{ finding.recommendation if finding.recommendation else "-" }}</td>
                </tr>
                {% endif %}
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
    rendered = template.render(result=result, is_correlated_finding=is_correlated_finding)

    out_file.write_text(rendered, encoding="utf-8")
    return out_file