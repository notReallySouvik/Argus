from collections import defaultdict
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
            max-width: 1200px;
        }
        h1, h2, h3, h4 {
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
            background: #fff;
        }
        .asset-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .asset-block {
            padding: 0.75rem;
            border: 1px solid #eee;
            border-radius: 8px;
            background: #fafafa;
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
        .empty-box {
            padding: 0.8rem;
            border: 1px dashed #ccc;
            border-radius: 8px;
            color: #666;
            margin-bottom: 1.25rem;
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

        <div class="asset-grid">
            <div class="asset-block">
                <h4>Network</h4>
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
            </div>

            <div class="asset-block">
                <h4>Web</h4>
                <p><strong>Title:</strong> {{ asset.web.title if asset.web and asset.web.title else "-" }}</p>
                <p><strong>Status:</strong> {{ asset.web.status_code if asset.web and asset.web.status_code else "-" }}</p>
                <p><strong>Server:</strong> {{ asset.web.server if asset.web and asset.web.server else "-" }}</p>
                <p><strong>Technologies:</strong>
                    {% if asset.web and asset.web.technologies %}
                        {% for tech in asset.web.technologies %}
                            <span class="pill">{{ tech }}</span>
                        {% endfor %}
                    {% else %}
                        <span class="muted">-</span>
                    {% endif %}
                </p>
            </div>

            <div class="asset-block">
                <h4>Signals</h4>
                {% if asset.risk_signals %}
                    {% for signal in asset.risk_signals %}
                        <span class="pill">{{ signal }}</span>
                    {% endfor %}
                {% else %}
                    <p class="muted">-</p>
                {% endif %}
            </div>

            <div class="asset-block">
                <h4>Relationships</h4>
                {% if grouped_relationships[asset.host] %}
                    {% for rel_type, targets in grouped_relationships[asset.host].items() %}
                        <p><strong>{{ rel_type }}:</strong></p>
                        <ul>
                            {% for target in targets %}
                            <li>{{ target }}</li>
                            {% endfor %}
                        </ul>
                    {% endfor %}
                {% else %}
                    <p class="muted">-</p>
                {% endif %}
            </div>
        </div>
    </div>
    {% endfor %}

    <h2>Correlated Findings</h2>
    {% if correlated_findings %}
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
            {% for finding in correlated_findings %}
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
    {% else %}
    <div class="empty-box">No correlated findings were generated for this scan.</div>
    {% endif %}

    <h2>Base Findings</h2>
    {% if base_findings %}
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
            {% for finding in base_findings %}
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
    {% else %}
    <div class="empty-box">No base findings were generated for this scan.</div>
    {% endif %}
</body>
</html>
"""


def write_html_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / HTML_REPORT_NAME

    correlated_findings = [f for f in result.findings if is_correlated_finding(f.signal)]
    base_findings = [f for f in result.findings if not is_correlated_finding(f.signal)]

    grouped_relationships: dict[str, dict[str, list[str]]] = {}
    for asset in result.assets:
        rel_map: dict[str, list[str]] = defaultdict(list)
        for rel in asset.relationships:
            rel_map[rel.relationship_type].append(rel.target)
        grouped_relationships[asset.host] = dict(rel_map)

    template = Template(HTML_TEMPLATE)
    rendered = template.render(
        result=result,
        correlated_findings=correlated_findings,
        base_findings=base_findings,
        grouped_relationships=grouped_relationships,
    )

    out_file.write_text(rendered, encoding="utf-8")
    return out_file