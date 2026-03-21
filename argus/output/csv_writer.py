import csv
from pathlib import Path

from argus.config import CSV_REPORT_NAME
from argus.models.scan import ScanResult


def write_assets_csv(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / CSV_REPORT_NAME

    with out_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "host",
                "live",
                "confidence",
                "exposure_summary",
                "context_tags",
                "discovery_sources",
                "ip_addresses",
                "services",
                "title",
                "status_code",
                "server",
                "technologies",
                "risk_signals",
                "relationships",
            ]
        )

        for asset in result.assets:
            discovery_sources = (
                ", ".join(source.name for source in asset.discovery_sources)
                if asset.discovery_sources
                else ""
            )

            services = (
                ", ".join(
                    f"{svc.service_name or 'unknown'}:{svc.port}"
                    + (f" ({svc.classification})" if svc.classification else "")
                    for svc in asset.services
                )
                if asset.services
                else ""
            )

            relationships = (
                ", ".join(
                    f"{rel.relationship_type}:{rel.target}"
                    for rel in asset.relationships
                )
                if asset.relationships
                else ""
            )

            context_tags = ", ".join(asset.context_tags) if asset.context_tags else ""

            writer.writerow(
                [
                    asset.host,
                    asset.live,
                    asset.confidence,
                    asset.exposure_summary or "",
                    context_tags,
                    discovery_sources,
                    ", ".join(asset.ip_addresses),
                    services,
                    asset.web.title if asset.web and asset.web.title else "",
                    asset.web.status_code if asset.web and asset.web.status_code else "",
                    asset.web.server if asset.web and asset.web.server else "",
                    ", ".join(asset.web.technologies) if asset.web else "",
                    ", ".join(asset.risk_signals),
                    relationships,
                ]
            )

    return out_file