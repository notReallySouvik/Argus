import csv
from pathlib import Path
from argus.models.scan import ScanResult


def write_assets_csv(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "assets.csv"

    with out_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "host",
                "ip_addresses",
                "title",
                "status_code",
                "server",
                "technologies",
                "risk_signals",
                "confidence",
            ]
        )

        for asset in result.assets:
            writer.writerow(
                [
                    asset.host,
                    ", ".join(asset.ip_addresses),
                    asset.web.title if asset.web and asset.web.title else "",
                    asset.web.status_code if asset.web and asset.web.status_code else "",
                    asset.web.server if asset.web and asset.web.server else "",
                    ", ".join(asset.web.technologies) if asset.web else "",
                    ", ".join(asset.risk_signals),
                    asset.confidence,
                ]
            )

    return out_file