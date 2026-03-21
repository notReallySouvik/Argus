import json
from pathlib import Path

from argus.config import JSON_REPORT_NAME
from argus.models.scan import ScanResult


def write_json_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / JSON_REPORT_NAME

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(result.model_dump(), f, indent=2)

    return out_file