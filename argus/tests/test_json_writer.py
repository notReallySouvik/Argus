import json

from argus.models.scan import ScanResult
from argus.output.json_writer import write_json_report


def test_write_json_report_creates_file(tmp_path):
    result = ScanResult(target="example.com")
    output_file = write_json_report(result, tmp_path)

    assert output_file.exists()
    assert output_file.name == "findings.json"


def test_write_json_report_contains_expected_keys(tmp_path):
    result = ScanResult(target="example.com")
    output_file = write_json_report(result, tmp_path)

    data = json.loads(output_file.read_text(encoding="utf-8"))

    assert "target" in data
    assert "assets" in data
    assert "findings" in data
    assert "summary" in data