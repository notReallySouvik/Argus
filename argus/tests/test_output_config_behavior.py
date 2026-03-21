from argus.config import CSV_REPORT_NAME, HTML_REPORT_NAME, JSON_REPORT_NAME
from argus.models.scan import ScanResult
from argus.output.csv_writer import write_assets_csv
from argus.output.html_writer import write_html_report
from argus.output.json_writer import write_json_report


def test_json_writer_uses_config_name(tmp_path):
    result = ScanResult(target="example.com")
    output_file = write_json_report(result, tmp_path)
    assert output_file.name == JSON_REPORT_NAME


def test_csv_writer_uses_config_name(tmp_path):
    result = ScanResult(target="example.com")
    output_file = write_assets_csv(result, tmp_path)
    assert output_file.name == CSV_REPORT_NAME


def test_html_writer_uses_config_name(tmp_path):
    result = ScanResult(target="example.com")
    output_file = write_html_report(result, tmp_path)
    assert output_file.name == HTML_REPORT_NAME