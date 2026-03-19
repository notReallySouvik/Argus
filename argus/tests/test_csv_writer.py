from argus.models.scan import ScanResult
from argus.output.csv_writer import write_assets_csv


def test_csv_writer_creates_file(tmp_path):
    result = ScanResult(target="example.com")
    output_file = write_assets_csv(result, tmp_path)

    assert output_file.exists()
    assert output_file.name == "assets.csv"