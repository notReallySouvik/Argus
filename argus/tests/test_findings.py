from argus.core.engine import build_findings_for_asset
from argus.models.asset import Asset


def test_admin_keyword_generates_high_finding():
    asset = Asset(host="admin.example.com", risk_signals=["admin_keyword"])
    findings = build_findings_for_asset(asset)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].signal == "admin_keyword"


def test_non_production_keyword_generates_medium_finding():
    asset = Asset(host="dev.example.com", risk_signals=["non_production_keyword"])
    findings = build_findings_for_asset(asset)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].signal == "non_production_keyword"


def test_backup_keyword_generates_medium_finding():
    asset = Asset(host="backup.example.com", risk_signals=["backup_keyword"])
    findings = build_findings_for_asset(asset)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].signal == "backup_keyword"