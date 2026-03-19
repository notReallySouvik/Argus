from argus.core.findings import build_findings_for_asset
from argus.models.asset import Asset


def test_admin_keyword_finding_has_impact():
    asset = Asset(
        host="admin.example.com",
        risk_signals=["admin_keyword"],
        confidence=0.9,
    )

    findings = build_findings_for_asset(asset)

    assert len(findings) == 1
    f = findings[0]

    assert f.severity == "high"
    assert f.impact is not None
    assert "admin" in f.title.lower()


def test_database_service_finding_has_high_severity():
    asset = Asset(
        host="db.example.com",
        risk_signals=["database_service_exposed"],
        confidence=0.85,
    )

    findings = build_findings_for_asset(asset)

    assert len(findings) == 1
    f = findings[0]

    assert f.severity == "high"
    assert f.impact is not None
    assert "database" in f.title.lower()


def test_http_only_finding_has_useful_impact():
    asset = Asset(
        host="app.example.com",
        risk_signals=["exposed_http_only"],
        confidence=0.8,
    )

    findings = build_findings_for_asset(asset)

    assert len(findings) == 1
    f = findings[0]

    assert f.severity == "high"
    assert f.impact is not None
    assert "http" in f.title.lower()