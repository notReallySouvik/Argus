from argus.core.signals import apply_risk_signals
from argus.models.asset import Asset, ProbeResult, ServiceExposure, WebMetadata


def test_admin_signal_added_from_hostname():
    asset = Asset(host="admin.example.com")

    apply_risk_signals(asset)

    assert "admin_keyword" in asset.risk_signals


def test_http_only_signal_added_from_probe():
    asset = Asset(
        host="app.example.com",
        probe=ProbeResult(
            http_url="http://app.example.com",
            https_url=None,
            preferred_url="http://app.example.com",
        ),
    )

    apply_risk_signals(asset)

    assert "exposed_http_only" in asset.risk_signals


def test_database_service_signal_added():
    asset = Asset(
        host="db.example.com",
        services=[
            ServiceExposure(
                port=5432,
                protocol="tcp",
                service_name="postgresql",
                classification="database",
            )
        ],
    )

    apply_risk_signals(asset)

    assert "database_service_exposed" in asset.risk_signals


def test_login_panel_signal_added_from_web_title():
    asset = Asset(
        host="portal.example.com",
        web=WebMetadata(
            url="https://portal.example.com",
            status_code=200,
            title="Login",
            server="nginx",
            technologies=[],
            body_preview="",
        ),
    )

    apply_risk_signals(asset)

    assert "login_panel" in asset.risk_signals