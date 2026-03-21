from argus.core.signals import apply_risk_signals
from argus.models.asset import Asset, WebMetadata


def test_admin_keywords_drive_admin_signal():
    asset = Asset(host="dashboard.example.com")
    apply_risk_signals(asset)
    assert "admin_keyword" in asset.risk_signals


def test_non_prod_keywords_drive_non_prod_signal():
    asset = Asset(host="qa.example.com")
    apply_risk_signals(asset)
    assert "non_production_keyword" in asset.risk_signals


def test_backup_keywords_drive_backup_signal():
    asset = Asset(host="backup.example.com")
    apply_risk_signals(asset)
    assert "backup_keyword" in asset.risk_signals


def test_internal_keywords_drive_internal_signal():
    asset = Asset(host="corp.example.com")
    apply_risk_signals(asset)
    assert "internal_keyword" in asset.risk_signals


def test_legacy_keywords_drive_legacy_signal():
    asset = Asset(host="legacy.example.com")
    apply_risk_signals(asset)
    assert "legacy_keyword" in asset.risk_signals


def test_login_keywords_drive_login_signal():
    asset = Asset(
        host="portal.example.com",
        web=WebMetadata(
            url="https://portal.example.com",
            status_code=200,
            title="Sign In",
            server="nginx",
            technologies=[],
            body_preview="",
        ),
    )
    apply_risk_signals(asset)
    assert "login_panel" in asset.risk_signals


def test_admin_panel_keywords_drive_admin_panel_signal():
    asset = Asset(
        host="portal.example.com",
        web=WebMetadata(
            url="https://portal.example.com",
            status_code=200,
            title="Admin Console",
            server="nginx",
            technologies=[],
            body_preview="",
        ),
    )
    apply_risk_signals(asset)
    assert "admin_panel" in asset.risk_signals


def test_default_page_markers_drive_default_page_signal():
    asset = Asset(
        host="web.example.com",
        web=WebMetadata(
            url="http://web.example.com",
            status_code=200,
            title="Welcome",
            server="nginx",
            technologies=[],
            body_preview="welcome to nginx",
        ),
    )
    apply_risk_signals(asset)
    assert "default_page_detected" in asset.risk_signals


def test_directory_listing_markers_drive_directory_listing_signal():
    asset = Asset(
        host="files.example.com",
        web=WebMetadata(
            url="http://files.example.com",
            status_code=200,
            title="Index",
            server="apache",
            technologies=[],
            body_preview="index of /",
        ),
    )
    apply_risk_signals(asset)
    assert "directory_listing_possible" in asset.risk_signals


def test_error_page_markers_drive_error_page_signal():
    asset = Asset(
        host="api.example.com",
        web=WebMetadata(
            url="https://api.example.com",
            status_code=500,
            title="Error",
            server="nginx",
            technologies=[],
            body_preview="internal server error",
        ),
    )
    apply_risk_signals(asset)
    assert "error_page_exposed" in asset.risk_signals