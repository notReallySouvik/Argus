from argus.core.correlation import apply_correlated_signals
from argus.models.asset import Asset


def test_privileged_interface_exposed():
    asset = Asset(
        host="admin.example.com",
        risk_signals=["admin_keyword", "admin_panel"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "privileged_interface_exposed" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "privileged-interface"
        for rel in asset.relationships
    )


def test_public_remote_admin_surface():
    asset = Asset(
        host="ops.example.com",
        risk_signals=["remote_admin_service_exposed"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "public_remote_admin_surface" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "public-remote-admin"
        for rel in asset.relationships
    )


def test_internal_data_service_exposed():
    asset = Asset(
        host="internal-db.example.com",
        risk_signals=["database_service_exposed", "internal_keyword"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "internal_data_service_exposed" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "internal-data-service"
        for rel in asset.relationships
    )


def test_unhardened_non_production_surface():
    asset = Asset(
        host="staging.example.com",
        risk_signals=["non_production_keyword", "default_page_detected"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "unhardened_non_production_surface" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "unhardened-non-production"
        for rel in asset.relationships
    )


def test_externally_exposed_internal_service():
    asset = Asset(
        host="internal.example.com",
        risk_signals=["internal_keyword"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "externally_exposed_internal_service" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "externally-exposed-internal-service"
        for rel in asset.relationships
    )


def test_high_value_target_surface():
    asset = Asset(
        host="portal.example.com",
        risk_signals=["login_panel", "technology_disclosure"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "high_value_target_surface" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "high-value-target-surface"
        for rel in asset.relationships
    )


def test_weakly_protected_entry_point():
    asset = Asset(
        host="login.example.com",
        risk_signals=["login_panel", "exposed_http_only"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "weakly_protected_entry_point" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "weakly-protected-entry-point"
        for rel in asset.relationships
    )


def test_multi_signal_admin_surface():
    asset = Asset(
        host="admin.example.com",
        risk_signals=["admin_keyword", "admin_panel", "unexpected_server_banner"],
        live=True,
    )

    apply_correlated_signals(asset)

    assert "multi_signal_admin_surface" in asset.risk_signals
    assert any(
        rel.relationship_type == "has_exposure_type"
        and rel.target == "multi-signal-admin-surface"
        for rel in asset.relationships
    )