from argus.core.context import build_asset_context
from argus.models.asset import Asset, ServiceExposure, WebMetadata


def test_context_adds_admin_surface_and_summary():
    asset = Asset(
        host="admin.example.com",
        live=True,
        risk_signals=["admin_panel", "privileged_interface_exposed"],
        web=WebMetadata(
            url="https://admin.example.com",
            status_code=200,
            title="Admin Console",
            server="nginx",
            technologies=["nginx"],
            body_preview="",
        ),
    )

    build_asset_context(asset)

    assert "admin-surface" in asset.context_tags
    assert "internet-facing" in asset.context_tags
    assert "web-application" in asset.context_tags
    assert asset.exposure_summary is not None
    assert "administrative" in asset.exposure_summary.lower()
    assert any(
        rel.relationship_type == "has_context"
        and rel.target == "admin-surface"
        for rel in asset.relationships
    )


def test_context_adds_data_service_tag():
    asset = Asset(
        host="db.example.com",
        live=True,
        risk_signals=["database_service_exposed", "internal_data_service_exposed"],
        services=[
            ServiceExposure(
                port=5432,
                protocol="tcp",
                service_name="postgresql",
                classification="database",
            )
        ],
    )

    build_asset_context(asset)

    assert "data-service" in asset.context_tags
    assert asset.exposure_summary is not None
    assert "data" in asset.exposure_summary.lower()


def test_context_adds_remote_admin_tag():
    asset = Asset(
        host="ops.example.com",
        live=True,
        risk_signals=["remote_admin_service_exposed", "public_remote_admin_surface"],
        services=[
            ServiceExposure(
                port=22,
                protocol="tcp",
                service_name="ssh",
                classification="remote_admin",
            )
        ],
    )

    build_asset_context(asset)

    assert "remote-admin" in asset.context_tags
    assert asset.exposure_summary is not None
    assert "remote administration" in asset.exposure_summary.lower()


def test_context_adds_entry_point_tag():
    asset = Asset(
        host="login.example.com",
        live=True,
        risk_signals=["login_panel", "weakly_protected_entry_point"],
        web=WebMetadata(
            url="http://login.example.com",
            status_code=200,
            title="Login",
            server="nginx",
            technologies=["nginx"],
            body_preview="",
        ),
    )

    build_asset_context(asset)

    assert "entry-point" in asset.context_tags
    assert asset.exposure_summary is not None
    assert "authentication entry point" in asset.exposure_summary.lower()


def test_context_adds_non_production_tag():
    asset = Asset(
        host="staging.example.com",
        live=True,
        risk_signals=["non_production_keyword", "unhardened_non_production_surface"],
        web=WebMetadata(
            url="https://staging.example.com",
            status_code=200,
            title="Welcome",
            server="nginx",
            technologies=["nginx"],
            body_preview="welcome to nginx",
        ),
    )

    build_asset_context(asset)

    assert "non-production" in asset.context_tags
    assert asset.exposure_summary is not None
    assert "non-production" in asset.exposure_summary.lower()


def test_context_adds_internal_facing_pattern_tag():
    asset = Asset(
        host="internal.example.com",
        live=True,
        risk_signals=["internal_keyword", "externally_exposed_internal_service"],
    )

    build_asset_context(asset)

    assert "internal-facing-pattern" in asset.context_tags
    assert asset.exposure_summary is not None
    assert "internal" in asset.exposure_summary.lower()


def test_context_adds_technology_profiled_tag():
    asset = Asset(
        host="app.example.com",
        live=True,
        risk_signals=[],
        web=WebMetadata(
            url="https://app.example.com",
            status_code=200,
            title="App",
            server="nginx",
            technologies=["react", "nginx"],
            body_preview="",
        ),
    )

    build_asset_context(asset)

    assert "technology-profiled" in asset.context_tags
    assert "web-application" in asset.context_tags
    assert "internet-facing" in asset.context_tags


def test_context_has_fallback_summary():
    asset = Asset(
        host="example.com",
        live=False,
        risk_signals=[],
    )

    build_asset_context(asset)

    assert asset.exposure_summary is not None
    assert "partial exposure context" in asset.exposure_summary.lower()