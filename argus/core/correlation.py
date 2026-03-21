from argus.core.correlation_rules import get_exposure_type
from argus.models.asset import Asset, Relationship


def _add_signal(asset: Asset, signal: str) -> None:
    if signal not in asset.risk_signals:
        asset.risk_signals.append(signal)


def _add_exposure_relationship(asset: Asset, signal: str) -> None:
    exposure_type = get_exposure_type(signal)
    if not exposure_type:
        return

    for relationship in asset.relationships:
        if (
            relationship.relationship_type == "has_exposure_type"
            and relationship.source == asset.host
            and relationship.target == exposure_type
        ):
            return

    asset.relationships.append(
        Relationship(
            relationship_type="has_exposure_type",
            source=asset.host,
            target=exposure_type,
        )
    )


def apply_correlated_signals(asset: Asset) -> None:
    signals = set(asset.risk_signals)

    # 1. privileged_interface_exposed
    if "admin_keyword" in signals and "admin_panel" in signals:
        _add_signal(asset, "privileged_interface_exposed")

    # 2. public_remote_admin_surface
    if "remote_admin_service_exposed" in signals and asset.live:
        _add_signal(asset, "public_remote_admin_surface")

    # 3. internal_data_service_exposed
    if "database_service_exposed" in signals and "internal_keyword" in signals:
        _add_signal(asset, "internal_data_service_exposed")

    # 4. unhardened_non_production_surface
    if "non_production_keyword" in signals and (
        "default_page_detected" in signals or "empty_title" in signals
    ):
        _add_signal(asset, "unhardened_non_production_surface")

    # 5. externally_exposed_internal_service
    if "internal_keyword" in signals and asset.live:
        _add_signal(asset, "externally_exposed_internal_service")

    # 6. high_value_target_surface
    if (
        "admin_panel" in signals or "login_panel" in signals
    ) and (
        "technology_disclosure" in signals
        or "unexpected_server_banner" in signals
        or "redirect_chain_detected" in signals
    ):
        _add_signal(asset, "high_value_target_surface")

    # 7. weakly_protected_entry_point
    if "login_panel" in signals and "exposed_http_only" in signals:
        _add_signal(asset, "weakly_protected_entry_point")

    # 8. multi_signal_admin_surface
    if (
        "admin_keyword" in signals
        and "admin_panel" in signals
        and ("login_panel" in signals or "unexpected_server_banner" in signals)
    ):
        _add_signal(asset, "multi_signal_admin_surface")

    asset.risk_signals = sorted(set(asset.risk_signals))

    for signal in asset.risk_signals:
        _add_exposure_relationship(asset, signal)