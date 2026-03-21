from argus.models.asset import Asset, Relationship


def _add_context_tag(asset: Asset, tag: str) -> None:
    if tag not in asset.context_tags:
        asset.context_tags.append(tag)


def _add_relationship(asset: Asset, relationship_type: str, target: str) -> None:
    for relationship in asset.relationships:
        if (
            relationship.relationship_type == relationship_type
            and relationship.source == asset.host
            and relationship.target == target
        ):
            return

    asset.relationships.append(
        Relationship(
            relationship_type=relationship_type,
            source=asset.host,
            target=target,
        )
    )


def build_asset_context(asset: Asset) -> None:
    signals = set(asset.risk_signals)
    technologies = set(asset.web.technologies) if asset.web and asset.web.technologies else set()

    if asset.live:
        _add_context_tag(asset, "internet-facing")

    if asset.web:
        _add_context_tag(asset, "web-application")

    if "admin_panel" in signals or "privileged_interface_exposed" in signals or "multi_signal_admin_surface" in signals:
        _add_context_tag(asset, "admin-surface")
        _add_relationship(asset, "has_context", "admin-surface")

    if "login_panel" in signals or "weakly_protected_entry_point" in signals:
        _add_context_tag(asset, "entry-point")
        _add_relationship(asset, "has_context", "entry-point")

    if "database_service_exposed" in signals or "internal_data_service_exposed" in signals:
        _add_context_tag(asset, "data-service")
        _add_relationship(asset, "has_context", "data-service")

    if "remote_admin_service_exposed" in signals or "public_remote_admin_surface" in signals:
        _add_context_tag(asset, "remote-admin")
        _add_relationship(asset, "has_context", "remote-admin")

    if "internal_keyword" in signals or "externally_exposed_internal_service" in signals:
        _add_context_tag(asset, "internal-facing-pattern")
        _add_relationship(asset, "has_context", "internal-facing-pattern")

    if "non_production_keyword" in signals or "unhardened_non_production_surface" in signals:
        _add_context_tag(asset, "non-production")
        _add_relationship(asset, "has_context", "non-production")

    if "high_value_target_surface" in signals:
        _add_context_tag(asset, "high-value-target")
        _add_relationship(asset, "has_context", "high-value-target")

    if technologies:
        _add_context_tag(asset, "technology-profiled")

    # exposure summary
    if "multi_signal_admin_surface" in signals:
        asset.exposure_summary = "Externally reachable administrative surface with multiple aligned high-risk indicators."
    elif "privileged_interface_exposed" in signals:
        asset.exposure_summary = "Administrative web surface likely exposing privileged operational functionality."
    elif "public_remote_admin_surface" in signals:
        asset.exposure_summary = "Internet-facing remote administration surface with direct host access implications."
    elif "internal_data_service_exposed" in signals:
        asset.exposure_summary = "Data-oriented service with internal-facing characteristics exposed more broadly than expected."
    elif "externally_exposed_internal_service" in signals:
        asset.exposure_summary = "Asset appears internal by naming or role but is externally reachable."
    elif "weakly_protected_entry_point" in signals:
        asset.exposure_summary = "Authentication entry point appears reachable without confirmed transport protection."
    elif "high_value_target_surface" in signals:
        asset.exposure_summary = "High-interest target surface combining an entry or admin point with useful recon indicators."
    elif "unhardened_non_production_surface" in signals:
        asset.exposure_summary = "Non-production environment shows signs of incomplete or weak hardening."
    elif "database_service_exposed" in signals:
        asset.exposure_summary = "Database-related service exposed at the network boundary."
    elif "remote_admin_service_exposed" in signals:
        asset.exposure_summary = "Remote administration capability exposed on a reachable host."
    elif asset.live and asset.web:
        asset.exposure_summary = "Live internet-facing web asset with observable technologies and exposure signals."
    elif asset.live:
        asset.exposure_summary = "Live externally reachable asset."
    else:
        asset.exposure_summary = "Resolved asset with partial exposure context available."

    asset.context_tags = sorted(set(asset.context_tags))