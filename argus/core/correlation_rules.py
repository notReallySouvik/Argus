CORRELATED_RULES = {
    "privileged_interface_exposed": {
        "exposure_type": "privileged-interface",
        "priority": 95,
        "category": "administrative-surface",
    },
    "public_remote_admin_surface": {
        "exposure_type": "public-remote-admin",
        "priority": 95,
        "category": "remote-access",
    },
    "internal_data_service_exposed": {
        "exposure_type": "internal-data-service",
        "priority": 92,
        "category": "data-exposure",
    },
    "unhardened_non_production_surface": {
        "exposure_type": "unhardened-non-production",
        "priority": 78,
        "category": "non-production-exposure",
    },
    "externally_exposed_internal_service": {
        "exposure_type": "externally-exposed-internal-service",
        "priority": 90,
        "category": "internal-service-exposure",
    },
    "high_value_target_surface": {
        "exposure_type": "high-value-target-surface",
        "priority": 85,
        "category": "high-value-surface",
    },
    "weakly_protected_entry_point": {
        "exposure_type": "weakly-protected-entry-point",
        "priority": 88,
        "category": "entry-point",
    },
    "multi_signal_admin_surface": {
        "exposure_type": "multi-signal-admin-surface",
        "priority": 96,
        "category": "administrative-surface",
    },
}

CORRELATED_SIGNALS = set(CORRELATED_RULES.keys())


def get_exposure_type(signal: str) -> str | None:
    rule = CORRELATED_RULES.get(signal)
    if not rule:
        return None
    return rule["exposure_type"]


def get_correlation_priority(signal: str) -> int:
    rule = CORRELATED_RULES.get(signal)
    if not rule:
        return 0
    return int(rule["priority"])


def get_correlation_category(signal: str) -> str | None:
    rule = CORRELATED_RULES.get(signal)
    if not rule:
        return None
    return rule["category"]