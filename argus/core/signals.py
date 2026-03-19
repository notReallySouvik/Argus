from argus.config import (
    ADMIN_KEYWORDS,
    ADMIN_PANEL_KEYWORDS,
    BACKUP_KEYWORDS,
    DEFAULT_PAGE_MARKERS,
    DIRECTORY_LISTING_MARKERS,
    ERROR_PAGE_MARKERS,
    INTERNAL_KEYWORDS,
    LEGACY_KEYWORDS,
    LOGIN_KEYWORDS,
    NON_PROD_KEYWORDS,
    UNEXPECTED_STATUS_CODES,
)
from argus.models.asset import Asset


def apply_risk_signals(asset: Asset) -> None:
    host_lower = asset.host.lower()

    if any(keyword in host_lower for keyword in ADMIN_KEYWORDS):
        asset.risk_signals.append("admin_keyword")

    if any(keyword in host_lower for keyword in NON_PROD_KEYWORDS):
        asset.risk_signals.append("non_production_keyword")

    if any(keyword in host_lower for keyword in BACKUP_KEYWORDS):
        asset.risk_signals.append("backup_keyword")

    if any(keyword in host_lower for keyword in INTERNAL_KEYWORDS):
        asset.risk_signals.append("internal_keyword")

    if any(keyword in host_lower for keyword in LEGACY_KEYWORDS):
        asset.risk_signals.append("legacy_keyword")

    if asset.probe:
        if asset.probe.http_url and not asset.probe.https_url:
            asset.risk_signals.append("exposed_http_only")

        if asset.probe.redirect_chain_detected:
            asset.risk_signals.append("redirect_chain_detected")

    if asset.web:
        title_lower = (asset.web.title or "").strip().lower()
        server_lower = (asset.web.server or "").strip().lower()
        body_lower = (asset.web.body_preview or "").strip().lower()

        if any(keyword in title_lower for keyword in LOGIN_KEYWORDS):
            asset.risk_signals.append("login_panel")

        if any(keyword in title_lower for keyword in ADMIN_PANEL_KEYWORDS):
            asset.risk_signals.append("admin_panel")

        if asset.web.status_code and not title_lower:
            asset.risk_signals.append("empty_title")

        if asset.web.status_code in UNEXPECTED_STATUS_CODES:
            asset.risk_signals.append("unexpected_status_code")

        if any(marker in body_lower for marker in DIRECTORY_LISTING_MARKERS):
            asset.risk_signals.append("directory_listing_possible")

        if any(marker in body_lower for marker in DEFAULT_PAGE_MARKERS):
            asset.risk_signals.append("default_page_detected")

        if any(marker in body_lower for marker in ERROR_PAGE_MARKERS):
            asset.risk_signals.append("error_page_exposed")

        if server_lower and server_lower not in {"cloudflare"}:
            asset.risk_signals.append("unexpected_server_banner")

        if asset.web.technologies:
            asset.risk_signals.append("technology_disclosure")

            if any(t in {"react", "vue.js", "wordpress"} for t in asset.web.technologies):
                asset.risk_signals.append("framework_disclosure")

            if "cloudflare" in asset.web.technologies:
                asset.risk_signals.append("cdn_detected")

    for service in asset.services:
        if service.classification == "remote_admin":
            asset.risk_signals.append("remote_admin_service_exposed")

        if service.classification == "database":
            asset.risk_signals.append("database_service_exposed")

        if service.service_name in {"ftp", "pop3", "imap"}:
            asset.risk_signals.append("plaintext_service_exposed")

    asset.risk_signals = sorted(set(asset.risk_signals))