import httpx

from argus.config import (
    ADMIN_KEYWORDS,
    ADMIN_PANEL_KEYWORDS,
    BACKUP_KEYWORDS,
    CONFIDENCE_PRIMARY,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_PAGE_MARKERS,
    DIRECTORY_LISTING_MARKERS,
    ERROR_PAGE_MARKERS,
    INTERNAL_KEYWORDS,
    LEGACY_KEYWORDS,
    LOGIN_KEYWORDS,
    NON_PROD_KEYWORDS,
    UNEXPECTED_STATUS_CODES,
    USER_AGENT,
)
from argus.core.scope import validate_target
from argus.models.asset import Asset, Relationship
from argus.models.finding import Finding
from argus.models.scan import ScanResult, ScanSummary
from argus.modules.discovery import calculate_confidence, discover_subdomains
from argus.modules.dns import resolve_a_records
from argus.modules.ports import scan_common_ports
from argus.modules.tech import fingerprint_technologies
from argus.modules.validate import probe_http
from argus.modules.web import fetch_web_metadata
from argus.utils.logger import get_logger
from argus.core.findings import build_findings_for_asset
from argus.core.signals import apply_risk_signals

logger = get_logger(__name__)

def run_scan(target: str, enable_tech: bool = True) -> ScanResult:
    logger.info("Starting scan for target: %s", target)
    target = validate_target(target)

    assets: list[Asset] = []
    findings: list[Finding] = []

    discovered = discover_subdomains(target)
    summary = ScanSummary(candidate_hosts=len(discovered))
    headers = {"User-Agent": USER_AGENT}

    for host, sources in discovered.items():
        try:
            logger.info("Processing host: %s", host)

            ips = resolve_a_records(host)
            if not ips:
                continue

            summary.resolved_hosts += 1

            asset = Asset(
                host=host,
                ip_addresses=ips,
                discovery_sources=sources,
                confidence=CONFIDENCE_PRIMARY if host == target else calculate_confidence(sources),
                live=False,
            )

            for ip in ips:
                asset.relationships.append(
                    Relationship(
                        relationship_type="resolves_to",
                        source=host,
                        target=ip,
                    )
                )

            asset.services = scan_common_ports(host)
            summary.exposed_services += len(asset.services)

            for service in asset.services:
                asset.relationships.append(
                    Relationship(
                        relationship_type="exposes_service",
                        source=host,
                        target=f"{service.service_name or 'unknown'}:{service.port}",
                    )
                )

            probe = probe_http(host)
            asset.probe = probe

            if probe.preferred_url:
                asset.live = True
                summary.live_web_assets += 1

                web = fetch_web_metadata(probe.preferred_url)
                if web and enable_tech:
                    try:
                        response = httpx.get(
                            probe.preferred_url,
                            timeout=DEFAULT_HTTP_TIMEOUT,
                            follow_redirects=True,
                            headers=headers,
                        )
                        web.technologies = fingerprint_technologies(web, response.text)
                    except Exception:
                        web.technologies = fingerprint_technologies(web, "")

                asset.web = web

                if web and web.technologies:
                    for tech in web.technologies:
                        asset.relationships.append(
                            Relationship(
                                relationship_type="runs_technology",
                                source=host,
                                target=tech,
                            )
                        )

            apply_risk_signals(asset)

            if asset.risk_signals:
                summary.assets_with_signals += 1
                findings.extend(build_findings_for_asset(asset))

            assets.append(asset)

        except Exception as exc:
            logger.exception("Host processing failed for %s: %s", host, exc)
            continue

    return ScanResult(
        target=target,
        assets=assets,
        findings=findings,
        summary=summary,
    )