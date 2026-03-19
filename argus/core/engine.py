import httpx

from argus.config import (
    ADMIN_KEYWORDS,
    ADMIN_PANEL_KEYWORDS,
    BACKUP_KEYWORDS,
    CONFIDENCE_PRIMARY,
    CONFIDENCE_SECONDARY,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_PAGE_MARKERS,
    DIRECTORY_LISTING_MARKERS,
    ERROR_PAGE_MARKERS,
    INTERNAL_KEYWORDS,
    LOGIN_KEYWORDS,
    NON_PROD_KEYWORDS,
    LEGACY_KEYWORDS,
    UNEXPECTED_STATUS_CODES,
    USER_AGENT,
)
from argus.core.scope import validate_target
from argus.models.asset import Asset
from argus.models.finding import Finding
from argus.models.scan import ScanResult, ScanSummary
from argus.modules.dns import resolve_a_records
from argus.modules.subdomains import generate_candidate_subdomains
from argus.modules.tech import fingerprint_technologies
from argus.modules.validate import probe_http
from argus.modules.web import fetch_web_metadata
from argus.utils.logger import get_logger

logger = get_logger(__name__)


def build_findings_for_asset(asset: Asset) -> list[Finding]:
    findings: list[Finding] = []

    for signal in asset.risk_signals:
        if signal == "admin_keyword":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Administrative naming pattern detected",
                    severity="high",
                    description="The hostname contains an administrative keyword, which may indicate a sensitive or privileged interface.",
                    signal=signal,
                    confidence=0.75,
                    recommendation="Review whether this asset is intended to be externally reachable and confirm access controls are appropriate.",
                )
            )

        elif signal == "non_production_keyword":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Non-production naming pattern detected",
                    severity="medium",
                    description="The hostname appears to reference a development, staging, or test environment, which may carry elevated exposure risk.",
                    signal=signal,
                    confidence=0.72,
                    recommendation="Verify that non-production environments are not unintentionally exposed and are configured to the same security baseline as production where appropriate.",
                )
            )

        elif signal == "backup_keyword":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Backup-related naming pattern detected",
                    severity="medium",
                    description="The hostname suggests backup-related infrastructure, which may expose old or less tightly controlled systems.",
                    signal=signal,
                    confidence=0.70,
                    recommendation="Review whether this asset is necessary, externally reachable, and aligned with current security controls.",
                )
            )

        elif signal == "internal_keyword":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Internal naming pattern detected",
                    severity="medium",
                    description="The hostname suggests an internal-facing function that may not be intended for internet exposure.",
                    signal=signal,
                    confidence=0.70,
                    recommendation="Verify whether this asset is supposed to be externally accessible and restrict exposure if not required.",
                )
            )

        elif signal == "legacy_keyword":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Legacy naming pattern detected",
                    severity="medium",
                    description="The hostname suggests legacy or outdated infrastructure, which may indicate weaker maintenance or older configurations.",
                    signal=signal,
                    confidence=0.69,
                    recommendation="Review the asset for continued necessity and confirm it meets current security and maintenance standards.",
                )
            )

        elif signal == "exposed_http_only":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="HTTP exposed without HTTPS",
                    severity="high",
                    description="The service appears reachable over HTTP without confirmed HTTPS availability, increasing the risk of insecure transport.",
                    signal=signal,
                    confidence=0.78,
                    recommendation="Enable HTTPS and redirect plain HTTP traffic where appropriate.",
                )
            )

        elif signal == "redirect_chain_detected":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Redirect chain observed",
                    severity="info",
                    description="A redirect chain was observed while probing the asset, which may indicate layered routing or application forwarding behavior.",
                    signal=signal,
                    confidence=0.62,
                    recommendation="Review redirect behavior to ensure it is expected and not masking unintended exposure.",
                )
            )

        elif signal == "unexpected_status_code":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Unexpected web status observed",
                    severity="info",
                    description="The web service responded with a status code that may indicate restricted access, application instability, or error conditions.",
                    signal=signal,
                    confidence=0.64,
                    recommendation="Review the observed response and confirm whether the status is expected for this asset.",
                )
            )

        elif signal == "login_panel":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Login interface detected",
                    severity="medium",
                    description="The web page title suggests the presence of a login interface, which may indicate an authentication surface exposed to the internet.",
                    signal=signal,
                    confidence=0.68,
                    recommendation="Confirm that the login surface is intended to be publicly reachable and protected by appropriate access controls and monitoring.",
                )
            )

        elif signal == "admin_panel":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Administrative interface detected",
                    severity="high",
                    description="The page appears to expose an administrative interface, which may represent a sensitive operational surface.",
                    signal=signal,
                    confidence=0.76,
                    recommendation="Confirm the interface is intentionally exposed and protected with strong access controls, authentication, and monitoring.",
                )
            )

        elif signal == "empty_title":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Web service returned an empty page title",
                    severity="info",
                    description="A live web service responded without a meaningful HTML title, which can indicate a bare service, default page, or incomplete configuration.",
                    signal=signal,
                    confidence=0.55,
                    recommendation="Review the asset to confirm whether the service is expected and whether default or incomplete configurations are exposed.",
                )
            )

        elif signal == "directory_listing_possible":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Possible directory listing exposure",
                    severity="high",
                    description="The response body contains markers commonly associated with directory listing pages.",
                    signal=signal,
                    confidence=0.80,
                    recommendation="Disable directory listing and confirm that file or directory indexes are not publicly exposed.",
                )
            )

        elif signal == "default_page_detected":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Default web page detected",
                    severity="medium",
                    description="The response appears to contain a default server or platform landing page, which may indicate incomplete deployment or unintended exposure.",
                    signal=signal,
                    confidence=0.74,
                    recommendation="Review whether the asset should expose a default page and confirm that unused services are removed or hardened.",
                )
            )

        elif signal == "error_page_exposed":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Error page exposed",
                    severity="info",
                    description="The response body contains markers commonly associated with application or server error pages.",
                    signal=signal,
                    confidence=0.63,
                    recommendation="Review whether the exposed error condition is expected and minimize unnecessary error detail disclosure where possible.",
                )
            )

        elif signal == "unexpected_server_banner":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Server banner disclosed",
                    severity="info",
                    description="The web service exposed a server header that may reveal implementation details useful for reconnaissance.",
                    signal=signal,
                    confidence=0.60,
                    recommendation="Consider minimizing unnecessary server banner disclosure where operationally appropriate.",
                )
            )

        elif signal == "technology_disclosure":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Technology stack disclosure detected",
                    severity="info",
                    description="The asset appears to disclose elements of its technology stack through headers, content, or fingerprinting markers.",
                    signal=signal,
                    confidence=0.66,
                    recommendation="Review whether technology disclosure can be reduced without affecting normal operations.",
                )
            )

        elif signal == "framework_disclosure":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="Framework disclosure detected",
                    severity="info",
                    description="The asset appears to reveal framework-level implementation details that may help profile the application stack.",
                    signal=signal,
                    confidence=0.67,
                    recommendation="Review exposed framework indicators and reduce unnecessary implementation disclosure where feasible.",
                )
            )

        elif signal == "cdn_detected":
            findings.append(
                Finding(
                    asset=asset.host,
                    title="CDN presence detected",
                    severity="info",
                    description="The asset appears to be served behind a content delivery network, which is useful infrastructure context during reconnaissance.",
                    signal=signal,
                    confidence=0.70,
                    recommendation="Confirm CDN configuration is expected and that origin exposure is appropriately restricted.",
                )
            )

    return findings


def apply_risk_signals(asset: Asset) -> None:
    host_lower = asset.host.lower()

    if any(keyword in host_lower for keyword in ADMIN_KEYWORDS):
        if "admin_keyword" not in asset.risk_signals:
            asset.risk_signals.append("admin_keyword")

    if any(keyword in host_lower for keyword in NON_PROD_KEYWORDS):
        if "non_production_keyword" not in asset.risk_signals:
            asset.risk_signals.append("non_production_keyword")

    if any(keyword in host_lower for keyword in BACKUP_KEYWORDS):
        if "backup_keyword" not in asset.risk_signals:
            asset.risk_signals.append("backup_keyword")

    if any(keyword in host_lower for keyword in INTERNAL_KEYWORDS):
        if "internal_keyword" not in asset.risk_signals:
            asset.risk_signals.append("internal_keyword")

    if any(keyword in host_lower for keyword in LEGACY_KEYWORDS):
        if "legacy_keyword" not in asset.risk_signals:
            asset.risk_signals.append("legacy_keyword")

    if asset.probe:
        if asset.probe.http_url and not asset.probe.https_url:
            if "exposed_http_only" not in asset.risk_signals:
                asset.risk_signals.append("exposed_http_only")

        if asset.probe.https_url and "https_available" not in asset.risk_signals:
            asset.risk_signals.append("https_available")

        if asset.probe.redirect_chain_detected and "redirect_chain_detected" not in asset.risk_signals:
            asset.risk_signals.append("redirect_chain_detected")

    if asset.web:
        title_lower = (asset.web.title or "").strip().lower()
        server_lower = (asset.web.server or "").strip().lower()
        body_lower = (asset.web.body_preview or "").strip().lower()

        if any(keyword in title_lower for keyword in LOGIN_KEYWORDS):
            if "login_panel" not in asset.risk_signals:
                asset.risk_signals.append("login_panel")

        if any(keyword in title_lower for keyword in ADMIN_PANEL_KEYWORDS):
            if "admin_panel" not in asset.risk_signals:
                asset.risk_signals.append("admin_panel")

        if asset.web.status_code and not title_lower:
            if "empty_title" not in asset.risk_signals:
                asset.risk_signals.append("empty_title")

        if asset.web.status_code in UNEXPECTED_STATUS_CODES:
            if "unexpected_status_code" not in asset.risk_signals:
                asset.risk_signals.append("unexpected_status_code")

        if any(marker in body_lower for marker in DIRECTORY_LISTING_MARKERS):
            if "directory_listing_possible" not in asset.risk_signals:
                asset.risk_signals.append("directory_listing_possible")

        if any(marker in body_lower for marker in DEFAULT_PAGE_MARKERS):
            if "default_page_detected" not in asset.risk_signals:
                asset.risk_signals.append("default_page_detected")

        if any(marker in body_lower for marker in ERROR_PAGE_MARKERS):
            if "error_page_exposed" not in asset.risk_signals:
                asset.risk_signals.append("error_page_exposed")

        if server_lower and server_lower not in {"cloudflare"}:
            if "unexpected_server_banner" not in asset.risk_signals:
                asset.risk_signals.append("unexpected_server_banner")

        if asset.web.technologies:
            if "technology_disclosure" not in asset.risk_signals:
                asset.risk_signals.append("technology_disclosure")

            framework_markers = {"react", "vue.js", "wordpress"}
            if any(t in framework_markers for t in asset.web.technologies):
                if "framework_disclosure" not in asset.risk_signals:
                    asset.risk_signals.append("framework_disclosure")

            if "cloudflare" in asset.web.technologies:
                if "cdn_detected" not in asset.risk_signals:
                    asset.risk_signals.append("cdn_detected")


def run_scan(target: str, enable_tech: bool = True) -> ScanResult:
    logger.info("Starting scan for target: %s", target)
    target = validate_target(target)

    assets: list[Asset] = []
    findings: list[Finding] = []
    candidates = generate_candidate_subdomains(target)

    summary = ScanSummary(candidate_hosts=len(candidates))
    headers = {"User-Agent": USER_AGENT}

    for host in candidates:
        try:
            logger.info("Processing host: %s", host)

            ips = resolve_a_records(host)
            if not ips:
                logger.debug("No A records found for host: %s", host)
                continue

            summary.resolved_hosts += 1

            asset = Asset(
                host=host,
                ip_addresses=ips,
                confidence=CONFIDENCE_SECONDARY if host != target else CONFIDENCE_PRIMARY,
            )

            probe = probe_http(host)
            asset.probe = probe

            if probe.preferred_url:
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
                    except httpx.HTTPError as exc:
                        logger.debug("Technology fingerprint fetch failed for %s: %s", probe.preferred_url, exc)
                        web.technologies = fingerprint_technologies(web, "")
                    except Exception as exc:
                        logger.exception("Unexpected technology fingerprint error for %s: %s", probe.preferred_url, exc)
                        web.technologies = fingerprint_technologies(web, "")

                asset.web = web

            apply_risk_signals(asset)

            if asset.risk_signals:
                summary.assets_with_signals += 1
                findings.extend(build_findings_for_asset(asset))

            assets.append(asset)

        except Exception as exc:
            logger.exception("Host processing failed for %s: %s", host, exc)
            continue

    result = ScanResult(
        target=target,
        assets=assets,
        findings=findings,
        summary=summary,
    )

    logger.info(
        "Scan complete for %s | assets=%d findings=%d resolved=%d live_web=%d",
        target,
        len(result.assets),
        len(result.findings),
        result.summary.resolved_hosts,
        result.summary.live_web_assets,
    )

    return result