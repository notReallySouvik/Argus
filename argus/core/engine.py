import httpx

from argus.core.scope import validate_target
from argus.models.asset import Asset
from argus.models.finding import Finding
from argus.models.scan import ScanResult, ScanSummary
from argus.modules.subdomains import generate_candidate_subdomains
from argus.modules.dns import resolve_a_records
from argus.modules.validate import probe_http
from argus.modules.web import fetch_web_metadata
from argus.modules.tech import fingerprint_technologies


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

    return findings


def run_scan(target: str, enable_tech: bool = True) -> ScanResult:
    target = validate_target(target)

    assets: list[Asset] = []
    findings: list[Finding] = []
    candidates = generate_candidate_subdomains(target)

    summary = ScanSummary(candidate_hosts=len(candidates))

    for host in candidates:
        ips = resolve_a_records(host)
        if not ips:
            continue

        summary.resolved_hosts += 1

        asset = Asset(
            host=host,
            ip_addresses=ips,
            confidence=0.70 if host != target else 0.95,
        )

        live_url = probe_http(host)
        if live_url:
            summary.live_web_assets += 1
            web = fetch_web_metadata(live_url)
            if web and enable_tech:
                try:
                    response = httpx.get(live_url, timeout=8.0, follow_redirects=True)
                    web.technologies = fingerprint_technologies(web, response.text)
                except Exception:
                    web.technologies = fingerprint_technologies(web, "")
            asset.web = web

        if "admin" in host:
            asset.risk_signals.append("admin_keyword")
        if "dev" in host or "staging" in host or "test" in host:
            asset.risk_signals.append("non_production_keyword")

        if asset.risk_signals:
            summary.assets_with_signals += 1
            findings.extend(build_findings_for_asset(asset))

        assets.append(asset)

    return ScanResult(
        target=target,
        assets=assets,
        findings=findings,
        summary=summary,
    )