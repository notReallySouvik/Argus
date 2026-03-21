from argus.core.correlation_rules import CORRELATED_SIGNALS
from argus.models.asset import Asset
from argus.models.finding import Finding


SIGNAL_DETAILS = {
    "admin_keyword": {
        "title": "Administrative naming pattern detected",
        "severity": "high",
        "description": "The hostname contains terms commonly associated with administrative or control interfaces.",
        "impact": "This may expose a privileged operational surface that attackers would prioritize.",
        "recommendation": "Confirm whether this asset is intended to be internet-facing and review access controls.",
    },
    "non_production_keyword": {
        "title": "Non-production naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests a development, staging, test, QA, or beta environment.",
        "impact": "Non-production environments are often less hardened and may expose weaker controls.",
        "recommendation": "Review whether this environment should be public and confirm it follows an appropriate security baseline.",
    },
    "backup_keyword": {
        "title": "Backup-related naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests backup, archive, or snapshot-related infrastructure.",
        "impact": "Backup-related assets may expose stale data or overlooked systems.",
        "recommendation": "Verify whether this asset is still needed and review retained data or outdated services.",
    },
    "internal_keyword": {
        "title": "Internal naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests an internal-facing purpose such as corporate, staff, or internal operations.",
        "impact": "If exposed externally, it may reveal systems not meant for public access.",
        "recommendation": "Confirm whether this asset should be public at all and restrict access if not required.",
    },
    "legacy_keyword": {
        "title": "Legacy naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests an older or legacy system.",
        "impact": "Legacy systems are more likely to have outdated configurations or weaker maintenance.",
        "recommendation": "Review whether the system is still required and confirm current hardening and patching status.",
    },
    "exposed_http_only": {
        "title": "HTTP exposed without HTTPS",
        "severity": "high",
        "description": "The asset appears reachable over plain HTTP without confirmed HTTPS support.",
        "impact": "Traffic may be vulnerable to interception or tampering.",
        "recommendation": "Enable HTTPS and redirect HTTP traffic to HTTPS.",
    },
    "redirect_chain_detected": {
        "title": "Redirect chain observed",
        "severity": "info",
        "description": "The asset redirected requests before reaching the final page.",
        "impact": "Unexpected redirect chains can hide where traffic ultimately lands and reveal alternate paths.",
        "recommendation": "Review redirect behavior to ensure it is intentional and minimal.",
    },
    "unexpected_status_code": {
        "title": "Unexpected web status observed",
        "severity": "info",
        "description": "The asset returned a status code commonly associated with access restrictions or application errors.",
        "impact": "This can reveal protected endpoints, broken routing, or service instability.",
        "recommendation": "Check whether the response is expected and review access controls or service health.",
    },
    "login_panel": {
        "title": "Login interface detected",
        "severity": "medium",
        "description": "The page appears to expose a login or authentication interface.",
        "impact": "Public login surfaces increase the chance of password attacks and credential stuffing.",
        "recommendation": "Review authentication strength, MFA coverage, and rate limiting.",
    },
    "admin_panel": {
        "title": "Administrative interface detected",
        "severity": "high",
        "description": "The page appears to expose an administrative or control interface.",
        "impact": "If compromised, it may provide direct control over sensitive application or operational functions.",
        "recommendation": "Restrict access, require strong authentication, and confirm exposure is intentional.",
    },
    "empty_title": {
        "title": "Web service returned an empty page title",
        "severity": "info",
        "description": "A live web response was observed without a meaningful page title.",
        "impact": "This can indicate a bare service, placeholder page, or incomplete deployment.",
        "recommendation": "Confirm what should be running here and whether the service is intentional.",
    },
    "directory_listing_possible": {
        "title": "Possible directory listing exposure",
        "severity": "high",
        "description": "The response contains text patterns commonly associated with directory listing.",
        "impact": "Directory listing can reveal files, scripts, backups, and internal structure.",
        "recommendation": "Disable directory listing and review exposed folders.",
    },
    "default_page_detected": {
        "title": "Default web page detected",
        "severity": "medium",
        "description": "The response looks like a default server or platform landing page.",
        "impact": "This may indicate incomplete deployment, weak hardening, or unnecessary exposure.",
        "recommendation": "Review the host configuration and remove or harden unused default content.",
    },
    "error_page_exposed": {
        "title": "Error page exposed",
        "severity": "info",
        "description": "The response appears to show an application or server error page.",
        "impact": "Error pages may reveal stack behavior or operational instability.",
        "recommendation": "Review the failing path and reduce unnecessary detail in error responses.",
    },
    "unexpected_server_banner": {
        "title": "Server banner disclosed",
        "severity": "info",
        "description": "The service exposed a server header that reveals implementation details.",
        "impact": "Banner disclosure helps attackers profile the environment more quickly.",
        "recommendation": "Reduce unnecessary banner disclosure where practical.",
    },
    "technology_disclosure": {
        "title": "Technology stack disclosure detected",
        "severity": "info",
        "description": "The asset appears to reveal technologies in use through headers or content markers.",
        "impact": "This makes reconnaissance faster and helps attackers focus on likely weaknesses.",
        "recommendation": "Review whether visible stack details can be reduced.",
    },
    "framework_disclosure": {
        "title": "Framework disclosure detected",
        "severity": "info",
        "description": "The asset appears to reveal application framework details.",
        "impact": "Framework disclosure helps attackers focus on framework-specific weaknesses.",
        "recommendation": "Ensure the framework is current and securely configured.",
    },
    "cdn_detected": {
        "title": "CDN presence detected",
        "severity": "info",
        "description": "The asset appears to be served behind a content delivery network.",
        "impact": "This is useful infrastructure context and may mask routing behavior.",
        "recommendation": "Confirm CDN configuration is expected and that the origin is appropriately protected.",
    },
    "remote_admin_service_exposed": {
        "title": "Remote administration service exposed",
        "severity": "high",
        "description": "A remote administration service such as SSH or RDP appears reachable.",
        "impact": "This increases the risk of brute-force attacks and direct host compromise if controls are weak.",
        "recommendation": "Restrict network exposure and confirm strong authentication and logging.",
    },
    "database_service_exposed": {
        "title": "Database service exposed",
        "severity": "high",
        "description": "A database service appears reachable over the network boundary.",
        "impact": "This may expose direct data access and increase risk of credential attacks or destructive queries.",
        "recommendation": "Confirm whether direct external database exposure is necessary and tightly restrict access.",
    },
    "plaintext_service_exposed": {
        "title": "Plaintext service exposed",
        "severity": "medium",
        "description": "A service commonly associated with weaker or plaintext communication appears exposed.",
        "impact": "Credentials or traffic may be vulnerable to interception.",
        "recommendation": "Prefer encrypted alternatives and review whether public exposure is necessary.",
    },
    # Correlated findings
    "privileged_interface_exposed": {
        "title": "Privileged interface exposed",
        "severity": "high",
        "description": "This asset shows both administrative naming patterns and an administrative interface, which strongly suggests it exposes a privileged management surface rather than a normal public page.",
        "impact": "If this interface is reachable from the internet and not tightly protected, it could become a direct path to operational control, sensitive settings, or administrator-only functionality.",
        "recommendation": "Confirm whether this interface is intentionally public. If not, restrict access immediately. If it must remain reachable, review authentication strength, access restrictions, and monitoring.",
    },
    "public_remote_admin_surface": {
        "title": "Public remote administration surface detected",
        "severity": "high",
        "description": "A remote administration service is exposed on a host that appears externally reachable. This usually means direct host management access is available from the network boundary.",
        "impact": "Publicly reachable remote administration services increase the chance of brute-force attempts, credential reuse attacks, and direct host compromise if authentication or network controls are weak.",
        "recommendation": "Review whether remote administration needs to be publicly reachable at all. Prefer access restrictions, allowlists, VPN-only exposure, and strong authentication with logging.",
    },
    "internal_data_service_exposed": {
        "title": "Internal data-oriented service exposed",
        "severity": "high",
        "description": "This asset combines internal-facing naming patterns with exposed database-related services, suggesting a data-oriented system that may have been intended for limited or private access.",
        "impact": "If this service is reachable more broadly than expected, it can increase the risk of unauthorized data access, destructive queries, credential attacks, or exposure of sensitive operational data.",
        "recommendation": "Confirm whether this service should be externally reachable. Review network boundaries, authentication controls, and whether sensitive data systems are exposed outside their intended trust zone.",
    },
    "unhardened_non_production_surface": {
        "title": "Unhardened non-production surface detected",
        "severity": "medium",
        "description": "This asset looks like a non-production environment and also shows signs of incomplete or weak web configuration.",
        "impact": "Non-production systems often have weaker controls and may reveal application behavior, test data, or less hardened deployment states.",
        "recommendation": "Review whether the environment should be public and bring its configuration closer to a secure baseline.",
    },
    "externally_exposed_internal_service": {
        "title": "Externally exposed internal-facing service",
        "severity": "high",
        "description": "The asset appears to be internal by naming pattern, but it is externally reachable.",
        "impact": "This may expose internal workflows, operational systems, or trusted interfaces to public access attempts.",
        "recommendation": "Verify intended exposure and remove or restrict public access if this system was meant for internal use.",
    },
    "high_value_target_surface": {
        "title": "High-value target surface detected",
        "severity": "high",
        "description": "This asset exposes a login or administrative surface along with additional recon value such as disclosure or redirect behavior.",
        "impact": "Combined indicators make the asset especially attractive for targeted reconnaissance and access attempts.",
        "recommendation": "Review the full exposure of this asset, harden authentication paths, and reduce unnecessary disclosure where possible.",
    },
    "weakly_protected_entry_point": {
        "title": "Weakly protected entry point detected",
        "severity": "high",
        "description": "A login-facing surface appears reachable over HTTP without confirmed HTTPS protection, which suggests authentication traffic may not be consistently protected in transit.",
        "impact": "If credentials or session traffic are served without transport protection, they may be exposed to interception or tampering, turning a normal login surface into a much riskier entry point.",
        "recommendation": "Prioritize HTTPS enforcement for this asset. Confirm that login and session traffic are never served over plaintext HTTP and that redirects to HTTPS are consistent and immediate.",
    },
    "multi_signal_admin_surface": {
        "title": "Multi-signal administrative surface detected",
        "severity": "high",
        "description": "Several indicators align on this asset: administrative naming, an administrative interface, and additional signals consistent with a high-interest management surface.",
        "impact": "This combination strongly suggests a sensitive exposed system that would be a priority target during an attack.",
        "recommendation": "Treat this as a high-priority review item. Confirm intended exposure, restrict access, and harden both authentication and service configuration.",
    },
}


def build_findings_for_asset(asset: Asset) -> list[Finding]:
    findings: list[Finding] = []

    for signal in asset.risk_signals:
        details = SIGNAL_DETAILS.get(signal)
        if not details:
            continue

        findings.append(
            Finding(
                asset=asset.host,
                title=details["title"],
                severity=details["severity"],
                description=details["description"],
                signal=signal,
                confidence=asset.confidence,
                impact=details["impact"],
                recommendation=details["recommendation"],
            )
        )

    return findings


def is_correlated_finding(signal: str) -> bool:
    return signal in CORRELATED_SIGNALS