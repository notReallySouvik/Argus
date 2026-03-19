from argus.models.asset import Asset
from argus.models.finding import Finding


SIGNAL_DETAILS = {
    "admin_keyword": {
        "title": "Administrative naming pattern detected",
        "severity": "high",
        "description": "The hostname contains terms commonly associated with administrative or control interfaces. This often means the asset may serve an operational, privileged, or management-facing function.",
        "impact": "If this interface is externally reachable and weakly protected, it may increase the risk of unauthorized administrative access or targeted brute-force and credential attacks.",
        "recommendation": "Confirm whether this asset is meant to be internet-facing, review authentication controls, and ensure privileged interfaces are restricted and monitored.",
    },
    "non_production_keyword": {
        "title": "Non-production naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests a development, staging, test, QA, or beta environment. These systems are often less tightly controlled than production and may expose unfinished or weaker configurations.",
        "impact": "If exposed publicly, non-production assets can reveal internal logic, debug behavior, weak credentials, or less hardened services that expand the attack surface.",
        "recommendation": "Review whether the environment needs public exposure and confirm that non-production systems follow an appropriate security baseline.",
    },
    "backup_keyword": {
        "title": "Backup-related naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests backup, archive, or snapshot-related infrastructure. These systems may hold older copies of data or services and are sometimes overlooked during hardening.",
        "impact": "If accessible externally, backup-related assets may expose stale data, unmaintained services, or systems with weaker controls than primary production infrastructure.",
        "recommendation": "Verify whether this asset is still needed, restrict unnecessary exposure, and review whether it contains retained data or outdated services.",
    },
    "internal_keyword": {
        "title": "Internal naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests an internal-facing purpose such as corporate, staff, or internal operations. This may indicate the asset was not originally intended for broad public exposure.",
        "impact": "If an internal-oriented system is externally reachable, it can expose operational interfaces, internal workflows, or sensitive functions to unauthorized access attempts.",
        "recommendation": "Confirm whether the asset should be public at all and restrict external access if it was meant for internal use only.",
    },
    "legacy_keyword": {
        "title": "Legacy naming pattern detected",
        "severity": "medium",
        "description": "The hostname suggests an older or legacy system. Legacy services are often retained for compatibility and may receive less maintenance or slower security updates.",
        "impact": "Legacy infrastructure can increase risk through outdated configurations, weaker controls, and overlooked exposure that remains available to attackers.",
        "recommendation": "Review whether the system is still required, confirm patching and hardening status, and retire or isolate it if no longer necessary.",
    },
    "exposed_http_only": {
        "title": "HTTP exposed without HTTPS",
        "severity": "high",
        "description": "The asset appears reachable over plain HTTP without confirmed HTTPS support. This usually means traffic may not be protected in transit.",
        "impact": "Unencrypted transport can expose credentials, session tokens, and application traffic to interception or tampering, especially on untrusted networks.",
        "recommendation": "Enable HTTPS, redirect plaintext HTTP to HTTPS, and verify certificate deployment and transport security settings.",
    },
    "redirect_chain_detected": {
        "title": "Redirect chain observed",
        "severity": "info",
        "description": "The asset redirected requests before reaching the final page. This may be normal, but it can also reflect layered routing, proxying, or redirect-based exposure patterns.",
        "impact": "Unexpected redirect chains can hide where traffic ultimately lands, complicate visibility, and sometimes expose alternate hosts or application paths.",
        "recommendation": "Review redirect behavior to ensure it is intentional, minimal, and not revealing unintended application flow or host relationships.",
    },
    "unexpected_status_code": {
        "title": "Unexpected web status observed",
        "severity": "info",
        "description": "The asset returned a status code commonly associated with access restrictions or application errors. This may indicate a guarded interface, a broken route, or service instability.",
        "impact": "Unexpected responses can reveal protected endpoints, unstable services, or operational weaknesses that may help attackers profile the system.",
        "recommendation": "Check whether the response is expected for this asset and review access controls, routing, and service health.",
    },
    "login_panel": {
        "title": "Login interface detected",
        "severity": "medium",
        "description": "The page appears to expose a login or authentication interface. This often indicates a user or operator access point reachable from the internet.",
        "impact": "Public login surfaces increase the chance of password attacks, credential stuffing, session abuse, and targeted attempts against exposed accounts.",
        "recommendation": "Review authentication strength, rate limiting, MFA coverage, and monitoring for suspicious access attempts.",
    },
    "admin_panel": {
        "title": "Administrative interface detected",
        "severity": "high",
        "description": "The page appears to expose an administrative or control interface. This usually means the asset may provide privileged management capabilities.",
        "impact": "If compromised, administrative interfaces can lead to direct control over application settings, users, infrastructure behavior, or sensitive operational functions.",
        "recommendation": "Restrict access to trusted networks or identity layers, require strong authentication, and confirm the interface is intentionally exposed.",
    },
    "empty_title": {
        "title": "Web service returned an empty page title",
        "severity": "info",
        "description": "A live web response was observed without a meaningful page title. This may indicate a bare service, a placeholder page, or an incomplete deployment state.",
        "impact": "While not necessarily dangerous by itself, it can signal neglected or partially configured services that deserve review.",
        "recommendation": "Confirm what application should be running here and review whether the service is intentional, complete, and properly configured.",
    },
    "directory_listing_possible": {
        "title": "Possible directory listing exposure",
        "severity": "high",
        "description": "The response contains text patterns commonly associated with directory listing. This may mean the server is exposing browsable file or folder indexes.",
        "impact": "Directory listing can reveal file names, internal structure, backups, scripts, and sensitive content that help attackers map the system or access exposed data.",
        "recommendation": "Disable directory listing and review whether any publicly accessible folders expose files that should not be reachable.",
    },
    "default_page_detected": {
        "title": "Default web page detected",
        "severity": "medium",
        "description": "The response looks like a default server or platform landing page. This often means the service is incompletely configured or not serving its intended application.",
        "impact": "Default pages can reveal platform details, suggest misrouted infrastructure, and indicate services that were deployed but not fully hardened.",
        "recommendation": "Review the host configuration, verify the expected application is deployed, and remove or harden unused default content.",
    },
    "error_page_exposed": {
        "title": "Error page exposed",
        "severity": "info",
        "description": "The response appears to show an application or server error page. This can happen during routing issues, backend problems, or unhandled application states.",
        "impact": "Error pages may reveal stack behavior, deployment details, or operational instability that can help attackers profile the system.",
        "recommendation": "Review the failing path, confirm whether the response is expected, and reduce unnecessary detail in externally visible error handling.",
    },
    "unexpected_server_banner": {
        "title": "Server banner disclosed",
        "severity": "info",
        "description": "The service exposed a server header that reveals implementation details about the web stack or infrastructure layer.",
        "impact": "Banner disclosure helps attackers profile the environment, narrow technology guesses, and target stack-specific weaknesses more efficiently.",
        "recommendation": "Reduce unnecessary banner disclosure where practical and confirm that exposed stack details are not more specific than needed.",
    },
    "technology_disclosure": {
        "title": "Technology stack disclosure detected",
        "severity": "info",
        "description": "The asset appears to reveal technologies in use through headers, content markers, or fingerprinting signals.",
        "impact": "Technology disclosure can make reconnaissance faster by helping attackers identify likely frameworks, middleware, and infrastructure components.",
        "recommendation": "Review whether the exposed stack details can be reduced and confirm that visible technologies are fully maintained and expected.",
    },
    "framework_disclosure": {
        "title": "Framework disclosure detected",
        "severity": "info",
        "description": "The asset appears to reveal application framework details through content markers or web behavior.",
        "impact": "Framework disclosure helps attackers focus on framework-specific weaknesses, default behaviors, and known misconfiguration patterns.",
        "recommendation": "Review whether framework fingerprints are unnecessarily exposed and ensure the identified framework is current and securely configured.",
    },
    "cdn_detected": {
        "title": "CDN presence detected",
        "severity": "info",
        "description": "The asset appears to be served behind a content delivery network or edge delivery layer.",
        "impact": "This is useful infrastructure context. It may reduce direct origin exposure, but it can also mask routing behavior that should still be reviewed.",
        "recommendation": "Confirm CDN configuration is intentional and ensure the origin is not unnecessarily exposed outside the edge layer.",
    },
    "remote_admin_service_exposed": {
        "title": "Remote administration service exposed",
        "severity": "high",
        "description": "A remote administration service such as SSH or RDP appears reachable from the network boundary. This usually indicates direct operator access is available remotely.",
        "impact": "Exposed remote administration services increase the risk of brute-force attacks, credential attacks, and direct host compromise if authentication or access controls are weak.",
        "recommendation": "Restrict remote administration exposure, review network allowlists, and confirm strong authentication and logging are in place.",
    },
    "database_service_exposed": {
        "title": "Database service exposed",
        "severity": "high",
        "description": "A database service appears reachable over the network boundary. This may indicate direct data-layer exposure rather than application-only access.",
        "impact": "Externally reachable databases can increase the risk of unauthorized data access, destructive queries, credential attacks, and information disclosure if controls are weak.",
        "recommendation": "Confirm whether direct external database exposure is necessary, restrict network access tightly, and verify authentication and encryption settings.",
    },
    "plaintext_service_exposed": {
        "title": "Plaintext service exposed",
        "severity": "medium",
        "description": "A service commonly associated with weaker or plaintext communication appears exposed. This may mean data or credentials are transmitted without strong transport protection.",
        "impact": "Plaintext or weakly protected services can expose credentials and operational traffic to interception, replay, or unauthorized access attempts.",
        "recommendation": "Prefer encrypted alternatives where possible and review whether this service needs public exposure at all.",
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