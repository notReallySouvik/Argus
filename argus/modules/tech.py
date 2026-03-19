from argus.config import ADMIN_PANEL_KEYWORDS, LOGIN_KEYWORDS
from argus.models.asset import WebMetadata


def fingerprint_technologies(web: WebMetadata, html: str = "") -> list[str]:
    technologies = []

    server = (web.server or "").lower()
    title = (web.title or "").lower()
    body = (html or "").lower()

    if "cloudflare" in server:
        technologies.append("cloudflare")
    if "nginx" in server:
        technologies.append("nginx")
    if "apache" in server:
        technologies.append("apache")
    if "iis" in server:
        technologies.append("iis")

    if "wordpress" in body or "wp-content" in body:
        technologies.append("wordpress")
    if "react" in body:
        technologies.append("react")
    if "vue" in body:
        technologies.append("vue.js")

    if any(k in title for k in LOGIN_KEYWORDS):
        technologies.append("login-panel")

    if any(k in title for k in ADMIN_PANEL_KEYWORDS):
        technologies.append("admin-panel")

    return sorted(set(technologies))