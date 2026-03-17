from typing import List
from argus.models.asset import WebMetadata


def fingerprint_technologies(web: WebMetadata, html: str = "") -> List[str]:
    technologies = []

    server = (web.server or "").lower()
    title = (web.title or "").lower()
    body = html.lower()

    if "cloudflare" in server:
        technologies.append("cloudflare")
    if "nginx" in server:
        technologies.append("nginx")
    if "apache" in server:
        technologies.append("apache")

    if "wordpress" in body or "wp-content" in body:
        technologies.append("wordpress")
    if "react" in body:
        technologies.append("react")
    if "vue" in body:
        technologies.append("vue.js")

    if "admin" in title:
        technologies.append("admin-panel")

    return sorted(set(technologies))