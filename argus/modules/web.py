from typing import Optional
import httpx
from selectolax.parser import HTMLParser
from argus.models.asset import WebMetadata


def fetch_web_metadata(url: str, timeout: float = 8.0) -> Optional[WebMetadata]:
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        html = response.text
        tree = HTMLParser(html)

        title_node = tree.css_first("title")
        title = title_node.text(strip=True) if title_node else None

        server = response.headers.get("server")

        return WebMetadata(
            url=str(response.url),
            status_code=response.status_code,
            title=title,
            server=server,
            technologies=[],
        )
    except Exception:
        return None