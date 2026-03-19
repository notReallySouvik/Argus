import httpx
from selectolax.parser import HTMLParser

from argus.config import DEFAULT_HTTP_TIMEOUT, USER_AGENT
from argus.models.asset import WebMetadata
from argus.utils.logger import get_logger

logger = get_logger(__name__)


def fetch_web_metadata(url: str, timeout: float = DEFAULT_HTTP_TIMEOUT) -> WebMetadata | None:
    headers = {"User-Agent": USER_AGENT}

    try:
        response = httpx.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
        )
    except httpx.HTTPError as exc:
        logger.warning("HTTP error fetching metadata for %s: %s", url, exc)
        return None
    except Exception as exc:
        logger.exception("Unexpected error fetching metadata for %s: %s", url, exc)
        return None

    html = response.text or ""
    title = None

    try:
        tree = HTMLParser(html)
        title_node = tree.css_first("title")
        title = title_node.text(strip=True) if title_node else None
    except Exception as exc:
        logger.warning("HTML parsing failed for %s: %s", url, exc)

    return WebMetadata(
        url=str(response.url),
        status_code=response.status_code,
        title=title,
        server=response.headers.get("server"),
        technologies=[],
        body_preview=html[:4000].lower(),
    )