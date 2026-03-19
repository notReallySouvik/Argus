from typing import Optional

import httpx

from argus.config import DEFAULT_PROBE_TIMEOUT, USER_AGENT
from argus.models.asset import ProbeResult
from argus.utils.logger import get_logger

logger = get_logger(__name__)


def probe_http(host: str, timeout: float = DEFAULT_PROBE_TIMEOUT) -> ProbeResult:
    headers = {"User-Agent": USER_AGENT}
    result = ProbeResult()

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"

        try:
            response = httpx.get(
                url,
                timeout=timeout,
                follow_redirects=True,
                headers=headers,
            )

            final_url = str(response.url)

            if scheme == "https":
                result.https_url = final_url
            else:
                result.http_url = final_url

            if len(response.history) > 0:
                result.redirect_chain_detected = True

        except httpx.HTTPError as exc:
            logger.debug("HTTP probe failed for %s: %s", url, exc)

        except Exception as exc:
            logger.exception("Unexpected probe error for %s: %s", url, exc)

    result.preferred_url = result.https_url or result.http_url
    return result