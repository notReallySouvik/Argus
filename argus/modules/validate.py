from typing import Optional
import httpx


def probe_http(host: str, timeout: float = 5.0) -> Optional[str]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            response = httpx.get(url, timeout=timeout, follow_redirects=True)
            if response.status_code:
                return str(response.url)
        except Exception:
            continue
    return None