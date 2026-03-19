from typing import List

import dns.exception
import dns.resolver

from argus.config import DEFAULT_DNS_LIFETIME, DEFAULT_DNS_TIMEOUT
from argus.utils.logger import get_logger

logger = get_logger(__name__)


def resolve_a_records(host: str) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DEFAULT_DNS_LIFETIME
    resolver.timeout = DEFAULT_DNS_TIMEOUT

    try:
        answers = resolver.resolve(host, "A")
        return sorted({answer.to_text() for answer in answers})

    except dns.resolver.NXDOMAIN:
        logger.debug("DNS NXDOMAIN for host: %s", host)
        return []

    except dns.resolver.NoAnswer:
        logger.debug("DNS no A record answer for host: %s", host)
        return []

    except dns.resolver.NoNameservers:
        logger.warning("DNS no nameservers available for host: %s", host)
        return []

    except dns.resolver.LifetimeTimeout:
        logger.warning("DNS lookup timed out for host: %s", host)
        return []

    except dns.exception.DNSException as exc:
        logger.warning("DNS error for host %s: %s", host, exc)
        return []

    except Exception as exc:
        logger.exception("Unexpected DNS error for host %s: %s", host, exc)
        return []