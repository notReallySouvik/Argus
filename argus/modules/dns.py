from typing import List
import dns.resolver


def resolve_a_records(host: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(host, "A")
        return sorted({answer.to_text() for answer in answers})
    except Exception:
        return []