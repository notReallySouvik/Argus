from typing import List

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "mail",
    "vpn",
]


def generate_candidate_subdomains(target: str) -> List[str]:
    candidates = [target]
    candidates.extend(f"{sub}.{target}" for sub in COMMON_SUBDOMAINS)
    return candidates