from typing import List

from argus.config import COMMON_SUBDOMAINS


def generate_candidate_subdomains(target: str) -> List[str]:
    candidates = [target]
    candidates.extend(f"{sub}.{target}" for sub in COMMON_SUBDOMAINS)
    return candidates