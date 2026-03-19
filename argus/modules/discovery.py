import httpx
from typing import Dict, List

from argus.config import SOURCE_CONFIDENCE
from argus.models.asset import DiscoverySource
from argus.modules.subdomains import generate_candidate_subdomains


def _add_candidate(store: Dict[str, List[DiscoverySource]], host: str, source_name: str) -> None:
    if host not in store:
        store[host] = []

    existing = {src.name for src in store[host]}
    if source_name not in existing:
        store[host].append(
            DiscoverySource(
                name=source_name,
                confidence=SOURCE_CONFIDENCE.get(source_name, 0.5),
            )
        )


def discover_from_wordlist(target: str) -> Dict[str, List[DiscoverySource]]:
    results: Dict[str, List[DiscoverySource]] = {}
    for host in generate_candidate_subdomains(target):
        _add_candidate(results, host, "wordlist")
    return results


def discover_from_passive_sources(target: str) -> Dict[str, List[DiscoverySource]]:
    results: Dict[str, List[DiscoverySource]] = {}

    url = f"https://crt.sh/?q=%25.{target}&output=json"

    try:
        response = httpx.get(url, timeout=10.0)

        if response.status_code != 200:
            return results

        data = response.json()

        for entry in data:
            name_value = entry.get("name_value", "")
            if not name_value:
                continue

            names = name_value.split("\n")

            for name in names:
                name = name.strip().lower()

                if not name:
                    continue

                # remove wildcard
                if name.startswith("*."):
                    name = name[2:]

                if name.endswith(target):
                    _add_candidate(results, name, "crtsh")

    except Exception:
        return results

    return results


def merge_discovery_results(*sources: Dict[str, List[DiscoverySource]]) -> Dict[str, List[DiscoverySource]]:
    merged: Dict[str, List[DiscoverySource]] = {}

    for source_map in sources:
        for host, source_list in source_map.items():
            for source in source_list:
                _add_candidate(merged, host, source.name)

    return merged


def calculate_confidence(sources: List[DiscoverySource]) -> float:
    if not sources:
        return 0.0

    total = sum(source.confidence for source in sources)
    score = min(total / len(sources), 0.99)
    return round(score, 2)


def discover_subdomains(target: str) -> Dict[str, List[DiscoverySource]]:
    wordlist_results = discover_from_wordlist(target)
    passive_results = discover_from_passive_sources(target)
    return merge_discovery_results(wordlist_results, passive_results)