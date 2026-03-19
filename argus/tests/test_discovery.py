from argus.models.asset import DiscoverySource
from argus.modules.discovery import calculate_confidence


def test_confidence_calculation():
    sources = [
        DiscoverySource(name="wordlist", confidence=0.55),
        DiscoverySource(name="crtsh", confidence=0.80),
    ]

    score = calculate_confidence(sources)

    assert 0.55 < score <= 0.99


def test_confidence_empty_sources_is_zero():
    score = calculate_confidence([])

    assert score == 0.0