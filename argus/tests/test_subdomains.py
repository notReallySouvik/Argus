from argus.modules.subdomains import generate_candidate_subdomains


def test_generate_candidate_subdomains_includes_target():
    target = "example.com"
    results = generate_candidate_subdomains(target)
    assert target in results


def test_generate_candidate_subdomains_includes_common_entries():
    target = "example.com"
    results = generate_candidate_subdomains(target)

    assert "www.example.com" in results
    assert "api.example.com" in results
    assert "admin.example.com" in results