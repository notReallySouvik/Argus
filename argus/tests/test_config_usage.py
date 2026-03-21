from pathlib import Path

import argus.config as config


PROJECT_ROOT = Path(__file__).resolve().parents[1]

ALLOWED_UNUSED = {
    "VERSION",
}

IGNORED_PREFIXES = {"__"}


def test_all_config_constants_are_used_or_allowed():
    config_names = []

    for name in dir(config):
        if any(name.startswith(prefix) for prefix in IGNORED_PREFIXES):
            continue

        value = getattr(config, name)

        if callable(value):
            continue

        config_names.append(name)

    py_files = [
        p for p in PROJECT_ROOT.rglob("*.py")
        if p.name != "config.py" and "tests" not in p.parts
    ]

    all_code = "\n".join(path.read_text(encoding="utf-8") for path in py_files)

    unused = []

    for name in config_names:
        if name in ALLOWED_UNUSED:
            continue
        if name not in all_code:
            unused.append(name)

    assert not unused, f"Unused config values found: {unused}"