import re


DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$"
)


def validate_target(target: str) -> str:
    target = target.strip().lower()

    if not DOMAIN_REGEX.match(target):
        raise ValueError(f"Invalid target domain: {target}")

    return target