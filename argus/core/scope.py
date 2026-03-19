import re
from urllib.parse import urlparse


DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def normalize_target(target: str) -> str:
    target = target.strip()

    # Strip scheme
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.netloc

    # Remove port if present
    if ":" in target:
        target = target.split(":", 1)[0]

    return target.strip(".").lower()


def validate_target(target: str) -> str:
    normalized = normalize_target(target)

    if not normalized:
        raise ValueError("Empty target")

    # Allow localhost explicitly
    if normalized == "localhost":
        return normalized

    # Basic domain validation
    if not DOMAIN_REGEX.match(normalized):
        raise ValueError(f"Invalid target domain: {target}")

    return normalized