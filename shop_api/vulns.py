"""The ten vulnerabilities that can be planted in the demo API, and how to ask for them."""

from __future__ import annotations

# id -> (what is wrong, OWASP category)
VULNERABILITIES: dict[str, tuple[str, str]] = {
    "V01": ("Any signed-in user can read any other user's order",
            "API1:2023 Broken Object Level Authorization"),
    "V02": ("Session tokens are predictable: a token can be forged from a username",
            "API2:2023 Broken Authentication"),
    "V03": ("No lockout: unlimited password guesses",
            "API2:2023 Broken Authentication"),
    "V04": ("The password hash is returned in the profile response",
            "API3:2023 Broken Object Property Level Authorization"),
    "V05": ("Mass assignment: a user can set their own role to admin",
            "API3:2023 Broken Object Property Level Authorization"),
    "V06": ("No cap on page size: one request can ask for every row",
            "API4:2023 Unrestricted Resource Consumption"),
    "V07": ("The admin delete endpoint works for any signed-in user",
            "API5:2023 Broken Function Level Authorization"),
    "V08": ("SQL injection in the product search",
            "A03:2021 Injection"),
    "V09": ("Error responses include a stack trace",
            "API8:2023 Security Misconfiguration"),
    "V10": ("Security headers are missing and a framework version is revealed",
            "API8:2023 Security Misconfiguration"),
}


def parse_vulns(value: str) -> frozenset[str]:
    """'none' -> nothing planted, 'all' -> everything, 'V01,V05' -> just those."""
    value = (value or "none").strip()
    if value.lower() == "none":
        return frozenset()
    if value.lower() == "all":
        return frozenset(VULNERABILITIES)
    ids = frozenset(part.strip().upper() for part in value.split(",") if part.strip())
    unknown = ids - set(VULNERABILITIES)
    if unknown:
        raise ValueError(f"unknown vulnerability id: {', '.join(sorted(unknown))}")
    return ids
