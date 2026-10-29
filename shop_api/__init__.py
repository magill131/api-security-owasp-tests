"""A small shop API used as the target of the security tests. It is a practice system, not a real product."""

from .app import create_app
from .vulns import VULNERABILITIES, parse_vulns

__all__ = ["create_app", "VULNERABILITIES", "parse_vulns"]
