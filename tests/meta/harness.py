"""Run the functional and security tests in a separate pytest process against an API
with chosen weaknesses planted, and read back which tests failed."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VULN_PREFIX = re.compile(r"^test_(v\d\d)_", re.IGNORECASE)


@dataclass
class SuiteRun:
    returncode: int
    passed: list[tuple[str, str]] = field(default_factory=list)  # (classname, test name)
    failed: list[tuple[str, str]] = field(default_factory=list)

    @staticmethod
    def vuln_of(name: str) -> str | None:
        match = VULN_PREFIX.match(name)
        return match.group(1).upper() if match else None

    def _security(self, tests):
        return [t for t in tests if ".security." in t[0]]

    @property
    def functional_failures(self) -> list[str]:
        return sorted(name for cls, name in self.failed if ".functional." in cls)

    @property
    def unlabelled_security_failures(self) -> list[str]:
        return sorted(name for _, name in self._security(self.failed) if self.vuln_of(name) is None)

    @property
    def failed_vulns(self) -> set[str]:
        return {v for _, name in self._security(self.failed) if (v := self.vuln_of(name))}

    @property
    def security_vulns_present(self) -> set[str]:
        return {v for _, name in self._security(self.passed + self.failed) if (v := self.vuln_of(name))}

    @property
    def unlabelled_security_tests(self) -> list[str]:
        return sorted(n for _, n in self._security(self.passed + self.failed) if self.vuln_of(n) is None)

    def failed_names_for(self, vuln_id: str) -> list[str]:
        return sorted(name for _, name in self._security(self.failed) if self.vuln_of(name) == vuln_id)

    def names_for(self, vuln_id: str) -> list[str]:
        """Every security test named after this weakness, passed or failed."""
        return sorted(name for _, name in self._security(self.passed + self.failed) if self.vuln_of(name) == vuln_id)


def is_guard(name: str) -> bool:
    """Guard tests (test_vNN_guard_...) must pass with and without the weakness."""
    return re.match(r"^test_v\d\d_guard_", name, re.IGNORECASE) is not None


def run_suite(vulns: str, timeout: int = 300) -> SuiteRun:
    """vulns: 'none', 'all' or a list such as 'V01,V05'."""
    with tempfile.TemporaryDirectory() as tmp:
        junit = Path(tmp) / "junit.xml"
        command = [
            sys.executable, "-m", "pytest", "tests/functional", "tests/security",
            "-q", "-p", "no:cacheprovider", f"--vulns={vulns}",
            f"--junitxml={junit}", "-o", "junit_family=xunit2",
        ]
        proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        if not junit.exists():
            tail = (proc.stdout + proc.stderr).strip().splitlines()[-5:]
            raise RuntimeError("pytest produced no results: " + " | ".join(tail))
        run = SuiteRun(returncode=proc.returncode)
        for case in ET.fromstring(junit.read_text(encoding="utf-8")).iter("testcase"):
            key = (case.get("classname", ""), case.get("name", ""))
            if case.find("failure") is not None or case.find("error") is not None:
                run.failed.append(key)
            elif case.find("skipped") is None:
                run.passed.append(key)
        return run
