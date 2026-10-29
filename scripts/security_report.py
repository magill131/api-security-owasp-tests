"""Plant each weakness in turn, run the tests, and write docs/security_report.md.

Exit code 1 if any weakness is missed, caught by the wrong tests, or if the secure
API fails a test.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shop_api import VULNERABILITIES  # noqa: E402
from tests.meta.harness import is_guard, run_suite  # noqa: E402


def main() -> int:
    secure = run_suite("none")
    secure_ok = secure.returncode == 0 and not secure.failed

    rows, problems = [], []
    for vuln_id in sorted(VULNERABILITIES):
        title, owasp = VULNERABILITIES[vuln_id]
        run = run_suite(vuln_id)
        caught = run.failed_names_for(vuln_id)
        others = sorted(run.failed_vulns - {vuln_id}) + run.functional_failures
        if not caught:
            problems.append(f"{vuln_id} was not caught by any test")
        never_failed = [n for n in run.names_for(vuln_id) if not is_guard(n) and n not in caught]
        if never_failed:
            problems.append(f"{vuln_id} has tests that did not fail when it was planted: {', '.join(never_failed)}")
        if others:
            problems.append(f"{vuln_id} also failed: {', '.join(others)}")
        rows.append((vuln_id, title, owasp, caught, others))

    lines = [
        "# Security test report",
        "",
        "Each weakness was planted in the demo API on its own, and the functional and security tests were run.",
        "",
        f"Secure API: {len(secure.passed)} tests passed, {len(secure.failed)} failed.",
        "",
        "| ID | Weakness | OWASP category | Tests that failed | Wrongly failing tests |",
        "|---|---|---|---|---|",
    ]
    for vuln_id, title, owasp, caught, others in rows:
        lines.append(f"| {vuln_id} | {title} | {owasp} | {len(caught)} | {len(others)} |")

    lines += ["", "## Which tests caught which weakness", ""]
    for vuln_id, title, _, caught, _ in rows:
        lines.append(f"**{vuln_id}** {title}")
        lines += [f"- `{name}`" for name in caught] or ["- none"]
        lines.append("")

    caught_all = sum(1 for _, _, _, caught, _ in rows if caught)
    lines.append(f"{caught_all} of {len(rows)} weaknesses were caught, only by their own tests, and every test "
                 "for a weakness failed when it was planted (guard tests, which must keep passing, excepted)."
                 if not problems else "Problems found: " + "; ".join(problems))
    lines.append("")

    out = ROOT / "docs" / "security_report.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out}")
    print(f"secure API: {len(secure.passed)} passed, {len(secure.failed)} failed")
    for vuln_id, _, _, caught, others in rows:
        print(f"{vuln_id}: caught by {len(caught)} test(s), wrongly failing {len(others)}")
    for problem in problems:
        print("PROBLEM:", problem)
    return 0 if secure_ok and not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
