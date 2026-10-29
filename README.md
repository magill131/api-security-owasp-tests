# API Security Tests (OWASP API Top 10)

Security tests in pytest for a small demo shop API, mapped to the OWASP API Security Top 10. The API is written so that ten weaknesses can be planted in it, one at a time. The test suite has to catch each one, and it has to catch it through the tests written for it and no others.

That last part is the point of the project. A security test that passes proves little unless it is known to fail when the weakness is really there. Here that is checked on every run.

The API is a practice system made for this repo. It runs in-process with Flask's test client: no server, no network, no real site is tested. The users and passwords in it are made up.

## The ten weaknesses

| ID | Weakness | OWASP category |
|---|---|---|
| V01 | Any signed-in user can read any other user's order | API1:2023 Broken Object Level Authorization |
| V02 | Session tokens are predictable: a token can be forged from a username | API2:2023 Broken Authentication |
| V03 | No lockout: unlimited password guesses | API2:2023 Broken Authentication |
| V04 | The password hash is returned in the profile response | API3:2023 Broken Object Property Level Authorization |
| V05 | Mass assignment: a user can set their own role to admin | API3:2023 Broken Object Property Level Authorization |
| V06 | No cap on page size: one request can ask for every row | API4:2023 Unrestricted Resource Consumption |
| V07 | The admin delete endpoint works for any signed-in user | API5:2023 Broken Function Level Authorization |
| V08 | SQL injection in the product search | A03:2021 Injection |
| V09 | Error responses include a stack trace | API8:2023 Security Misconfiguration |
| V10 | Security headers are missing and a framework version is revealed | API8:2023 Security Misconfiguration |

`create_app()` builds the secure API. `create_app({"V01", "V05"})` plants those two weaknesses. The tests take the same choice with `--vulns` (`none`, `all` or a list such as `V01,V05`).

## The tests

| Folder | Tests | What it checks |
|---|---|---|
| `tests/functional` | 34 | Normal behaviour: login, profile, orders, product search, admin delete, error format. Must pass with and without every weakness |
| `tests/security` | 38 | One group per weakness. Every test name starts with its weakness id, such as `test_v03_account_locks_after_repeated_failed_logins` |
| `tests/meta` | 26 | Checks the other two folders (see below) |

Examples of what the security tests do: read another user's order and expect a refusal, forge a token with `base64("admin")`, make five wrong password guesses and expect a lockout, send `zzz%' OR published = 0 --` to the search and expect no unpublished products back, ask for `limit=1000` with 120 products stored and expect at most 50, crash the API and look for a stack trace in the body.

## Testing the tests

The meta tests rebuild the API with one weakness planted at a time and run the functional and security tests against it. They check that:

- the secure API passes everything,
- every weakness has tests, and every security test is named after a known weakness,
- planting one weakness fails the tests for that weakness and no others, with no functional test failing,
- every test for a weakness fails when it is planted. Only tests named `test_vNN_guard_...` may pass, and they must pass. They stop a fix from going too far, for example locking every account out,
- planting all ten fails tests for all ten.

This found two real problems while the project was being built. A V05 test checked admin power through the delete endpoint, so planting only V07 made it fail and blamed the wrong weakness. A V09 test could only fail if V08 was also planted, so it was replaced with one that stands alone.

The tests were also broken on purpose. Weakening a lockout test, a SQL injection test and a single-header test to `assert True` was caught each time, once the multi-assertion tests were split so one assertion cannot hide behind another. Breaking the secure API (removing the order ownership check, raising the lockout limit to 500, raising the page cap to 5000) was caught each time as well.

## Results

98 tests pass offline in about 20 seconds, run locally on Python 3.13 (see `docs/test_results.png`). `docs/security_report.md` lists, for each weakness, the tests that caught it: 10 of 10 weaknesses caught, no test wrongly failing.

What this does not show: that the tests catch every variant of an attack. The SQL injection tests use one injection pattern, and the token tests cover one way of forging a token. They show the suite can fail for each weakness, not that the API is secure against everything.

## CI

`.github/workflows/ci.yml` runs on every push and pull request: the 98 tests, then `scripts/security_report.py`, which plants each weakness in turn and exits with an error if one is missed or caught by the wrong tests, then uploads the report.

## Tools

Python, pytest, Flask, SQLite (built in), GitHub Actions.

## How to run

```
pip install -r requirements.txt
python -m pytest
python scripts/security_report.py
```

To see the tests catch a weakness, plant it:

```
python -m pytest tests/security --vulns=V03
python -m pytest tests/security --vulns=all
```

## Project layout

```
shop_api/app.py                 the demo API, with the ten weaknesses behind switches
shop_api/vulns.py               the weakness list and the --vulns parser
tests/conftest.py               the --vulns option and shared fixtures
tests/functional/               normal behaviour, passes with every weakness
tests/security/                 security tests, named test_vNN_...
tests/meta/                     proves each test can fail, and only for its own weakness
scripts/security_report.py      plants each weakness in turn and writes the report
docs/security_report.md         latest report
docs/test_results.png           results screenshot
.github/workflows/ci.yml        CI
```
