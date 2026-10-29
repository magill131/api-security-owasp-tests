"""Testing the tests.

A security test that passes proves little unless it is known to fail when the
weakness is really there. Here the API is rebuilt with one weakness planted at a
time, and the suite must notice that weakness, and only that one.
"""

import pytest

from shop_api import VULNERABILITIES, create_app, parse_vulns
from tests.meta.harness import is_guard, run_suite

ALL_IDS = sorted(VULNERABILITIES)


@pytest.fixture(scope="module")
def secure_run():
    return run_suite("none")


def test_the_secure_api_passes_every_functional_and_security_test(secure_run):
    assert secure_run.returncode == 0
    assert secure_run.failed == []
    assert len(secure_run.passed) > 50


def test_every_weakness_has_at_least_one_test_named_after_it(secure_run):
    assert secure_run.security_vulns_present == set(ALL_IDS)


def test_every_security_test_is_named_after_a_known_weakness(secure_run):
    assert secure_run.unlabelled_security_tests == []


@pytest.mark.parametrize("vuln_id", ALL_IDS)
def test_planting_one_weakness_fails_its_own_tests_and_no_others(vuln_id):
    run = run_suite(vuln_id)
    assert run.returncode == 1
    assert run.failed_vulns == {vuln_id}
    assert run.functional_failures == []
    assert run.unlabelled_security_failures == []


@pytest.mark.parametrize("vuln_id", ALL_IDS)
def test_every_test_for_a_weakness_can_actually_fail(vuln_id):
    # A test that cannot fail when its weakness is present proves nothing. Only guard tests
    # (test_vNN_guard_...) are allowed to pass, and they must pass.
    run = run_suite(vuln_id)
    names = run.names_for(vuln_id)
    failed = set(run.failed_names_for(vuln_id))
    never_failed = [n for n in names if not is_guard(n) and n not in failed]
    guards_that_failed = [n for n in names if is_guard(n) and n in failed]
    assert never_failed == []
    assert guards_that_failed == []


def test_planting_every_weakness_fails_tests_for_every_weakness():
    run = run_suite("all")
    assert run.failed_vulns == set(ALL_IDS)
    assert run.functional_failures == []


def test_parse_vulns_understands_none_all_and_lists():
    assert parse_vulns("none") == frozenset()
    assert parse_vulns("") == frozenset()
    assert parse_vulns("all") == frozenset(ALL_IDS)
    assert parse_vulns("v01, V05") == {"V01", "V05"}


def test_an_unknown_weakness_id_is_refused():
    with pytest.raises(ValueError):
        parse_vulns("V99")
    with pytest.raises(ValueError):
        create_app({"V99"})
