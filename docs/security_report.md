# Security test report

Each weakness was planted in the demo API on its own, and the functional and security tests were run.

Secure API: 72 tests passed, 0 failed.

| ID | Weakness | OWASP category | Tests that failed | Wrongly failing tests |
|---|---|---|---|---|
| V01 | Any signed-in user can read any other user's order | API1:2023 Broken Object Level Authorization | 2 | 0 |
| V02 | Session tokens are predictable: a token can be forged from a username | API2:2023 Broken Authentication | 4 | 0 |
| V03 | No lockout: unlimited password guesses | API2:2023 Broken Authentication | 2 | 0 |
| V04 | The password hash is returned in the profile response | API3:2023 Broken Object Property Level Authorization | 3 | 0 |
| V05 | Mass assignment: a user can set their own role to admin | API3:2023 Broken Object Property Level Authorization | 3 | 0 |
| V06 | No cap on page size: one request can ask for every row | API4:2023 Unrestricted Resource Consumption | 2 | 0 |
| V07 | The admin delete endpoint works for any signed-in user | API5:2023 Broken Function Level Authorization | 2 | 0 |
| V08 | SQL injection in the product search | A03:2021 Injection | 3 | 0 |
| V09 | Error responses include a stack trace | API8:2023 Security Misconfiguration | 4 | 0 |
| V10 | Security headers are missing and a framework version is revealed | API8:2023 Security Misconfiguration | 12 | 0 |

## Which tests caught which weakness

**V01** Any signed-in user can read any other user's order
- `test_v01_the_rule_works_in_both_directions`
- `test_v01_user_cannot_read_another_users_order`

**V02** Session tokens are predictable: a token can be forged from a username
- `test_v02_a_forged_token_cannot_reach_admin_functions`
- `test_v02_a_token_forged_from_a_username_is_rejected`
- `test_v02_every_login_gets_a_different_token`
- `test_v02_tokens_are_not_derived_from_the_username`

**V03** No lockout: unlimited password guesses
- `test_v03_account_locks_after_repeated_failed_logins`
- `test_v03_the_correct_password_is_refused_while_locked`

**V04** The password hash is returned in the profile response
- `test_v04_profile_does_not_include_the_password_hash`
- `test_v04_the_hash_value_never_appears_in_the_response_text`
- `test_v04_the_profile_update_response_does_not_leak_it_either`

**V05** Mass assignment: a user can set their own role to admin
- `test_v05_a_role_change_attempt_does_not_survive_a_new_login`
- `test_v05_extra_fields_are_refused_not_silently_accepted`
- `test_v05_user_cannot_make_themselves_an_admin`

**V06** No cap on page size: one request can ask for every row
- `test_v06_a_huge_page_size_is_capped`
- `test_v06_one_over_the_cap_is_still_capped`

**V07** The admin delete endpoint works for any signed-in user
- `test_v07_normal_user_cannot_delete_users`
- `test_v07_the_target_user_still_exists_after_a_refused_delete`

**V08** SQL injection in the product search
- `test_v08_a_lone_quote_does_not_break_the_search`
- `test_v08_a_quote_in_the_search_is_treated_as_text`
- `test_v08_injected_sql_cannot_reveal_unpublished_products`

**V09** Error responses include a stack trace
- `test_v09_a_crash_does_not_include_a_stack_trace`
- `test_v09_a_crash_does_not_reveal_file_paths_or_exception_names[.py]`
- `test_v09_a_crash_does_not_reveal_file_paths_or_exception_names[RuntimeError]`
- `test_v09_a_crash_does_not_reveal_file_paths_or_exception_names[line ]`

**V10** Security headers are missing and a framework version is revealed
- `test_v10_every_response_sets_the_security_headers[/api/nothing-here-Cache-Control-no-store]`
- `test_v10_every_response_sets_the_security_headers[/api/nothing-here-X-Content-Type-Options-nosniff]`
- `test_v10_every_response_sets_the_security_headers[/api/nothing-here-X-Frame-Options-DENY]`
- `test_v10_every_response_sets_the_security_headers[/api/products-Cache-Control-no-store]`
- `test_v10_every_response_sets_the_security_headers[/api/products-X-Content-Type-Options-nosniff]`
- `test_v10_every_response_sets_the_security_headers[/api/products-X-Frame-Options-DENY]`
- `test_v10_every_response_sets_the_security_headers[/api/users/me-Cache-Control-no-store]`
- `test_v10_every_response_sets_the_security_headers[/api/users/me-X-Content-Type-Options-nosniff]`
- `test_v10_every_response_sets_the_security_headers[/api/users/me-X-Frame-Options-DENY]`
- `test_v10_responses_do_not_reveal_framework_versions[/api/boom]`
- `test_v10_responses_do_not_reveal_framework_versions[/api/products]`
- `test_v10_responses_do_not_reveal_framework_versions[/api/users/me]`

10 of 10 weaknesses were caught, only by their own tests, and every test for a weakness failed when it was planted (guard tests, which must keep passing, excepted).
