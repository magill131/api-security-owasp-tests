"""Who is allowed to do what. Covers V01, V05 and V07.

Every test name starts with the id of the weakness it exists to catch (test_v01_...).
"""

from tests.conftest import PASSWORDS


# V01 - API1:2023 Broken Object Level Authorization

def test_v01_user_cannot_read_another_users_order(client, login):
    response = client.get("/api/orders/3", headers=login("alice"))  # order 3 belongs to bob
    assert response.status_code in (403, 404)
    assert "Monitor arm" not in response.get_data(as_text=True)


def test_v01_the_rule_works_in_both_directions(client, login):
    response = client.get("/api/orders/1", headers=login("bob"))  # order 1 belongs to alice
    assert response.status_code in (403, 404)
    assert "Laptop stand" not in response.get_data(as_text=True)


# V05 - API3:2023 Broken Object Property Level Authorization (mass assignment)

def test_v05_user_cannot_make_themselves_an_admin(client, login):
    headers = login("alice")
    client.patch("/api/users/me", json={"role": "admin"}, headers=headers)
    assert client.get("/api/users/me", headers=headers).get_json()["role"] == "user"


def test_v05_a_role_change_attempt_does_not_survive_a_new_login(client, login):
    client.patch("/api/users/me", json={"role": "admin"}, headers=login("alice"))
    assert client.get("/api/users/me", headers=login("alice")).get_json()["role"] == "user"


def test_v05_extra_fields_are_refused_not_silently_accepted(client, login):
    response = client.patch("/api/users/me", json={"email": "a@example.com", "role": "admin"}, headers=login("alice"))
    assert response.status_code == 400


# V07 - API5:2023 Broken Function Level Authorization

def test_v07_normal_user_cannot_delete_users(client, login):
    response = client.delete("/api/admin/users/2", headers=login("alice"))
    assert response.status_code == 403


def test_v07_the_target_user_still_exists_after_a_refused_delete(client, login):
    client.delete("/api/admin/users/2", headers=login("alice"))
    still_there = client.post("/api/login", json={"username": "bob", "password": PASSWORDS["bob"]})
    assert still_there.status_code == 200
