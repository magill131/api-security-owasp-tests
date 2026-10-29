"""Ordinary behaviour of the API.

These tests pass whether or not weaknesses are planted. If one of them fails when a
weakness is planted, the weakness has broken normal behaviour, which a security
test should never be blamed for.
"""

import pytest

from tests.conftest import PASSWORDS


# ---- login -------------------------------------------------------------

def test_login_returns_a_token(client):
    response = client.post("/api/login", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert response.status_code == 200
    assert response.get_json()["token"]


def test_wrong_password_is_rejected(client):
    response = client.post("/api/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 401


def test_unknown_user_gets_the_same_answer_as_a_wrong_password(client):
    wrong_password = client.post("/api/login", json={"username": "alice", "password": "wrong"})
    unknown_user = client.post("/api/login", json={"username": "nobody", "password": "wrong"})
    assert unknown_user.status_code == wrong_password.status_code == 401
    assert unknown_user.get_json() == wrong_password.get_json()


@pytest.mark.parametrize("body", [{}, {"username": "alice"}, {"password": "x"}, {"username": 1, "password": 2}])
def test_login_needs_a_username_and_a_password(client, body):
    assert client.post("/api/login", json=body).status_code == 400


def test_login_still_works_after_a_few_failed_attempts(client):
    for _ in range(4):
        client.post("/api/login", json={"username": "alice", "password": "wrong"})
    response = client.post("/api/login", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert response.status_code == 200


# ---- profile -----------------------------------------------------------

def test_profile_shows_the_signed_in_user(client, login):
    body = client.get("/api/users/me", headers=login("alice")).get_json()
    assert (body["username"], body["role"], body["email"]) == ("alice", "user", "alice@example.com")


def test_profile_needs_a_token(client):
    assert client.get("/api/users/me").status_code == 401


def test_profile_rejects_a_token_that_is_not_valid(client):
    response = client.get("/api/users/me", headers={"Authorization": "Bearer not-a-real-token!"})
    assert response.status_code == 401


def test_user_can_change_their_email(client, login):
    headers = login("alice")
    response = client.patch("/api/users/me", json={"email": "new@example.com"}, headers=headers)
    assert response.status_code == 200
    assert client.get("/api/users/me", headers=headers).get_json()["email"] == "new@example.com"


def test_email_must_look_like_an_email(client, login):
    assert client.patch("/api/users/me", json={"email": "nope"}, headers=login("alice")).status_code == 400


def test_empty_profile_update_is_rejected(client, login):
    assert client.patch("/api/users/me", json={}, headers=login("alice")).status_code == 400


# ---- orders ------------------------------------------------------------

def test_user_sees_only_their_own_orders_in_the_list(client, login):
    orders = client.get("/api/orders", headers=login("alice")).get_json()["orders"]
    assert {order["id"] for order in orders} == {1, 2}


def test_user_can_read_their_own_order(client, login):
    body = client.get("/api/orders/1", headers=login("alice")).get_json()
    assert body["item"] == "Laptop stand"


def test_missing_order_is_not_found(client, login):
    assert client.get("/api/orders/999", headers=login("alice")).status_code == 404


def test_orders_need_a_token(client):
    assert client.get("/api/orders").status_code == 401
    assert client.get("/api/orders/1").status_code == 401


# ---- products ----------------------------------------------------------

def test_product_list_uses_the_default_page_size(client):
    products = client.get("/api/products").get_json()["products"]
    assert 0 < len(products) <= 10


def test_product_search_filters_by_name(client):
    products = client.get("/api/products?search=lamp").get_json()["products"]
    assert [p["name"] for p in products] == ["Desk lamp"]


def test_product_search_with_no_match_is_empty(client):
    assert client.get("/api/products?search=zzzz").get_json()["products"] == []


def test_product_limit_is_respected_inside_the_cap(client):
    assert len(client.get("/api/products?limit=3").get_json()["products"]) == 3


@pytest.mark.parametrize("limit", ["0", "-5", "abc", "1.5"])
def test_product_limit_must_be_a_positive_whole_number(client, limit):
    assert client.get(f"/api/products?limit={limit}").status_code == 400


def test_unpublished_products_are_not_listed(client):
    names = {p["name"] for p in client.get("/api/products?limit=50").get_json()["products"]}
    assert "Unreleased prototype" not in names and "Internal test item" not in names


# ---- admin -------------------------------------------------------------

def test_admin_can_delete_a_user(client, login):
    response = client.delete("/api/admin/users/2", headers=login("admin"))
    assert response.status_code == 200
    assert client.post("/api/login", json={"username": "bob", "password": PASSWORDS["bob"]}).status_code == 401


def test_deleting_a_missing_user_is_not_found(client, login):
    assert client.delete("/api/admin/users/999", headers=login("admin")).status_code == 404


def test_delete_needs_a_token(client):
    assert client.delete("/api/admin/users/2").status_code == 401


def test_a_deleted_users_token_stops_working(client, login):
    bob = login("bob")
    client.delete("/api/admin/users/2", headers=login("admin"))
    assert client.get("/api/users/me", headers=bob).status_code == 401


# ---- errors ------------------------------------------------------------

def test_unknown_route_is_a_json_404(client):
    response = client.get("/api/nothing-here")
    assert response.status_code == 404
    assert "error" in response.get_json()


def test_wrong_method_is_a_json_405(client):
    response = client.put("/api/products")
    assert response.status_code == 405
    assert "error" in response.get_json()


def test_a_crash_returns_a_json_500(client):
    response = client.get("/api/boom")
    assert response.status_code == 500
    assert "error" in response.get_json()
