"""Who you say you are, and how well that is protected. Covers V02, V03 and V04."""

import base64

from tests.conftest import PASSWORDS


# V02 - API2:2023 Broken Authentication (tokens)

def test_v02_a_token_forged_from_a_username_is_rejected(client):
    forged = base64.b64encode(b"admin").decode()
    response = client.get("/api/users/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_v02_a_forged_token_cannot_reach_admin_functions(client):
    forged = base64.b64encode(b"admin").decode()
    response = client.delete("/api/admin/users/2", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_v02_tokens_are_not_derived_from_the_username(client, login):
    token = login("alice")["Authorization"].split(" ", 1)[1]
    assert token != base64.b64encode(b"alice").decode()
    assert len(token) >= 20


def test_v02_every_login_gets_a_different_token(client, login):
    assert login("alice") != login("alice")


# V03 - API2:2023 Broken Authentication (guessing passwords)

def test_v03_account_locks_after_repeated_failed_logins(client):
    codes = [client.post("/api/login", json={"username": "alice", "password": f"guess-{i}"}).status_code
             for i in range(8)]
    assert 429 in codes


def test_v03_the_correct_password_is_refused_while_locked(client):
    for i in range(5):
        client.post("/api/login", json={"username": "alice", "password": f"guess-{i}"})
    response = client.post("/api/login", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert response.status_code == 429


def test_v03_guard_locking_one_account_does_not_lock_another(client):
    # A guard test: it passes with and without the weakness. It stops the lockout from being
    # "fixed" by locking everyone out.
    for i in range(6):
        client.post("/api/login", json={"username": "alice", "password": f"guess-{i}"})
    response = client.post("/api/login", json={"username": "bob", "password": PASSWORDS["bob"]})
    assert response.status_code == 200


# V04 - API3:2023 Broken Object Property Level Authorization (too much data)

def test_v04_profile_does_not_include_the_password_hash(client, login):
    body = client.get("/api/users/me", headers=login("alice")).get_json()
    assert not [key for key in body if "password" in key or "hash" in key or "salt" in key]


def test_v04_the_hash_value_never_appears_in_the_response_text(client, login, app):
    stored = app.extensions["db"].execute("SELECT password_hash FROM users WHERE username = 'alice'").fetchone()[0]
    text = client.get("/api/users/me", headers=login("alice")).get_data(as_text=True)
    assert stored not in text


def test_v04_the_profile_update_response_does_not_leak_it_either(client, login, app):
    stored = app.extensions["db"].execute("SELECT password_hash FROM users WHERE username = 'alice'").fetchone()[0]
    response = client.patch("/api/users/me", json={"email": "a@example.com"}, headers=login("alice"))
    assert stored not in response.get_data(as_text=True)
