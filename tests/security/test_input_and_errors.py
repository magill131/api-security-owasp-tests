"""What happens with hostile input, big requests and crashes. Covers V06, V08, V09 and V10."""

import pytest

SQL_PAYLOAD = "zzz%' OR published = 0 --"
UNPUBLISHED = {"Unreleased prototype", "Internal test item"}


# V06 - API4:2023 Unrestricted Resource Consumption

def _add_products(app, count):
    db = app.extensions["db"]
    db.executemany("INSERT INTO products (name, price, published) VALUES (?, ?, 1)",
                   [(f"Bulk item {i}", 1.0, ) for i in range(count)])
    db.commit()


def test_v06_a_huge_page_size_is_capped(client, app):
    _add_products(app, 120)
    products = client.get("/api/products?limit=1000").get_json()["products"]
    assert len(products) <= 50


def test_v06_one_over_the_cap_is_still_capped(client, app):
    _add_products(app, 120)
    assert len(client.get("/api/products?limit=51").get_json()["products"]) <= 50


# V08 - A03:2021 Injection

def test_v08_injected_sql_cannot_reveal_unpublished_products(client):
    response = client.get("/api/products", query_string={"search": SQL_PAYLOAD})
    names = {p["name"] for p in (response.get_json() or {}).get("products", [])}
    assert not names & UNPUBLISHED


def test_v08_a_lone_quote_does_not_break_the_search(client):
    response = client.get("/api/products", query_string={"search": "'"})
    assert response.status_code != 500


def test_v08_a_quote_in_the_search_is_treated_as_text(client):
    response = client.get("/api/products", query_string={"search": "o'brien"})
    assert response.status_code == 200
    assert response.get_json()["products"] == []


# V09 - API8:2023 Security Misconfiguration (error details)

def test_v09_a_crash_does_not_include_a_stack_trace(client):
    text = client.get("/api/boom").get_data(as_text=True)
    assert "Traceback" not in text
    assert "simulated crash" not in text


@pytest.mark.parametrize("clue", ["RuntimeError", ".py", "line "])
def test_v09_a_crash_does_not_reveal_file_paths_or_exception_names(client, clue):
    assert clue not in client.get("/api/boom").get_data(as_text=True)


# V10 - API8:2023 Security Misconfiguration (headers)

@pytest.mark.parametrize("header, value", [
    ("X-Content-Type-Options", "nosniff"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
])
@pytest.mark.parametrize("path", ["/api/products", "/api/users/me", "/api/nothing-here"])
def test_v10_every_response_sets_the_security_headers(client, path, header, value):
    assert client.get(path).headers.get(header) == value  # includes 401 and 404 responses


@pytest.mark.parametrize("path", ["/api/products", "/api/users/me", "/api/boom"])
def test_v10_responses_do_not_reveal_framework_versions(client, path):
    headers = client.get(path).headers
    assert "X-Powered-By" not in headers
