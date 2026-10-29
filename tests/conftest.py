import pytest

from shop_api import create_app, parse_vulns

PASSWORDS = {"alice": "alice-pass-1", "bob": "bob-pass-2", "admin": "admin-pass-3"}


def pytest_addoption(parser):
    parser.addoption(
        "--vulns",
        default="none",
        help="weaknesses to plant in the API under test: none, all, or a list such as V01,V05",
    )


@pytest.fixture
def app(request):
    return create_app(parse_vulns(request.config.getoption("--vulns")))


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def login(client):
    """login("alice") -> the Authorization header for a signed-in alice."""

    def _login(username):
        response = client.post("/api/login", json={"username": username, "password": PASSWORDS[username]})
        assert response.status_code == 200, response.get_json()
        return {"Authorization": f"Bearer {response.get_json()['token']}"}

    return _login
