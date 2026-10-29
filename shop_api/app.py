"""The demo shop API.

create_app() builds a secure API. Passing vulnerability ids (see vulns.py) plants
those weaknesses on purpose, one id per weakness, so the security tests can be
checked against a target whose flaws are known.

The users and passwords below are made-up practice data.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import secrets
import sqlite3
import traceback

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from .vulns import VULNERABILITIES

LOCKOUT_LIMIT = 5
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 50

# id, username, password, role, email
USERS = [
    (1, "alice", "alice-pass-1", "user", "alice@example.com"),
    (2, "bob", "bob-pass-2", "user", "bob@example.com"),
    (3, "admin", "admin-pass-3", "admin", "admin@example.com"),
]
# id, user id, item, total
ORDERS = [
    (1, 1, "Laptop stand", 49.99),
    (2, 1, "USB hub", 24.50),
    (3, 2, "Monitor arm", 89.00),
    (4, 2, "Desk lamp", 31.25),
]
# id, name, price, published
PRODUCTS = [
    (1, "Laptop stand", 49.99, 1),
    (2, "USB hub", 24.50, 1),
    (3, "Monitor arm", 89.00, 1),
    (4, "Desk lamp", 31.25, 1),
    (5, "Webcam", 59.00, 1),
    (6, "Keyboard", 79.00, 1),
    (7, "Unreleased prototype", 999.00, 0),
    (8, "Internal test item", 1.00, 0),
]
UNPUBLISHED_NAMES = {"Unreleased prototype", "Internal test item"}


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 1000).hex()


def _seed(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt TEXT,
                            password_hash TEXT, role TEXT, email TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, published INTEGER);
        """
    )
    for user_id, username, password, role, email in USERS:
        salt = f"salt-{username}"
        db.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                   (user_id, username, salt, hash_password(password, salt), role, email))
    db.executemany("INSERT INTO orders VALUES (?, ?, ?, ?)", ORDERS)
    db.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", PRODUCTS)
    db.commit()


def error(status: int, message: str):
    return jsonify(error=message), status


def create_app(vulns=frozenset()) -> Flask:
    vulns = frozenset(vulns)
    unknown = vulns - set(VULNERABILITIES)
    if unknown:
        raise ValueError(f"unknown vulnerability id: {', '.join(sorted(unknown))}")

    app = Flask(__name__)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    _seed(db)
    app.extensions["db"] = db
    app.extensions["vulns"] = vulns

    tokens: dict[str, int] = {}
    failed_logins: dict[str, int] = {}

    def authenticate():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        token = header[len("Bearer "):].strip()
        if "V02" in vulns:
            try:
                username = base64.b64decode(token, validate=True).decode()
            except (binascii.Error, UnicodeDecodeError):
                return None
            return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        user_id = tokens.get(token)
        if user_id is None:
            return None
        return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def login_required(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            user = authenticate()
            if user is None:
                response, status = error(401, "authentication required")
                response.headers["WWW-Authenticate"] = "Bearer"
                return response, status
            g.user = user
            return view(*args, **kwargs)
        return wrapper

    def profile(user) -> dict:
        body = {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
        if "V04" in vulns:
            body["salt"] = user["salt"]
            body["password_hash"] = user["password_hash"]
        return body

    @app.post("/api/login")
    def login():
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        username, password = body.get("username"), body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return error(400, "username and password are required")
        if "V03" not in vulns and failed_logins.get(username, 0) >= LOCKOUT_LIMIT:
            return error(429, "too many failed attempts")
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        valid = user is not None and hmac.compare_digest(hash_password(password, user["salt"]), user["password_hash"])
        if not valid:
            failed_logins[username] = failed_logins.get(username, 0) + 1
            return error(401, "invalid credentials")
        if "V02" in vulns:
            token = base64.b64encode(username.encode()).decode()
        else:
            token = secrets.token_urlsafe(24)
            tokens[token] = user["id"]
        return jsonify(token=token)

    @app.get("/api/users/me")
    @login_required
    def get_me():
        return jsonify(profile(g.user))

    @app.patch("/api/users/me")
    @login_required
    def update_me():
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not body:
            return error(400, "a JSON object with fields to change is required")
        allowed = {"email", "role"} if "V05" in vulns else {"email"}
        for field in body:
            if field not in allowed:
                return error(400, f"field not allowed: {field}")
        if "email" in body and not (isinstance(body["email"], str) and "@" in body["email"]):
            return error(400, "email is not valid")
        for field in body:  # field names come from the allowed set above, never from the request
            db.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (body[field], g.user["id"]))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
        return jsonify(profile(user))

    @app.get("/api/orders")
    @login_required
    def list_orders():
        rows = db.execute("SELECT * FROM orders WHERE user_id = ?", (g.user["id"],)).fetchall()
        return jsonify(orders=[dict(row) for row in rows])

    @app.get("/api/orders/<int:order_id>")
    @login_required
    def get_order(order_id: int):
        row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if row is None:
            return error(404, "order not found")
        if "V01" not in vulns and row["user_id"] != g.user["id"]:
            return error(404, "order not found")
        return jsonify(dict(row))

    @app.get("/api/products")
    def list_products():
        search = request.args.get("search", "")
        try:
            limit = int(request.args.get("limit", DEFAULT_PAGE_SIZE))
        except ValueError:
            return error(400, "limit must be a whole number")
        if limit < 1:
            return error(400, "limit must be at least 1")
        if "V06" not in vulns:
            limit = min(limit, MAX_PAGE_SIZE)
        if "V08" in vulns:
            query = f"SELECT id, name, price FROM products WHERE published = 1 AND name LIKE '%{search}%' LIMIT {limit}"
            rows = db.execute(query).fetchall()
        else:
            rows = db.execute(
                "SELECT id, name, price FROM products WHERE published = 1 AND name LIKE ? LIMIT ?",
                (f"%{search}%", limit),
            ).fetchall()
        return jsonify(products=[dict(row) for row in rows])

    @app.delete("/api/admin/users/<int:user_id>")
    @login_required
    def delete_user(user_id: int):
        if "V07" not in vulns and g.user["role"] != "admin":
            return error(403, "admin role required")
        if db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
            return error(404, "user not found")
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        return jsonify(deleted=user_id)

    @app.get("/api/boom")
    def boom():
        raise RuntimeError("simulated crash")

    @app.errorhandler(Exception)
    def handle_error(exc):
        if isinstance(exc, HTTPException):
            return error(exc.code, (exc.name or "error").lower())
        if "V09" in vulns:
            return jsonify(error="internal server error", trace=traceback.format_exc()), 500
        return error(500, "internal server error")

    @app.after_request
    def add_headers(response):
        if "V10" in vulns:
            response.headers["X-Powered-By"] = "Flask/3.1 Werkzeug/3.1"
        else:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Frame-Options"] = "DENY"
        return response

    return app
