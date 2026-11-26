"""Deliberately vulnerable demo API used to validate IDOR Helper end to end.

This app exists only so the README walkthrough can show the tool working
against a real, local, intentionally vulnerable target. It binds to
127.0.0.1 and stores everything in memory. Never deploy it, never expose
it on a network, and never point it or IDOR Helper at any system you do
not own or lack explicit permission to test.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = {
    1: {
        "user_id": 1,
        "username": "alice",
        "full_name": "Alice Demo",
        "email": "alice@example.test",
        "phone": "+201000000001",
        "role": "user",
        "created_at": "2026-01-10T09:30:00Z",
    },
    2: {
        "user_id": 2,
        "username": "bob",
        "full_name": "Bob Demo",
        "email": "bob@example.test",
        "phone": "+201000000002",
        "role": "user",
        "created_at": "2026-02-14T17:45:00Z",
    },
}

SESSION_COOKIE = "demo_session"


def current_user_id():
    """Return the logged-in demo user id from the cookie, or None."""
    value = request.cookies.get(SESSION_COOKIE, "")
    try:
        user_id = int(value)
    except ValueError:
        return None
    return user_id if user_id in USERS else None


@app.get("/login/<int:user_id>")
def login(user_id):
    """Pretend to log in as a demo user by setting an insecure cookie.

    Real authentication is out of scope for this lab; the cookie simply
    records which demo account the requests below belong to.
    """
    if user_id not in USERS:
        return jsonify({"error": "unknown demo user"}), 404
    response = jsonify({"message": f"logged in as user {user_id}"})
    response.set_cookie(SESSION_COOKIE, str(user_id), httponly=True)
    return response


@app.get("/api/users/<int:user_id>/profile")
def get_profile_vulnerable(user_id):
    """VULNERABLE ON PURPOSE: returns any profile without an ownership check.

    The session cookie is read only to prove the point: the logged-in user
    and the requested profile are allowed to differ, which is the IDOR.
    """
    if current_user_id() is None:
        return jsonify({"error": "not logged in"}), 401
    user = USERS.get(user_id)
    if user is None:
        return jsonify({"error": "user not found"}), 404
    return jsonify(user)


@app.get("/api/v2/users/<int:user_id>/profile")
def get_profile_fixed(user_id):
    """Fixed version: the requester may only read their own profile."""
    session_user_id = current_user_id()
    if session_user_id is None:
        return jsonify({"error": "not logged in"}), 401
    if session_user_id != user_id:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(USERS[user_id])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
