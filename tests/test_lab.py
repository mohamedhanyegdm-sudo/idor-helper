"""Tests for the deliberately vulnerable local lab app.

These tests pin down the lab's intended behavior: the v1 profile endpoint
is vulnerable to IDOR on purpose, and the v2 endpoint enforces ownership.
The lab binds to localhost and is never part of the analyzer itself.
"""

import unittest

from lab.vulnerable_app import app


class LabAppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def login(self, user_id):
        self.client.get(f"/login/{user_id}")

    def test_vulnerable_endpoint_returns_own_profile(self):
        self.login(1)
        response = self.client.get("/api/users/1/profile")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["user_id"], 1)

    def test_vulnerable_endpoint_leaks_other_users_profile(self):
        # This is the intentional IDOR the README walkthrough demonstrates.
        self.login(1)
        response = self.client.get("/api/users/2/profile")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["user_id"], 2)

    def test_fixed_endpoint_blocks_other_users_profile(self):
        self.login(1)
        response = self.client.get("/api/v2/users/2/profile")
        self.assertEqual(response.status_code, 403)

    def test_fixed_endpoint_allows_own_profile(self):
        self.login(1)
        response = self.client.get("/api/v2/users/1/profile")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["user_id"], 1)

    def test_profile_requires_login(self):
        client = app.test_client()
        response = client.get("/api/users/1/profile")
        self.assertEqual(response.status_code, 401)

    def test_unknown_profile_returns_404(self):
        self.login(1)
        response = self.client.get("/api/users/99/profile")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
