import unittest
from idor_helper import checks
from idor_helper.analyzer import analyze_responses, build_report

A = 'HTTP/1.1 200 OK\nCache-Control: no-store\n\n{"id":1,"user_id":7,"email":"a@example.test","plan":"x"}'
SAME = 'HTTP/1.1 200 OK\nCache-Control: no-store\n\n{"id":1,"user_id":7,"email":"a@example.test","plan":"x"}'
OTHER = 'HTTP/1.1 200 OK\nCache-Control: no-store\n\n{"id":2,"user_id":8,"email":"b@example.test","plan":"y"}'


class ChecksTests(unittest.TestCase):
    def test_flatten_nested(self):
        self.assertEqual(checks.flatten({"a": {"b": 1}, "c": [2]}), {"a.b": 1, "c[0]": 2})

    def test_mask_hides_middle(self):
        self.assertEqual(checks.mask("alice@example.test"), "al**************st")
        self.assertEqual(checks.mask("abc"), "***")

    def test_field_differences(self):
        changed, only_a, only_b = checks.field_differences('{"a":1,"b":2}', '{"a":1,"b":3,"c":4}')
        self.assertEqual(changed, ["b"])
        self.assertEqual(only_a, [])
        self.assertEqual(only_b, ["c"])

    def test_field_differences_non_json(self):
        self.assertIsNone(checks.field_differences("plain", '{"a":1}'))

    def test_sensitive_fields(self):
        self.assertEqual(checks.sensitive_fields('{"email":"x","name":"y","profile":{"phone":"1"}}'), ["email", "profile.phone"])

    def test_owner_mismatch_detects_same_owner(self):
        self.assertEqual(checks.owner_mismatch('{"user_id":7}', '{"user_id":7}'), ["user_id"])
        self.assertEqual(checks.owner_mismatch('{"user_id":7}', '{"user_id":8}'), [])

    def test_shared_identifiers(self):
        self.assertEqual(checks.shared_identifiers('{"id":1}', '{"id":1}'), ["id"])

    def test_emails_in(self):
        self.assertEqual(checks.emails_in("a@example.test, b@example.test a@example.test"), ["a@example.test", "b@example.test"])

    def test_header_findings(self):
        found = checks.header_findings({"set-cookie": "s=1"}, {"access-control-allow-origin": "*"})
        self.assertTrue(any("sets a cookie" in f for f in found))
        self.assertTrue(any("CORS" in f for f in found))

    def test_error_message_findings(self):
        found = checks.error_message_findings('{"error":"not found"}', '{"error":"Forbidden"}')
        self.assertEqual(len(found), 2)

    def test_size_finding(self):
        self.assertIsNotNone(checks.size_finding("abcdef", "abcdef"))
        self.assertIsNone(checks.size_finding("a", "abcdefgh"))


class AnalyzerIntegrationTests(unittest.TestCase):
    def test_same_object_flagged(self):
        result = analyze_responses(A, SAME)
        self.assertTrue(any("same user's object" in o for o in result["observations"]))

    def test_different_owner_not_flagged(self):
        result = analyze_responses(A, OTHER)
        self.assertFalse(any("same user's object" in o for o in result["observations"]))
        self.assertIn("email", result["details"]["sensitive_fields_a"])

    def test_emails_masked_in_details(self):
        result = analyze_responses(A, OTHER)
        self.assertNotIn("a@example.test", str(result["details"]["emails_differing"]))

    def test_report_lists_changed_fields(self):
        report = build_report(analyze_responses(A, OTHER))
        self.assertIn("## Changed JSON fields", report)
        self.assertIn("`user_id`", report)

    def test_empty_inputs_do_not_crash(self):
        result = analyze_responses("", "")
        self.assertEqual(result["status_a"], 0)


if __name__ == "__main__":
    unittest.main()
