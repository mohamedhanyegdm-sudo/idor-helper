import unittest
from idor_helper.analyzer import parse_http_response, analyze_responses, normalize_body

class AnalyzerTests(unittest.TestCase):
    def test_parse_raw_response(self):
        status, headers, body = parse_http_response("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"error\":\"denied\"}")
        self.assertEqual(status, 403)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertIn("denied", body)

    def test_body_only_defaults_to_200(self):
        self.assertEqual(parse_http_response('{"id":1}')[0], 200)

    def test_json_key_order_normalized(self):
        self.assertEqual(normalize_body('{"a":1,"b":2}'), normalize_body('{"b":2,"a":1}'))

    def test_different_access_outcomes_flagged(self):
        a = "HTTP/1.1 200 OK\n\n{\"user\":\"alice\"}"
        b = "HTTP/1.1 403 Forbidden\n\n{\"error\":\"denied\"}"
        result = analyze_responses(a, b)
        self.assertIn("different access outcomes", result["assessment"])

if __name__ == "__main__":
    unittest.main()
