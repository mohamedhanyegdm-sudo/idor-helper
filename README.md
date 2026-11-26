# IDOR Helper

A small, local-first assistant for **analyzing two HTTP responses** captured during an authorized IDOR/BOLA assessment.

> Safety by design: this tool does not send requests, crawl websites, change identifiers, or contact targets. Paste responses you already captured in Burp Suite or another authorized testing tool. Analyze only systems you are permitted to test.

## Features

- Compare HTTP status codes, headers, and response bodies.
- Normalize likely volatile values (timestamps, request IDs) before comparing.
- Highlight possible access-control warning signs, such as a successful response containing another user's record.
- Produce a Markdown finding template with evidence and limitations.
- Simple Flask web interface and command-line interface.
- Field-level comparison of JSON bodies, listing which fields changed.
- Detection of identical owner or account fields, shared identifiers, and fields that look sensitive (email, phone, token, and similar).
- Masked display of differing email addresses so reports do not copy personal data.
- Header checks: cookies, missing `Cache-Control` restrictions, wildcard CORS.
- Error message checks that can reveal whether an object exists (object enumeration signals).
- Unit tests for the parser, normalizer, checks, and report builder.

## Requirements

- Python 3.10+
- Flask (for the web interface)

## Setup

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows
# .venv\Scripts\activate

pip install -r requirements.txt
```

## Run the web interface

```bash
python app.py
```

Open `http://127.0.0.1:5000`.

The server binds to localhost only. Do not expose it to the public internet.

## CLI

Save two captured HTTP responses as text files, for example `user_a.txt` and `user_b.txt`:

```bash
python -m idor_helper.cli user_a.txt user_b.txt --report report.md
```

## Suggested authorized workflow

1. Use two test accounts you control in a lab or an explicitly authorized program.
2. Capture the response to the same resource with each account.
3. Paste or save the complete raw HTTP responses.
4. Compare them with IDOR Helper.
5. Manually verify authorization behavior and document the exact evidence.
6. Do not treat a heuristic result as proof of a vulnerability.

## Examples

Sample captured responses are in `examples/`.

```bash
python -m idor_helper.cli examples/response_user_a.txt examples/response_user_b_denied.txt
```

```text
Assessment: Review required - different access outcomes
Status: 200 vs 403
Body similarity: 19.3%
- The comparison response is denied or not found, while Response A is successful. Confirm which account made each request.
- Bodies differ substantially; inspect the changed fields and determine whether differences are expected.
- The responses reference different email addresses (masked in this report); check whether one belongs to another account.
- Response B says access is forbidden; a different message from a 'not found' reply can reveal that an object exists.
```

When both accounts receive the same object:

```bash
python -m idor_helper.cli examples/response_user_a.txt examples/response_user_b_same_object.txt --report report.md
```

```text
Assessment: Inconclusive - highly similar responses
Status: 200 vs 200
Body similarity: 100.0%
- Both responses returned HTTP 200; verify whether the requester was authorized to access the represented object.
- Bodies are highly similar after normalization; inspect whether both contain the same protected object.
- Owner or account fields are identical in both bodies (user_id); both requests may have returned the same user's object.
- Successful responses contain fields that look sensitive (email); confirm the requester may see them.
- Body sizes are nearly identical (112 and 112 characters).
```

The saved report includes a "Changed JSON fields" section (here only `created_at`, which is volatile).

## Validation on a local lab

`lab/vulnerable_app.py` is a small Flask API that is vulnerable to IDOR on purpose. It exists so the tool can be validated end to end against a real local target instead of pasted samples. It binds to `127.0.0.1` only; never deploy it or expose it on a network.

The lab has two demo users (1 and 2). `GET /api/users/<id>/profile` checks only that someone is logged in, not that the requester owns the profile, so user 1 can read user 2's profile. `GET /api/v2/users/<id>/profile` is the fixed version and returns `403` for anyone but the owner.

Run it and capture two responses (these captures are committed in `lab/captures/`):

```bash
python lab/vulnerable_app.py &
curl -c cookies.txt http://127.0.0.1:5001/login/1
curl -i -b cookies.txt http://127.0.0.1:5001/api/users/1/profile > lab/captures/response_own.txt
curl -i -b cookies.txt http://127.0.0.1:5001/api/users/2/profile > lab/captures/response_idor.txt
```

Both responses are HTTP 200. Only the account context reveals the problem: user 1's session received user 2's record. Comparing the captures:

```bash
python -m idor_helper.cli lab/captures/response_own.txt lab/captures/response_idor.txt --report lab/captures/report_idor.md
```

```text
Assessment: Inconclusive - manual authorization review required
Status: 200 vs 200
Body similarity: 90.5%
- Both responses returned HTTP 200; verify whether the requester was authorized to access the represented object.
- Successful responses contain fields that look sensitive (email, phone); confirm the requester may see them.
- The responses reference different email addresses (masked in this report); check whether one belongs to another account.
- Response A has no 'no-store' or 'private' Cache-Control; authenticated data may be cacheable.
- Response B has no 'no-store' or 'private' Cache-Control; authenticated data may be cacheable.
Report saved to: lab/captures/report_idor.md
```

The saved report's "Changed JSON fields" section lists every identity field (`user_id`, `username`, `email`, `phone`, `full_name`), which is what an analyst expects when one endpoint returns two different users' objects.

The fixed endpoint shows the expected contrast:

```bash
curl -i -b cookies.txt http://127.0.0.1:5001/api/v2/users/2/profile > lab/captures/response_blocked.txt
python -m idor_helper.cli lab/captures/response_own.txt lab/captures/response_blocked.txt
```

This reports `Review required - different access outcomes` (200 vs 403), the expected result once object-level authorization is enforced.

This is a synthetic local demo. It confirms the tool's checks fire on a real IDOR-shaped capture; it says nothing about the security of any other application.

## Tests

```bash
python -m unittest discover -s tests -t .
```

## Input format

Paste a raw HTTP response including the status line and headers, followed by a blank line and the body. A body-only JSON response is also accepted; it will be treated as status `200`.

## Limitations

This is an evidence-comparison helper, not an automatic vulnerability scanner. Similar responses do not prove authorization is correct, and different responses do not prove IDOR. The analyst must verify whether the data belongs to another account and whether access was actually unauthorized.

## Project structure

```text
idor-helper/
├── app.py
├── idor_helper/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── checks.py
│   └── cli.py
├── examples/
├── lab/
│   ├── vulnerable_app.py
│   └── captures/
├── tests/
│   ├── test_analyzer.py
│   ├── test_checks.py
│   └── test_lab.py
├── requirements.txt
└── README.md
```

## License

MIT
