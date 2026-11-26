import json
import re
from difflib import SequenceMatcher
from . import checks

VOLATILE_PATTERNS = [
    (re.compile(r'"(timestamp|created_at|updated_at)"\s*:\s*"[^"]*"', re.I), r'"\1":"<VOLATILE>"'),
    (re.compile(r'"(request_id|trace_id|correlation_id)"\s*:\s*"[^"]*"', re.I), r'"\1":"<VOLATILE>"'),
    (re.compile(r'\b\d{4}-\d\d-\d\d[T ][\d:.+-]+Z?\b'), '<TIMESTAMP>'),
]

def parse_http_response(raw: str):
    raw = (raw or "").replace("\r\n", "\n").strip()
    if not raw:
        return 0, {}, ""
    head, sep, body = raw.partition("\n\n")
    first = head.splitlines()[0] if head else ""
    match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", first, re.I)
    if not match:
        # Accept body-only JSON/text for convenience.
        return 200, {}, raw
    status = int(match.group(1))
    header_text = "\n".join(head.splitlines()[1:])
    headers = {}
    for line in header_text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return status, headers, body if sep else ""

def normalize_body(body: str) -> str:
    normalized = body
    for pattern, replacement in VOLATILE_PATTERNS:
        normalized = pattern.sub(replacement, normalized)
    try:
        parsed = json.loads(normalized)
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (ValueError, TypeError):
        return re.sub(r"\s+", " ", normalized).strip()

def analyze_responses(response_a: str, response_b: str):
    status_a, headers_a, body_a = parse_http_response(response_a)
    status_b, headers_b, body_b = parse_http_response(response_b)
    norm_a, norm_b = normalize_body(body_a), normalize_body(body_b)
    similarity = SequenceMatcher(None, norm_a, norm_b).ratio() if norm_a or norm_b else 1.0
    header_keys = sorted(set(headers_a) | set(headers_b))
    header_diffs = [
        f"{key}: A={headers_a.get(key, '<missing>')} | B={headers_b.get(key, '<missing>')}"
        for key in header_keys if headers_a.get(key) != headers_b.get(key)
    ]
    observations = []
    if status_a == status_b == 200:
        observations.append("Both responses returned HTTP 200; verify whether the requester was authorized to access the represented object.")
    if status_a == 200 and status_b in (401, 403, 404):
        observations.append("The comparison response is denied or not found, while Response A is successful. Confirm which account made each request.")
    if status_b == 200 and status_a in (401, 403, 404):
        observations.append("Response B is successful while Response A is denied or not found. Confirm account identity and object ownership.")
    if similarity >= 0.95:
        observations.append("Bodies are highly similar after normalization; inspect whether both contain the same protected object.")
    elif similarity <= 0.35:
        observations.append("Bodies differ substantially; inspect the changed fields and determine whether differences are expected.")
    details = {}
    diff = checks.field_differences(body_a, body_b)
    if diff is not None:
        changed, only_a, only_b = diff
        details["changed_fields"] = changed
        details["fields_only_in_a"] = only_a
        details["fields_only_in_b"] = only_b
    shared_owner = checks.owner_mismatch(body_a, body_b)
    if shared_owner:
        observations.append("Owner or account fields are identical in both bodies (" + ", ".join(shared_owner) + "); both requests may have returned the same user's object.")
    shared_ids = checks.shared_identifiers(body_a, body_b)
    if shared_ids:
        details["shared_identifiers"] = shared_ids
    sens_a, sens_b = checks.sensitive_fields(body_a), checks.sensitive_fields(body_b)
    details["sensitive_fields_a"], details["sensitive_fields_b"] = sens_a, sens_b
    if status_a == 200 and status_b == 200 and (sens_a or sens_b):
        observations.append("Successful responses contain fields that look sensitive (" + ", ".join(sorted(set(sens_a) | set(sens_b))) + "); confirm the requester may see them.")
    emails = sorted(set(checks.emails_in(body_a)) ^ set(checks.emails_in(body_b)))
    if emails:
        details["emails_differing"] = [checks.mask(e) for e in emails]
        observations.append("The responses reference different email addresses (masked in this report); check whether one belongs to another account.")
    observations.extend(checks.header_findings(headers_a, headers_b))
    observations.extend(checks.error_message_findings(body_a, body_b))
    note = checks.size_finding(body_a, body_b)
    if note:
        observations.append(note)
    if not observations:
        observations.append("No strong heuristic signal. Review status, headers, and body differences manually.")
    if status_a == status_b and similarity > 0.95:
        assessment = "Inconclusive - highly similar responses"
    elif (status_a == 200) != (status_b == 200):
        assessment = "Review required - different access outcomes"
    else:
        assessment = "Inconclusive - manual authorization review required"
    return {
        "status_a": status_a, "status_b": status_b,
        "similarity_percent": round(similarity * 100, 1),
        "header_differences": header_diffs,
        "observations": observations,
        "details": details,
        "assessment": assessment,
        "caveat": "This is a heuristic comparison, not proof of IDOR. Verify account ownership, request context, and authorization rules in an approved test environment."
    }

def build_report(result: dict) -> str:
    observations = "\n".join(f"- {item}" for item in result["observations"])
    headers = "\n".join(f"- {item}" for item in result["header_differences"]) or "- No header differences detected."
    details = result.get("details", {})
    changed = details.get("changed_fields") or []
    changed_text = "\n".join(f"- `{p}`" for p in changed) or "- No changed JSON fields (or bodies are not JSON)."
    return f"""# Potential IDOR / BOLA Assessment

## Summary
{result['assessment']}

## Evidence
- Response A status: `{result['status_a']}`
- Response B status: `{result['status_b']}`
- Normalized body similarity: `{result['similarity_percent']}%`

## Observations
{observations}

## Changed JSON fields
{changed_text}

## Header differences
{headers}

## Manual verification required
- Confirm the identity and role of each test account.
- Confirm the tested object belongs to a different account.
- Confirm access was not explicitly authorized.
- Record sanitized request/response evidence and timestamps.

## Limitations
{result['caveat']}

## Impact
_To be completed after manual verification._

## Remediation
_Enforce server-side object-level authorization on every request. Derive object access from the authenticated principal and deny access by default._
"""
