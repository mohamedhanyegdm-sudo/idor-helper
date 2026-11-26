"""Additional offline checks on already-captured responses. No network access."""
import json
import re

SENSITIVE_KEY_HINTS = (
    "email", "phone", "address", "ssn", "dob", "birth", "iban", "card",
    "password", "token", "secret", "api_key", "apikey", "salary",
)
OWNER_KEYS = ("user_id", "userid", "owner_id", "ownerid", "account_id", "accountid", "customer_id", "uid", "owner", "username")
ID_KEYS = ("id", "uuid", "order_id", "invoice_id")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def load_json(body: str):
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def flatten(data, prefix=""):
    """Flatten nested JSON into {dotted.path: value}."""
    out = {}
    if isinstance(data, dict):
        for key, value in data.items():
            out.update(flatten(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            out.update(flatten(value, f"{prefix}[{index}]"))
    else:
        out[prefix] = data
    return out


def mask(value) -> str:
    """Mask a value so reports do not copy personal data."""
    text = str(value)
    if len(text) <= 4:
        return "***"
    return text[:2] + "*" * (len(text) - 4) + text[-2:]


def last_key(path: str) -> str:
    return re.sub(r"\[\d+\]", "", path.split(".")[-1]).lower()


def field_differences(body_a: str, body_b: str):
    """Return (changed, only_a, only_b) field paths for JSON bodies."""
    a, b = load_json(body_a), load_json(body_b)
    if a is None or b is None:
        return None
    fa, fb = flatten(a), flatten(b)
    changed = sorted(k for k in fa.keys() & fb.keys() if fa[k] != fb[k])
    return changed, sorted(fa.keys() - fb.keys()), sorted(fb.keys() - fa.keys())


def sensitive_fields(body: str):
    """Paths of fields whose names suggest personal or secret data."""
    data = load_json(body)
    if data is None:
        return []
    return sorted(p for p in flatten(data) if any(h in last_key(p) for h in SENSITIVE_KEY_HINTS))


def owner_mismatch(body_a: str, body_b: str):
    """Owner-like fields that are identical in both responses (same object returned)."""
    a, b = load_json(body_a), load_json(body_b)
    if a is None or b is None:
        return []
    fa, fb = flatten(a), flatten(b)
    return sorted(k for k in fa.keys() & fb.keys() if last_key(k) in OWNER_KEYS and fa[k] == fb[k])


def shared_identifiers(body_a: str, body_b: str):
    """Identifier fields that carry the same value in both responses."""
    a, b = load_json(body_a), load_json(body_b)
    if a is None or b is None:
        return []
    fa, fb = flatten(a), flatten(b)
    return sorted(k for k in fa.keys() & fb.keys() if last_key(k) in ID_KEYS and fa[k] == fb[k])


def emails_in(body: str):
    return sorted(set(EMAIL_RE.findall(body or "")))


def header_findings(headers_a: dict, headers_b: dict):
    findings = []
    for label, headers in (("A", headers_a), ("B", headers_b)):
        if "set-cookie" in headers:
            findings.append(f"Response {label} sets a cookie; make sure session material is not included in shared evidence.")
        cache = headers.get("cache-control", "").lower()
        if headers and ("no-store" not in cache and "private" not in cache):
            findings.append(f"Response {label} has no 'no-store' or 'private' Cache-Control; authenticated data may be cacheable.")
        if "access-control-allow-origin" in headers and headers["access-control-allow-origin"].strip() == "*":
            findings.append(f"Response {label} allows any CORS origin; review this for authenticated endpoints.")
    return findings


def error_message_findings(body_a: str, body_b: str):
    """Differences in error wording that let a caller tell 'exists' from 'missing'."""
    findings = []
    for label, body in (("A", body_a), ("B", body_b)):
        lowered = (body or "").lower()
        if "not found" in lowered or "does not exist" in lowered:
            findings.append(f"Response {label} says the object does not exist; compare with the denied response to check for object enumeration.")
        if "forbidden" in lowered or "not authorized" in lowered or "permission" in lowered:
            findings.append(f"Response {label} says access is forbidden; a different message from a 'not found' reply can reveal that an object exists.")
    return findings


def size_finding(body_a: str, body_b: str):
    la, lb = len(body_a or ""), len(body_b or "")
    if la and lb and abs(la - lb) / max(la, lb) <= 0.02:
        return f"Body sizes are nearly identical ({la} and {lb} characters)."
    return None
