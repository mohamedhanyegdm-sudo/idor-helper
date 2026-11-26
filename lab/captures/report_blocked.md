# Potential IDOR / BOLA Assessment

## Summary
Review required - different access outcomes

## Evidence
- Response A status: `200`
- Response B status: `403`
- Normalized body similarity: `17.5%`

## Observations
- The comparison response is denied or not found, while Response A is successful. Confirm which account made each request.
- Bodies differ substantially; inspect the changed fields and determine whether differences are expected.
- The responses reference different email addresses (masked in this report); check whether one belongs to another account.
- Response A has no 'no-store' or 'private' Cache-Control; authenticated data may be cacheable.
- Response B has no 'no-store' or 'private' Cache-Control; authenticated data may be cacheable.
- Response B says access is forbidden; a different message from a 'not found' reply can reveal that an object exists.

## Changed JSON fields
- No changed JSON fields (or bodies are not JSON).

## Header differences
- content-length: A=161 | B=22

## Manual verification required
- Confirm the identity and role of each test account.
- Confirm the tested object belongs to a different account.
- Confirm access was not explicitly authorized.
- Record sanitized request/response evidence and timestamps.

## Limitations
This is a heuristic comparison, not proof of IDOR. Verify account ownership, request context, and authorization rules in an approved test environment.

## Impact
_To be completed after manual verification._

## Remediation
_Enforce server-side object-level authorization on every request. Derive object access from the authenticated principal and deny access by default._
