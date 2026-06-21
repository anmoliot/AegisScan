# Security model

## Defaults

- All product routes require bearer authentication except health and auth endpoints.
- Every scan, finding, and report query includes user ownership.
- Production fails startup for weak secrets, wildcard origins, insecure cookies, or non-PostgreSQL storage.
- API docs and OpenAPI are unavailable in production.
- Registration is configurable and disabled by the included production blueprint.

## Outbound request controls

Every initial URL and redirect is parsed, resolved, and checked. All resolved addresses must be public. Requests remain on the originally approved hostname and ports 80/443. Responses are streamed into a bounded buffer. Time, request, redirect, response-size, and concurrency budgets prevent unbounded work.

DNS rebinding cannot be eliminated perfectly at the application layer because HTTPX resolves again when connecting. Production should add an egress firewall or outbound proxy that also blocks private and metadata ranges for defense in depth.

## Authentication

Passwords use Argon2id. Access tokens are short-lived and expected to remain in frontend memory. Opaque refresh tokens live in Secure, HttpOnly cookies; only their SHA-256 digests are stored. Refresh rotates the token and validates browser Origin when supplied.

## Known v1 limits

Rate limits and scan concurrency are process-local. Authorization confirmation records intent but does not prove ownership. Lightweight checks do not replace a manual penetration test. Audit events are append-only at the application level but are not externally immutable.
