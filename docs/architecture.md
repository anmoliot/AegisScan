# Architecture

## Runtime

The React/Vite frontend is static. It calls a single FastAPI service that owns authentication, target policy, scan execution, findings, and report rendering. PostgreSQL is the only production stateful dependency.

Scan creation returns `202` immediately. A bounded in-process executor runs enabled plugins and persists normalized results. The UI polls scan state. A backend restart marks queued or running scans failed so interrupted work is visible rather than stuck.

## Boundaries

- `auth/`: identity, passwords, access tokens, and rotating refresh tokens
- `scanner/`: target policy, safe HTTP transport, and executor
- `plugins/`: static registry and detector implementations
- `scans/`: persistence, ownership, schemas, and routes
- `reports/`: escaped server-side HTML rendering
- `core/`: cross-cutting middleware such as rate limiting

The registry is static and code-owned. Arbitrary module paths, uploaded plugins, and runtime imports are intentionally unsupported.

## Scaling boundary

V1 supports one backend process. Horizontal scaling requires a durable queue and shared rate-limit storage; that is intentionally deferred until usage justifies extra infrastructure.
