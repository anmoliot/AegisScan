# Old project migration map

Source reviewed read-only: `C:\Users\Anmol\OneDrive\Desktop\web_scanner\adaptive-web-vuln-scanner`.

## Reused with cleanup

- `backend/detection/base_detector.py`: retained only the abstract plugin idea and normalized result concept; removed crawler/site-map coupling and POST policy.
- `backend/core/finding_schema.py`: retained severity, confidence, evidence, remediation, and deterministic fingerprints; reduced the oversized enterprise/correlation schema.
- `backend/detection/registry.py`: retained the curated-registry idea; replaced JSON-driven dynamic imports with a static allowlist.
- `backend/core/request_handler.py`: retained request-budget and timeout principles; rewrote transport around target and redirect validation.
- `backend/detection/xss_detector.py` and `sqli_detector.py`: retained bounded query-parameter test ideas; replaced payload-heavy, POST, time-delay, UNION, crawler, and analyzer dependencies.

## Rewritten from scratch

- Authentication, refresh-token persistence, database models, API routes, scan lifecycle, target validation, report rendering, configuration, frontend, migrations, Docker, and deployment files.
- `backend/security/ssrf_guard.py`: security-critical and insufficient as a drop-in boundary for the new transport.
- `backend/reports/report_generator.py`: replaced with an autoescaped database-to-HTML renderer and protected owner route.

## Not migrated

- AI, ML, embeddings, copilot, offensive intelligence, and vector modules
- Enterprise, commercial, billing, SSO, organizations, RBAC, and platform modules
- Cloud and attack-surface discovery
- Celery workers, queue orchestration, schedulers, monitoring, WebSockets, and object storage
- Heavy crawler/recon, JavaScript analysis, OpenVAS, network tooling, deep API/GraphQL analysis
- Payload catalogs, dangerous detector families, demo/seed scripts, generated exports, recovery scripts, and old dependency manifests
- Old frontend components and visual assets

No old file was copied directly. The old repository served only as reviewed design input.
