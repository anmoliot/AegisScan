# Plugin development

Plugins subclass `BasePlugin`, declare metadata, and implement:

```python
async def run(self, target_url: str, client: SafeHttpClient) -> list[PluginResult]:
    ...
```

Use only the supplied client. It enforces target, redirect, timeout, size, and request-budget policy. A plugin must be stateless, deterministic where practical, and return normalized results. Never create a separate network client, accept user payloads, submit state-changing requests, or suppress the central target policy.

Add reviewed plugins explicitly to `app/plugins/registry.py`. Dynamic discovery is intentionally prohibited. Include tests for no-finding, positive-signal, malformed-response, and budget-exhaustion behavior.

Evidence must be concise and must not contain secrets, full response bodies, authorization headers, or cookies. Describe signals honestly; a reflection signal is not automatically confirmed XSS.
