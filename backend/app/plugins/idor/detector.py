"""
IDOR / BOLA / BFLA Detection Plugin.

Detects:
- Object-level authorization issues (BOLA) via identifier mutation
- Broken Function-Level Authorization (BFLA) via admin endpoint probing
- Multi-identifier correlation for complex access patterns
"""

from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.plugins.base import BasePlugin, Confidence, PluginResult, Severity
from app.plugins.idor.strategies import (
    ADMIN_PATHS,
    IdentifiedParam,
    IdentifierMutator,
    IdentifierType,
    PathIdentifierStrategy,
    QueryIdentifierStrategy,
    discover_all_identifiers,
)


class IdorBolaPlugin(BasePlugin):
    name = "idor_bola"
    description = "Looks for object identifier mutation signals that may indicate IDOR or BOLA"
    category = "authorization"
    active = True

    identifier_names = (
        "id", "user", "user_id", "uid", "account", "account_id",
        "org", "org_id", "tenant", "tenant_id", "object_id",
    )

    def __init__(self):
        self._mutator = IdentifierMutator()

    async def run(self, target_url, client):
        findings = []

        # --- Phase 1: Query + Path identifier BOLA detection ---
        candidates = discover_all_identifiers(target_url)
        if candidates:
            baseline = await client.get(target_url)
            query_and_path = [c for c in candidates if c.source in ("query", "path")]
            for candidate in query_and_path[:5]:
                finding = await self._probe_identifier(
                    target_url, baseline, candidate, client
                )
                if finding:
                    findings.append(finding)

            # --- Multi-identifier correlation ---
            if len(query_and_path) >= 2:
                multi_finding = await self._probe_multi_identifier(
                    target_url, baseline, query_and_path[:3], client
                )
                if multi_finding:
                    findings.append(multi_finding)

        # --- Phase 2: BFLA detection ---
        bfla_findings = await self._probe_admin_endpoints(target_url, client)
        findings.extend(bfla_findings)

        return findings

    async def _probe_identifier(
        self,
        target_url: str,
        baseline,
        candidate: IdentifiedParam,
        client,
    ) -> PluginResult | None:
        mutated_value = self._mutator.mutate(candidate.value, candidate.id_type)
        if mutated_value is None or mutated_value == candidate.value:
            return None

        probe_url = self._build_probe_url(target_url, candidate, mutated_value)
        if probe_url is None:
            return None

        response = await client.get(probe_url)
        confidence, score = self._score_response(
            baseline.status_code, baseline.text,
            response.status_code, response.text,
        )
        if confidence is None:
            return None

        return PluginResult(
            self.name,
            f"Object identifier {candidate.name} remained accessible after mutation",
            "Changing a likely object identifier returned an accessible and similar "
            "response. This is a BOLA/IDOR signal that requires authenticated "
            "validation with two users or roles.",
            Severity.high if confidence == Confidence.high else Severity.medium,
            confidence,
            self.category,
            target_url,
            f"Mutated {candidate.name} ({candidate.source}) from {candidate.value!r} "
            f"to {mutated_value!r}; status {response.status_code}; "
            f"similarity {score:.2f}.",
            "Enforce object-level authorization on every request using the "
            "authenticated principal, tenant, role, and ownership checks. "
            "Add negative tests for cross-user and cross-role access.",
            "CWE-639",
            {
                "parameter": candidate.name,
                "source": candidate.source,
                "identifier_type": candidate.id_type.value,
                "original_value": candidate.value,
                "mutated_value": mutated_value,
                "probe_url": probe_url,
                "status_code": response.status_code,
                "baseline_status_code": baseline.status_code,
                "similarity": round(score, 3),
                "validation_status": "signal_only_requires_authenticated_role_comparison",
                "comparison": {
                    "authorization_comparison": "not_available_without_user_pair",
                    "role_comparison": "not_available_without_role_pair",
                    "user_to_user_validation": "pending_authenticated_replay",
                },
            },
        )

    async def _probe_multi_identifier(
        self,
        target_url: str,
        baseline,
        candidates: list[IdentifiedParam],
        client,
    ) -> PluginResult | None:
        """Mutate multiple identifiers simultaneously to detect correlated access issues."""
        parsed = urlsplit(target_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        query_candidates = [c for c in candidates if c.source == "query"]
        if len(query_candidates) < 2:
            return None

        mutated_params = list(params)
        mutations = {}
        for candidate in query_candidates[:2]:
            mutated_value = self._mutator.mutate(candidate.value, candidate.id_type)
            if mutated_value and mutated_value != candidate.value:
                mutated_params[candidate.position] = (candidate.name, mutated_value)
                mutations[candidate.name] = {
                    "original": candidate.value,
                    "mutated": mutated_value,
                }

        if len(mutations) < 2:
            return None

        probe_url = urlunsplit((
            parsed.scheme, parsed.netloc, parsed.path,
            urlencode(mutated_params), "",
        ))
        response = await client.get(probe_url)
        confidence, score = self._score_response(
            baseline.status_code, baseline.text,
            response.status_code, response.text,
        )
        if confidence is None:
            return None

        param_names = ", ".join(mutations.keys())
        return PluginResult(
            self.name,
            f"Multi-identifier mutation ({param_names}) remained accessible",
            "Simultaneously mutating multiple object identifiers still returned "
            "an accessible response. This suggests authorization may not validate "
            "the combination of resource identifiers.",
            Severity.high,
            confidence,
            self.category,
            target_url,
            f"Mutated {len(mutations)} identifiers; status {response.status_code}; "
            f"similarity {score:.2f}.",
            "Validate that all resource identifiers in a request belong to the "
            "authenticated user and are consistently authorized together.",
            "CWE-639",
            {
                "mutations": mutations,
                "probe_url": probe_url,
                "status_code": response.status_code,
                "baseline_status_code": baseline.status_code,
                "similarity": round(score, 3),
                "validation_status": "multi_id_signal_requires_role_validation",
            },
        )

    async def _probe_admin_endpoints(
        self, target_url: str, client,
    ) -> list[PluginResult]:
        """Probe common administrative endpoints to detect BFLA."""
        parsed = urlsplit(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings = []

        for admin_path in sorted(ADMIN_PATHS)[:6]:
            admin_url = base + admin_path
            try:
                response = await client.get(admin_url)
            except (ValueError, RuntimeError):
                continue

            if response.status_code in {401, 403, 404, 405, 500}:
                continue

            if response.status_code < 400 and len(response.text) > 50:
                confidence = Confidence.medium
                if any(marker in response.text.lower() for marker in
                       ("admin", "dashboard", "manage", "console", "settings")):
                    confidence = Confidence.high

                findings.append(PluginResult(
                    self.name,
                    f"Administrative endpoint accessible: {admin_path}",
                    "An administrative or internal endpoint returned a successful "
                    "response without apparent authorization enforcement. This is "
                    "a Broken Function-Level Authorization (BFLA) signal.",
                    Severity.high if confidence == Confidence.high else Severity.medium,
                    confidence,
                    self.category,
                    admin_url,
                    f"HTTP {response.status_code} on {admin_path} with "
                    f"{len(response.text)} bytes of content.",
                    "Restrict administrative endpoints to authorized roles. "
                    "Implement function-level access control checks and return "
                    "403 or 404 for unauthorized callers.",
                    "CWE-285",
                    {
                        "admin_path": admin_path,
                        "status_code": response.status_code,
                        "content_length": len(response.text),
                        "bfla_indicators": True,
                        "validation_status": "bfla_signal_requires_role_comparison",
                    },
                ))
        return findings

    def _build_probe_url(
        self,
        target_url: str,
        candidate: IdentifiedParam,
        mutated_value: str,
    ) -> str | None:
        parsed = urlsplit(target_url)

        if candidate.source == "query":
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if candidate.position >= len(params):
                return None
            params[candidate.position] = (candidate.name, mutated_value)
            return urlunsplit((
                parsed.scheme, parsed.netloc, parsed.path,
                urlencode(params), "",
            ))

        if candidate.source == "path":
            segments = parsed.path.split("/")
            real_segments = [s for s in segments if s]
            if candidate.position >= len(real_segments):
                return None
            real_segments[candidate.position] = mutated_value
            new_path = "/" + "/".join(real_segments)
            return urlunsplit((
                parsed.scheme, parsed.netloc, new_path,
                parsed.query, "",
            ))

        return None

    def _looks_like_identifier(self, name: str, value: str) -> bool:
        lowered = name.lower()
        return lowered in self.identifier_names or lowered.endswith("_id") or value.isdigit()

    def _mutate_identifier(self, value: str) -> str:
        if value.isdigit():
            return str(int(value) + 1)
        if "-" in value:
            return value.rsplit("-", 1)[0] + "-probe"
        return f"{value}2"

    def _score_response(self, baseline_status, baseline_text, probe_status, probe_text):
        if probe_status in {401, 403, 404}:
            return None, 0.0
        similarity = SequenceMatcher(
            None, baseline_text[:5000], probe_text[:5000]
        ).ratio()
        if probe_status == baseline_status and similarity >= 0.85:
            return Confidence.high, similarity
        if probe_status < 400 and similarity >= 0.55:
            return Confidence.medium, similarity
        return None, similarity
