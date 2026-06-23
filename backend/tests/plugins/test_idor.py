"""Tests for the IDOR / BOLA / BFLA detection plugin."""

import httpx
import pytest

from app.plugins.base import Confidence, Severity
from app.plugins.idor.detector import IdorBolaPlugin
from app.plugins.idor.strategies import (
    IdentifiedParam,
    IdentifierMutator,
    IdentifierType,
    PathIdentifierStrategy,
    QueryIdentifierStrategy,
    classify_value,
    discover_all_identifiers,
)
from app.scanner.http_client import ScanResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeClient:
    """Configurable fake HTTP client for plugin testing."""

    def __init__(self, responses: dict[str, ScanResponse] | None = None, default: ScanResponse | None = None):
        self._responses = responses or {}
        self._default = default or ScanResponse("https://example.com/", 200, httpx.Headers({}), "ok", 1.0)
        self.request_count = 0

    async def get(self, url: str) -> ScanResponse:
        self.request_count += 1
        return self._responses.get(url, self._default)

    async def close(self):
        pass


def _response(url="https://example.com/", status=200, text="ok", headers=None):
    return ScanResponse(url, status, httpx.Headers(headers or {}), text, 1.0)


# ===========================================================================
# Strategy Tests
# ===========================================================================

class TestClassifyValue:
    def test_numeric(self):
        assert classify_value("123") == IdentifierType.numeric

    def test_uuid(self):
        assert classify_value("550e8400-e29b-41d4-a716-446655440000") == IdentifierType.uuid

    def test_slug(self):
        assert classify_value("my-resource-name") == IdentifierType.slug

    def test_non_identifier(self):
        assert classify_value("hello") is None

    def test_empty_string(self):
        assert classify_value("") is None


class TestQueryIdentifierStrategy:
    def test_discovers_numeric_id(self):
        strategy = QueryIdentifierStrategy()
        results = strategy.discover("https://example.com/api?user_id=42&name=alice")
        ids = [r for r in results if r.name == "user_id"]
        assert len(ids) == 1
        assert ids[0].id_type == IdentifierType.numeric
        assert ids[0].value == "42"
        assert ids[0].source == "query"

    def test_discovers_uuid_id(self):
        strategy = QueryIdentifierStrategy()
        results = strategy.discover("https://example.com/api?id=550e8400-e29b-41d4-a716-446655440000")
        assert len(results) == 1
        assert results[0].id_type == IdentifierType.uuid

    def test_discovers_by_name(self):
        strategy = QueryIdentifierStrategy()
        results = strategy.discover("https://example.com/api?account_id=abc123")
        assert len(results) == 1
        assert results[0].id_type == IdentifierType.opaque

    def test_no_identifiers(self):
        strategy = QueryIdentifierStrategy()
        results = strategy.discover("https://example.com/api")
        assert results == []


class TestPathIdentifierStrategy:
    def test_discovers_numeric_in_path(self):
        strategy = PathIdentifierStrategy()
        results = strategy.discover("https://example.com/api/users/42/orders")
        nums = [r for r in results if r.id_type == IdentifierType.numeric]
        assert len(nums) == 1
        assert nums[0].value == "42"
        assert nums[0].name == "users"
        assert nums[0].source == "path"

    def test_discovers_uuid_in_path(self):
        strategy = PathIdentifierStrategy()
        results = strategy.discover("https://example.com/resources/550e8400-e29b-41d4-a716-446655440000")
        assert len(results) == 1
        assert results[0].id_type == IdentifierType.uuid

    def test_skips_api_prefix(self):
        strategy = PathIdentifierStrategy()
        results = strategy.discover("https://example.com/api/v1/items/99")
        names = [r.name for r in results]
        assert "api" not in names
        assert "v1" not in names

    def test_no_identifiers(self):
        strategy = PathIdentifierStrategy()
        results = strategy.discover("https://example.com/about")
        assert results == []


class TestIdentifierMutator:
    def test_mutate_numeric(self):
        mutator = IdentifierMutator()
        assert mutator.mutate("42", IdentifierType.numeric) == "43"

    def test_mutate_uuid(self):
        mutator = IdentifierMutator()
        result = mutator.mutate("550e8400-e29b-41d4-a716-446655440000", IdentifierType.uuid)
        assert result is not None
        assert result != "550e8400-e29b-41d4-a716-446655440000"
        assert len(result.split("-")) == 5

    def test_mutate_slug(self):
        mutator = IdentifierMutator()
        assert mutator.mutate("my-resource", IdentifierType.slug) == "my-probe"

    def test_mutate_slug_underscore(self):
        mutator = IdentifierMutator()
        assert mutator.mutate("my_resource", IdentifierType.slug) == "my_probe"

    def test_mutate_opaque(self):
        mutator = IdentifierMutator()
        assert mutator.mutate("token", IdentifierType.opaque) == "token2"

    def test_alternatives(self):
        mutator = IdentifierMutator()
        alts = mutator.mutate_alternatives("42", IdentifierType.numeric)
        assert "43" in alts
        assert "41" in alts
        assert "0" in alts


class TestDiscoverAll:
    def test_combines_query_and_path(self):
        url = "https://example.com/users/42?order_id=99"
        results = discover_all_identifiers(url)
        sources = {r.source for r in results}
        assert "query" in sources
        assert "path" in sources

    def test_deduplicates(self):
        url = "https://example.com/api?id=123"
        results = discover_all_identifiers(url)
        values = [r.value for r in results]
        assert values.count("123") == 1


# ===========================================================================
# Plugin Tests
# ===========================================================================

class TestIdorBolaPlugin:
    @pytest.mark.asyncio
    async def test_detects_bola_on_numeric_query_id(self):
        """When mutating a numeric ID still returns 200 with similar content, flag it."""
        baseline = _response(url="https://example.com/api?user_id=42", text="<html>User Profile Data</html>")
        mutated = _response(url="https://example.com/api?user_id=43", text="<html>User Profile Data</html>")
        client = FakeClient(responses={
            "https://example.com/api?user_id=42": baseline,
            "https://example.com/api?user_id=43": mutated,
        }, default=_response(status=404, text="not found"))
        plugin = IdorBolaPlugin()
        findings = await plugin.run("https://example.com/api?user_id=42", client)
        bola = [f for f in findings if "user_id" in f.title]
        assert len(bola) >= 1
        assert bola[0].severity in (Severity.high, Severity.medium)
        assert bola[0].cwe_id == "CWE-639"
        assert "user_id" in bola[0].evidence_data.get("parameter", "")

    @pytest.mark.asyncio
    async def test_no_finding_when_403(self):
        """When the mutated request gets 403, no BOLA finding should be reported."""
        baseline = _response(url="https://example.com/api?id=1", text="ok")
        mutated = _response(url="https://example.com/api?id=2", status=403, text="forbidden")
        client = FakeClient(responses={
            "https://example.com/api?id=1": baseline,
            "https://example.com/api?id=2": mutated,
        }, default=_response(status=404, text="not found"))
        plugin = IdorBolaPlugin()
        findings = await plugin.run("https://example.com/api?id=1", client)
        bola = [f for f in findings if "id" in f.title and "BFLA" not in f.title and "admin" not in f.title.lower()]
        assert len(bola) == 0

    @pytest.mark.asyncio
    async def test_no_finding_without_identifiers(self):
        """URLs without identifiers should produce no BOLA findings."""
        client = FakeClient(default=_response(status=404, text="not found"))
        plugin = IdorBolaPlugin()
        findings = await plugin.run("https://example.com/about", client)
        # May have BFLA findings but no BOLA
        bola = [f for f in findings if f.cwe_id == "CWE-639"]
        assert len(bola) == 0

    @pytest.mark.asyncio
    async def test_bfla_detection(self):
        """When admin endpoints return 200 with content, report BFLA."""
        admin_response = _response(
            url="https://example.com/admin",
            text="<html><h1>Admin Dashboard</h1><p>Manage users and settings here</p></html>",
        )
        client = FakeClient(responses={
            "https://example.com/admin": admin_response,
        }, default=_response(status=404, text="not found"))
        plugin = IdorBolaPlugin()
        findings = await plugin.run("https://example.com/", client)
        bfla = [f for f in findings if f.cwe_id == "CWE-285"]
        assert len(bfla) >= 1
        assert bfla[0].evidence_data.get("bfla_indicators") is True

    @pytest.mark.asyncio
    async def test_evidence_data_completeness(self):
        """Evidence data should contain all required fields."""
        baseline = _response(url="https://example.com/api?id=1", text="resource data content here")
        mutated = _response(url="https://example.com/api?id=2", text="resource data content here")
        client = FakeClient(responses={
            "https://example.com/api?id=1": baseline,
            "https://example.com/api?id=2": mutated,
        }, default=_response(status=404, text="not found"))
        plugin = IdorBolaPlugin()
        findings = await plugin.run("https://example.com/api?id=1", client)
        bola = [f for f in findings if f.cwe_id == "CWE-639"]
        if bola:
            evidence = bola[0].evidence_data
            assert "parameter" in evidence
            assert "validation_status" in evidence
            assert "similarity" in evidence
            assert "source" in evidence

    @pytest.mark.asyncio
    async def test_fingerprint_is_64_chars(self):
        baseline = _response(url="https://example.com/api?id=1", text="some content")
        mutated = _response(url="https://example.com/api?id=2", text="some content")
        client = FakeClient(responses={
            "https://example.com/api?id=1": baseline,
            "https://example.com/api?id=2": mutated,
        }, default=_response(status=404, text="not found"))
        plugin = IdorBolaPlugin()
        findings = await plugin.run("https://example.com/api?id=1", client)
        for f in findings:
            assert len(f.fingerprint) == 64
