"""
Identifier discovery and mutation strategies for IDOR/BOLA detection.

Supports query parameters, URL path segments, and custom headers.
"""

import re
import uuid as uuid_mod
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import parse_qsl, urlsplit


class IdentifierType(str, Enum):
    numeric = "numeric"
    uuid = "uuid"
    slug = "slug"
    opaque = "opaque"


@dataclass(frozen=True, slots=True)
class IdentifiedParam:
    """A candidate identifier found in a request."""
    source: str          # "query", "path", "header"
    name: str            # parameter/segment/header name
    value: str           # original value
    id_type: IdentifierType
    position: int        # index within its source


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_NUMERIC_RE = re.compile(r"^\d+$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)+$", re.I)

IDENTIFIER_NAMES = frozenset({
    "id", "user", "user_id", "uid", "account", "account_id",
    "org", "org_id", "tenant", "tenant_id", "object_id",
    "order_id", "item_id", "doc_id", "file_id", "project_id",
    "resource_id", "record_id", "profile_id", "customer_id",
})

ADMIN_PATHS = frozenset({
    "/admin", "/manage", "/internal", "/dashboard/admin",
    "/api/admin", "/api/internal", "/api/v1/admin",
    "/api/v1/internal", "/api/v1/manage", "/console",
})


def classify_value(value: str) -> IdentifierType | None:
    """Classify a string value as an identifier type, or None if not identifier-like."""
    if _NUMERIC_RE.match(value):
        return IdentifierType.numeric
    if _UUID_RE.match(value):
        return IdentifierType.uuid
    if _SLUG_RE.match(value) and len(value) <= 128:
        return IdentifierType.slug
    return None


def _looks_like_identifier_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in IDENTIFIER_NAMES or lowered.endswith("_id")


class QueryIdentifierStrategy:
    """Discovers identifiers in URL query parameters."""

    def discover(self, url: str) -> list[IdentifiedParam]:
        parsed = urlsplit(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)[:10]
        results = []
        for index, (name, value) in enumerate(params):
            if not value:
                continue
            id_type = classify_value(value)
            if id_type is not None or _looks_like_identifier_name(name):
                results.append(IdentifiedParam(
                    source="query",
                    name=name,
                    value=value,
                    id_type=id_type or IdentifierType.opaque,
                    position=index,
                ))
        return results


class PathIdentifierStrategy:
    """Discovers identifiers in URL path segments."""

    _API_PREFIX_RE = re.compile(r"^(?:api|v\d+)$", re.I)

    def discover(self, url: str) -> list[IdentifiedParam]:
        parsed = urlsplit(url)
        segments = [seg for seg in parsed.path.split("/") if seg]
        results = []
        for index, segment in enumerate(segments):
            if self._API_PREFIX_RE.match(segment):
                continue
            id_type = classify_value(segment)
            if id_type is not None:
                # Use the preceding segment as the "name" context if available
                context = segments[index - 1] if index > 0 else f"segment_{index}"
                results.append(IdentifiedParam(
                    source="path",
                    name=context,
                    value=segment,
                    id_type=id_type,
                    position=index,
                ))
        return results


class HeaderIdentifierStrategy:
    """Discovers identifiers in custom request headers (used for API analysis)."""

    IDENTITY_HEADERS = frozenset({
        "x-user-id", "x-account-id", "x-tenant-id", "x-org-id",
        "x-customer-id", "x-request-user",
    })

    def discover(self, headers: dict[str, str]) -> list[IdentifiedParam]:
        results = []
        for index, (name, value) in enumerate(headers.items()):
            if name.lower() in self.IDENTITY_HEADERS:
                id_type = classify_value(value) or IdentifierType.opaque
                results.append(IdentifiedParam(
                    source="header",
                    name=name,
                    value=value,
                    id_type=id_type,
                    position=index,
                ))
        return results


class IdentifierMutator:
    """Generates mutated identifier values for probing."""

    def mutate(self, value: str, id_type: IdentifierType) -> str | None:
        """Return a mutated value, or None if mutation is not possible."""
        if id_type == IdentifierType.numeric:
            return self._mutate_numeric(value)
        if id_type == IdentifierType.uuid:
            return self._mutate_uuid(value)
        if id_type == IdentifierType.slug:
            return self._mutate_slug(value)
        if id_type == IdentifierType.opaque:
            return self._mutate_opaque(value)
        return None

    def mutate_alternatives(self, value: str, id_type: IdentifierType) -> list[str]:
        """Return multiple mutation candidates for multi-probe scenarios."""
        primary = self.mutate(value, id_type)
        if primary is None:
            return []
        alternatives = [primary]
        if id_type == IdentifierType.numeric:
            num = int(value)
            if num > 1:
                alternatives.append(str(num - 1))
            alternatives.append("0")
        return alternatives[:3]

    @staticmethod
    def _mutate_numeric(value: str) -> str:
        return str(int(value) + 1)

    @staticmethod
    def _mutate_uuid(value: str) -> str:
        parts = value.split("-")
        # Increment the last segment
        last = int(parts[-1], 16)
        parts[-1] = format((last + 1) % (16 ** len(parts[-1])), f"0{len(parts[-1])}x")
        return "-".join(parts)

    @staticmethod
    def _mutate_slug(value: str) -> str:
        if "-" in value:
            return value.rsplit("-", 1)[0] + "-probe"
        if "_" in value:
            return value.rsplit("_", 1)[0] + "_probe"
        return f"{value}-probe"

    @staticmethod
    def _mutate_opaque(value: str) -> str:
        return f"{value}2"


def discover_all_identifiers(url: str, headers: dict[str, str] | None = None) -> list[IdentifiedParam]:
    """Run all discovery strategies and return deduplicated candidates."""
    query_strategy = QueryIdentifierStrategy()
    path_strategy = PathIdentifierStrategy()
    header_strategy = HeaderIdentifierStrategy()

    results = query_strategy.discover(url)
    results.extend(path_strategy.discover(url))
    if headers:
        results.extend(header_strategy.discover(headers))

    # Deduplicate by (source, name, value)
    seen: set[tuple[str, str, str]] = set()
    unique: list[IdentifiedParam] = []
    for param in results:
        key = (param.source, param.name, param.value)
        if key not in seen:
            seen.add(key)
            unique.append(param)
    return unique
