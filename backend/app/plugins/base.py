import hashlib
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from app.scanner.http_client import SafeHttpClient


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


@dataclass(slots=True)
class PluginResult:
    plugin: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    url: str
    evidence: str
    remediation: str
    cwe_id: str | None = None
    evidence_data: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        parameter = str(self.evidence_data.get("parameter", ""))
        raw = f"{self.plugin}|{self.url}|{self.title}|{parameter}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        value["confidence"] = self.confidence.value
        value["fingerprint"] = self.fingerprint
        return value


class BasePlugin(ABC):
    name = "base"
    description = ""
    category = "generic"
    active = False

    @abstractmethod
    async def run(self, target_url: str, client: "SafeHttpClient") -> list[PluginResult]:
        raise NotImplementedError
