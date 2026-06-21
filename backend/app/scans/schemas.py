from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl, model_validator


class ScanCreate(BaseModel):
    target_url: HttpUrl
    authorization_confirmed: bool
    enabled_plugins: list[str] | None = None

    @model_validator(mode="after")
    def authorization_gate(self):
        if not self.authorization_confirmed:
            raise ValueError("You must confirm authorization to scan this target")
        return self


class FindingResponse(BaseModel):
    id: str
    plugin: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    url: str
    evidence: str
    remediation: str
    cwe_id: str | None
    evidence_data: dict
    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: str
    target_url: str
    target_host: str
    status: str
    enabled_plugins: list[str]
    error_message: str | None
    request_count: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    findings: list[FindingResponse] = Field(default_factory=list)
    model_config = {"from_attributes": True}
