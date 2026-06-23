from pydantic import BaseModel, Field
from typing import Any

class DeduplicateFindingsRequest(BaseModel):
    findings: list[dict[str, Any]]


class DeduplicateFindingsResponse(BaseModel):
    unique_findings: list[dict[str, Any]]


class AiAnalysisResponse(BaseModel):
    scan_id: str
    remediation_plan: list[dict[str, Any]]
    insights: str


class AiExecutiveSummaryResponse(BaseModel):
    asset_id: str
    summary: str
