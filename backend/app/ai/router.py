from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.deps import CurrentUser, DbSession
from app.scans.models import Scan
from app.asm.models import Asset
from app.ai.provider import get_provider
from app.ai.rule_engine import RuleBasedRiskEngine
from app.ai.prioritization_engine import AiPrioritizationEngine
from app.ai.schemas import (
    DeduplicateFindingsRequest, DeduplicateFindingsResponse,
    AiAnalysisResponse, AiExecutiveSummaryResponse
)

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/analyze/{scan_id}", response_model=AiAnalysisResponse)
async def analyze_scan_findings(scan_id: str, user: CurrentUser, session: DbSession):
    stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id).options(selectinload(Scan.findings))
    scan = await session.scalar(stmt)
    if not scan:
        raise HTTPException(404, "Scan not found")

    if not scan.findings:
        return AiAnalysisResponse(
            scan_id=scan_id,
            remediation_plan=[],
            insights="No findings available to analyze for this scan."
        )

    # 1. Prepare findings context for prompt
    findings_data = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "url": f.url,
            "remediation": f.remediation
        }
        for f in scan.findings
    ]

    findings_summary = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']} in category {f['category']} at {f['url']}"
        for f in findings_data
    )
    
    prompt = (
        f"You are the Lead Exposure Intelligence AI. Analyze these findings for host '{scan.target_host}':\n"
        f"{findings_summary}\n\n"
        "Provide a concise executive summary of the aggregate exposure risk and explain any potential attack chains."
    )

    # 2. Query Gemini / Fallback provider
    provider = get_provider()
    insights = await provider.analyze_findings(prompt)

    # 3. Generate prioritized remediation checklist
    plan = AiPrioritizationEngine.generate_prioritized_remediation_plan(
        findings=findings_data,
        asset_exposure_score=50.0  # Default baseline asset exposure
    )

    return AiAnalysisResponse(
        scan_id=scan_id,
        remediation_plan=plan,
        insights=insights
    )


@router.get("/summary/{asset_id}", response_model=AiExecutiveSummaryResponse)
async def get_asset_summary(asset_id: str, user: CurrentUser, session: DbSession):
    stmt = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id).options(selectinload(Asset.subdomains))
    asset = await session.scalar(stmt)
    if not asset:
        raise HTTPException(404, "Asset not found")

    prompt = (
        f"Provide a cybersecurity executive summary for the asset '{asset.domain}'.\n"
        f"Exposure Score: {asset.exposure_score}/100\n"
        f"Active Subdomains Count: {len(asset.subdomains)}\n"
        "Keep it professional, high-level, and outline the key defensive priorities."
    )

    provider = get_provider()
    summary = await provider.analyze_findings(prompt)

    return AiExecutiveSummaryResponse(
        asset_id=asset_id,
        summary=summary
    )


@router.post("/deduplicate", response_model=DeduplicateFindingsResponse)
async def deduplicate_findings_endpoint(payload: DeduplicateFindingsRequest, user: CurrentUser):
    unique = RuleBasedRiskEngine.deduplicate_findings(payload.findings)
    return DeduplicateFindingsResponse(unique_findings=unique)
