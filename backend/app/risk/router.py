from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.deps import CurrentUser, DbSession
from app.asm.models import Asset
from app.scans.models import Finding
from app.risk.scoring_engine import RiskScoringEngine
from app.risk.prioritization import FindingPrioritizationEngine

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/score/{asset_id}")
async def get_asset_risk_score(asset_id: str, user: CurrentUser, session: DbSession):
    stmt = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id)
    asset = await session.scalar(stmt)
    if not asset:
        raise HTTPException(404, "Asset not found")

    # Fetch associated findings
    # For simplicity, we can fetch all findings matching the domain/host
    stmt_findings = select(Finding).where(Finding.url.like(f"%{asset.domain}%"))
    findings = (await session.scalars(stmt_findings)).all()
    
    # Calculate a composite risk score
    # Count of findings by severity
    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    med_count = sum(1 for f in findings if f.severity == "medium")
    
    vuln_subscore = min((crit_count * 5.0) + (high_count * 3.0) + (med_count * 1.0), 10.0)
    
    # Calculate risk score
    score = RiskScoringEngine.calculate_score(
        internet_exposure_score=15.0 if asset.subdomains else 5.0,
        auth_status_score=10.0,
        sensitive_data_score=5.0,
        exploitability_score=10.0 if crit_count or high_count else 0.0,
        vulnerability_score=vuln_subscore,
        attack_path_criticality=5.0 if crit_count else 0.0,
        asset_importance=10.0
    )

    return {
        "asset_id": asset.id,
        "domain": asset.domain,
        "exposure_score": asset.exposure_score,
        "composite_risk_score": score,
        "trend": RiskScoringEngine.calculate_trend(asset.exposure_score - 2.0, score), # dummy trend baseline comparison
        "findings_count": len(findings)
    }


@router.get("/dashboard")
async def get_risk_dashboard(user: CurrentUser, session: DbSession):
    stmt_assets = select(Asset).where(Asset.user_id == user.id).options(selectinload(Asset.subdomains))
    assets = (await session.scalars(stmt_assets)).unique()

    total_assets = len(assets)
    if total_assets == 0:
        return {
            "average_exposure_score": 0.0,
            "assets_at_risk": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "top_findings": []
        }

    total_exposure = 0.0
    risk_categories = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for asset in assets:
        score = asset.exposure_score
        total_exposure += score
        if score >= 75.0:
            risk_categories["critical"] += 1
        elif score >= 50.0:
            risk_categories["high"] += 1
        elif score >= 25.0:
            risk_categories["medium"] += 1
        else:
            risk_categories["low"] += 1

    # Fetch top findings
    # Select all findings for user's scans
    stmt_findings = select(Finding).order_by(Finding.created_at.desc()).limit(20)
    findings = (await session.scalars(stmt_findings)).all()
    
    findings_list = []
    for f in findings:
        findings_list.append({
            "id": f.id,
            "plugin": f.plugin,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "url": f.url,
            "created_at": f.created_at
        })

    # Prioritize findings with average exposure
    avg_exposure = total_exposure / total_assets
    prioritized_findings = FindingPrioritizationEngine.rank_findings(findings_list, avg_exposure)

    return {
        "average_exposure_score": round(avg_exposure, 2),
        "total_assets": total_assets,
        "assets_at_risk": risk_categories,
        "top_findings": prioritized_findings[:5] # Top 5 prioritized findings
    }
