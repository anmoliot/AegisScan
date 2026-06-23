from typing import Any

class FindingPrioritizationEngine:
    """
    Ranks vulnerability findings based on a calculated prioritization score.
    Factors in finding severity, finding confidence, and target asset exposure score.
    """
    SEVERITY_WEIGHTS = {
        "critical": 40.0,
        "high": 30.0,
        "medium": 20.0,
        "low": 10.0,
        "info": 0.0
    }

    CONFIDENCE_WEIGHTS = {
        "high": 10.0,
        "medium": 5.0,
        "low": 2.0
    }

    @classmethod
    def calculate_priority_score(
        cls,
        severity: str,
        confidence: str,
        asset_exposure_score: float
    ) -> float:
        sev_score = cls.SEVERITY_WEIGHTS.get(severity.lower(), 10.0)
        conf_score = cls.CONFIDENCE_WEIGHTS.get(confidence.lower(), 5.0)
        
        # Priority score = Severity (40%) + Confidence (10%) + Asset Exposure (50%)
        # Normalizing asset exposure contribution to 50 max points
        asset_score = min(max(asset_exposure_score, 0.0), 100.0) * 0.5
        
        return sev_score + conf_score + asset_score

    @classmethod
    def rank_findings(cls, findings: list[dict[str, Any]], asset_exposure_score: float) -> list[dict[str, Any]]:
        """
        Takes list of findings and returns them sorted by priority score descending.
        """
        ranked = []
        for f in findings:
            severity = f.get("severity", "medium")
            confidence = f.get("confidence", "medium")
            
            p_score = cls.calculate_priority_score(severity, confidence, asset_exposure_score)
            
            # Map score to label
            if p_score >= 80.0:
                p_label = "P0 - Immediate Action"
            elif p_score >= 60.0:
                p_label = "P1 - High Priority"
            elif p_score >= 40.0:
                p_label = "P2 - Medium Priority"
            else:
                p_label = "P3 - Low Priority"

            item = dict(f)
            item["priority_score"] = p_score
            item["priority_label"] = p_label
            ranked.append(item)

        return sorted(ranked, key=lambda x: x["priority_score"], reverse=True)
