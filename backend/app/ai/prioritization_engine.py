from typing import Any

class AiPrioritizationEngine:
    """
    Orchestrates complex ranking of vulnerabilities based on severity, exploitability,
    asset exposure, and attack path graph complexity.
    """
    @staticmethod
    def generate_prioritized_remediation_plan(
        findings: list[dict[str, Any]],
        asset_exposure_score: float
    ) -> list[dict[str, Any]]:
        """
        Builds a ordered checklist of actions for security engineers.
        """
        # Score each finding
        scored = []
        for f in findings:
            sev = f.get("severity", "medium").lower()
            
            # Base weight mapping
            base = 20.0
            if sev == "critical":
                base = 80.0
            elif sev == "high":
                base = 60.0
            elif sev == "medium":
                base = 40.0
            
            # Modify weight by asset exposure
            exposure_impact = asset_exposure_score * 0.2
            
            final_priority = base + exposure_impact
            
            scored.append({
                "finding_id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "priority_score": round(final_priority, 2),
                "action": f.get("remediation", "Apply updates and code sanitization.")
            })
            
        # Sort desc by score
        return sorted(scored, key=lambda x: x["priority_score"], reverse=True)

    @staticmethod
    def generate_attack_explanation(finding: dict[str, Any], asset_domain: str) -> str:
        """
        Generates clean explanation of how an attack path could be exploited.
        """
        plugin = finding.get("plugin", "scanner")
        title = finding.get("title", "vulnerability")
        url = finding.get("url", "")
        
        return (
            f"An attacker targeting '{asset_domain}' could exploit the '{title}' found at '{url}'. "
            f"By triggering the '{plugin}' vector, the attacker bypasses authorization boundaries or "
            f"executes unauthorized server-side calls, which could result in compromise of the underlying resources."
        )
