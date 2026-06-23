from app.ai.prioritization_engine import AiPrioritizationEngine

def test_ai_prioritization_engine_plan():
    findings = [
        {"id": "f1", "title": "SQLi", "severity": "critical", "remediation": "Fix SQL injection"},
        {"id": "f2", "title": "XSS", "severity": "medium", "remediation": "Escape outputs"}
    ]

    plan = AiPrioritizationEngine.generate_prioritized_remediation_plan(findings, asset_exposure_score=75.0)
    assert len(plan) == 2
    # Critical should be ranked first
    assert plan[0]["finding_id"] == "f1"
    assert plan[0]["priority_score"] == 80.0 + (75.0 * 0.2)
    assert plan[0]["action"] == "Fix SQL injection"


def test_ai_prioritization_engine_explanation():
    finding = {
        "title": "BOLA",
        "plugin": "idor",
        "url": "https://example.com/api/users/123"
    }

    explanation = AiPrioritizationEngine.generate_attack_explanation(finding, "example.com")
    assert "example.com" in explanation
    assert "BOLA" in explanation
    assert "https://example.com/api/users/123" in explanation
