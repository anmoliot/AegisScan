from app.risk.prioritization import FindingPrioritizationEngine

def test_finding_prioritization_engine():
    # Test priority score calculations
    # Critical severity (40.0) + High confidence (10.0) + 80 exposure (80 * 0.5 = 40.0) = 90.0
    score_p0 = FindingPrioritizationEngine.calculate_priority_score("critical", "high", 80.0)
    assert score_p0 == 90.0

    # Low severity (10.0) + Low confidence (2.0) + 10 exposure (10 * 0.5 = 5.0) = 17.0
    score_p3 = FindingPrioritizationEngine.calculate_priority_score("low", "low", 10.0)
    assert score_p3 == 17.0

    # Rank findings list
    findings = [
        {"id": "1", "severity": "low", "confidence": "low", "title": "Low Vuln"},
        {"id": "2", "severity": "critical", "confidence": "high", "title": "Crit Vuln"},
        {"id": "3", "severity": "high", "confidence": "medium", "title": "High Vuln"}
    ]
    
    ranked = FindingPrioritizationEngine.rank_findings(findings, 80.0)
    assert len(ranked) == 3
    # Check correct order
    assert ranked[0]["id"] == "2"
    assert ranked[0]["priority_label"] == "P0 - Immediate Action"
    assert ranked[1]["id"] == "3"
    assert ranked[2]["id"] == "1"
    assert ranked[2]["priority_label"] == "P2 - Medium Priority"
