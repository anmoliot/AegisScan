from app.risk.scoring_engine import RiskScoringEngine

def test_risk_scoring_engine():
    # Test normal score calculation
    score = RiskScoringEngine.calculate_score(
        internet_exposure_score=10.0,
        auth_status_score=5.0,
        sensitive_data_score=5.0,
        exploitability_score=10.0,
        vulnerability_score=5.0,
        attack_path_criticality=5.0,
        asset_importance=5.0
    )
    assert score == 45.0

    # Test clamping behaviour (max out values)
    max_score = RiskScoringEngine.calculate_score(
        internet_exposure_score=50.0,
        auth_status_score=50.0,
        sensitive_data_score=50.0,
        exploitability_score=50.0,
        vulnerability_score=50.0,
        attack_path_criticality=50.0,
        asset_importance=50.0
    )
    assert max_score == 100.0

    # Test trend calculation
    assert RiskScoringEngine.calculate_trend(None, 45.0) == "stable"
    assert RiskScoringEngine.calculate_trend(40.0, 45.0) == "increasing"
    assert RiskScoringEngine.calculate_trend(50.0, 45.0) == "decreasing"
    assert RiskScoringEngine.calculate_trend(45.2, 45.0) == "stable"
