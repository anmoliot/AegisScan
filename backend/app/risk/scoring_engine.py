
class RiskScoringEngine:
    """
    Computes a normalized, composite risk score (0-100) based on weighted factors:
    1. Internet exposure (0-20)
    2. Authentication status (0-15)
    3. Sensitive data indicators (0-15)
    4. Exploitability (0-20)
    5. Vulnerability count (0-10)
    6. Attack path criticality (0-10)
    7. Asset importance (0-10)
    """
    @staticmethod
    def calculate_score(
        internet_exposure_score: float,       # 0.0 - 20.0
        auth_status_score: float,              # 0.0 - 15.0
        sensitive_data_score: float,           # 0.0 - 15.0
        exploitability_score: float,           # 0.0 - 20.0
        vulnerability_score: float,            # 0.0 - 10.0
        attack_path_criticality: float,        # 0.0 - 10.0
        asset_importance: float                # 0.0 - 10.0
    ) -> float:
        # Clamp inputs
        ie = min(max(internet_exposure_score, 0.0), 20.0)
        auth = min(max(auth_status_score, 0.0), 15.0)
        sd = min(max(sensitive_data_score, 0.0), 15.0)
        exp = min(max(exploitability_score, 0.0), 20.0)
        vuln = min(max(vulnerability_score, 0.0), 10.0)
        ap = min(max(attack_path_criticality, 0.0), 10.0)
        imp = min(max(asset_importance, 0.0), 10.0)

        raw_score = ie + auth + sd + exp + vuln + ap + imp
        return min(max(raw_score, 0.0), 100.0)

    @staticmethod
    def calculate_trend(previous_score: float | None, current_score: float) -> str:
        """
        Returns trend: 'increasing', 'decreasing', or 'stable'.
        """
        if previous_score is None:
            return "stable"
        
        diff = current_score - previous_score
        if diff > 0.5:
            return "increasing"
        elif diff < -0.5:
            return "decreasing"
        else:
            return "stable"
