from app.api_security.endpoint_mapper import EndpointMapper
from app.api_security.auth_boundary_analysis import AuthBoundaryAnalysis
from app.api_security.mass_assignment import MassAssignmentDetector
from app.api_security.bola_analysis import BolaAnalyzer

def test_endpoint_mapper_mapping():
    endpoints = [
        {"path": "/api/v1/users", "method": "GET", "auth_required": True},
        {"path": "/api/v1/users/{id}", "method": "GET", "auth_required": True},
        {"path": "/api/v1/users/{id}", "method": "PUT", "auth_required": True},
        {"path": "/admin/settings", "method": "POST", "auth_required": True},
    ]

    mapper = EndpointMapper(endpoints)
    groups = mapper.map_relationships()

    assert "users" in groups
    assert len(groups["users"]) == 3
    assert groups["users"][0]["is_bola_prone"] is False
    assert groups["users"][1]["is_bola_prone"] is True

    assert "admin" in groups
    assert groups["admin"][0]["privilege_level"] == "admin"


def test_auth_boundary_analysis():
    endpoints = [
        {"path": "/api/v1/public/info", "method": "GET", "auth_required": False},
        {"path": "/api/v1/public/delete-user", "method": "POST", "auth_required": False},
        {"path": "/api/v1/users", "method": "GET", "auth_required": True},
    ]

    analysis = AuthBoundaryAnalysis(endpoints).analyze()
    assert analysis["authenticated_count"] == 1
    assert analysis["public_count"] == 2
    assert len(analysis["exposed_sensitive_endpoints"]) == 1
    assert analysis["exposed_sensitive_endpoints"][0]["path"] == "/api/v1/public/delete-user"


def test_mass_assignment_detector():
    endpoints = [
        {
            "path": "/api/v1/users",
            "method": "POST",
            "parameters": [
                {"name": "username", "type": "string"},
                {"name": "is_admin", "type": "boolean"}
            ]
        },
        {
            "path": "/api/v1/users",
            "method": "GET",
            "parameters": []
        }
    ]

    detector = MassAssignmentDetector(endpoints)
    findings = detector.detect()

    assert len(findings) == 1
    assert findings[0]["path"] == "/api/v1/users"
    assert findings[0]["sensitive_parameters"][0]["name"] == "is_admin"


def test_bola_analyzer():
    endpoints = [
        {"path": "/api/v1/users/{id}", "method": "GET", "auth_required": True},
        {"path": "/api/v1/users/{id}", "method": "PUT", "auth_required": True},
        {"path": "/api/v1/status", "method": "GET", "auth_required": False},
    ]

    analyzer = BolaAnalyzer(endpoints)
    susceptible = analyzer.analyze()

    assert len(susceptible) == 2
    assert any(s["method"] == "GET" and s["susceptibility"] == "medium" for s in susceptible)
    assert any(s["method"] == "PUT" and s["susceptibility"] == "high" for s in susceptible)
