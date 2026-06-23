from app.api_security.openapi_parser import OpenApiParser

def test_openapi_parser_valid_spec():
    raw_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "security": [],
                    "parameters": [
                        {"name": "limit", "in": "query", "required": False, "schema": {"type": "integer"}}
                    ]
                },
                "post": {
                    "summary": "Create user",
                    "security": [{"ApiKeyAuth": []}],
                    "parameters": []
                }
            }
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
            }
        }
    }

    parser = OpenApiParser(raw_spec)
    result = parser.parse()

    assert len(result["endpoints"]) == 2
    assert result["security_schemes"] == ["ApiKeyAuth"]

    get_ep = next(e for e in result["endpoints"] if e["method"] == "GET")
    assert get_ep["path"] == "/users"
    assert get_ep["auth_required"] is False
    assert len(get_ep["parameters"]) == 1
    assert get_ep["parameters"][0]["name"] == "limit"

    post_ep = next(e for e in result["endpoints"] if e["method"] == "POST")
    assert post_ep["path"] == "/users"
    assert post_ep["auth_required"] is True


def test_openapi_parser_detects_undocumented():
    raw_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path", "required": True}]
                }
            }
        }
    }

    parser = OpenApiParser(raw_spec)
    observed = ["/users/123", "/users/admin/config", "/roles"]
    undocumented = parser.detect_undocumented_patterns(observed)

    # /users/123 matches /users/{id}, others don't
    assert "/users/123" not in undocumented
    assert "/users/admin/config" in undocumented
    assert "/roles" in undocumented
