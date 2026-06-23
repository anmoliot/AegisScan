from app.api_security.graphql_analyzer import GraphQLAnalyzer

def test_graphql_analyzer_is_graphql_path():
    analyzer = GraphQLAnalyzer()
    assert analyzer.is_graphql_path("/graphql") is True
    assert analyzer.is_graphql_path("/api/v1/gql") is True
    assert analyzer.is_graphql_path("/users") is False


def test_graphql_analyzer_introspection():
    introspection_data = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "me"},
                            {"name": "users"}
                        ]
                    },
                    {
                        "name": "Mutation",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "login"},
                            {"name": "deleteUser"}
                        ]
                    },
                    {
                        "name": "UserToken",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "token"},
                            {"name": "expiry"}
                        ]
                    },
                    {
                        "name": "Product",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "id"},
                            {"name": "name"}
                        ]
                    }
                ]
            }
        }
    }

    analyzer = GraphQLAnalyzer(introspection_data)
    schema_info = analyzer.analyze_schema()

    assert "me" in schema_info["queries"]
    assert "login" in schema_info["mutations"]
    assert len(schema_info["types"]) == 2  # Product and UserToken (excluding Query/Mutation)
    
    # Sensitive types detection check
    assert "UserToken" in schema_info["sensitive_types"]
    assert "Product" not in schema_info["sensitive_types"]


def test_graphql_analyzer_query_generation():
    analyzer = GraphQLAnalyzer()
    query = analyzer.generate_introspection_query()
    assert "__schema" in query
    assert "queryType" in query
    assert "mutationType" in query
