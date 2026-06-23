import json
import re
from typing import Any

class GraphQLAnalyzer:
    """
    Analyzes GraphQL endpoints, parses schema introspection query results,
    extracts types/queries/mutations, and identifies sensitive data structures.
    """
    def __init__(self, introspection_result: str | dict[str, Any] | None = None):
        if isinstance(introspection_result, str):
            try:
                self.introspection = json.loads(introspection_result)
            except json.JSONDecodeError:
                self.introspection = {}
        else:
            self.introspection = introspection_result or {}

    def is_graphql_path(self, path: str) -> bool:
        """
        Determines if a URL path looks like a GraphQL endpoint.
        """
        lowered = path.lower()
        return any(term in lowered for term in ("/graphql", "/gql", "/graphql/v1", "/query", "/api/graphql"))

    def analyze_schema(self) -> dict[str, Any]:
        """
        Parses GraphQL Introspection JSON to extract queries, mutations, and types.
        """
        if not self.introspection or "__schema" not in self.introspection:
            # Check if nested in a data block
            data = self.introspection.get("data", {})
            schema = data.get("__schema", {})
            if not schema:
                return {"queries": [], "mutations": [], "types": [], "sensitive_types": []}
        else:
            schema = self.introspection["__schema"]

        queries = []
        mutations = []
        types_list = []
        sensitive_types = []

        query_type_name = schema.get("queryType", {}).get("name", "Query") if schema.get("queryType") else "Query"
        mutation_type_name = schema.get("mutationType", {}).get("name", "Mutation") if schema.get("mutationType") else "Mutation"

        types = schema.get("types", [])
        for t in types:
            if not isinstance(t, dict):
                continue
            name = t.get("name", "")
            if name.startswith("__"):
                continue  # Skip built-in introspection fields

            # Extract fields if available
            fields = t.get("fields") or []
            field_names = [f.get("name") for f in fields if isinstance(f, dict)]

            if name == query_type_name:
                queries = field_names
            elif name == mutation_type_name:
                mutations = field_names
            else:
                types_list.append({
                    "name": name,
                    "kind": t.get("kind"),
                    "fields": field_names
                })
                # Check for sensitive types
                if any(pattern in name.lower() for pattern in ("user", "account", "token", "session", "admin", "credential", "auth", "secret")):
                    sensitive_types.append(name)

        return {
            "queries": queries,
            "mutations": mutations,
            "types": types_list,
            "sensitive_types": sensitive_types
        }

    def generate_introspection_query(self) -> str:
        """
        Returns a standard GraphQL Introspection query string.
        """
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  name
                  description
                  type {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
                type {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
        """
