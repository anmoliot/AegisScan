from typing import Any

class AttackPathAnalyzer:
    """
    Computes potential attack paths across the relationships in graph nodes and edges.
    Traces paths from exposed assets/subdomains down to vulnerable findings.
    """
    def __init__(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]):
        self.nodes = {n["id"]: n for n in nodes}
        self.edges = edges

    def compute_attack_paths(self) -> list[dict[str, Any]]:
        """
        Computes attack chains (paths) starting from root asset/subdomain
        and ending at critical/high findings.
        """
        # Build adjacency list: source_id -> list of (target_id, relationship, weight)
        adj = {}
        for edge in self.edges:
            src = edge["source_id"]
            tgt = edge["target_id"]
            if src not in adj:
                adj[src] = []
            adj[src].append((tgt, edge["relationship_type"], edge["weight"]))

        paths = []
        
        # Find root nodes (types: asset, falling back to subdomain if no asset nodes)
        roots = [nid for nid, node in self.nodes.items() if node["type"] == "asset"]
        if not roots:
            roots = [nid for nid, node in self.nodes.items() if node["type"] == "subdomain"]
        
        # DFS traversal to find paths terminating at findings
        def dfs(curr_id: str, current_path: list[dict[str, Any]], path_score: float):
            # Check if current node is a finding
            curr_node = self.nodes.get(curr_id)
            if not curr_node:
                return

            node_repr = {
                "id": curr_id,
                "type": curr_node["type"],
                "label": curr_node["label"]
            }
            new_path = current_path + [node_repr]

            if curr_node["type"] == "finding":
                # Path completed! Save it.
                paths.append({
                    "chain": new_path,
                    "criticality_score": round(path_score, 2),
                    "description": f"Attack Path via {new_path[0]['label']} leading to {curr_node['label']}"
                })
                return

            # Keep traversing if we have outputs
            for (tgt_id, rel, weight) in adj.get(curr_id, []):
                # Avoid infinite loops / cycles
                if any(step["id"] == tgt_id for step in new_path):
                    continue
                dfs(tgt_id, new_path, path_score + weight)

        for root in roots:
            dfs(root, [], 1.0)

        # Sort paths by criticality score descending
        return sorted(paths, key=lambda x: x["criticality_score"], reverse=True)
