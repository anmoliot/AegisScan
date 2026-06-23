from typing import Any
from app.graph.models import GraphNode, GraphEdge

class GraphSerializer:
    """
    Serializes Graph database models into standard JSON representations
    suitable for frontend rendering (d3, cytoscape, or SVG charts).
    """
    @staticmethod
    def serialize_node(node: GraphNode) -> dict[str, Any]:
        return {
            "id": node.id,
            "asset_id": node.asset_id,
            "type": node.node_type,
            "label": node.label,
            "metadata": node.metadata_json
        }

    @staticmethod
    def serialize_edge(edge: GraphEdge) -> dict[str, Any]:
        return {
            "id": edge.id,
            "asset_id": edge.asset_id,
            "source": edge.source_id,
            "target": edge.target_id,
            "relationship": edge.relationship_type,
            "weight": edge.weight
        }

    @classmethod
    def serialize_graph(cls, nodes: list[GraphNode], edges: list[GraphEdge]) -> dict[str, list[dict[str, Any]]]:
        return {
            "nodes": [cls.serialize_node(n) for n in nodes],
            "edges": [cls.serialize_edge(e) for e in edges]
        }
