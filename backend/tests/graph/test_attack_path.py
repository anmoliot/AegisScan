from app.graph.attack_path import AttackPathAnalyzer

def test_attack_path_analyzer():
    nodes = [
        {"id": "asset-1", "type": "asset", "label": "example.com"},
        {"id": "sub-1", "type": "subdomain", "label": "www.example.com"},
        {"id": "find-1", "type": "finding", "label": "Critical SQLi Finding"}
    ]

    edges = [
        {"source_id": "asset-1", "target_id": "sub-1", "relationship_type": "resolves", "weight": 1.0},
        {"source_id": "sub-1", "target_id": "find-1", "relationship_type": "has_finding", "weight": 3.0}
    ]

    analyzer = AttackPathAnalyzer(nodes, edges)
    paths = analyzer.compute_attack_paths()

    assert len(paths) == 1
    path = paths[0]
    assert len(path["chain"]) == 3
    assert path["chain"][0]["id"] == "asset-1"
    assert path["chain"][2]["id"] == "find-1"
    assert path["criticality_score"] == 5.0  # 1.0 (start) + 1.0 (edge 1) + 3.0 (edge 2)
