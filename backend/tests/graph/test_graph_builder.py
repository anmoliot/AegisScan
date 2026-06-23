from unittest.mock import AsyncMock, MagicMock
import pytest
from app.graph.graph_builder import GraphBuilder
from app.graph.models import GraphNode, GraphEdge
from app.graph.serializers import GraphSerializer
from app.asm.models import Asset, Subdomain, Service
from app.scans.models import Finding

@pytest.mark.asyncio
async def test_graph_builder():
    session = AsyncMock()
    
    # Mock asset
    asset = Asset(id="asset-123", domain="example.com", exposure_score=50.0)
    session.scalar.return_value = asset

    # Mock subdomains, services, findings
    subdomain = Subdomain(id="sub-123", hostname="www.example.com", ip_addresses=["1.1.1.1"])
    service = Service(id="srv-123", subdomain_id="sub-123", port=8443, protocol="TCP", banner="Test nginx")
    finding = Finding(id="find-123", url="https://www.example.com/api", title="SQLi", severity="critical")

    # Scalars mock
    mock_scalars = MagicMock()
    mock_scalars.all.side_effect = [
        [subdomain],  # subdomains query
        [service],    # services query
        [finding]     # findings query
    ]
    session.scalars.return_value = mock_scalars

    builder = GraphBuilder(session)
    await builder.build_graph(asset_id="asset-123")
    
    # Assert session.add was called for nodes and edges
    assert session.add.call_count > 0


def test_graph_serializer():
    node = GraphNode(id="asset-1", asset_id="a1", node_type="asset", label="example.com", metadata_json={"score": 80})
    edge = GraphEdge(id="edge-1", asset_id="a1", source_id="n1", target_id="n2", relationship_type="has", weight=2.5)

    res = GraphSerializer.serialize_graph([node], [edge])
    assert len(res["nodes"]) == 1
    assert res["nodes"][0]["label"] == "example.com"
    assert res["nodes"][0]["metadata"]["score"] == 80
    assert len(res["edges"]) == 1
    assert res["edges"][0]["weight"] == 2.5
