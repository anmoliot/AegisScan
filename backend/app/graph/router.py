from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from app.deps import CurrentUser, DbSession
from app.asm.models import Asset
from app.graph.models import GraphNode, GraphEdge
from app.graph.graph_builder import GraphBuilder
from app.graph.serializers import GraphSerializer
from app.graph.attack_path import AttackPathAnalyzer

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/assets/{asset_id}")
async def get_asset_graph(asset_id: str, user: CurrentUser, session: DbSession):
    # Verify asset ownership
    stmt_asset = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id)
    asset = await session.scalar(stmt_asset)
    if not asset:
        raise HTTPException(404, "Asset not found")

    # Check if nodes/edges already exist
    stmt_nodes = select(GraphNode).where(GraphNode.asset_id == asset_id)
    nodes = (await session.scalars(stmt_nodes)).all()

    if not nodes:
        # Build graph on the fly
        builder = GraphBuilder(session)
        await builder.build_graph(asset_id)
        await session.commit()
        
        # Re-fetch
        stmt_nodes = select(GraphNode).where(GraphNode.asset_id == asset_id)
        nodes = (await session.scalars(stmt_nodes)).all()

    stmt_edges = select(GraphEdge).where(GraphEdge.asset_id == asset_id)
    edges = (await session.scalars(stmt_edges)).all()

    return GraphSerializer.serialize_graph(nodes, edges)


@router.get("/attack-paths/{asset_id}")
async def get_attack_paths(asset_id: str, user: CurrentUser, session: DbSession):
    stmt_asset = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id)
    asset = await session.scalar(stmt_asset)
    if not asset:
        raise HTTPException(404, "Asset not found")

    # Fetch nodes and edges
    stmt_nodes = select(GraphNode).where(GraphNode.asset_id == asset_id)
    nodes = (await session.scalars(stmt_nodes)).all()
    
    if not nodes:
        # Build graph on the fly
        builder = GraphBuilder(session)
        await builder.build_graph(asset_id)
        await session.commit()
        
        stmt_nodes = select(GraphNode).where(GraphNode.asset_id == asset_id)
        nodes = (await session.scalars(stmt_nodes)).all()

    stmt_edges = select(GraphEdge).where(GraphEdge.asset_id == asset_id)
    edges = (await session.scalars(stmt_edges)).all()

    serialized = GraphSerializer.serialize_graph(nodes, edges)
    
    # Analyze paths
    analyzer = AttackPathAnalyzer(serialized["nodes"], serialized["edges"])
    paths = analyzer.compute_attack_paths()
    
    return {
        "asset_id": asset_id,
        "domain": asset.domain,
        "attack_paths": paths
    }
