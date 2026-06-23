from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.asm.models import Asset, Subdomain, Service
from app.scans.models import Finding
from app.graph.models import GraphNode, GraphEdge

class GraphBuilder:
    """
    Builds the attack surface relationship graph from existing asset elements
    and stores it in the database.
    """
    def __init__(self, session: AsyncSession):
        self.session = session

    async def build_graph(self, asset_id: str) -> None:
        # Clear existing graph nodes/edges for this asset
        await self.session.execute(delete(GraphEdge).where(GraphEdge.asset_id == asset_id))
        await self.session.execute(delete(GraphNode).where(GraphNode.asset_id == asset_id))
        await self.session.flush()

        # Fetch asset with all subrelations
        stmt = select(Asset).where(Asset.id == asset_id)
        asset = await self.session.scalar(stmt)
        if not asset:
            return

        # 1. Create root asset node
        asset_node_id = f"asset:{asset.id}"
        asset_node = GraphNode(
            id=asset_node_id,
            asset_id=asset_id,
            node_type="asset",
            label=asset.domain,
            metadata_json={"domain": asset.domain, "exposure_score": asset.exposure_score},
            created_at=str(datetime.utcnow()),
            updated_at=str(datetime.utcnow())
        )
        self.session.add(asset_node)

        # Fetch subdomains
        stmt_subs = select(Subdomain).where(Subdomain.asset_id == asset_id)
        subdomains = (await self.session.scalars(stmt_subs)).all()

        for sub in subdomains:
            # 2. Create subdomain node
            sub_node_id = f"subdomain:{sub.id}"
            sub_node = GraphNode(
                id=sub_node_id,
                asset_id=asset_id,
                node_type="subdomain",
                label=sub.hostname,
                metadata_json={"hostname": sub.hostname, "ip_addresses": sub.ip_addresses},
                created_at=str(datetime.utcnow()),
                updated_at=str(datetime.utcnow())
            )
            self.session.add(sub_node)
            
            # Create edge: Asset -> Subdomain
            e1 = GraphEdge(
                asset_id=asset_id,
                source_id=asset_node_id,
                target_id=sub_node_id,
                relationship_type="resolves_to",
                weight=1.0,
                created_at=str(datetime.utcnow()),
                updated_at=str(datetime.utcnow())
            )
            self.session.add(e1)

            # Fetch services
            stmt_servs = select(Service).where(Service.subdomain_id == sub.id)
            services = (await self.session.scalars(stmt_servs)).all()

            for s in services:
                # 3. Create service node
                service_node_id = f"service:{s.id}"
                service_node = GraphNode(
                    id=service_node_id,
                    asset_id=asset_id,
                    node_type="service",
                    label=f"{sub.hostname}:{s.port} ({s.protocol})",
                    metadata_json={"port": s.port, "protocol": s.protocol, "banner": s.banner, "technology": s.technology},
                    created_at=str(datetime.utcnow()),
                    updated_at=str(datetime.utcnow())
                )
                self.session.add(service_node)

                # Create edge: Subdomain -> Service
                e2 = GraphEdge(
                    asset_id=asset_id,
                    source_id=sub_node_id,
                    target_id=service_node_id,
                    relationship_type="runs_service",
                    weight=1.0,
                    created_at=str(datetime.utcnow()),
                    updated_at=str(datetime.utcnow())
                )
                self.session.add(e2)

        # Fetch findings that match domain
        stmt_findings = select(Finding).where(Finding.url.like(f"%{asset.domain}%"))
        findings = (await self.session.scalars(stmt_findings)).all()

        for f in findings:
            # 4. Create finding node
            finding_node_id = f"finding:{f.id}"
            finding_node = GraphNode(
                id=finding_node_id,
                asset_id=asset_id,
                node_type="finding",
                label=f.title,
                metadata_json={"severity": f.severity, "category": f.category, "plugin": f.plugin, "cwe_id": f.cwe_id},
                created_at=str(datetime.utcnow()),
                updated_at=str(datetime.utcnow())
            )
            self.session.add(finding_node)

            # Look for a matching subdomain node or asset node to link finding to
            # If the finding URL contains a subdomain, link to that subdomain node. Otherwise, link to asset node.
            linked_node_id = asset_node_id
            for sub in subdomains:
                if sub.hostname in f.url:
                    linked_node_id = f"subdomain:{sub.id}"
                    break
            
            # Create edge: Node -> Finding
            # Critical/High findings have higher edge weights (representing attack paths)
            weight = 3.0 if f.severity in {"critical", "high"} else 1.5
            e3 = GraphEdge(
                asset_id=asset_id,
                source_id=linked_node_id,
                target_id=finding_node_id,
                relationship_type="has_finding",
                weight=weight,
                created_at=str(datetime.utcnow()),
                updated_at=str(datetime.utcnow())
            )
            self.session.add(e3)

        await self.session.flush()
