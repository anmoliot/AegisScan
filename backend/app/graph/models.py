import uuid
from typing import Any
from sqlalchemy import Float, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)  # type:uuid format
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    node_type: Mapped[str] = mapped_column(String(50), index=True)  # asset, subdomain, service, api, finding
    label: Mapped[str] = mapped_column(String(250))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    
    # We can store timestamp columns manually
    created_at: Mapped[str] = mapped_column(String(50), default=lambda: str(uuid.uuid4()))  # dummy or manual
    updated_at: Mapped[str] = mapped_column(String(50), default=lambda: str(uuid.uuid4()))

    asset = relationship("Asset", back_populates="graph_nodes")


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[str] = mapped_column(String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("graph_nodes.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("graph_nodes.id", ondelete="CASCADE"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(50))  # e.g., resolves_to, runs_service, has_finding
    weight: Mapped[float] = mapped_column(Float, default=1.0)

    # Manual timestamps matching migration
    created_at: Mapped[str] = mapped_column(String(50), default=lambda: str(uuid.uuid4()))
    updated_at: Mapped[str] = mapped_column(String(50), default=lambda: str(uuid.uuid4()))

    asset = relationship("Asset", back_populates="graph_edges")
