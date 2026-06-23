"""Create graph tables."""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    # 1. graph_nodes table
    op.create_table(
        "graph_nodes",
        sa.Column("id", sa.String(100), primary_key=True),  # usually format: "type:id" or UUID
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_type", sa.String(50), nullable=False),
        sa.Column("label", sa.String(250), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_graph_nodes_asset_id", "graph_nodes", ["asset_id"])
    op.create_index("ix_graph_nodes_node_type", "graph_nodes", ["node_type"])

    # 2. graph_edges table
    op.create_table(
        "graph_edges",
        sa.Column("id", sa.String(100), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(100), sa.ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.String(100), sa.ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(50), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_graph_edges_asset_id", "graph_edges", ["asset_id"])
    op.create_index("ix_graph_edges_source_id", "graph_edges", ["source_id"])
    op.create_index("ix_graph_edges_target_id", "graph_edges", ["target_id"])


def downgrade():
    op.drop_table("graph_edges")
    op.drop_table("graph_nodes")
