"""Create ASM and API Security tables."""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def timestamps():
    return [sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)]


def upgrade():
    # 1. assets table
    op.create_table(
        "assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("exposure_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("last_scanned", sa.DateTime(timezone=True)),
        *timestamps()
    )
    op.create_index("ix_assets_user_id", "assets", ["user_id"])
    op.create_index("ix_assets_domain", "assets", ["domain"])

    # 2. subdomains table
    op.create_table(
        "subdomains",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("ip_addresses", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        *timestamps()
    )
    op.create_index("ix_subdomains_asset_id", "subdomains", ["asset_id"])
    op.create_index("ix_subdomains_hostname", "subdomains", ["hostname"])

    # 3. certificates table
    op.create_table(
        "certificates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject", sa.String(253), nullable=False),
        sa.Column("issuer", sa.String(253), nullable=False),
        sa.Column("serial", sa.String(100)),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fingerprint", sa.String(64)),
        *timestamps()
    )
    op.create_index("ix_certificates_asset_id", "certificates", ["asset_id"])

    # 4. services table
    op.create_table(
        "services",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("subdomain_id", sa.String(36), sa.ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(20), nullable=False),
        sa.Column("banner", sa.Text()),
        sa.Column("technology", sa.String(100)),
        *timestamps()
    )
    op.create_index("ix_services_subdomain_id", "services", ["subdomain_id"])

    # 5. technologies table
    op.create_table(
        "technologies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("subdomain_id", sa.String(36), sa.ForeignKey("subdomains.id", ondelete="CASCADE")),
        sa.Column("service_id", sa.String(36), sa.ForeignKey("services.id", ondelete="CASCADE")),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.String(50)),
        sa.Column("category", sa.String(50)),
        *timestamps()
    )
    op.create_index("ix_technologies_subdomain_id", "technologies", ["subdomain_id"])
    op.create_index("ix_technologies_service_id", "technologies", ["service_id"])

    # 6. api_inventories table
    op.create_table(
        "api_inventories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE")),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("api_type", sa.String(50), nullable=False),
        sa.Column("schema_definition", sa.Text()),
        sa.Column("endpoints_count", sa.Integer(), nullable=False, server_default="0"),
        *timestamps()
    )
    op.create_index("ix_api_inventories_asset_id", "api_inventories", ["asset_id"])

    # 7. api_endpoints table
    op.create_table(
        "api_endpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("inventory_id", sa.String(36), sa.ForeignKey("api_inventories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("auth_required", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("parameters", sa.JSON(), nullable=False),
        *timestamps()
    )
    op.create_index("ix_api_endpoints_inventory_id", "api_endpoints", ["inventory_id"])

    # 8. asset_apis table
    op.create_table(
        "asset_apis",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("api_inventory_id", sa.String(36), sa.ForeignKey("api_inventories.id", ondelete="CASCADE"), nullable=False),
        *timestamps()
    )
    op.create_index("ix_asset_apis_asset_id", "asset_apis", ["asset_id"])
    op.create_index("ix_asset_apis_api_inventory_id", "asset_apis", ["api_inventory_id"])


def downgrade():
    op.drop_table("asset_apis")
    op.drop_table("api_endpoints")
    op.drop_table("api_inventories")
    op.drop_table("technologies")
    op.drop_table("services")
    op.drop_table("certificates")
    op.drop_table("subdomains")
    op.drop_table("assets")
