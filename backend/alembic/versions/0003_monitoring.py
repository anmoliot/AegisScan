"""Create monitoring tables."""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def timestamps():
    return [sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)]


def upgrade():
    # 1. monitor_schedules table
    op.create_table(
        "monitor_schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("frequency", sa.String(50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("last_run", sa.DateTime(timezone=True)),
        *timestamps()
    )
    op.create_index("ix_monitor_schedules_asset_id", "monitor_schedules", ["asset_id"])

    # 2. alerts table
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey("monitor_schedules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_type", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_alerts_schedule_id", "alerts", ["schedule_id"])
    op.create_index("ix_alerts_acknowledged", "alerts", ["acknowledged"])


def downgrade():
    op.drop_table("alerts")
    op.drop_table("monitor_schedules")
