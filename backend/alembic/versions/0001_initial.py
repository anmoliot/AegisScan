"""Initial AegisScan schema."""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def timestamps():
    return [sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)]


def upgrade():
    op.create_table("users", sa.Column("id", sa.String(36), primary_key=True),
                    sa.Column("email", sa.String(320), nullable=False), sa.Column("password_hash", sa.String(255), nullable=False),
                    sa.Column("display_name", sa.String(100)), sa.Column("is_active", sa.Boolean(), nullable=False), *timestamps())
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table("refresh_tokens", sa.Column("id", sa.String(36), primary_key=True),
                    sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
                    sa.Column("token_hash", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
                    sa.Column("revoked_at", sa.DateTime(timezone=True)), *timestamps())
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)
    status = sa.Enum("queued", "running", "completed", "failed", name="scanstatus")
    op.create_table("scans", sa.Column("id", sa.String(36), primary_key=True),
                    sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
                    sa.Column("target_url", sa.String(2048), nullable=False), sa.Column("target_host", sa.String(253), nullable=False),
                    sa.Column("status", status, nullable=False), sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
                    sa.Column("enabled_plugins", sa.JSON(), nullable=False), sa.Column("error_message", sa.String(500)),
                    sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("completed_at", sa.DateTime(timezone=True)),
                    sa.Column("request_count", sa.Integer(), nullable=False), *timestamps())
    op.create_index("ix_scans_user_id", "scans", ["user_id"])
    op.create_index("ix_scans_target_host", "scans", ["target_host"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_table("findings", sa.Column("id", sa.String(36), primary_key=True),
                    sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
                    sa.Column("fingerprint", sa.String(64), nullable=False), sa.Column("plugin", sa.String(80), nullable=False),
                    sa.Column("title", sa.String(250), nullable=False), sa.Column("description", sa.Text(), nullable=False),
                    sa.Column("severity", sa.String(20), nullable=False), sa.Column("confidence", sa.String(20), nullable=False),
                    sa.Column("category", sa.String(80), nullable=False), sa.Column("url", sa.String(2048), nullable=False),
                    sa.Column("evidence", sa.Text(), nullable=False), sa.Column("remediation", sa.Text(), nullable=False),
                    sa.Column("cwe_id", sa.String(20)), sa.Column("evidence_data", sa.JSON(), nullable=False), *timestamps())
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_table("audit_events", sa.Column("id", sa.String(36), primary_key=True),
                    sa.Column("user_id", sa.String(36)), sa.Column("event_type", sa.String(80), nullable=False),
                    sa.Column("object_id", sa.String(36)), sa.Column("ip_hash", sa.String(64)),
                    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_audit_events_user_id", "audit_events", ["user_id"])
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])


def downgrade():
    op.drop_table("audit_events")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
    sa.Enum(name="scanstatus").drop(op.get_bind(), checkfirst=True)
