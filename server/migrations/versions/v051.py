"""Preserve the measurement origin and installation identity separately from delivery."""
from alembic import op

revision = "v051"
down_revision = "v050"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE core.session ADD COLUMN device_id uuid, ADD COLUMN device_method text,
            ADD COLUMN device_reason text, ADD COLUMN measured_ip inet;
        CREATE TABLE core.run_origin (
            session_id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES security.principal(id),
            address inet NOT NULL, observed_at timestamptz NOT NULL DEFAULT now());
        CREATE INDEX session_device_history ON core.session(owner_id,device_id,started_at DESC)
            WHERE device_id IS NOT NULL;
        CREATE INDEX session_ip_history ON core.session((coalesce(measured_ip,source_ip)),started_at DESC);
    """)


def downgrade():
    op.execute("""
        DROP TABLE core.run_origin;
        ALTER TABLE core.session DROP COLUMN measured_ip, DROP COLUMN device_reason,
            DROP COLUMN device_method, DROP COLUMN device_id;
    """)
