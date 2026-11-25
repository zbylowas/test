"""Store optional transfer measurements with the original session."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "v040"
down_revision = "v030"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("session", sa.Column("throughput", JSONB, nullable=True), schema="core")


def downgrade():
    op.drop_column("session", "throughput", schema="core")
