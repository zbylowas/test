"""Preserve the acquisition settings reported by v0.2 clients."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "v020"
down_revision = "v010"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("session", sa.Column("measurement", JSONB, nullable=True), schema="core")


def downgrade():
    op.drop_column("session", "measurement", schema="core")
