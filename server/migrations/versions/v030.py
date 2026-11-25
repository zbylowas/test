"""Persist the optional local inventory captured at session opening."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "v030"
down_revision = "v020"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("session", sa.Column("inventory", JSONB, nullable=True), schema="core")


def downgrade():
    op.drop_column("session", "inventory", schema="core")
