"""PostgreSQL foundation for Internet Diagnostics."""

from datetime import timedelta

from alembic import op

revision = "v010"
down_revision = None
branch_labels = None
depends_on = None

SCHEMAS = ("core", "device", "lan", "measurement", "mtr", "diagnostics", "integration", "report", "security")


def upgrade():
    for schema in SCHEMAS:
        op.execute(f"CREATE SCHEMA {schema}")
    op.execute("""
        CREATE TABLE security.principal (
            id uuid PRIMARY KEY, tenant uuid NOT NULL, role text NOT NULL CHECK(role IN ('client','operator')),
            token_hash bytea NOT NULL UNIQUE, enabled boolean NOT NULL DEFAULT true,
            rate_minute timestamptz, rate_count integer NOT NULL DEFAULT 0
        )""")
    op.execute("""
        CREATE TABLE core.session (
            id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES security.principal,
            started_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
            touched_at timestamptz NOT NULL DEFAULT now(), ended_at timestamptz,
            client_version text NOT NULL, mode text NOT NULL CHECK(mode IN ('portable','agent')),
            source_ip inet NOT NULL, match_state text NOT NULL DEFAULT 'anonymous',
            state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','completed','partial','cancelled','failed')),
            open_digest bytea NOT NULL, finish_digest bytea, total_bytes bigint NOT NULL DEFAULT 0
        )""")
    op.execute("CREATE INDEX session_owner_time ON core.session(owner_id, received_at DESC, id)")
    op.execute("CREATE INDEX session_open ON core.session(touched_at) WHERE state='open'")
    op.execute("""
        CREATE TABLE core.chunk (
            session_id uuid REFERENCES core.session, sequence integer CHECK(sequence BETWEEN 0 AND 65535),
            digest bytea NOT NULL, row_count int NOT NULL CHECK(row_count BETWEEN 1 AND 256),
            PRIMARY KEY(session_id, sequence)
        )""")
    op.execute("""
        CREATE TABLE mtr.sample_key (
            session_id uuid REFERENCES core.session, target inet, protocol text, phase text, ttl int, attempt int,
            received_day date NOT NULL, PRIMARY KEY(session_id,target,protocol,phase,ttl,attempt)
        )""")
    op.execute("CREATE INDEX sample_key_day ON mtr.sample_key(received_day)")
    op.execute("""
        CREATE TABLE mtr.sample (
            received_day date NOT NULL, session_id uuid NOT NULL, sequence int NOT NULL,
            row_no int NOT NULL, payload jsonb NOT NULL, PRIMARY KEY(received_day, session_id, sequence, row_no),
            FOREIGN KEY(session_id,sequence) REFERENCES core.chunk
        ) PARTITION BY RANGE(received_day)""")
    op.execute("CREATE INDEX sample_session ON mtr.sample(session_id,sequence,row_no)")
    today = op.get_bind().exec_driver_sql("SELECT (now() AT TIME ZONE 'UTC')::date").scalar_one()
    for day in (today, today + timedelta(days=1)):
        end = day + timedelta(days=1)
        op.execute(
            f"CREATE TABLE mtr.p{day:%Y%m%d} PARTITION OF mtr.sample FOR VALUES FROM ('{day}') TO ('{end}')"
        )
    op.execute("""
        CREATE TABLE diagnostics.job (
            session_id uuid PRIMARY KEY REFERENCES core.session, state text NOT NULL DEFAULT 'pending'
            CHECK(state IN ('pending','running','done','failed')), generation int NOT NULL DEFAULT 0,
            available_at timestamptz NOT NULL DEFAULT now(), lease_until timestamptz, error text
        )""")
    op.execute("CREATE INDEX job_ready ON diagnostics.job(available_at) WHERE state IN ('pending','running')")
    op.execute("""
        CREATE TABLE diagnostics.analysis (
            session_id uuid REFERENCES core.session, rules_version text, input_digest bytea NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(), result jsonb NOT NULL,
            PRIMARY KEY(session_id,rules_version,input_digest)
        )""")
    op.execute("""
        CREATE TABLE security.audit (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT now(),
            actor uuid, session_id uuid, event text NOT NULL
        )""")


def downgrade():
    for table in (
        "security.audit",
        "diagnostics.analysis",
        "diagnostics.job",
        "mtr.sample",
        "mtr.sample_key",
        "core.chunk",
        "core.session",
        "security.principal",
    ):
        op.execute(f"DROP TABLE {table}")
    for schema in reversed(SCHEMAS):
        op.execute(f"DROP SCHEMA {schema}")
