"""Bound self-enrollment to client accounts in the portal's configured tenant."""
from alembic import op

revision = "v050"
down_revision = "v040"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE security.portal_issuer(tenant uuid PRIMARY KEY);
        CREATE TABLE security.portal_enrollment(day date NOT NULL, peer_hash bytea NOT NULL);
        CREATE INDEX portal_enrollment_day ON security.portal_enrollment(day,peer_hash);
        CREATE FUNCTION security.enroll_client(principal_id uuid, digest bytea, peer bytea)
        RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
        DECLARE organization uuid; today date := (now() AT TIME ZONE 'UTC')::date;
        BEGIN
            SELECT tenant INTO STRICT organization FROM security.portal_issuer;
            PERFORM pg_advisory_xact_lock(7401050);
            DELETE FROM security.portal_enrollment WHERE day < today;
            IF (SELECT count(*) FROM security.portal_enrollment) >= 64 OR
               (SELECT count(*) FROM security.portal_enrollment WHERE peer_hash=peer) >= 4 THEN
                RETURN false;
            END IF;
            INSERT INTO security.principal(id, tenant, role, token_hash)
                VALUES(principal_id, organization, 'client', digest);
            INSERT INTO security.portal_enrollment VALUES(today, peer);
            INSERT INTO security.audit(actor,event) VALUES(principal_id,'portal.enroll');
            RETURN true;
        END $$;
        REVOKE ALL ON FUNCTION security.enroll_client(uuid,bytea,bytea) FROM PUBLIC;
    """)


def downgrade():
    op.execute("DROP FUNCTION security.enroll_client(uuid,bytea,bytea)")
    op.execute("DROP TABLE security.portal_enrollment, security.portal_issuer")
