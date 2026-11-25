-- Run as the owner in internet_diagnostics after the migration.
-- Create netdiag_api and netdiag_worker as dedicated LOGIN roles before granting.
GRANT USAGE ON SCHEMA core, mtr, security, diagnostics TO netdiag_api;
GRANT SELECT ON public.alembic_version TO netdiag_api;
GRANT SELECT ON security.principal TO netdiag_api;
GRANT UPDATE(rate_minute, rate_count) ON security.principal TO netdiag_api;
GRANT INSERT ON security.audit TO netdiag_api;
GRANT SELECT, INSERT, UPDATE ON core.session TO netdiag_api;
GRANT SELECT, INSERT ON core.chunk TO netdiag_api;
GRANT SELECT, INSERT ON core.run_origin TO netdiag_api;
GRANT SELECT ON mtr.sample TO netdiag_api;
GRANT INSERT ON mtr.sample_key, mtr.sample, diagnostics.job TO netdiag_api;
GRANT SELECT ON diagnostics.analysis TO netdiag_api;
GRANT EXECUTE ON FUNCTION security.enroll_client(uuid,bytea,bytea) TO netdiag_api;
GRANT USAGE ON SCHEMA core, mtr, diagnostics TO netdiag_worker;
GRANT SELECT ON core.chunk, mtr.sample TO netdiag_worker;
GRANT SELECT, UPDATE ON diagnostics.job TO netdiag_worker;
GRANT SELECT, INSERT ON diagnostics.analysis TO netdiag_worker;
