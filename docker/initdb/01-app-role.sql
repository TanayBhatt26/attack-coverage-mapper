-- 01-app-role.sql -- Least-privilege application role for attack-coverage-mapper.
--
-- Executed automatically by the official postgres Docker image on FIRST
-- initialisation of the data volume (mounted at /docker-entrypoint-initdb.d/)
-- as the bootstrap superuser defined by docker-compose.yml
-- (POSTGRES_USER=attack_mapper, POSTGRES_DB=attack_coverage).
--
-- Creates the non-superuser principal `attack_app` (LOGIN, password
-- 'attack_mapper') and scopes it to exactly what the coverage engine needs:
--   * USAGE on schema public,
--   * SELECT/INSERT/UPDATE/DELETE on every table in schema public,
--   * USAGE/SELECT on every sequence in schema public (serial PKs need
--     sequence USAGE for nextval; SELECT allows currval),
--   * identical privileges auto-granted to FUTURE tables/sequences created
--     in schema public by the role that ran this script (i.e. attack_mapper,
--     the account that later runs SQLAlchemy Base.metadata.create_all),
--   * CREATE on schema public revoked from PUBLIC (defense in depth; note
--     PostgreSQL >= 15 already omits it by default -- kept for explicitness
--     and for compatibility with the postgres:13/14 image line).
--
-- Notes:
--   * ALL TABLES covers views and foreign tables as well (PostgreSQL
--     semantics), which is intentional.
--   * Idempotent-ish: safe to re-run manually against a live cluster. Role
--     creation is guarded by a DO block; GRANT/REVOKE are naturally
--     idempotent. Re-runs deliberately do NOT reset the password, so an
--     operator-rotated credential survives.
--   * Password literal is stored SCRAM-SHA-256 hashed on PostgreSQL >= 14
--     (default password_encryption).
--   * CONNECT needs no grant: PUBLIC holds CONNECT on databases by default
--     and we do not revoke it here.
--   * Verify afterwards with: \du attack_app  and  \dp public.*
--   * This script never touches data; schema creation stays with
--     SQLAlchemy create_all / migrations.

-- ---------------------------------------------------------------------------
-- 1. Role creation (guarded for idempotency)
-- ---------------------------------------------------------------------------
DO $create_role$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname = 'attack_app'
    ) THEN
        CREATE ROLE attack_app
            WITH LOGIN
            PASSWORD 'CHANGE_ME_IN_PROD'
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$create_role$;

-- ---------------------------------------------------------------------------
-- 2. Grants on existing objects (covers manual re-runs against a live DB)
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO attack_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO attack_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO attack_app;

-- ---------------------------------------------------------------------------
-- 3. Default privileges for objects created LATER by this role's session
--    owner (attack_mapper per docker-compose.yml) in schema public of this
--    database. Without these, tables made by create_all AFTER first init
--    would be invisible to attack_app. They must target FOR ROLE
--    attack_mapper: the compose entrypoint creates tables as the
--    POSTGRES_USER superuser, not as the bootstrap admin running this file,
--    and default privileges are tracked per-creating-role.
-- ---------------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES FOR ROLE attack_mapper IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO attack_app;

ALTER DEFAULT PRIVILEGES FOR ROLE attack_mapper IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO attack_app;

-- ---------------------------------------------------------------------------
-- 4. Hardening: nobody but owners may create objects in schema public.
--    No-op on PostgreSQL >= 15, effective on <= 14.
-- ---------------------------------------------------------------------------
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
