#!/usr/bin/env bash
# Invoked only by the PostgreSQL image's first-empty-volume initialization.
# Do not enable tracing: private passwords enter psql through its environment.
set -euo pipefail
# First-install values are canonical. Existing manifests may supply legacy names.
export VESTA_DATABASE="${VESTA_DATABASE-${VNBUI_DATABASE-}}"
export VESTA_OWNER_ROLE="${VESTA_OWNER_ROLE-${VNBUI_OWNER_ROLE-}}"
export VESTA_RUNTIME_ROLE="${VESTA_RUNTIME_ROLE-${VNBUI_RUNTIME_ROLE-}}"
[[ -n "$VESTA_DATABASE" && -n "$VESTA_OWNER_ROLE" && -n "$VESTA_RUNTIME_ROLE" ]] || exit 1
export VESTA_OWNER_PASSWORD VESTA_RUNTIME_PASSWORD
VESTA_OWNER_PASSWORD=$(< /bootstrap/OWNER_PASSWORD)
VESTA_RUNTIME_PASSWORD=$(< /bootstrap/RUNTIME_PASSWORD)
[[ -n "$VESTA_OWNER_PASSWORD" && -n "$VESTA_RUNTIME_PASSWORD" ]] || exit 1
psql -X --no-password --username "$POSTGRES_USER" --dbname postgres --set ON_ERROR_STOP=1 <<'SQL'
\set ECHO none
\getenv owner_role VESTA_OWNER_ROLE
\getenv runtime_role VESTA_RUNTIME_ROLE
\getenv database VESTA_DATABASE
\getenv owner_password VESTA_OWNER_PASSWORD
\getenv runtime_password VESTA_RUNTIME_PASSWORD
CREATE ROLE :"owner_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'owner_password';
CREATE ROLE :"runtime_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'runtime_password';
CREATE DATABASE :"database" OWNER :"owner_role";
REVOKE ALL ON DATABASE :"database" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"database" TO :"owner_role", :"runtime_role";
SQL
psql -X --no-password --username "$POSTGRES_USER" --dbname "$VESTA_DATABASE" --set ON_ERROR_STOP=1 <<'SQL'
\set ECHO none
\getenv owner_role VESTA_OWNER_ROLE
\getenv runtime_role VESTA_RUNTIME_ROLE
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO :"owner_role";
-- A NOINHERIT owner may use public without being able to grant its USAGE.
GRANT USAGE ON SCHEMA public TO :"runtime_role";
SQL
unset VESTA_OWNER_PASSWORD VESTA_RUNTIME_PASSWORD
