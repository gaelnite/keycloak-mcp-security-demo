#!/bin/sh
set -eu

# Pass the first-install credential to psql through its process environment.
# The shell and psql read the mounted file without printing its contents.
export KEYCLOAK_DB_CREDENTIAL="$(cat /run/db-secret/application-password)"
psql --no-psqlrc --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
\getenv auth KEYCLOAK_DB_CREDENTIAL
CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'auth';
CREATE DATABASE keycloak OWNER keycloak;
REVOKE CONNECT ON DATABASE keycloak FROM PUBLIC;
SQL
unset KEYCLOAK_DB_CREDENTIAL
