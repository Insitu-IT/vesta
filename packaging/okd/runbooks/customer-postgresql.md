# Customer-provided PostgreSQL delivery

The Community kit uses the `customer-postgresql` profile. Its image and
release manifests identify this profile and exactly three supplied images:
backend, frontend and agent. `full` is a separate delivery with a fourth
`postgres` image. Check both manifests and the supply contract before transfer.
The verifier traverses every OCI manifest/index/config/layer descriptor, checks
its digest and size, and refuses extra image directories and orphan blobs.
Application OS layers, psycopg2/libpq and other embedded dependencies remain
supplied by Vesta; their obligations remain in the supply contract.

This profile uses an existing customer-operated PostgreSQL service. It never
installs, downloads or falls back to a database image from a Vesta cache/mirror.
It does not move an existing installation's database. A change of database
requires a separately reviewed backup/recovery and cutover plan.

## Preparation before the airgap

Use PostgreSQL 17.x with `plpgsql` enabled on a writable primary. Record the server and extension versions and confirm TLS hostname verification from the application namespace. Keep the database, schema owner and restricted runtime credentials separate.

The customer may provision a managed service or acquire the official
`docker.io/library/postgres` image directly. The exact reviewed upstream image
reference/digest is recorded in `install/supply-contract.json`/the generated
manifest contract; a floating tag is never an approved import identity. Obtain
it through customer credentials and a customer-owned upstream mirror if needed,
verify its digest, preserve its OCI multi-platform descriptors with
`--all --preserve-digests`, and import it into the customer's registry before
isolating the site. Retain customer acquisition and destination digest receipts.
If the contract has no reviewed upstream digest, stop and review one before
import. For this profile, obtain PostgreSQL directly from your provider, upstream distributor or your own mirror. Vesta's `import-images` command imports only
its three application images. It cannot supply the missing database.

The customer owns database provisioning, installation, patches, availability,
storage/capacity, database backup/recovery, credentials, certificates/trust and
network/firewall access. Vesta owns its schema/migration and grant contract,
supported-server compatibility validation and product integration defects.
Database recovery must preserve the catalog together with Vesta configuration
keys, backup keys and agent journals; see [recovery](upgrade-recovery.md).

## Private configuration and prerequisite refusal

The extracted installer inherits its verified release profile when an older
private site JSON omits `delivery_profile`; an explicit contradictory `full`
value is refused. Source-tree and legacy profile-less installers retain their
full default. You may explicitly set `"delivery_profile": "customer-postgresql"`
in the private site JSON. Before use, authenticate the received archive checksum
and run `python3 install/kit.py verify --source .`. Renderer entry checks bind
only the small installer/profile inputs, without rereading all OCI blobs; they
do not authenticate mutable local manifests or replace full kit verification. Keep
release manifests and the supply contract free of site credentials. Provision
separate database/bootstrap administrator, schema owner/migrator and application
runtime credentials. The schema owner/migrator connection performs reviewed
schema/grant operations; the API receives only the restricted runtime connection.
Runtime must be LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
NOREPLICATION NOINHERIT, without role memberships or ownership of database/public
schema. The database administrator remains customer-controlled.

Ensure the runtime role has `USAGE` on the `public` schema and lacks `CREATE`.
If the schema owner has direct privileges without the ability to grant schema
`USAGE`, the database administrator must grant runtime `USAGE` explicitly.
Successful migrations do not prove that this grant took effect: verify schema
visibility using the runtime connection before starting the API. Table and
sequence privileges still come from Vesta's reviewed migration/grant operation;
do not give runtime schema ownership, owner-role membership or RLS bypass.

Create the existing `database_owner`, `database_runtime` and trust Secrets from
private files/secret-manager inputs as in [installation](installation.md).
Both URLs must use `sslmode=verify-full`, the server DNS identity covered by its
certificate and the explicit CA at `/trust/ca.crt`. Use an explicit TCP host in
the URL authority or `host` query parameter; empty-host/environment fallback and
Unix/abstract sockets are refused because TLS is ignored on local sockets.
Customer connections enforce `gssencmode=disable` so GSS transport cannot
substitute for TLS; remove conflicting URL/environment values. URL options overriding
verification (including `sslmode=require`) are rejected before schema-owner or
runtime connections open. Runtime synchronous connections receive explicit
verify-full/CA parameters; asynchronous connections receive a hostname-verifying
SSLContext using the same CA. Test the actual runtime TLS handshake as part of
acceptance. No secret values belong in argv or shared receipts.

All rendered fresh/restore-grants/upgrade/rollback Jobs pass the profile to the
existing installation guard. Before advisory locks, grants or schema changes it
checks the database identity, PostgreSQL 17.x, plpgsql, writable primary, actual
encrypted connection and effective libpq verify-full/CA parameters, then existing
runtime-role restrictions. Failure rolls back and reports a sanitized error.
A missing database/role/trust prerequisite must be repaired by its owner; never
wipe or recreate a populated database to satisfy fresh-install checks.

For a separate read-only check, render the intended schema Job to a private JSON
file and replace its operation argument (`--fresh`, `--restored`,
`--upgrade-managed-files` or `--rollback-managed-files`) with
`--check-prerequisites`; give the copied Job a distinct name. Keep its original
image, owner Secret, database/runtime-role arguments and trust mount, inspect and
server-dry-run it, then run it before the intended schema Job. This mode explicitly sets the transaction READ ONLY before its SELECT checks,
without schema/grant changes or advisory locks. A passed
preflight is a point-in-time result; each actual schema Job repeats its guard.

## Check the connection and keep a recovery copy

Use the runtime login to confirm that it can connect over verified TLS, see the expected schema, and perform only its granted operations. Check readiness and sign in before enrolling the agent. Verify database backup and restore into an isolated target with the same application configuration, keys and journals. Keep your database maintenance and recovery procedure with the site file.

For encrypted control-plane capture, the customer profile also requires explicit
TCP identity and CA inputs; a libpq service alone does not establish TLS policy:

```bash
python3 install/kit.py seal-control-plane --config /private/site.json \
  --pg-service vesta-backup --pg-host database.example.org \
  --pg-ca-file /private/database-ca.crt --quiesced \
  --custody /private/quiesced-custody --recipients /private/age-recipients \
  --destination /private/new-sealed-recovery
```

The kit derives the profile from its bundled release (or the explicit site/
`--profile` choice in the source tool). It passes properly quoted explicit
`host`, `sslrootcert`, `sslmode=verify-full` and `gssencmode=disable` parameters to
pg_dump, overriding weaker service/environment transport settings. Database
passwords stay in the private libpq service/passfile. Host/CA paths are not
written into shared control-plane metadata. Quiescence and backup/recovery
acceptance remain separate requirements.
