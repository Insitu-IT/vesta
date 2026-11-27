# Rotate the installation encryption key

Vesta uses `VESTA_ENCRYPTION_KEY` to protect stored integration credentials, local key-encryption keys (KEKs) and the installation’s recovery signing key. Rotate it in an offline PostgreSQL 17 restore of your catalog. The tool verifies the recovery signing key against its recorded public identity and rewraps it with the new installation key. Recovery workstations can keep using their saved trust and encrypted backups.

Bucket credentials at the provider, license signing keys, PostgreSQL and route TLS keys, and Linux file recovery identities have their own rotation procedures.

Use the exact API image digest and schema revision running at your site. Rehearse on an isolated restore first. For a suspected compromise, preserve the recovery set and keep the installation fenced while following the compromise steps below.

## Capture the recovery set

1. Record the accepted deployment targets, database endpoints, admission settings, schedules and cleanup settings. Pause new backup admission, schedules and cleanup. Check active and uncertain attempts and preserve their producer journals. Follow [backup safety](backup-safety.md) to settle work before taking the API, scheduler and any other catalog writers offline. Fence external callers and agents from writes for the cutover.
2. Retain the source database and a recoverable, quiesced dump with the old application encryption key, deployment and Secret references, agent/PKI identity, key exports and producer journals in private off-pod storage. Use an approved backup connection that can read all tenant data through the source's existing policies. Record the dump checksum and the facts below from the source through that private connection. Compare the UUID to the installation you intended to maintain.
3. Keep the source fenced through capture, restore and validation. Keep its database and its Secret versions available for rollback.

```sql
SELECT current_database(), current_setting('server_version_num');
SELECT installation_id, revision FROM public.storage_configuration_clock WHERE slot = 1;
SELECT version_num FROM public.alembic_version;
```

Use the PostgreSQL 17 releases of `pg_dump`, `pg_restore` and `psql`. The examples use a private libpq service file with `rotation_source` for the source backup connection and `rotation_owner` for the clone owner connection. Use verified TLS on TCP and place passwords in a private passfile. Confirm `current_database()` on each connection before continuing. Set a restrictive file creation mask and keep the archive on private storage.

```sh
umask 077
export PGSERVICEFILE=/private/rotation/pg_service.conf
pg_dump --format=custom --file=/private/rotation/source.dump 'service=rotation_source'
pg_restore --list /private/rotation/source.dump > /private/rotation/source.toc
```

## Restore into a separate database

Have your DBA create an empty PostgreSQL 17 database from `template0` with the source's encoding and locale, a **different database name**, and a dedicated login as database owner. This login must own the restored objects directly, have no role members, and have no SUPERUSER, BYPASSRLS or REPLICATION privilege. Restrict the clone endpoint to the restore tooling and the maintenance job. Superusers can connect despite ACLs, so keep monitoring, replication, background tools and interactive DBA sessions away from the clone for the rewrite. Keep existing runtime logins and deployments pointed at the source. Prepare a restricted runtime role for the clone, following [customer PostgreSQL](customer-postgresql.md).

In the example the new database is `vesta_rotation` and its owner is `vesta_clone_owner`. As the DBA, inspect its database ACL and ensure that only the owner has `CONNECT`; revoke any other explicit connection grants on this new database. Retain the owner's `TEMPORARY` and database ownership.

```sql
REVOKE ALL ON DATABASE vesta_rotation FROM PUBLIC;
SELECT datname, datdba::regrole, datacl
FROM pg_database WHERE datname = 'vesta_rotation';
```

Connect to the empty clone as `vesta_clone_owner`. Compare the returned database and login to your plan. Establish the owner's private default ACLs before creating objects, as described in [upgrade and recovery](upgrade-recovery.md). Clear any additional default grants to the runtime role as described there. The function default below is required even when restoring without archive ACLs.

```sh
psql -X -v ON_ERROR_STOP=1 'service=rotation_owner' \
  -c 'SELECT current_database(), current_user, session_user'
psql -X -v ON_ERROR_STOP=1 'service=rotation_owner' \
  -c 'ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM PUBLIC'

pg_restore --dbname='service=rotation_owner' --no-owner --no-acl \
  --single-transaction --section=pre-data --section=data /private/rotation/source.dump
```

Keep the remainder of the archive for the next step. Leave the clone without post-data objects while rotating. The restore puts the trigger definitions, indexes, foreign keys and row security policies back in the following phase.

## Plan and apply

Run the matching API image as a one-off maintenance container with the command given below in place of the normal API command. Give this container only the isolated owner connection and the private files for the rotation. Mount the inputs read-only and grant the maintenance user access to a private, durable directory for the receipt and any generated key. Use mode `0600` or `0400` for input files and a private directory. A read-only Secret projection may grant read access to the maintenance pod's private `fsGroup` with mode `0440`. Keep any libpq passfile at mode `0600`. Keep the container, credential mounts, dump and both roots out of shared logs and temporary public storage.

The old and new key files each contain one canonical Fernet key. To generate a new key into a new file, use the matching API image:

```sh
python -m core.installation_key_rotation new-key /private/rotation/new-root
```

Back up the new key in your secret manager before cutover. Create a private manifest like this and replace the example UUID and database names with your observed source UUID and reviewed database names.

```json
{
  "installation_id": "6150e149-03bd-4d32-bc86-390dc3a659fd",
  "source_database": "vesta",
  "target_database": "vesta_rotation",
  "owner_dsn_file": "/private/rotation/owner.dsn",
  "old_key_file": "/private/rotation/old-root",
  "new_key_file": "/private/rotation/new-root",
  "receipt_file": "/private/rotation/receipt"
}
```

The DSN file contains one libpq URI or keyword connection string. Use an explicit single host, database and login. Point it at the same clone as the `rotation_owner` service. For TCP, include `sslmode=verify-full` and the explicit CA file path. For example, use this line with a mode `0600` PostgreSQL passfile containing the owner credential:

```text
host=clone-db.example.org port=5432 dbname=vesta_rotation user=vesta_clone_owner sslmode=verify-full sslrootcert=/private/rotation/db-ca.crt passfile=/private/rotation/owner.pgpass
```

Use an absent receipt path on a durable private filesystem. Run these commands in order as the maintenance user. Check that the reported configuration revision matches the source and the counts match the planned KEK and stored secret inventory.

```sh
python -m core.installation_key_rotation plan /private/rotation/manifest.json
python -m core.installation_key_rotation apply /private/rotation/manifest.json
python -m core.installation_key_rotation plan /private/rotation/manifest.json
```

Expect `ready`, then `rotated`, then `already_rotated`. The command authenticates every encrypted value, checks the plaintext KEK hashes, and verifies the rewritten values in one database transaction. The private receipt binds the clone and both supplied roots to the verified inventory. If the response to `apply` was interrupted, keep the receipt and rerun the same plan before restoring post-data. A plan that returns `ready` can be followed by the same apply. A plan that returns `already_rotated` confirms the committed rewrite. Keep a refused clone isolated and use a fresh clone from the original dump if you cannot account for the refusal. Unsupported KEK providers, invalid envelopes, mixed roots, or lack of any encrypted record to authenticate the old root require a reviewed recovery. Older installations can also have historical KEK metadata without material in the catalog. Keep the original recovery keys needed for that history.

## Restore controls and validate before cutover

```sh
pg_restore --dbname='service=rotation_owner' --no-owner --no-acl \
  --single-transaction --section=post-data /private/rotation/source.dump
```

Run the matching `restore-grants` stage against the clone with its actual owner connection, clone database name, and restricted runtime role. Use the **restore-grants** render stage for a restored catalog. You can also invoke its command from the matching API image with `DATABASE_URL` supplied through the private owner Secret and the site's PostgreSQL profile and trust mount:

```sh
python -m core.portable_install --restored --database vesta_rotation --runtime-role vesta_clone_runtime
```

Require schema acceptance and compare effective table, sequence and routine privileges with the source's reviewed runtime grants. Check that triggers and row-level policies were restored and that the restricted login cannot see or change data outside its tenant scope. The installation UUID, storage configuration revision and KEK hashes must match the source. Check that retained backup key references and wrapped DEKs are intact.

Create separate runtime Secret versions for the clone connection and the new `VESTA_ENCRYPTION_KEY`. Keep the legacy `VNBUI_ENCRYPTION_KEY` alias equal if your manifests still set it. While API writers are stopped, deploy the **database and root version together** with the same API image, site settings and agent identity. Limit access during validation. Confirm readiness, catalog and recovery key visibility, stored storage and authentication integration functionality, and an authenticated agent heartbeat. Verify an existing encrypted backup by restoring a disposable workload and checking its contents. Reopen admission, schedules, cleanup and normal traffic only after acceptance.

## Roll back or respond to compromise

If validation fails before work resumes, stop the clone API and any writers, preserve the clone and its logs, and redeploy the previous configuration pointing at the **source database and old key together**. Verify readiness and custody before resuming work. If the clone already accepted new operations, fence both sets of writers and use [coordinated recovery](upgrade-recovery.md) to preserve the new catalog and custody records. Keep every older dump or recovery snapshot paired with its original root as long as that recovery point is retained.

Rewrapping protects the new catalog under the new root. If an attacker had the old root and a readable catalog copy, they may already have the underlying credentials and KEK material. Rotate exposed integration credentials at the source systems, then update Vesta through the supported integration configuration workflows. Review the storage custody and configuration revision impacts of changing a storage credential. Rotate affected KEKs for new backups, assess exposure of data encrypted by the affected keys, and preserve recoverability of retained backups before retiring any old key. Include any other potentially exposed credential or private key in the incident response.
