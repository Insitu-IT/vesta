# Upgrade or recover your control plane

Use the kit for the version you are moving to and keep the kit and rendered configuration for the version you are running. For a same-schema update, confirm that the target kit expects the schema installed at your site. Your catalog, keys, agent identity and backup journals stay with your installation.

## Prepare the update

In **Settings → Backup → Backup admission**, pause new backups. Pause schedules and automatic cleanup. Give work already underway time to finish. If an operation is held or has an uncertain outcome, keep its journal and follow the [backup safety guide](backup-safety.md) before touching its producer.

Save the accepted site configuration, current image digests and exact application and agent targets. Keep a recoverable copy of the database, TLS and encryption keys and agent journals in private storage. Check the installed schema with your database administrator. For another starting schema, use the migration for that exact transition. Take your target kit and its matching runbook into an air-gapped site together.

Verify the downloaded kit and work from its extracted directory. If you already have a `vesta.json`, use your accepted copy. When moving from an older flat site configuration, run `./vesta init`, set the same cluster context and on-site registry, and copy your accepted configuration into the new file’s `site` object, omitting the old `images` field. The kit supplies the new application image digests. Preserve the original settings, including an omitted resource prefix. Keep the current PostgreSQL instance, Secret names, persistent volumes, recovery keys and agent enrollment.

```sh
./vesta verify
./vesta plan
./vesta import-images
./vesta prepare-upgrade --output-dir /private/vesta/update
```

You can skip the import when your registry already contains the exact digests shown by the plan. The last command writes the application target and, for KubeVirt sites, the agent target. It leaves the running site available for comparison.

## Roll out a same-schema update

Use the OpenShift context named in the accepted manifest. Review `oc diff -k /private/vesta/update/api` and, on KubeVirt sites, `oc diff -k /private/vesta/update/agent`. A diff exit status of 1 indicates changes to review. If your site uses GitOps or carries custom patches, carry the image and configuration updates through that deployment and preserve those patches. Resolve unexpected changes to access, identities, storage, Secrets or database configuration before continuing.

Apply the application target with `oc apply -k /private/vesta/update/api`. Wait for both application deployments in your namespace to finish rolling out. For a KubeVirt site, apply the agent target with `oc apply -k /private/vesta/update/agent` and wait for its deployment. For a native libvirt host, use the `vesta-agent` RPM from the matching release and retain its existing configuration and identity. Leave the database and its migration jobs alone for this transition.

Run `./vesta status`. Sign in at your usual address and check the catalog, recovery keys and authenticated agent heartbeat. Confirm you can recover a disposable workload before reopening admissions, schedules and cleanup. Keep the previous kit and accepted targets through this check.

## If the rollout is interrupted

Keep new work paused. Inspect the rollout and [collect diagnostics](operations.md). For the same-schema update, with producers settled and custody intact, reapply the previous accepted agent and application targets from your recovery set. Check readiness, identity and catalog access before restoring the original schedule. If the database or retained backup formats changed, use a coordinated recovery of the database, configuration, keys and journals.

## Before a schema-changing upgrade or recovery

Pause scheduled/new admissions, then inspect active and uncertain attempts.
Preserve producer journals and all required source/key/storage custody. A paused
scheduler does not prove an already-started producer stopped. Do not restart a
VM, libvirt, PostgreSQL or a node to create an upgrade window.

Retain the current digest-pinned images, rendered configuration, database dump,
application encryption settings, PKI/identity material, exported KEKs and agent
journals in private off-pod recovery storage. Capture them at a consistent,
quiesced point. An encrypted key export without its password, or a database dump
without application/key/journal custody, is not a complete recovery set.

Verify a restore rehearsal into an isolated database/resources before applying
an important migration. A reviewed forward migration uses owner authority only
for that operation; normal API processes keep the restricted runtime login.
Never enable SUPERUSER/BYPASSRLS on the API or disable isolation to make it start.

## Apply and check

Use the approved transition's ordered migration/grant/rollout steps and exact
image digests. Inspect readiness, runtime database identity, agent enrollment,
existing catalog/key counts and the first bounded operation. Changing an image
tag or seeing Ready pods is not proof that data and authorization were preserved.
Retain the previous recovery set until the new release has been accepted.

If the exact transition has no supported migration/recovery procedure, stop and
obtain one. Do not adapt a fresh-install Job, delete old rows or improvise SQL
against the running installation. Collect [diagnostics](operations.md) instead.

## Rollback and control plane recovery

Schema changes may prevent image-only rollback. Fence new work and restore the
consistent database/configuration/key/journal set into isolated targets first.
Use the matching previous images and runtime grants, then validate catalog and
key custody before resuming dispatch. Do not overwrite an active database or
merge competing journal identities. Keep uncertain producer state fenced until
its original ownership and termination have been established.

For an already restored **exact-schema** database, the install renderer's
`restore-grants` stage applies restricted runtime grants; it does not restore data
or run an upgrade. Never combine it with the `migrate` fresh-install stage.

Before `pg_restore`, prepare private defaults in the **new, empty target database**
under the **actual replacement owner** that will create restored objects. Defaults
are local to each database and creating role; copying a source role's default ACL
or applying defaults after restore does not protect newly created functions.
PostgreSQL otherwise gives PUBLIC EXECUTE on new functions, including when
`--no-owner` maps them to a replacement owner or `--no-acl` skips archive ACLs.

Use the separately mounted owner connection with verified TLS. Confirm
`current_database()` and `current_user` match the reviewed target and replacement
owner, confirm the public schema contains no relations or routines, then execute
in that database as that same owner, before restoring any object:

```sql
BEGIN;
-- GLOBAL is deliberate: an IN SCHEMA revoke cannot remove global defaults.
ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM PUBLIC;
COMMIT;
```

Establish the remaining reviewed owner/runtime defaults before restore as well;
the shared `core.runtime_grants.apply_default_runtime_grants` routine clears
PUBLIC and runtime defaults for tables, sequences and functions under its actual
current user. A login migrator using `SET ROLE` must select the same replacement
owner for this preparation and `pg_restore --role`. Do not set defaults only for
the login identity. Never perform this preparation against an existing target as
an improvised repair.

Keep the dump and its ACL inventory. If retaining archive ACLs, precreate only
reviewed inert source-owner identities and restricted ACL recipients as required;
`--no-owner` does not remap ACL role names. If the reviewed procedure uses
`--no-acl`, run the matching `restore-grants` stage afterward. In either case,
compare effective table, sequence and routine privileges with the accepted source
before starting writers. Require zero unexpected differences. A default-ACL
preparation performed too late needs a fresh isolated restore; do not waive the
difference or apply blanket post-restore grants/revokes to hide it.

The optional `install/kit.py seal-control-plane` command encrypts a PostgreSQL
dump and a prepared private custody snapshot using `age`. It requires a libpq
service and recipients file, explicit `--quiesced`, and a new destination.
For a customer-postgresql release, also pass `--pg-host` (explicit TCP server
certificate identity) and `--pg-ca-file` (existing private CA file). The bundled
profile is inherited, or source tools may select it with `--config`/`--profile`;
a contradictory site profile is refused. Explicit verify-full/CA/TCP/GSS-disabled
parameters override weaker service/environment settings. See
[customer PostgreSQL capture](customer-postgresql.md) for the complete command. It
does not itself pause dispatch, stop producers, capture live journal consistency
or copy S3 payloads. Use `--help` for the installed command; pass no credentials
in URLs or shell arguments. Verify the archive and retain its decryption identity
separately. S3 data and its exact versions need their own retention/recovery plan.

A same-cluster restore exercise demonstrates only that environment. Independent
site recovery requires separate storage and key custody and its own rehearsal;
do not report it as passed on the strength of a local application reinstall.
