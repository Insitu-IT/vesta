# Dedicated PostgreSQL

This is the separately named `full` delivery profile. For a kit containing only
three application images, follow [customer-provided PostgreSQL](customer-postgresql.md)
and skip database rendering/deployment here. Never obtain a fallback database
image from a Vesta mirror under the customer-provided profile.

The dedicated-database profile installs one PostgreSQL 17 Debian/bookworm
instance and a retained RWO Filesystem PVC in the application namespace. It is
not a replicated/HA database or an independent backup. Keep control-plane
database backups and both configuration/encryption-key custody outside its pod.
The approved image digest must be included in the received kit's image manifest
as `postgres`; never substitute a floating tag or a different major release.
An installation using an existing customer-managed PostgreSQL service skips
this stage, not the separate owner/runtime privilege requirements.

Supply site-issued database certificates and keys. The dedicated deployment loads `tls.crt` and `tls.key` from the configured Secret. Use the service hostname recorded in the server certificate for connections.

## Private inputs

Copy [postgres.example.json](../postgres.example.json) outside the kit and fill
the imported `postgres` image reference, Filesystem storage class and size,
resource limits and Secret names. Keep `owner_role`, `database` and
`runtime_role` distinct from the database bootstrap account; the latter is only the database
bootstrap administrator and is never an application credential.

Create these application-namespace Secrets through the customer's secret manager
or private mode-0600 files. Do not put values in arguments, terminal history or
the non-secret JSON configuration:

| Secret | Keys |
|---|---|
| `bootstrap_secret` | `POSTGRES_PASSWORD`, `OWNER_PASSWORD`, `RUNTIME_PASSWORD` |
| `tls_secret` | `tls.crt` (server chain), `tls.key` |
| Site `database_owner` | `DATABASE_URL` for `owner_role` |
| Site `database_runtime` | `DATABASE_URL` for `runtime_role` |

Use three independently generated strong passwords. The owner/runtime URL
passwords must match the bootstrap inputs; percent-encode URL special characters.
The bootstrap password must never appear in either application URL. Use host
`${RESOURCE_PREFIX}-postgres.${APP_NAMESPACE}.svc`, database from `site.json` and
`sslmode=verify-full`. The site trust Secret's `ca.crt` must include the database
issuing CA. The server certificate must cover that service DNS name.

## Install before migration

Initialize `APP_NAMESPACE` and `RESOURCE_PREFIX` from the reviewed site file
using [installed naming](installed-profile.md#installed-namespaces-and-resource-names).
From the release root, with the namespace and Secrets already created:

```bash
python3 install/check_fresh_target.py --config /private/site.json \
  --postgres-config /private/postgres.json
python3 install/postgres.py --config /private/site.json \
  --postgres-config /private/postgres.json --output-dir /private/vesta-postgres
oc kustomize /private/vesta-postgres
oc apply --dry-run=server -k /private/vesta-postgres
oc apply -k /private/vesta-postgres
oc -n "$APP_NAMESPACE" wait --for=create \
  "pod/${RESOURCE_PREFIX}-postgres-0" --timeout=10m
oc -n "$APP_NAMESPACE" wait --for=condition=Ready \
  "pod/${RESOURCE_PREFIX}-postgres-0" --timeout=10m
```

Inspect the rendered resources and server-side dry-run before the actual apply.
This creates namespaced application resources only. It does not restart a node,
change HCO, modify a customer VM, or use a privileged SCC. Existing namespace
policies must allow the backend and migration pods to reach port 5432; the
dedicated NetworkPolicy admits those two pod roles only from the same namespace.
NetworkPolicies are additive: review existing broader ingress policies too.

Readiness means PostgreSQL is accepting connections, not that application
credentials/schema are correct. Continue with the fresh migration stage in
the [installation guide](installation.md); that stage must succeed using the
restricted owner connection before deploying the API. Inspect actual runtime
privileges and authenticated health during installation acceptance.

## Interrupted initialization and maintenance

Role/database creation runs **only on an initially empty data directory**.
If initialization fails, stop and collect diagnostics/logs. Never delete the
PVC, wipe PGDATA, rerun the initialization script manually or reset credentials
to make readiness green. A populated volume is not a fresh-install target.
Keep any partial state for diagnosis; repair requires an explicit database plan.

The StatefulSet uses `OnDelete`: changing its template does not silently restart
the database. Certificate renewal, password rotation, image patching and major
version upgrades need a planned database maintenance procedure and current
backup. Changing bootstrap Secret values does **not** change existing database
passwords. The private TLS copy is loaded at pod initialization; it is not an
automatic certificate rotation mechanism. Do not restart nodes or virtualization
services to repair a database or certificate problem.

Use the [operations guide](operations.md) and installation diagnostic collector.
For database logs, collect locally with a bound, review before sharing:

```bash
oc -n "$APP_NAMESPACE" logs "statefulset/${RESOURCE_PREFIX}-postgres" --since=1h --tail=200 --limit-bytes=262144 --timestamps=true
```

For recovery, preserve the database PVC, database backup, configuration key,
backup KEKs and agent journals together. Follow the
[control-plane recovery guide](upgrade-recovery.md). Reinstalling this database
stage is not a recovery plan and does not restore backup keys or catalog state.
