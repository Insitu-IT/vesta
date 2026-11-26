# Upgrade and rollback

Use the upgrade runbook shipped in your **target kit**. Match your installed release, current database schema, operating profile and retained backup formats to one of its transitions. Keep the current site available while you confirm the path for an older or unlisted installation. [Find the target release](https://github.com/Insitu-IT/vesta/releases)

## Check the versions you run

| Component | Where to check | What to keep aligned |
| --- | --- | --- |
| Vesta API | `GET /api/v1/version` on the API origin or `vesta-cli doctor` | Use the API and console images from the same kit. Record the image digests and verify the database schema matches the upgrade runbook. |
| Web console | **Settings → Compatibility** and the console Deployment’s image digest | A different major is reported as incompatible. A different minor is reported as degraded. |
| KubeVirt or native agent | Agents in the console, the deployed container digest, or the installed native RPM version | A different major blocks mutating requests to the agent. A different minor is reported as degraded. The actual operation can also require specific capabilities and backup formats. |
| PostgreSQL | Ask the database administrator for the server version and the actual Vesta schema revision | The customer PostgreSQL profile requires PostgreSQL 17.x. Apply Vesta schema changes using the procedure for the target release and leave database-server upgrades to your database maintenance process. |
| KubeVirt or native platform | Cluster preflight and your virtualization inventory, or the native host’s libvirt and running QEMU versions | Use the required served APIs, storage behavior and supported host versions for your target release. Test a backup and fresh restore after changing the platform. |
| Operator CLI | `vesta-cli version`, `vesta-cli doctor --offline` and `vesta-cli doctor --deadline 30s` | The CLI has its own version series. Its live report shows the site’s version, capabilities and observed credentials. |
| Standalone restore | Release archive and its signed checksum inventory | Keep a tested reader for every retained chain and plan format. Keep a copy accessible if the control plane is unavailable. |

Vesta versions use `MAJOR.MINOR.PATCH`. A major change can break an interface, a minor adds compatible functionality, and a patch carries corrections. Coordinate a major change across the API, console and agents. Keep the same minor to retain full alignment. On coordinated release branches, the API, console and agent ship at the same patch as well. Development branches can carry independent component patches where allowed by their release policy. For a minor or major development change, validate compatibility and then synchronize the other components. The native RPM and the agent container use the Vesta agent version. The operator CLI is released independently.

### What a running agent accepts

The API reads the selected agent’s current version before sending a mutating request. The live version must be a complete numeric major, minor and patch.

| Running agent compared with the API | Version check |
| --- | --- |
| Same major and minor, including a different patch | Aligned |
| Same major with a different minor | Compatible with a degraded status |
| Different major | Incompatible. The API withholds the mutating request. |
| Missing, malformed or unavailable version | The API withholds the mutating request until it can verify the agent. |

Read-only agent requests can still be used for diagnostics under the applicable permissions. A compatible version passes the version check. The operation still depends on the running agent’s advertised capabilities, the schema and the chain or plan format. Always use the target release’s transition instructions.

## Prepare the update

1. Keep the previous kit, accepted manifest and rendered targets, image digests, database backup, application and backup keys, TLS credentials, and agent journals together in private recovery custody. Include passwords and trust material in your site’s recovery process.
2. In the console, pause new backup admission, schedules and automatic cleanup. Wait for known producers to settle. Preserve held operations and their journals.
3. Rehearse any schema change with an isolated recovery copy. Use the schema-owner login for the designated migration. Run the API with the restricted runtime login.
4. Verify a reader can open the retained chain formats and interpret held plans and journals. For example, a reader that predates the KubeVirt 32 MiB transfer profile cannot open plans that use it. Changing the active profile affects future plans.

## A same-schema update

Use this path when the target kit lists the installed database schema as compatible. Keep the accepted `vesta.json`, resource names, database, Secrets, volumes, keys and agent identity.

From the verified target kit:

```sh
./vesta verify
./vesta plan
./vesta import-images
./vesta prepare-upgrade --output-dir /private/vesta/update
```

Skip import when your registry already contains the exact planned digests. Review the rendered API and, where used, agent targets in the correct cluster context. Use your established deployment or GitOps path. Roll out the API and console first and wait for readiness. Then roll out the KubeVirt agent or update native hosts with the matching `vesta-agent` RPM. Keep existing database and migration jobs as they are for this transition.

Check `./vesta status`, sign in and confirm the expected catalog, keys and authenticated agent heartbeat. Recover a disposable workload before reopening admission, schedules and cleanup.

## Recover from a failed rollout

Keep new work paused and retain the failed operation, logs and journals. For a documented same-schema rollback, wait for producers to settle and confirm preserved custody and reader compatibility. Reapply the previous accepted agent and application targets and verify readiness and catalog access before restoring the original schedule.

If the schema or retained format changed, follow the target kit’s coordinated recovery procedure. Restore the consistent database, configuration, keys and journals into isolated targets with the matching previous images and runtime grants. Verify catalog and key access there before switching production. Preserve unresolved producer state until you establish its ownership and termination. Use the fresh-install command only for an empty site.
