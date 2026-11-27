# Manage a Vesta site from one manifest

Run the bundled `vesta` command from the extracted kit. On another working directory, call the launcher by its absolute path. Commands that use a site manifest look for `vesta.json` in the working directory or accept `--manifest /private/site.json` after the command. The kit runs on an operator workstation with Python 3.11 or later and an authenticated OpenShift `oc` session. KubeVirt discovery also uses Bash and `jq`.

## Prepare and install

Authenticate the archive against the release evidence from the trusted distribution channel before extracting or executing it. `verify` checks the extracted payload against the bundled inventory.

```bash
./vesta verify
./vesta init
# Edit vesta.json, then provision the site inputs it references.
./vesta plan
./vesta check
./vesta import-images
./vesta install
```

Use `import-images` with `skopeo` and the workstation's approved registry credentials when the registry needs the images from the archive. If the exact digest-pinned images are already mirrored at the repository names shown by `plan`, skip the import. Arrange cluster pull authorization and registry trust separately. The tool uses `${registry}/backend`, `${registry}/frontend` and `${registry}/agent` plus `${registry}/postgres` for the full kit.

The site supplies namespaces, DNS, certificates, trust, storage, and Kubernetes Secrets. Use the [Secret inventory](../secrets.example.yaml) and the [installation requirements](installation.md). The full kit starter includes dedicated PostgreSQL. Remove the `postgres` object only when supplying a separately managed database. The `customer-postgresql` kit always uses a [customer-managed database](customer-postgresql.md).

`check` looks for collisions, required Secret keys, storage classes and authorization to create the planned objects through server-side dry-runs. With `agent: "kubevirt"`, both `check` and `install` run the [site preflight](../preflight/README.md) once before any application resources are created. They require a passing result for HCO configuration, the rendered CBT selectors and the exact served backup, tracker and export APIs. The operator context needs read access to HCO, KubeVirt and the relevant CRDs. Use `--preflight-output /private/vesta/preflight` on either command to retain the scope and runtime CBT evidence. Failed reports are retained by default at the printed path. Use the `preflight` command to collect another report independently. Review the individual VMI evidence and validate scratch placement against the actual pilot workload. The registration Secret can be created after installation.

`install` repeats the checks and creates the dedicated database stage if declared, waits for fresh schema migration, then creates the backend and UI. It waits for readiness and probes DNS and trusted HTTPS on the configured routes. The command targets an empty site. On an interrupted installation, preserve the database, Secrets and all resources and follow [upgrade and recovery](upgrade-recovery.md). If you rerun `install` against populated or partially created resources, it refuses the collision.

## Check one VM

On a KubeVirt site, run a read-only check against one VM in a source namespace
listed in the site manifest. Use the same command before or after installation.

```sh
./vesta preflight --vm protected-vms/example
./vesta preflight --vm protected-vms/example --output-dir /private/vesta/example-check
```

The check reports observed backup APIs, platform gates, selector match, and CBT
state on a running instance owned by the VM. Use a new private output directory
to retain the report. When the output directory is omitted, the launcher uses a
temporary report. The `vesta-readiness.json` summary contains fixed finding
codes without VM identifiers. Keep the detailed projections private. Exit
status 0 means the observed prerequisites passed. Exit status 2 means action
is required or evidence is unavailable. Optional group-snapshot checks do not
affect the exit status. When a plain VM selector can be satisfied by adding
labels, the check can show a server-side dry-run preview. Review any change
with the platform administrator.

A readiness result covers the observed prerequisites. This check leaves
checkpoint history, snapshot creation and workload recovery to their respective
workflows. Review any VM restart with the platform administrator. If several disks have verified bindings to the same CSI driver and
the cluster serves matching group-snapshot APIs and a class, the check reports
a group-snapshot candidate for a separate pilot. [Check changed-block tracking](https://vestabackup.com/docs/storage-compatibility/#check-changed-block-tracking) · [Review multiple disks and group snapshots](https://vestabackup.com/docs/storage-compatibility/#multiple-disks-and-group-snapshots)

## Configure and enroll

After signing in, prepare the versioned S3 bucket and OIDC client if the site will use them. Add the corresponding top-level objects to the same manifest. Values below illustrate field names. Secrets are created out of band in the application namespace.

```json
{
  "s3": {
    "endpoint": "https://objects.example.org",
    "bucket": "vesta-protection",
    "region": "us-east-1",
    "prefix": "site-a/backup-data",
    "secret": "vesta-s3"
  },
  "oidc": {
    "issuer": "https://identity.example.org/realms/vesta",
    "client_id": "vesta-site-a",
    "scopes": "openid profile email groups",
    "role_claim": "groups",
    "admin_values": "vesta-admins",
    "operator_values": "vesta-operators",
    "secret": "vesta-oidc"
  }
}
```

- `s3.secret` refers to the backup writer’s `access_key` and `secret_key`. Use an HTTPS endpoint, or `""` for AWS S3. The API's connection test checks access to the bucket. Review [S3 requirements](first-configuration.md#2-configure-s3) for versioning, scoped permissions and acceptance. An existing configured S3 location must match the manifest. Plan storage migration separately if the endpoint, bucket, region or prefix needs to change.
- Set `s3.recovery_secret` to the separate recovery reader's Secret reference. The Secret uses the same key names, `access_key` and `secret_key`. A recovery-only site can omit `s3.secret`. The backend also accepts `S3_RECOVERY_ACCESS_KEY` and `S3_RECOVERY_SECRET_KEY` from its environment. Use the configured S3 endpoint, bucket and region for both accounts.
- `oidc` refers to `client_secret`. Scopes default to `openid profile email`. Optional role values are comma-separated. Unmapped users receive viewer permissions. Prepare provider callbacks and allowed origins for the actual site, keep a local recovery account and verify a separate OIDC browser session with the site's MFA and role mappings. See [authentication configuration](first-configuration.md#3-configure-authentication).
- `configure` applies only the declared integrations using an interactive local admin login. `--username` selects a different local admin. It uses existing configured credentials by default. Add `--refresh-credentials` to write the current Secret values for all declared integrations, for example after a planned rotation. An incomplete check or failed connection returns an error and the settings already saved remain in the API for diagnosis.

For a new KubeVirt agent, issue a short-lived enrollment key and complete the agent registration Secret from the site secret manager. The launcher uses the technical ID shown by `plan` when you omit `--hostname`. Alternatively issue the key in the UI. The stable keystore identity and shared agent key are separate required Secret inputs.

```bash
./vesta agent-key --output /private/vesta/registration-key
# Provision the agent registration Secret, then configure the site.
./vesta configure
./vesta status
```

`configure` creates an absent KubeVirt agent stage, waits for readiness, and checks that its identity has a recent authenticated heartbeat. It verifies matching existing objects before checking the heartbeat on repeat runs. Use [reconfiguration](reconfiguration.md) for changes to installed KubeVirt resources or scope. An interrupted agent creation needs diagnosis before retrying.

With `agent: "external"`, omit the KubeVirt deployment and set up each native host separately with its approved agent package. Use `./vesta agent-key --hostname HOST --output /private/vesta/HOST.key` for a fresh per-host registration credential. Use the host's exact configured technical identity. The credential file expires in one hour, has one use, and has mode 0600. Transfer its contents through the site secret manager and retain stable agent identity. Agent keys for existing hosts follow the [key rotation procedure](../../../docs/operations/agent-key-rotation.md).

The [first-configuration guide](first-configuration.md) covers encryption key custody, inventory validation, disposable backup and restore acceptance, and the explicit admission and scheduling decisions after acceptance.

## Manifest fields and maintenance

| Field | Value |
|---|---|
| `schema` | `vesta-site/1` |
| `context` | Exact context of the authenticated operator's `oc` configuration |
| `registry` | Cluster-reachable registry host and repository prefix, without scheme or image tag |
| `agent` | `kubevirt` for an in-cluster agent, or `external` for separately enrolled agents |
| `site` | Fields in [`config.example.json`](../config.example.json) except `images`, which the kit supplies. Keep the same resource prefix, namespaces and agent ID after installation. For external agents, the common renderer still requires syntactically valid KubeVirt site fields. |
| `postgres` | Optional fields in [`postgres.example.json`](../postgres.example.json) except `image`, which the full kit supplies |
| `ca_file` | Optional path to the workstation's PEM CA bundle for HTTPS probes and admin API calls, relative to the manifest or absolute. Omit it to use system trust. |
| `s3`, `oidc` | Optional settings above, with Secret names and no credential values |

Keep the operator manifest and any private inputs outside the artifact inventory. `vesta.json` at the kit root is the sole supported local addition for `./vesta verify`. Keep credentials, reports and generated key files outside the extracted kit.

For an update, download and verify the new kit, retain the accepted site manifest and use the planned image names from that new kit. `./vesta prepare-upgrade --manifest /private/vesta/site.json --output-dir /private/vesta/new-targets` renders the application and, when selected, the KubeVirt agent targets to a new directory for review. Follow [upgrade and recovery](upgrade-recovery.md) for the actual database schema, draining, mounted inputs, rollout, rollback and verification.

### Change the installed configuration

Save the accepted manifest before editing `vesta.json`. Review the compatible fields and prepare external DNS, trust, SSO and storage inputs in the [reconfiguration guide](reconfiguration.md). Keep the same agent identity, registry, database and integration settings during this transaction. Use `configure` separately for S3 credentials and OIDC settings.

```bash
./vesta reconfigure plan --previous /private/vesta/site.accepted.json --state /private/vesta/change-001
./vesta reconfigure apply --state /private/vesta/change-001 --quiesced --custody-confirmed --external-ready
./vesta reconfigure accept --state /private/vesta/change-001 --quiesced --paths-verified
```

Review the saved plan before applying. The plan binds the transaction to the selected OpenShift context and API server and records the existing object and Secret metadata used by the checks. Apply only after fencing dispatch, reviewing active work, preserving the accepted configuration and recovery material, and arranging the external paths. Verify old and new browser, authentication and agent paths before accepting. Retain the accepted `vesta.json` and the private transaction directory. If rollback is required, keep dispatch fenced and run `./vesta reconfigure rollback --state /private/vesta/change-001 --quiesced`. Verify the restored paths and custody before resuming work.
