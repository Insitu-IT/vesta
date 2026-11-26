# Use Vesta and recover safely

Use the UI to inspect backups, restores, schedules, agent health and verification
results. A queued/admitted request is not a completed backup; a completed upload
is not proof of fresh-VM recoverability. Keep operation IDs and UTC times when
reporting a failure.

Before enabling new protected workloads, review [backup safety and operation
budgets](backup-safety.md): actual scratch reserve, service probes, size-based
timeouts, progress diagnostics and retained attempts after exhaustion.

## Everyday workflow

After completing [first configuration](first-configuration.md), use these paths:

| Task | UI path and what to confirm |
|---|---|
| Check protection | Dashboard and Agents: recent observations/heartbeat, intended namespace scope, capacity and failed/refused work. A Ready pod or green chart alone is insufficient. |
| Find a VM | Virtual Machines: search/filter, confirm source identity, observed RAM/disks/CBT and eligibility warnings. Several namespaces still belong to the same installed organization. |
| Run a backup | Use the chosen VM's Backup action, review full/incremental policy and disks, then follow the actual operation to its result. Queued/admitted is not completed. |
| Schedule protection | Schedules: choose the intended VM/group, cron/timezone, policy and retention. An organization admin explicitly enrolls the scheduler grant. Review the first automatic result. |
| Verify stored bytes | Verification: select the exact accepted point/chain and read the recorded result. A pass is an artifact check, not guest/application recovery. |
| Recover a VM | Use a backup's Restore action and the [fresh restore guide](restore.md). Select fresh identity, destination and storage; review network mapping before boot. |
| Investigate a problem | System Health diagnostics and the original operation IDs; preserve keys, journal and storage custody before recovery. |

VM table values are observations. Unknown/unreported RAM or capacity does not
mean zero; optical disks are excluded from data-disk summaries. CBT labels show
reported VM/VMI state, not an assumption based on the storage class. Read the
eligibility warning and contextual help before enabling protection; do not relabel
or restart an important VM merely to make a displayed state change.

Use help icons with hover, keyboard focus or touch; Enter/click keeps an
explanation open and Escape closes it. Switch English/Hebrew through Profile,
and use the icon beside Profile for light/dark. The login screen has the same
controls. Theme preference is browser-local and scoped to the UI address.
See [Read the console](appearance.md) to find agent and VM status.

If realtime connectivity is interrupted, Vesta can fall back to periodic
authenticated HTTP polling. Confirm observations stay fresh and collect
diagnostics if reconnection or polling fails. A working polling fallback does
not establish that WebSocket transport is healthy.

## Offline API reference and registration

Visit `/docs` or `/redoc` on the configured API host to browse operations, or download `/openapi.json`.
Documentation scripts, styles, fonts and branding are local; no CDN, online
validator or telemetry service is required. Interactive API calls are real and
must be authorized for the intended action.

Open **Settings → Licensing** for the installation's local usage and license status. Follow the [offline licensing guide](licensing.md) to register, renew, or import the signed file through the console. Backup, restore, scheduling and login continue if a registration reminder appears. Normal permissions, capacity and source checks still apply.

## Diagnostics and logs

An organization admin can download the read-only diagnostic JSON in **System
Health**. It contains sampled scalar agent/operation state, IDs and timestamps;
at most 50 rows per section, with explicit truncation. It excludes names,
endpoints, configuration, raw errors/logs and key material. Review customer
identifiers before sharing. `partial` or an `unavailable` section means missing
information, not a healthy result.

The authenticated endpoint is `GET /api/v1/health/diagnostics`. Optional
`backup_id=BACKUP_UUID` focuses its operation sections. The endpoint cannot select
another organization and does not probe S3, repair holds, run a backup or restart
anything. It needs a working authenticated API/database session.

For an unavailable API or deeper investigation, use ordinary `oc` access. Replace
namespaces/pod names with those from the installation:

```bash
python3 install/diagnostics.py --config /private/site.json --output /private/install-diagnostics.json
```

The kit collector is read-only, limits each query to 25 seconds/2 MiB and each
section to 50 rows, with a 120-second overall query budget. It records labelled
workload/PVC state, never environment,
Secrets, raw events/messages or logs. Exit 2 indicates partial/unavailable or
truncated evidence, not a health pass. Inspect identifiers before sharing;
there is no automatic upload. A successful collection is not backup acceptance.

First initialize `APP_NAMESPACE`, `AGENT_NAMESPACE` and `RESOURCE_PREFIX` from
the accepted site file using [installed naming](installed-profile.md#installed-namespaces-and-resource-names).
For bounded logs, collected separately and reviewed locally:

```bash
oc -n "$APP_NAMESPACE" get pods
oc -n "$APP_NAMESPACE" logs "deployment/${RESOURCE_PREFIX}-backend" --since=1h --tail=200 --limit-bytes=262144 --timestamps=true
oc -n "$AGENT_NAMESPACE" logs "deployment/${RESOURCE_PREFIX}-agent" --since=1h --tail=200 --limit-bytes=262144 --timestamps=true
oc -n "$APP_NAMESPACE" logs BACKEND_POD --previous --tail=200 --limit-bytes=262144 --timestamps=true
```

On a native agent host, its administrator can run:

```bash
journalctl -u vesta-agent --since '1 hour ago' -n 200 --no-pager -o short-iso
```

Correlate operation UUIDs and collection time. Diagnostic collection logs its
report UUID under `diagnostic_collected` or `diagnostic_section_unavailable`.
Denied access, missing previous-container logs or missing events are unavailable
sources, not proof that nothing happened. Existing cluster logging/journald owns
aggregation and retention; no vendor monitoring service is required.

Raw logs can contain customer data. Inspect/sanitize them locally before sharing.
Do not collect raw Secrets, environment, database dumps, VM XML, private keys or
disk payloads as diagnostics. Do not automatically upload reports to a vendor.

## Failed or interrupted operations

1. Pause new admissions if necessary; do not kill a VM or virtualization service.
2. Record the original operation/attempt ID, state and last observation. Preserve
   agent journals, scratch, source disks/checkpoints, keys and storage objects.
3. Use the product's same-attempt resume/recovery action after correcting the
   named prerequisite. Do not create a replacement attempt to bypass a hold.
4. If ownership or writer termination is uncertain, keep the operation held and
   escalate with its diagnostic report and bounded logs. A missing journal,
   empty job query or expired retention is not independent cleanup authority.

Never abort an unidentified libvirt job, sweep checkpoint trees, delete guessed
S3 prefixes, manually mark success or clear database capacity holds. Independent
VM-changing clients are supported; their work is not Vesta's cleanup target.
If non-disruptive recovery cannot establish writer termination, an operator may
need to consider shutdown of the affected VM as a last resort. That is a separate,
explicitly approved action after review, never an automatic backup remedy.

## Verification and cancellation

Manual artifact verification reads the exact accepted chain. `passed` means the
recorded artifact checks passed, not that a guest booted or an application is
consistent. A failed or interrupted reader is not relabelled passed. Resume keeps
the original request/worker custody and bounded read budget. Cancellation may
remain pending until the original worker is confirmed stopped; it does not grant
authority for a new read or deletion. Preserve metadata when the outcome is unknown.

## Schedules and retention

Review failed/refused automatic runs, grant state and agent health. After changing
an execution-affecting schedule setting, have an organization admin explicitly
enroll its new grant. Disabling a schedule and revoking a grant concern future
authority, not termination of existing work.

Retention protects chain dependencies and requires exact object/version custody.
An old failed row, missing object or retention expiry alone never authorizes
deletion. Keep keys needed by retained points. Investigate held cleanup instead
of widening S3 permissions or deleting a bucket/prefix outside the product.

## Configuration and certificates

Changing a Secret does not prove a running container loaded it. The shipped
input-revision helper checks only metadata without printing Secret values:

```bash
python3 install/reconcile_inputs.py check --namespace "$APP_NAMESPACE" --deployment "${RESOURCE_PREFIX}-backend"
```

If drift is reported, fence new work, review active/uncertain operations and plan
the affected application rollout. The helper's explicit `reconcile --quiesced`
action can replace application pods; do not use it as a passive diagnostic. Do
not restart nodes, PostgreSQL, libvirt or unrelated services as a certificate fix.

## Upload throughput and progress

For KubeVirt transfers with fast source/S3 bursts but long gaps between parts,
compare the agent metrics over the same active transfer interval:
`vesta_agent_kube_api_throttle_seconds` measures client-side limiter wait,
`vesta_agent_kube_api_request_seconds` measures HTTP time to response headers,
and `vesta_agent_storage_step_seconds` separates export validation, source reads,
journal persistence, backend part authorization/acknowledgement and S3 PUTs.
Use changes in histogram `_sum` and `_count`. Export validation includes limiter
and API time; do not add those nested timings together.

The default agent settings are `KUBE_API_QPS=50` and `KUBE_API_BURST=100`, shared across Kubernetes clients, and `KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS=0` for the optional runner deadline. Each new attempt also has an immutable native lifetime. Check the configured ceiling and the [exporter’s actual window](native-backup-lifetime.md) before a long transfer.
QPS must be an integer 1–200; burst must be between QPS and 400. An explicit
total deadline must not exceed the configured native TTL. Individual network operations remain
bounded. These are installation-owned environment settings, changed through
the normal deployment workflow, not through UI/heartbeat configuration.
They cannot change an already running old process.

Uploaded/total bytes count durably acknowledged payload bytes, including encryption framing. Manifests and zero-filled ranges are excluded. The percentage stays below 100% until publication commits. Preserve the original journal if a transfer stops.

Use the [transfer profile and API budget guide](kubevirt-transfer-performance.md) for new-attempt sizing, supported installation tuning, matched performance
measurements and recovery-reader compatibility.
