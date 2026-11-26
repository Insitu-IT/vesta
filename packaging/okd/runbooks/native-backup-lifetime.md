# Set a time window for a KubeVirt backup

Vesta records a time limit when a backup starts. It estimates the window from disk capacity, expected throughput and your settings for preparation, progress and closure. Choose a ceiling your exporter certificates can cover. The existing attempt keeps its original deadline, including after a restart. See [backup safety](backup-safety.md) to size scratch storage and monitor the guest.

## Configure a supported window before creating an attempt

The accepted `site.json` supports these installation settings. The kit renders
them into the agent Deployment; the backend/UI cannot change them by heartbeat.

| Site setting | Agent environment | Default | Bounds |
| --- | --- | ---: | --- |
| `kubevirt_native_backup_ttl_seconds` | `KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS` | 36000 (10 hours) | 3600–2592000 (1 hour–30 days) |
| `kubevirt_transaction_timeout_seconds` | `KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS` | 0 | 0–native TTL; 0 disables only the additional runner deadline |

For example, the default site fragment is:

```json
{
  "kubevirt_native_backup_ttl_seconds": 36000,
  "kubevirt_transaction_timeout_seconds": 0
}
```

Change these settings through a quiesced agent deployment using the accepted site
and the current kit's `render.py --stage agent`, retaining the original namespace,
identity, credentials, journal and scratch. Review the rendered environment and
follow the [application upgrade procedure](upgrade-recovery.md). The narrower
`reconfigure.py` hostname/scope transaction rejects lifetime-setting changes.
Changing configuration affects new attempts; it cannot extend an existing one.

KubeVirt counts the native backup lifetime from the backup object's creation time. The export receives the remaining duration. Certificate rotation gives the exporter process a second deadline. The shorter deadline limits your transfer. Inspect the settings on the cluster that will run the backup.

Before creating the first attempt, inspect the **actual KubeVirt CR**, including
the exact JSON field `certificateRotateStrategy`:

```bash
oc get kubevirt -A
oc -n KUBEVIRT_NAMESPACE get kubevirt KUBEVIRT_NAME \
  -o jsonpath='{.spec.certificateRotateStrategy.selfSigned.server}{"\n"}'
```

Replace the two placeholders with that installation's resource identity. Subtract
`renewBefore` from `duration` and keep the selected native TTL below the resulting
window with startup headroom. An absent field is not proof of a default: check the
installed operator/version policy. The live exporter deadline remains authoritative.
Do not use the nonexistent JSON field `certificateRotationStrategy` or infer the
effective settings from an empty HCO field.

For a longer window, first have the cluster owner review its KubeVirt/HCO
certificate rotation policy. Raising Vesta's TTL alone cannot extend the original
exporter process. Vesta validates the export TTL and actual pod `DEADLINE` before
reading source data, resolving the encryption key or starting multipart uploads.
An exporter that cannot cover the configured window is retained for review before
payload production. Vesta never adjusts cluster certificate policy automatically
or adopts a replacement exporter pod. The native objects may already exist at
this refusal point; preserve their custody for the ordinary recovery procedure.

## Exact deadline and recovery behavior

The journal records the TTL and optional transaction timeout before native
creation, then binds the original VMB creation timestamp with its successful
create response. The optional transaction timeout starts at native preparation;
the runner may cancel earlier if its process budget was already consumed.
Source/S3 streaming stops at the earliest of the original VMB expiry, pinned
transaction deadline, export expiry and exporter process deadline. Individual
network-operation deadlines and shutdown cancellation continue to apply.

Every read/upload boundary and original-object finalization retains owner, UID,
source/checkpoint and expiry checks. Restart or a changed configuration cannot
renew these timestamps. Durable terminal success observed before expiry can still
finish its original publication after the controller removes the native object;
absence or expiry alone is never completion evidence.

Existing journals without the lifetime extension keep their original two-hour
policy and checksum. Held attempts remain held. Do not patch a live VMB's immutable
spec, edit a journal, release old capacity, clear a tracker or repeat multipart
production as part of this upgrade. Use [interrupted-attempt handling](operations.md).
Keep an agent image that can read each retained journal format, especially when rolling back. Use the [matching kit’s upgrade procedure](upgrade-recovery.md) before changing readers.

## Test a long backup on your storage

Use an approved disposable VM on the same storage class and volume mode as the workload you plan to protect.

1. Record the kit checksum, all image digests, KubeVirt/HCO version, storage class
   and Block volume mode, selected TTL and certificate rotation policy. Preserve
   recovery material and ensure earlier attempts have been reviewed separately.
2. Choose a representative dense payload and measured storage path so the same
   transfer remains active across two hours. Estimate duration from acknowledged
   payload bytes and measured pace, leaving time for preparation and publication
   inside all deadlines. Disk capacity is not the transferred size for sparse data.
3. Record the new backup/reservation IDs, original VMB/export/pod UIDs, VMB
   creation/TTL, export remaining TTL and exporter `DEADLINE`. Keep observations
   read-only; do not change clocks, native TTLs, journals or source trackers.
4. Observe increasing durably acknowledged bytes in the API/UI before and after
   two hours. Take aggregate metrics snapshots over the same interval. Separate
   Kubernetes throttle/API, validation, source, journal, backend and S3 timing;
   nested/concurrent histogram sums are not elapsed wall time.
5. Require normal receipt acceptance, original-object terminal evidence,
   checkpoint proof and committed publication. A ready exporter, 100% uploaded
   bytes or S3 objects alone are insufficient. Restore to a fresh authorized
   destination and compare known guest-data hashes.
6. Retain the measured duration, effective deadlines, progress and publication/
   restore results. If interrupted, retain the original attempt's custody and
   report the failing boundary; do not repeat it to manufacture a passing record.
