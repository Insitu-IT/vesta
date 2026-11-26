# Recover during an incident

Start with the last point you know you can read, your recovery keys and a clean destination. Decide whether you need a VM online, raw disks for investigation, or a single file. Keep the source VM and retained backup chain available while you verify the result. [Choose a restore path](backup-and-recovery.md#choose-the-recovery-you-need)

| What you see | First action | What establishes recovery |
| --- | --- | --- |
| An agent stops responding during a backup | Check its heartbeat, original agent identity, durable journal and free space. Pause new dispatch if necessary. Restore connectivity to the same agent and journal. Leave the original checkpoint, scratch reservation and attempt in place during review. | Check the final result on the original attempt. If it is held, use the recorded reason and the held-backup guide. A previous completed point is available for a separate restore. |
| The API, console or database is down | Recover the control plane with its matching database, installation secret and agent identities. For an urgent disk recovery, use the trusted chain bundle and keys you saved off the cluster. | Run the standalone reader against the selected object versions into a new destination. To recover service, validate the disks and boot the isolated guest. |
| An object is missing, corrupt or the wrong version | Preserve the failure and object-version information. Check versioning, retention and your independently protected copy. Select a complete earlier point if the damaged member belongs to a later chain. | Verify the entire selected chain and the reconstructed disks. A new incremental cannot repair a missing parent. |
| The S3 target or its credentials may be compromised | Follow the storage incident procedure. Isolate affected write credentials, preserve versions and access logs, and select an independent copy and trusted recovery keys. Use a separate read-only recovery identity. | Restore to a clean destination from a point that predates the incident. Check the application and your incident criteria before reconnecting production. |
| A database VM boots but its application is unhealthy | Keep the restored VM isolated. Check the database’s recovery logs, application backup or transaction logs, disk coverage and the last confirmed transaction. | Validate the required transaction or business operation. A disk checksum and a successful OS boot are earlier steps. |

## Prepare the bucket for loss or ransomware

Enable versioning on the backup bucket. Arrange independent credentials and protection for retained versions. If your target supports **S3 Object Lock**, configure retention and any replication with your storage administrator, and test both restore and expiry in a disposable prefix or bucket. Align the Vesta retention window with bucket retention. Vesta marks a point as deleting before it removes individual versions. If Object Lock denies a deletion, the point can stay partially deleted and unavailable for a restore from the console. Inspect the cleanup error and retain the independent copy. The bucket administrator controls WORM policy, bypass privileges and replica isolation. Versioning alone still allows a sufficiently privileged identity to remove versions. [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)

Save a catalog bundle for the point you may need during a control-plane outage. Update the recovery copy when you add a new point or rotate keys. Store the bundle, keys and recovery credentials so that the same incident cannot destroy all of them. [Offline recovery inputs](../okd/runbooks/restore.md#native-raw-disk-recovery)

### Recover from a replica or offline copy

The standalone reader checks the original endpoint, bucket, region and recorded object identities when it reads S3 directly. If your independent copy lives at another endpoint, recover the exact bytes of each required version into a local object tree under `<snapshot-root>/<original-bucket>/<original-object-key>`. Preserve the original chain bundle and full object keys. An object with the same filename from a different point is insufficient.

```sh
vesta-restore -chain chain.json -objects-dir /recovery/objects -keys-dir /recovery/keys -verify-only
vesta-restore -chain chain.json -objects-dir /recovery/objects -keys-dir /recovery/keys -output /recovery/fresh-disks
```

The output directory must be new. Keep keys and recovery copies private, then validate the reconstructed disks before boot. [Offline recovery inputs](../okd/runbooks/restore.md#native-raw-disk-recovery)

## Make missed protection visible

Set the schedule’s cron expression, timezone and retention to match your recovery objective. In the current release, retention defaults to 30 days. An automatic schedule can use both a full interval and a maximum number of incrementals. An active descendant can keep its ancestor longer than the nominal retention period. Teach your monitoring to alert on the age of the last accepted point, agent heartbeat, low journal or scratch capacity, missed schedules and failed chain verification.

Use **Verification** to read and validate an accepted chain. Schedule a separate drill that boots an isolated guest and tests a known file and application transaction. Keep the measured recovery time and the last successful drill alongside your service objective. [Daily operations](../okd/runbooks/operations.md) · [Held backups](../okd/runbooks/held-backup-review.md) · [Measure RPO and RTO](sizing-and-recovery-time.md)
