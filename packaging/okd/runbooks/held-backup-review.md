# Review a held backup

A held backup retains its capacity reservation, private agent journal and any
remote effects. A timeout, missing pod or native object, empty object listing,
zero acknowledged bytes or elapsed deadline does not prove those effects have
ended. Preserve the original request and evidence. Do not reset the attempt,
raise capacity to bypass the hold, edit journals or delete a bucket prefix.

Use [admission pause](backup-safety.md) to stop new work while existing work can
continue. Maintenance is a separate continuation fence; enabling it can interrupt
other attempts. Neither control establishes producer closure or releases a hold.
Collect [diagnostics](operations.md) and arrange an independent review before
changing custody. Keep credentials and full private journals in the site's
protected evidence store.

## Establish the disposition

1. Identify the exact backup, organization, source VM, capacity reservation,
   registered agent, original transaction, native producer and publications.
   Preserve the original journal and its SHA-256 before any disposition.
2. Fence the producer through the site's reviewed procedure. For KubeVirt,
   establish the final backup, export, checkpoint and controller state. For
   libvirt, establish the original domain's job and closed inventory. A missing
   API resource alone cannot establish either result. Preserve other jobs and
   checkpoints.
3. Reconcile every exact object version and multipart upload, including unknown
   create outcomes and outstanding signed upload authority. Check known upload
   IDs directly; an empty listing is insufficient. Establish that no accepted
   lineage or consumer depends on the attempt. An aborted checkpoint may require
   an independently reviewed tracker invalidation and a new full baseline.
4. Record `uncertain` or `occupied` if any prerequisite remains unresolved. A
   `released` decision additionally requires independent producer-quiescence,
   chain-custody, object-custody and original-journal evidence. A review artifact
   must contain the observations behind each digest; a digest is not itself proof.

The agent can seal a positively stopped, pristine queued
KubeVirt transaction as locally `held`, including on recovery. Native preparation,
uncertain effects and payload or publication progress exclude this transition.
Preserve the earlier evidence and bind any later review to the actual sealed
journal's hash. `no_native_started` alone still does not establish the independent
producer, object and lineage evidence required above, or authorize release.

## Owner review and journal retirement

The installed backend provides `python3 -m core.modern_capacity_review`. Run it
in a separately reviewed owner Job using the accepted backend image, a read-only
mounted plan, the site's migration-owner `DATABASE_URL` and verified PostgreSQL
TLS configuration. The normal backend uses the restricted runtime role and
cannot perform this review. Use the [schema-operation procedure](upgrade-recovery.md)
for owner credentials and writer fencing; never put credentials in the plan.

The plan has exactly `schema: 1` and `reviews` with 1–100 entries. Each entry has
`schema: 1`, a fresh UUID `operation_id`, exact `backup_id`, `org_id`, `vm_id` and
UUID `capacity_id`, `classification`, `evidence_sha256`, `approved_by` and `ticket`.
For `released`, also supply `producer_quiescence_sha256`, `chain_custody_sha256`,
`object_custody_sha256`, `journal_sha256` and the sorted, unique, nonempty
`publication_ids`. Digests are lowercase 64-character SHA-256 values.

First run `--plan /review/plan.json --database <actual-database>` without `--apply`.
This checks plan shape and current row identity in a read-only transaction; it
does not validate external evidence or prove that a later release will succeed.
After independent approval, `--apply` commits the complete plan atomically.
A release requires maintenance mode, an exact eligible unpublished payload set,
and no accepted lineage or active queue custody. Independently establish terminal
remote effects before applying the review. The database rechecks its authority
and custody predicates under locks, then marks eligible publications deleted and
the backup failed; do not edit those rows beforehand to manufacture eligibility.
If a reply is lost, inspect the recorded original operation before further action.

Only after the database has recorded the exact release may the site's authorized
operator call the original agent's `POST /api/backups/{backup_id}/retire` over
verified HTTPS with its configured orchestrator credential and only
`{"reservation_id":"<original-reservation-id>"}`. The agent obtains release proof
from the backend; caller-supplied evidence cannot replace it. An unsuccessful or
uncertain call retains custody and requires reconciliation.

Successful retirement appends a tombstone; it preserves the original journal and
does not delete VM disks, captured files or checkpoints. Verify retirement and
restart behavior before restoring normal admission. A scheduled attempt retains
its original permanent claim. Establish new accepted ancestry with a new full
backup, then validate a [fresh restore](restore.md). Disposal of retained files
remains a separate reviewed action.
