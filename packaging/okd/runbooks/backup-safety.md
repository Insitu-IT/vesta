# Backup safety and exhausted operation budgets

Set time and scratch budgets before starting new backups. If a backup stops, use its recorded reason to identify what can safely resume. Keep the original VM, journal, encryption keys and object versions until you know which provider operations finished. The [native lifetime](native-backup-lifetime.md), [transfer profile](kubevirt-transfer-performance.md) and [recovery](upgrade-recovery.md) guides cover the related settings.

## Configure estimates before new work

These optional `site.json` fields affect new operations. Render and review the
API and agent stages through the normal configuration workflow. Existing
operations keep their recorded budget, identities and expiry.

```json
{
  "max_concurrent_backups": 1,
  "kube_api_qps": 50,
  "kube_api_burst": 100,
  "kubevirt_native_backup_ttl_seconds": 36000,
  "kubevirt_transaction_timeout_seconds": 0,
  "operation_budget": {
    "time_coefficient": 3,
    "no_progress_coefficient": 3,
    "observation_coefficient": 3,
    "scratch_coefficient": 1.2,
    "bootstrap_bytes_per_second": 8388608,
    "preparation_estimate_seconds": 180,
    "control_estimate_seconds": 60
  },
  "source_health_probes": []
}
```

| Setting | Meaning and accepted range |
| --- | --- |
| `time_coefficient` | Multiply estimated work and preparation/closure allowances; finite 1–100 |
| `no_progress_coefficient` | Multiply the larger of estimated part time and control time; finite 1–100 |
| `observation_coefficient` | Multiply estimated control work for unavailable read-only observations; default 3, finite 1–100 |
| `scratch_coefficient` | Margin on all native persistent-disk capacities and measured growth during closure; finite 1–4 |
| `bootstrap_bytes_per_second` | Explicit planning throughput, 1–2⁴⁰ bytes/s; default 8 MiB/s |
| `preparation_estimate_seconds` | Expected admission/preparation time, 1–86400 seconds |
| `control_estimate_seconds` | Expected control/finalization time, 1–3600 seconds |

The equivalent agent environment variables are `OPERATION_` followed by the
uppercase field name. The renderer also supplies the policy to the API for
verification admission. Invalid values stop admission; they do not select defaults.
`OPERATION_OBSERVATION_COEFFICIENT` maps to
`operation_budget.observation_coefficient`. An omitted observation field in an
older persisted policy remains zero/disabled; zero is not a new installation
setting, and an upgrade cannot grant that attempt fresh grace.

For a new KubeVirt backup:

```
expected = ceil(selected full disk bytes / planning throughput) + preparation + control
run budget = ceil(time coefficient × expected)
closure reserve = ceil(time coefficient × control)
native TTL = max(1 hour, run budget + closure reserve)
```

The required window must fit the configured native ceiling, optional transaction
ceiling and actual exporter/certificate coverage. It is refused if it cannot fit;
the required duration is never silently shortened. A zero transaction ceiling
disables that extra ceiling only. It does not disable the dynamic budget.

With the defaults, 50 GiB estimates 6640 seconds, giving a 5h32m run budget and
3m closure reserve. A 100 GiB source would require more than the default 10h
ceiling and is refused. Review measured end-to-end performance and supported
exporter lifetime before choosing different estimates. The current implementation
records the configured bootstrap rate; it does not automatically learn throughput
or extend a running deadline from a slow sample.

Queue/preparation wait is 9m with the defaults. Useful-progress silence is 3m
for the supported 8/32 MiB parts. New validated map coverage, a durable stage
transition or acknowledged payload bytes counts as progress. Repeated pages,
retries, agent heartbeats and ExportReady do not. After original native terminal
proof, publication gets its own persisted control window. A restart or retry
does not renew any of these windows.

Fresh restores and verification estimate their receipt-bound byte work and keep
an absolute worker deadline. Restore reconstruction currently exposes milestones,
not a reliable byte-progress stream, so it uses the aggregate budget instead of
pretending a whole disk must finish inside a part-silence window. Native push
producers measure selected disks and usable output space before starting; their
existing uncertain-job fences remain in force.

## Scratch is a separate capacity domain

Vesta reserves at least
`scratch_coefficient × sum(all native persistent-disk capacities)` usable bytes,
including for incremental backups. Source schema 2 binds the native set separately
from the selected upload set. For example, selecting one 10 GiB disk from a VM
whose native backup includes two 10 GiB disks requires at least 24 GiB scratch
at coefficient 1.2, while transfer and restore still select only the requested
10 GiB disk. Agents lacking that negotiated contract refuse incompatible partial
selection before native work. Older requests/journals retain their original
contract; upgrades do not reinterpret them.

At 1.2, a 50 GiB native source needs 60 GiB **available**, after filesystem
overhead and existing files. A 4 GiB
scratch claim cannot safely admit it. PVC requested capacity, Bound status,
journal free space, CBT metadata size and Ceph pool capacity are different facts.

The agent creates an exclusive, non-expiring Lease for the scratch PVC UID and a
read-only probe Pod from the installation's pinned agent image. The Pod runs on
the source VMI's node and reports filesystem available bytes every five seconds.
It has no API token and opens no guest disks. Its original UID, image, command,
claim and node are checked before consuming its bounded log record. Admission
requires a sample at most 20 seconds old and rechecks before native creation.

ReadWriteOnce and ReadWriteMany filesystems are supported. ReadWriteOncePod,
block-mode scratch, other mounted/pending claim users, existing native backups
on that claim, unavailable measurements and incompatible placement are refused.
An uncertain Lease or Pod create is retained for review, not adopted or stolen.
A namespace scratch mapping therefore allows one holder of that claim, even if
the installation has more backup slots. Plan separate claims/agents for concurrent
sources; do not increase concurrency to bypass scratch admission.

During active native work, the guard retains the peak observed growth rate and
stops when free bytes reach the larger of the format margin and:

```
peak growth bytes/s × (20s detection allowance + closure reserve) × scratch coefficient
```

Filesystem samples do not establish shared storage-pool health or reserve space
against unrelated applications. Provision and independently monitor the pool,
CBT state and journal. A failed/full/unavailable agent journal can prevent durable
closure intent. Controller/API failure can prevent the native stop itself.

The installed KubeVirt 1.8.4 API does not expose QEMU's `break-snapshot` policy.
Polling and capacity margins do **not** provide an atomic guarantee of guest
availability. Do not inject QMP or set guest write-error policy to ignore.

## Unavailable observations have bounded recovery

A GET timeout means the observation is unavailable. Confirmed guest pause/IOError,
explicit native failure, changed identity and a definitive refused API response
remain immediate stops. The external Mesh observer treated a query timeout as
failure and enabled maintenance during a partial upload. The later 409 is
consistent with the maintenance fence; its unretained response body cannot prove
a narrower predicate. No full/incremental acceptance follows from that upload.
The internal watcher correction is a separately confirmed finding; it does not
establish the cause of that external interruption. Qualify the corrected external
observer independently before another customer canary.

The nominal unavailable-observation window is
`ceil(observation_coefficient × control_estimate_seconds)`; defaults give three
minutes. This is an upper estimate, not guaranteed grace. At the first failure,
the agent needs a previous complete healthy source/native/scratch inspection and
a scratch measurement no more than 20 seconds old at the start of the first
inspection, before its transport call. Elapsed API latency consumes the original
sample/episode deadline and headroom; it does not refresh either. A sample already
stale at inspection start remains ineligible. Remaining bytes must cover
**all native disk capacity with margin**, plus growth through the uncertainty
window, detection and the original closure reserve. The growth estimate uses
the greater of measured peak and configured bootstrap rate, with scratch margin.
Bootstrap throughput is not a qualified guest-write-rate limit. The agent refuses
grace if the baseline is absent or stale, available bytes are insufficient, or
arithmetic overflows.

Original run, native expiry and useful-progress deadlines cap recovery; native
expiry retains closure and detection allowance. The agent persists the original
uncertainty time/deadline and trustworthy measurement. Worker-read retries wait
one second; the health monitor keeps its five-second cadence. Each observation
is bounded to at most 20 seconds and the remaining window. Changing installation
settings, restarting or succeeding at an unrelated health check cannot renew that deadline.

Health checks and worker source/export/token validation have separate persisted
episodes. A healthy watchdog cannot clear a failing worker-read episode. Only a
complete successful check in that scope clears it. A denied grace decision is
`refused`, so an outer transaction retry cannot later acquire a new baseline and
replay the step. Eligible timeout/429/server failures authorize repeated reads
only. NotFound, 401/403, invalid contracts/mappings, identity drift, failed persistence and
confirmed unhealthy states do not authorize retries. A service transport timeout
can qualify; an observed non-2xx health response is a refusal.

At producer closure, the agent atomically rechecks both observation deadlines
and original operation/progress deadlines before creating a publication window.
A terminal response arriving after expiry cannot extend work. An already recorded
closure retains its publication deadline, and durable backend publication ACK
remains completed despite late negative observations.

## Monitor the application independently

Add a credential-free endpoint for each source that needs service-health gating:

```json
{
  "source_health_probes": [
    {
      "namespace": "protected-vms",
      "vm_name": "database",
      "url": "http://database-health.protected-vms.svc/ready"
    }
  ]
}
```

Use a check that establishes the application's useful service/write health and
does not depend on the protected monitoring database. Ensure the agent's network
policy permits it. Endpoints are installation configuration, pinned per attempt;
none is contacted unless configured. HTTP(S) 2xx is healthy. Redirects, query
credentials, URL user information and custom authentication headers are unsupported.
HTTPS uses the agent's system trust. A dedicated five-second transport sends no
backend/S3 credentials and does not use environment proxies.

The active guard checks service health, VMI Ready/Paused/PausedIOError, node,
scratch identity/free space/growth, native health and useful progress independently
of the payload journal lock, S3 cleanup and backend availability. Without a
configured endpoint it checks VM health only; Ready is not application proof.
Neither an operator pause nor an IOError pause authorizes automatic VM resume.

During normal pull finalization, KubeVirt temporarily reports `Aborting=True`
while stopping the job after Vesta's recorded delete intent. Vesta
continues bounded observation only when the original native object, accepted
receipt and finalize intent match. Native terminal and checkpoint proof are
still required before publication. An unexpected abort or explicit native
failure remains a stop; the upgrade does not clear earlier holds or replay them.

## Interpret a stop

The API reports `cleanup_required` with a bounded stage/reason diagnostic. Inspect
`tags.storage_hold.diagnostic` in the backup response for map cursor/counts, HTTP
status, first read/ACK timestamps, acknowledged bytes, useful-progress age,
budgets, scratch sample/growth/time-to-full and native stop phase. The diagnostic also reports health observation time/deadline/reason, last trustworthy observation
time, independent read-observation time/deadline/reason, and bounded
`expected_native_volumes`, `observed_native_volumes`, `observed_export_links`
counts. Health keys are `observation_uncertain_since`, `observation_deadline`,
`observation_reason` and `last_trustworthy_observation_at`; read keys are
`read_observation_uncertain_since`, `read_observation_deadline` and
`read_observation_reason`. API/UI diagnostics use allowlisted predicates, timestamps and counts;
never collect credentials, token values, arbitrary remote error bodies, URLs or
guest content to fill these fields. They authorize no deletion, publication or
capacity release.

| Reason/state | Response |
| --- | --- |
| `estimated_window_exceeds_native_limit`, `admission_wait_exhausted` | No new producer admitted; review capacity/estimate and the retained original attempt |
| `scratch_reserve_insufficient`, `scratch_in_use` | Correct actual capacity or resolve the existing holder through supported review; never steal a Lease |
| `map_stored_range_limit`, malformed/unsupported map | Native safety close; retain the validated cursor and original journal for diagnosis |
| `scratch_exhaustion_risk`, source pause, failed service probe | Stop payload work and request closure of only the original observed VMB |
| `native_delete_outcome_uncertain`, `native_close_budget_exhausted` | Inspect the original UID/controller and guest health; no replay of an uncertain DELETE or guest resume |
| `native_absent_unproven` | Absence is not terminal/checkpoint/publication proof; retain scratch, tracker and catalog custody |
| `observation_budget_exhausted`, or original read predicate with stage `observation` | Original bounded recovery ended or grace was refused; retain custody and inspect the original attempt; no new step/producer retry |
| `publication_budget_exhausted` | Keep verified output and proof for original-attempt review; never rerun the producer |
| Verification admission/worker budget exhausted | Observe retained results; no new reads. Cancel/review the original operation before explicitly requesting a new verification |

Native emergency closure uses original UID/resourceVersion preconditions and a
separate durable intent. A definite resourceVersion conflict permits rereading
the same UID and retrying within the original closure deadline; a lost reply does
not. Restarting never renews the closure window. It never deletes S3 versions, accepted trackers, source
PVCs, journal records or database reservations. Denied S3 deletion does not gate
this path. Normal successful publication can release only its own probe/Lease.
Failed native attempts retain their scratch reservation until supported custody
review establishes closure; deleting it manually is not a recovery procedure.

Old unfinished journals without a safety budget are retained rather than granted
a new window during upgrade. Completed backup catalog entries remain usable. Recovery recognizes durable
backend publication acknowledgements, including completed older journals without
a safety record; shutdown cannot turn a confirmed publication into a hold. If
the separate safety record fails after the publication ACK, the backup remains
completed and the agent logs that its scratch reservation needs review. Retained
scratch is a cleanup concern, not evidence that an accepted backup failed.
Read-only backend polling may continue to recover a delayed observation; it never
renews worker budgets or authorizes replay. Age alone no longer marks backup or
restore output failed or clean.

## Pause new work or enter maintenance deliberately

Settings exposes separate controls for these actions:

| Control | Policy | Effect |
| --- | --- | --- |
| Pause new backups | `backup.admission_pause`: `schema`, `revision`, `paused` | Prevent new capacity reservations, including scheduled work; existing reservations may drain under original authority |
| Capacity maintenance | Existing `backup.capacity_admission`: `schema`, `revision`, `limit`, `maintenance` | Fence new work and existing continuations; an active upload can be interrupted |

The admission-pause policy uses schema 1 and a positive revision, for example
`{"schema":1,"revision":2,"paused":true}`. Use the authenticated Settings API/UI
and the next revision of the policy actually read; this example is not a revision
to copy over current state. PostgreSQL serializes policy updates with reservation
admission. A changed or unknown write outcome requires a fresh read before
another change. Pause does not change the capacity limit or weaken maintenance.
Turning pause off does not resume a held attempt, grant new authority, release
capacity or renew an old budget. Maintenance remains the continuation fence;
do not enable it merely because a health query timed out.

Preserve every pre-existing hold, original journal, protected source and
PVC/Lease/probe custody while qualifying the installation. Keep the site's existing
source exclusions and accepted lineage; do not add a capacity slot or reset/replay
an attempt to bypass a hold. The
[reviewed retirement procedure](held-backup-review.md)
requires independent exact producer, chain, object and original-journal evidence
before owner release and authenticated retirement. Missing native objects,
elapsed time and fresh diagnostic observations do not satisfy those prerequisites.

## Check your settings on disposable data

Start with one disposable VM and the default API budget. Use the same storage class, volume mode and expected write rate as your intended VM. Watch guest and application health, scratch free space, acknowledged bytes and the final backup result. Restore a known file to a fresh target. Keep the original journal and identifiers if the run stops.

For storage qualification, use dedicated disposable volumes to exercise low-space refusal, full scratch, long transfers and RWO detach/reattach where applicable. Test pause and maintenance independently. Keep production VMs, retained holds and existing backup chains outside these exercises.

## Pending requests that never acquired custody

Vesta automatically fails a newly refused request only when the
server proves that no reservation or provider/storage custody exists. Its human
queue entry is closed atomically when applicable. Scheduled pause remains a
retryable queue condition and is not converted into a permanent failure.

For an older direct request left Pending after admission was paused, an
organization admin or operator may select **Close pending request** on Backups.
The confirmation asks the server to prove eligibility. The button is only a UI
hint: current status and all custody checks are rechecked atomically by the API.
A refusal leaves the request unchanged for review. This action is not available
for a reserved attempt or an associated queue, and it does not release capacity,
remove a journal, delete objects or resume work.

The offline API equivalent is `POST /api/v1/backups/{backup_id}/close-unreserved`
with body `{}` and a new saved `Idempotency-Key` UUID. Authenticate as the reviewing
operator using the site's normal TLS and authentication configuration. Confirm
that `GET /api/v1/operator/capabilities` advertises `backup.close_unreserved`.
Save that key before submission. If the response is lost, inspect
`GET /api/v1/operator/requests/{request_id}`; keep the same closeout key and intent
for any reviewed replay. Do not allocate another key just because a reply was lost.

Success returns 200 with `status: failed`, `capacity_state: unreserved` and
`reason: pre_dispatch_no_effect`, plus backup/request identifiers. Inspect the
current backup and audit entry. Its original create receipt remains historical
and may still say Pending; replaying that original create key never starts a
replacement backup. After the pause and resource prerequisites are resolved,
start a new backup deliberately with a new request identity.

For attempts that uploaded data or acquired capacity, use the existing supported
held-attempt review. A new agent, absent native object, zero progress display or
clock-race diagnosis is not proof authorizing release. Preserve original
reservations and journals until that separate procedure succeeds.
