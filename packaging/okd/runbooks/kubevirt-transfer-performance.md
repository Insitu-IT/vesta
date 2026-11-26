# KubeVirt transfer profiles and API budget

The KubeVirt agent can negotiate a 32 MiB transfer profile for a new backup. Larger ranges can reduce the number of API calls per GiB. Measure elapsed time on your own storage before changing the API budget. Each part still uses authorization, routing and durable journal checks.

## Install or change settings

Use the coordinated [upgrade procedure](upgrade-recovery.md). In the accepted
private `site.json`, these optional installation settings are supported:

| Field | Default | Values |
| --- | --- | --- |
| `kubevirt_transfer_profile` | `kubevirt-32m/1` | `kubevirt-32m/1` or `legacy` |
| `kube_api_qps` | 50 | Integer 1–200 |
| `kube_api_burst` | 100 | Integer from QPS through 400 |

The profile preference is rendered as backend `KUBEVIRT_TRANSFER_PROFILE`;
QPS/burst become agent `KUBE_API_QPS` / `KUBE_API_BURST`. The new profile is
selected only after the agent advertises support in its capabilities. An old
agent receives an old plan. Absence of `transfer_profile` in a stored plan means
legacy behavior; do not add or remove it manually.

For an already upgraded installation, follow [reconfiguration](reconfiguration.md)
with a private previous/proposed site file. Review the API/agent Deployment delta,
fence new dispatch and settle active producers before restarting workloads.
Custom GitOps installations retain their existing GitOps resource contract;
change the corresponding owned environment values there. Never overwrite their
identity, Secrets or mounts merely to make the stock renderer accept them.

Keep 50/100 while comparing profiles. Raise QPS/burst only in a separate fresh
trial when limiter wait is significant and cluster capacity permits. A higher
budget cannot remove backend, storage, hashing or journal latency. Each agent
has its own bucket shared by inventory, backup and restore.

## Compatibility and memory

Legacy plans keep 8 MiB source ranges and their original part-size algorithm.
The new profile uses source ranges up to 32 MiB and payload parts of at least
32 MiB. Large disks may use larger parts to remain within 10,000 parts; the
1 GiB maximum is unchanged. Manifests keep the old minimum. Sparse extents can
produce smaller requests. Encryption framing makes reads and parts independent.
There is up to four times as much source data between source-request checks.
Each source response is fully read and checked before its bytes
reach the uploader. This requires one additional buffer of at most 8 MiB for
legacy plans or 32 MiB for the new profile. Measure total RSS, including that
source buffer, encryption and transport buffers; it is larger than a single part.

The plan hash binds the selected profile for the whole attempt. Changing
settings cannot alter an existing plan, journal or multipart sequence. Installing
this release does not restart, repair or authorize discarding held attempts.
Keep a recovery reader that understands every profile in the retained plans, journals and restore chains. A legacy reader cannot process the 32 MiB profile. Selecting `legacy` affects new attempts only. Read the [upgrade and recovery procedure](upgrade-recovery.md) for the kit you're installing before changing these images.

## Compare fresh runs

Use fresh, isolated attempts on the same source data, encryption settings and
storage target, with the same 50/100 budget. Preserve existing work and custody.
Select `legacy` for one run and the new profile for another; confirm the stored
plan and exact image versions before measuring. Do not relabel saved attempts.

Capture metrics at both ends of the same active payload interval and record
elapsed time, acknowledged payload bytes, request count per GiB and peak RSS.
Use the agent's existing authenticated/local metrics access. Backend metrics are
disabled by default (`METRICS_ENABLED=false`). If backend stage timings are needed,
enable the existing switch only through the installation's private monitoring
configuration, then restore its previous value after the trial. No public
telemetry endpoint or external connection is required.

- `vesta_agent_kube_api_throttle_seconds`: client limiter wait.
- `vesta_agent_kube_api_requests_total{method,resource,status}`: bounded HTTP
  counts, including server 429 and transport errors.
- `vesta_agent_kube_api_resource_seconds{method,resource}`: latency to headers.
- `vesta_agent_storage_part_cycle_seconds{role="payload"}` and
  `vesta_agent_storage_uploaded_bytes_total{role="payload"}`: durable part cycle
  and ciphertext throughput. The first cycle starts after multipart creation.
- `vesta_agent_storage_step_seconds`: existing validation, source read,
  backend part/ACK, journal persistence and S3 timings.
- `vesta_storage_control_step_seconds{step}`: backend admission, persistence
  and signing/configuration stages, including database and other work.

Compare histogram `_sum` and `_count` deltas; nested timings must not be added.
Counter resets require a new baseline. Acknowledged bytes do not prove completion.
Require accepted publication and a fresh restore with source/guest hashes.
Compare results from the same provider, storage class and volume mode. Include the [native lifetime check](native-backup-lifetime.md) on the intended storage. Do not attribute unexplained elapsed time to a rate limit without the measurements.
