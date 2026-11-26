# Size a backup and measure recovery time

Start with a representative VM, the intended storage class and the actual S3 endpoint. Take a full, change data at a normal production rate, take an incremental and restore into an isolated target. Measure a quiet VM and a busy one separately. The [installation requirements](installation-requirements.md) list the kit’s CPU, memory, journal and scratch allocations.

## A measured example

A network-isolated KubeVirt guest with a 256 MiB data disk on RWX NFS took about **227 seconds for a full backup** and **32 seconds for the next incremental** in a Vesta lab run. About 220 seconds elapsed before the first acknowledged part of the full. The restored guest booted and matched all three expected file hashes. The run captured backup completion times. It did not time application recovery or sustained disk throughput.

This is why dividing the virtual disk capacity by total elapsed time can be misleading. Startup, native checkpoint preparation, sparse extents, upload and finalization all affect the result. There is no published fleet-wide throughput, deduplication factor or restore RTO. Use the following measurements to set a target for your site.

## Estimate the space

- **Scratch** is working space for the VM backup. At the default reserve coefficient, allow 1.2 times the total capacity of the native persistent disks, including disks excluded from upload, as usable free space. A 50 GiB disk set needs 60 GiB free at admission. Recheck capacity during high guest write activity. The agent journal needs its own persistent space.
- **Backup storage** holds full payloads, subsequent changes, manifests and retained object versions. For example, a measured 80 GiB stored full and six measured 5 GiB increments total 110 GiB of payload before metadata, older chains, replicas and unfinished uploads. A second full starts another chain. Bucket retention longer than the Vesta schedule extends storage use.
- **Restore storage** must accommodate fresh disks at the original virtual sizes, output filesystem overhead and the VM that will boot them. For planning, count both the base and all increments you need to read. Keep the original VM and backup objects during the recovery.

## Measure the recovery your users need

| Measurement | Start and finish |
| --- | --- |
| Transfer rate | Record the change in acknowledged payload bytes during an active transfer interval and divide by the elapsed seconds. Note encryption, source volume mode, concurrency and agent memory. |
| Recovery point objective (RPO) | At the time of a simulated outage, find the most recent **usable** backup point. Compare its capture time with the outage time. Missed or refused scheduled jobs increase this gap. |
| Recovery time objective (RTO) | Time from declaring the outage until the service can serve a known request. Include finding keys and catalog, reading the chain, provisioning disks, booting, database replay and checking the application. |

As a transfer-only example, reading 100 GiB at a measured sustained 25 MiB/s takes about 68 minutes before provisioning and application recovery. The kit’s default 8 MiB/s bootstrap value is an admission-planning input. Replace it with observations appropriate to your site.

The agent exposes Prometheus-format counters for acknowledged bytes, part-cycle time, Kubernetes throttling and source reads. Use the same interval at both endpoints and record whether the final backup was accepted. [KubeVirt transfer metrics](../okd/runbooks/kubevirt-transfer-performance.md) · [Your first recovery](../../docs/first-recovery.md)
