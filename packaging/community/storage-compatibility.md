# Choose a backup path for your storage

First identify **what owns the writes**. For a VM disk, QEMU can track changed blocks as the guest writes. For an ordinary application PVC, there is no QEMU process tracking those writes. The storage driver or a backup reader needs a different way to find changes. A backup tool can also read an entire snapshot and upload only unique chunks. All three may produce a smaller second upload, with very different source I/O and prerequisites.

## What the current Vesta release protects

| Source or destination | Coverage |
| --- | --- |
| KubeVirt VM on RWX NFS, Filesystem mode | Vesta has exercised a full, incremental and fresh-VM restore on a Linux NFS-backed fixture. The restored guest booted and its known file hashes matched. Tracking came from KubeVirt/QEMU. A NAS snapshot API was unnecessary. |
| KubeVirt VM disks on Ceph RBD through Rook or OpenShift Data Foundation | A CSI driver name alone cannot establish a working VM path. Confirm the VM backup and export APIs, actual CBT state, volume mode, scratch and destination restore behavior. RBD Block and RWO combinations still require Vesta qualification. |
| KubeVirt VM on NetApp, IBM or Dell storage | Check the precise driver, model, volume mode, access mode and platform version. The VM backup path requires the same QEMU and export capabilities. Vendor snapshot or replication support by itself does not qualify a Vesta restore. |
| Native libvirt VM | Full and incremental backup and fresh native recovery have been exercised with the compatible QEMU/libvirt profile and qcow2 disks. Check the running hypervisor stack as well as the installed RPM. [Native host requirements](../rpm/README.customer.md) |
| Ordinary Kubernetes PVC with no VM | The released Vesta agent protects VM-attached persistent disks. Standalone file shares, generic PVC data movers and database-native point-in-time recovery require a different workflow. |
| Guest operating system | Disk capture is outside the guest. Linux guests have boot-and-hash recovery evidence. Guest agent availability, firmware, drivers and application recovery can vary, including for Windows. Validate your actual guest before assigning a service objective. |
| S3 destination | Select an S3 endpoint, region, bucket, prefix and trusted TLS connection. Versioned multipart upload and exact-version reads are important for chain recovery and safe cleanup. MinIO has been used with Vesta. Amazon S3, Ceph RGW, NetApp StorageGRID and other compatible offerings should be checked against the same operations and policies on your installed version. There is no blanket certification by brand. |

The installation observations cover OKD 4.22 and the HCO/KubeVirt/CDI versions in the [installation requirements](installation-requirements.md). The same Kubernetes or platform version can serve different backup API versions and feature gates. A successful bucket test establishes access; the [first recovery](../../docs/first-recovery.md) exercises the whole path.

## Check changed-block tracking

Open **Virtual Machines**, choose the VM, and inspect its observed tracking state, disks and agent heartbeat. In your kit, run `./vesta preflight --help`. If it offers the per-VM option, check the intended VM on your active cluster:

```sh
./vesta preflight --vm workloads/accounts --output-dir /private/vesta/accounts-report
```

Replace `workloads/accounts` with your source namespace and VM. Open `vesta-readiness.json` locally in the reader on this page or read the finding in your terminal. A cluster-wide gate or a guest restart can affect other workloads, so the check proposes the applicable change for the virtualization administrator.

With a kit that offers the site-wide report, use `./vesta preflight --output-dir /private/vesta/preflight` and open `vesta-gates.json`. It checks the installed HCO and rendered KubeVirt configuration and served API versions. The adjacent scope report covers VM and namespace selectors. Use a new private output directory in either case.

| When the observation says… | What to do |
| --- | --- |
| A required tracker, VM backup or export API version is absent | Compare the served versions with the kit requirements. Use a matching platform and kit. Turning on tracking for a VM cannot install a missing API. |
| The installed stack supports the API, but tracking is disabled or the VM is outside the selector | Ask the virtualization administrator to review the HCO gate and the existing selectors. Where a VM label selector already exists, match this VM to it deliberately. Keep unrelated namespaces outside the change. |
| The instance is stopped, paused, unready or waiting for a node | The shipped native KubeVirt path needs a running, Ready instance on a node. Review the VM and its storage with the workload owner before changing its power state. |
| The selector matches but the running VMI has not reported `Enabled` | Check the VM state volume, operator reconciliation and the platform’s activation procedure. Schedule any required guest restart in a maintenance window. Read the new VMI status afterward. |
| Tracking is enabled but there is no accepted matching checkpoint | Start a new full baseline for the selected disk set. A previous full on another VM identity, or a catalog entry with a missing tracker, cannot be a parent for this incremental. |
| A status read was denied, unavailable or stale | Refresh under the appropriate read permissions. Until the active VM and disks can be identified, no one can infer a working incremental path from the storage class name. |

QEMU dirty bitmaps, VM state storage, backup scratch and the Vesta agent’s persistent journal do different jobs. A low-space warning for the agent journal refers to measured free space on that filesystem. The released stack exposes no universal counter for “remaining CBT history” on every backend. Use the applicable driver’s measurements when available. [Scratch and journal sizing](installation-requirements.md) · [What other backup tools track](storage-platforms.md)

## Multiple disks and group snapshots

The KubeVirt native operation covers the VM’s persistent disks together in a VM backup object. A selection can exclude a disk from upload while that disk still contributes to native scratch demand. The current Vesta engine does not create a CSI `VolumeGroupSnapshot`.

Where your application spans several PVCs, check whether the cluster serves the group snapshot API, all the PVCs are bound to the same supported CSI driver, and a matching group snapshot class and storage system can group those particular volumes. A driver may have pool, array or protocol restrictions. A group point is useful for multi-disk crash consistency. A database may also need guest quiescing, log replay or its own coordinated backup. The [roadmap](../../ROADMAP.md) describes how Vesta plans to use group snapshots and newer backup APIs.

## Before relying on a new combination

Choose a disposable VM with the intended disk layout. Record the driver and volume mode, change data on each selected disk between the full and incremental, restore into fresh volumes and check the data in the guest. Try a lost-checkpoint scenario on the disposable workload to learn the recovery path. An NFS result is useful for NFS. A raw Block restore on RBD or an array-backed volume deserves its own run. [Recovery granularity and consistency](backup-and-recovery.md) · [Sizing and recovery time](sizing-and-recovery-time.md)
