# Community roadmap

The current Community release protects VMs with a KubeVirt agent or native libvirt agent and sends backups to S3-compatible storage. Operators can recover a fresh VM or reconstruct raw disks with a saved chain and keys. See the [storage compatibility guide](packaging/community/storage-compatibility.md) for the combinations exercised today.

## OpenShift and OKD 5.x

| Planned work | What operators should gain |
| --- | --- |
| Follow the OpenShift Virtualization and upstream KubeVirt VM backup APIs | Discover versions actually served and per-VM tracking readiness. Qualify the newer VM backup/tracker APIs, per-disk checkpoint loss, stopped-VM behavior, full and incremental export, and fresh restores. Publish results by platform minor and volume mode. |
| Test widely used storage stacks | Start with Rook/Ceph RBD and OpenShift Data Foundation Block/RWO alongside Linux NFS Filesystem, then qualify specific NetApp, IBM and Dell driver/backend combinations. Exercise multi-disk guests, high write rates, scratch exhaustion and restore to empty targets. |
| Add CSI volume group snapshots where the driver supports them | Discover group classes and driver membership for **all** selected disks. Present the available consistency level before capture. Test restoration of every member and document any guest quiescing needed for databases. |
| Evaluate incremental protection for ordinary PVCs | Investigate CSI snapshot metadata and changed-block queries separately from VM/QEMU tracking. Measure both bytes read at the source and bytes transferred, and exercise parent loss and an independent restore. |

OpenShift/OKD 5.0 brought group snapshots to general availability on supported drivers. The downstream QEMU VM CBT and CSI changed-block paths have separate Technology Preview status. Upstream KubeVirt has its own release cadence. Vesta will qualify each combination as it becomes usable, including the recovery side. [OpenShift 5.0 release notes](https://docs.redhat.com/en/documentation/openshift_container_platform/5.0/html/release_notes/ocp-5-0-release-notes) · [OpenShift Virtualization 5](https://www.redhat.com/en/blog/unlocking-next-generation-workloads-whats-new-red-hat-openshift-virtualization-5) · [OKD 5.0 storage notes](https://okd.io/blog/2026/09/17/okd-5.0-release-notes/)

## Installation and operation

We plan a deployment option for people who run only libvirt/KVM and want to host Vesta without an OpenShift or OKD cluster. Packaging and operating requirements are open for design. [Track the standalone deployment](https://github.com/Insitu-IT/vesta/issues/9)

The console and operator API already show backup readiness for the selected VM. Next we plan to cover more storage configurations, give automation clients clearer recovery information, and simplify repeated setup steps. We also plan to improve keyboard navigation, translations and right-to-left layouts in the console.

Follow [GitHub Issues](https://github.com/Insitu-IT/vesta/issues) for open work and [release notes](CHANGELOG.md) for shipped changes. To contribute results from a storage stack or guest you use, include the release, driver, volume mode, backup and restore results using disposable data. [Contribution guide](CONTRIBUTING.md)
