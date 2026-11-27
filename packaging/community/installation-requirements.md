# Installation requirements

The Vesta Community kit runs the API and web console on amd64 OKD or OpenShift. Choose the in-cluster KubeVirt agent for virtual machines on that platform. If you protect native libvirt hosts, enroll a host agent in the same control plane. The operator CLI and offline recovery tool run separately on Linux amd64. [Choose a release download](https://github.com/Insitu-IT/vesta/releases/latest)

## Choose your deployment

| What you want to run | What to provide |
| --- | --- |
| Control plane with a KubeVirt agent | The amd64 kit, an OKD or OpenShift cluster with the required virtualization APIs, PostgreSQL 17.x, a cluster-reachable registry, and S3-compatible storage |
| Control plane with external native agents | The amd64 kit with `agent: "external"`, the same cluster, registry and database inputs, S3-compatible storage, and the matching x86_64 agent RPM for each host |
| Operator CLI | The `vesta-cli-linux-amd64` binary, a reachable Vesta API, its trusted CA, and an account or token with the required permissions |
| Managed Linux file sets | A supported Enterprise Linux x86-64 host, locally readable directories, room to stage one encrypted archive, an age public recipient, mutual TLS to the control plane, and a versioned HTTPS S3 bucket supporting conditional writes. [Configure a file set](../okd/runbooks/file-backups.md) |
| Offline recovery | The `vesta-restore-linux-amd64` binary, read-only access to the bucket, independent recovery trust and any required decryption keys, and a fresh output location. [Recover directly from S3](../okd/runbooks/bucket-recovery.md) |

The published Community kit contains three digest-pinned images and uses the `customer-postgresql` profile. Supply the database separately. Check the delivery profile in the kit before provisioning.

## Prepare the workstation and site

- Use Python 3.11 or later and an authenticated `oc` context. Add Bash and `jq` for KubeVirt preflight. Add `skopeo`, registry credentials and registry trust if you will import the bundled images. On an air-gapped site, bring the kit, signed verification files and required images and host packages into the site first.
- Provide the application namespace and, for KubeVirt, an agent namespace and explicit source and restore namespaces. The operator context needs read access to the applicable cluster prerequisites and permission to create the rendered resources. The kit installs scoped service accounts and roles.
- Provide DNS names for the console and API, trusted HTTPS certificates, pull credentials for the cluster registry, and the Secrets named in the site manifest. Plan network paths to PostgreSQL and S3, between the API and enrolled agents, and from the KubeVirt agent to the exports. If you use a private CA, distribute its trust to the callers that need it.
- Keep credentials in Secrets or your secret manager. Preserve the application encryption key, backup encryption keys and agent identities and journals in your recovery plan.

### PostgreSQL

For the customer-managed profile, use a writable PostgreSQL **17.x** primary with `plpgsql` available and `default_transaction_read_only=off`. The schema job checks these prerequisites before changing the database. For an advance connection check, use the read-only prerequisite job described in the database runbook.

Provision separate schema-owner and restricted runtime logins. The runtime login needs access to the `public` schema and Vesta’s granted objects. Keep it without role memberships, ownership of the database or public schema, schema creation privilege, or RLS bypass. Put each database URL in the corresponding Secret. Use an explicit TCP hostname from the server certificate, `sslmode=verify-full`, the mounted CA at `/trust/ca.crt` and `gssencmode=disable`. Manage database storage, availability, maintenance and recovery with your database team. [Prepare customer-managed PostgreSQL](../okd/runbooks/customer-postgresql.md)

### KubeVirt

The in-cluster agent uses the following served APIs:

| Resource | API version |
| --- | --- |
| VirtualMachine and VirtualMachineInstance | `kubevirt.io/v1` |
| VirtualMachineBackup and VirtualMachineBackupTracker | `backup.kubevirt.io/v1alpha1` |
| VirtualMachineExport | `export.kubevirt.io/v1beta1` |

Run the manifest preflight to check `IncrementalBackup` and `UtilityVolumes` on the installed virtualization platform. Review a missing gate with the platform administrator. Confirm that the `hco.kubevirt.io/v1` HyperConverged resource (HCO) and the resulting KubeVirt configuration agree on the changed-block tracking selectors. Check that each pilot VM matches the intended selectors and that its running VMI is Ready on a node, unpaused, and reports CBT `Enabled`. When a VM uses DataVolumes, include the site’s CDI configuration in the pilot.

Vesta’s documented lab baseline is HCO 1.18.1, KubeVirt 1.8.4 and CDI 1.65.0 on OKD 4.22, with NFS workloads. Treat these as tested versions and conditions. Verify your platform vendor’s support for the backup APIs and qualify your exact cluster, operator versions, CSI driver, volume modes and VM configuration before protecting production workloads. Include Ceph or Block-mode restore in your pilot if you use it.

### Native libvirt

Choose the x86_64 `vesta-agent` RPM matching the host’s Enterprise Linux major version. Releases provide separate EL9 and EL10 packages.

If your EL10 host runs the newer libvirt 12.9 and QEMU 11.1 combination, native VM backups on that stack await qualification.

The RPM requires libvirt, the QEMU driver and Python bindings at **11.10.0 or newer**, plus `qemu-img` **10.1.0 or newer**. For native VM backup, Vesta checks the actual virtualization stack. It accepts the libvirt **11.10.x** and **12.7.x** series, a running **QEMU 10.1.x** VM and **qemu-img 10.1.x** on the host. The agent connects to `qemu:///system` and needs at least one eligible qcow2 disk. Check the selected disks on mixed-format VMs.

The package uses systemd, Python 3, ACLs and polkit. Run the packaged service under its dedicated account. Prepare verified HTTPS in both directions, the agent’s server certificate and client CA, and the per-host enrollment credential from Vesta. Preserve the stable host identity, journals and keys under `/var/lib/vesta`. [Install a native agent](https://vestabackup.com/docs/manuals/native-agent/)

### S3 and optional single sign-on

Use a dedicated bucket or prefix with HTTPS and enable versioning before the first protected workload. The S3 endpoint must support signed multipart uploads with SHA-256 checksums, object metadata and reads for verification and restore. Recovery and retention use the exact stored object versions. Confirm permissions for the operations you enable, including version-specific deletion if Vesta manages retention. Keep an independently usable recovery identity and make sure a storage lifecycle rule cannot remove a version still needed by a retained chain. Check a real backup and restore through the same network and endpoint the agents will use.

For SSO, register a confidential OpenID Connect client with issuer discovery and authorization-code flow with PKCE S256. Supply the issuer, client ID, client Secret, scopes and role mappings. Register `/api/v1/auth/oidc/callback` on the actual HTTPS sign-in origin as the redirect URI. Make the identity provider reachable from the API and the browser through trusted HTTPS. Verify sign-in and role mapping in a separate browser session, then confirm the local recovery administrator still works.

## Size CPU, memory and storage

These are the kit’s starter allocations per pod. Use the request column when checking namespace quota and scheduler headroom. Confirm peak memory and throughput with a workload representative of your planned disk sizes and concurrency.

| Component | CPU / memory requested | CPU / memory limit |
| --- | ---: | ---: |
| API | 250m / 512 MiB | 2 CPUs / 2 GiB |
| Web console | 50m / 64 MiB | 500m / 256 MiB |
| KubeVirt agent | 250m / 256 MiB | 2 CPUs / 2 GiB |
| Schema or migration job | 250m / 256 MiB | 1 CPU / 1 GiB |
| Dedicated PostgreSQL example in the separate full kit | 250m / 256 MiB | 1 CPU / 1 GiB |
| KubeVirt scratch probe | 5m / 16 MiB | 100m / 64 MiB |
| KubeVirt restore worker | 100m / 128 MiB | 1 GiB memory |

The steady API, console and KubeVirt agent request **550m CPU and 832 MiB memory** together. With external agents, API and console request **300m CPU and 576 MiB**. Allow extra headroom for jobs, platform controllers, VM workloads and other workloads already on your cluster. For an external database, size CPU, memory and I/O for catalog and audit growth, database backups and WAL. The dedicated database example starts with a **10 GiB** data volume.

| Storage to budget | How to size it |
| --- | --- |
| Workstation, cluster registry and image cache | Use the compressed size listed in Release Assets and reserve additional space for extraction, registry storage and unpacked node image layers. |
| KubeVirt journal | The kit starts with a persistent **1 GiB** ReadWriteOnce filesystem claim. Monitor available space and retain its contents across updates. |
| KubeVirt scratch | The starter requests **64 GiB** per source namespace. Supply a ReadWriteOnce or ReadWriteMany filesystem that can mount on the source VMI’s node. At the default 1.2 coefficient, plan at least **1.2 × the total capacity of every persistent disk participating in the native backup** in usable free space, including for incrementals and disks excluded from upload. For a 50 GiB native disk set, that is 60 GiB available after filesystem overhead and existing files. Each scratch claim supports one reservation at a time. |
| Native agent storage | Size the journal and backup/restore paths for the protected disks, concurrent operations and retention of interrupted work. If using the fenced staging option, provision its dedicated ext4 filesystem for reserved bytes plus the configured free-space margin. |
| S3 | Budget for retained full chains, changed data, object versions and incomplete multipart uploads. Use measured growth and test the retention policy against a complete recoverable chain. |
| Restore destination | Budget capacity for every reconstructed disk plus filesystem overhead and VM boot resources. For KubeVirt, confirm the selected namespace, storage class and volume mode support fresh PVCs and the restore worker’s UID/GID/fsGroup 107. For offline recovery, the output directory must be new. Native backup chains also need Python 3 at `/usr/bin/python3` and `qemu-img` 10.1.x on the recovery workstation. |

The kit does not prescribe fixed CPU or RAM minima for a native host, an operator CLI runner or an offline recovery workstation. Measure the worker or agent alongside the actual workload. For KubeVirt, the 32 MiB transfer profile adds a source-read buffer per active stream on top of multipart, encryption and transport buffers. Use total process memory during a pilot rather than a single part size.

## Run the checks

After authenticating the archive with the signed release checksums, extract it and run:

```sh
./vesta verify
./vesta init
# Edit vesta.json and provision the site inputs it references.
./vesta plan
./vesta check
```

`plan` reads the manifest locally. `check` uses the selected cluster context to check resource collisions, required Secret keys, storage classes and authorization through server-side dry-runs. With the KubeVirt profile it also checks the HCO/CBT configuration and served APIs. Save the detailed report with `./vesta preflight --output-dir /private/vesta/preflight` if you are validating a new stack. The schema job checks database identity and prerequisites during installation.

Import the images if your registry needs the exact digests from the plan, then install and configure the site. After enrollment, run `./vesta status` and confirm the expected authenticated agent heartbeat. Back up a disposable VM and restore it under a fresh identity. Open a known file or compare its checksum before enabling schedules.

On a separate CLI runner, `vesta-cli version` and `vesta-cli doctor --offline` identify the local binary. With `VESTA_URL`, `VESTA_TOKEN_FILE` and, where applicable, `VESTA_CA_FILE` set, run `vesta-cli doctor --deadline 30s` to read the site’s version, capabilities and observed access. The CLI is versioned independently of the server. [Install and connect the operator CLI](https://vestabackup.com/docs/cli/)
