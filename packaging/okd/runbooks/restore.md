# Restore into fresh resources

Restore a selected accepted point in a full/incremental chain into fresh disks
and a new VM identity. Preserve the source and the accepted backups. Never use
an existing important VM, PVC or raw disk as a convenient test destination.

## Check the inputs

Select the exact backup point, source identity, encryption key custody and full
parent chain. Missing members, wrong keys, corrupt bytes or inconsistent metadata
must stop restore, not fall back to a different point. Manual artifact verification
helps check the retained bytes but is not a boot test.

Confirm the destination namespace is explicitly configured for this agent and
has sufficient new storage. The worker needs the namespaced permissions installed
by the agent stage and the storage/CSI permissions for its selected PVC mode.
Filesystem and Block destinations require their actual provisioner capabilities;
do not assume a Filesystem test qualifies a Ceph RBD Block destination.

KubeVirt restore workers run with the narrow UID/GID/fsGroup 107 permissions
required by their disk handoff. Arrange the corresponding CSI/SCC policy without
granting privileged SCC broadly. Review CPU/memory, scratch and disk capacity.

## Restore and validate

Use the restore workflow to select a fresh name, destination namespace, storage
class/mode and network mapping. The created KubeVirt VM is Halted by default.
Review the protected disks shown in the preview.
Known excluded disks are omitted from the new VM, including their disk devices;
they are not attached from the source or recreated without backed-up data. Map
every protected disk to fresh storage. If the boot disk or an application
dependency was excluded, the new VM may not boot or recover the application.
Successful reconstruction does not establish application consistency.

For a schema-2 backup, the destination agent must advertise the matching restore
capability; an older or downgraded agent is refused before credential delivery or
destination work. Unknown, duplicate, replaced or missing captured disk identities
remain refusal conditions. Older schema-1 captures still refuse an unprotected
persistent disk.

Review its disks, network/MAC/IP identity and boot behavior before starting it;
keep a test restore isolated from the original VM's production network.

Wait for the actual restore result. A helper Job being created, an accepted API
request or a Bound PVC does not establish successful reconstruction. Inspect the
operation ID and errors in the UI and [diagnostics](operations.md#diagnostics-and-logs).
Failed or cancelled work must not be reported as an accepted fresh VM.

Boot only the reviewed target, then check known guest files, their sizes/hashes,
and the relevant application data. Record the selected point and result. Stop the
test target afterward if it is not needed, while retaining its disks/evidence
under the site's policy. Do not remove the source or accepted chain as test cleanup.

## Native raw disk recovery

On a trusted Linux amd64 workstation, download `vesta-restore-linux-amd64` from the [matching GitHub release](https://github.com/Insitu-IT/vesta/releases). Check its entry in the signed checksums, then run `chmod +x vesta-restore-linux-amd64`. Run `./vesta-restore-linux-amd64 -h` to see its inputs. You can use it when the Vesta server and libvirt are unavailable. For native libvirt backup chains, the recovery workstation also needs Python 3 at `/usr/bin/python3` and `qemu-img` 10.1.x. Supply your saved chain catalog, read access to the S3 backup objects and the corresponding keys for encrypted backups.

The installed `vesta-restore` command and the KubeVirt agent image's
`/vesta-restore` can reconstruct raw images from a trusted catalog bundle. Export
the selected bundle using authenticated
`GET /api/v1/backups/BACKUP_UUID/restore-bundle`; keep its exact metadata intact.
The bundle is not a credential or proof of origin for arbitrary edited JSON.

Prepare private mode-0600 S3 configuration and per-member key files through the
site's recovery custody process. DEK files are base64-encoded 32-byte per-backup
DEKs named `BACKUP_UUID.key`, not a KEK export. Do not put keys on the command line.
Use `vesta-restore -h` for the shipped flags. For example:

```bash
vesta-restore -chain /private/chain.json -s3-config /private/s3.json \
  -keys-dir /private/restore-keys -output /restore/new-disks
```

The output directory must not exist. The command verifies exact chain members,
versions and byte digests, and does not write/delete S3 objects. It produces raw
disk images, not an in-place VM replacement. Attaching them or defining/booting a
native VM is a separate operator-reviewed action with fresh identity/networking.
`-verify-only` streams verification without creating disk images, but its CLI
result does not replace the backend's durable verification history.
