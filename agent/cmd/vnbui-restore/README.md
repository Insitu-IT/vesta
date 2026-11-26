# Restore raw KubeVirt and native disks

`vesta-restore` reconstructs verified raw disk images from the stored full backup
and its incremental extents. It uses the accepted transaction's exact object
keys, versions, sizes and SHA-256 hashes, and verifies ciphertext and plaintext
before reporting success. A changed extent replaces the corresponding disk
range; a zero extent clears that range.

Download `vesta-restore-linux-amd64` from the [matching GitHub release](https://github.com/Insitu-IT/vesta/releases), verify its signed checksum and run `chmod +x vesta-restore-linux-amd64`. Set `VESTA_RESTORE` to its path for the examples below. The same executable ships as `vesta-restore` in the native agent RPM and as `/vesta-restore` in the KubeVirt agent image. Native libvirt chains also require Python 3 and qemu-img 10.1.x on the recovery workstation.

Set `VESTA_RESTORE=/usr/bin/vesta-restore` on a host with the native agent package installed. Inside the agent image use `VESTA_RESTORE=/vesta-restore`. If you run the image as a restore container, override its entrypoint with `/vesta-restore` and mount the input files, trusted CA and a new output directory at the paths you pass. Keep encryption keys and S3 credentials on private read-only mounts.

## Inputs

Export the chosen backup's bundle through the authenticated backend endpoint
`GET /api/v1/backups/{backup_id}/restore-bundle`. Save its JSON response as
`chain.json`. The bundle contains ordered accepted `request` and `receipt`
members in a versioned KubeVirt bundle; it contains no credentials or
encryption keys. Treat the bundle as trusted backup metadata and keep it with
your recovery material. The command verifies its internal consistency; it does
not authenticate the origin of an arbitrary edited JSON file.

For S3, prepare a private mode-0600 `s3.json` file through your normal credential
provisioning process:

```json
{
  "endpoint": "https://s3.example.net",
  "bucket": "vm-backups",
  "region": "us-east-1",
  "access_key": "<read-only access key>",
  "secret_key": "<secret>",
  "ca_file": "customer-ca.pem"
}
```

`ca_file` is optional; absent means the system CA trust store. A relative CA
path resolves beside `s3.json`. A supplied CA file is the complete trust store
for this connection. HTTPS certificate verification is always enabled. The
configured endpoint, bucket and region must match every chain member. Optional
`session_token` supports temporary credentials. Grant object read access only;
the command performs no upload, deletion or bucket discovery.

For encrypted backups, place each member's unwrapped 32-byte DEK, base64-encoded,
in a mode-0600 file named `<backup-id>.key` inside a private key directory. The
files contain DEKs, not the wrapping KEK; each backup uses its own file even if
multiple backups share a KEK. Never pass literal keys in shell arguments.

```sh
"$VESTA_RESTORE" -chain chain.json -s3-config s3.json \
  -keys-dir /secure/restore-keys -output /restore/new-disks
```

Omit `-keys-dir` for an unencrypted chain. `-output` must not exist; the command
creates it privately and refuses to overwrite previous output. On success,
stdout is JSON listing each disk's source volume, path, length and SHA-256.
Failure returns a nonzero exit code and does not publish a successful result.
The default deadline is two hours; set `-timeout 8h` when required.

## Read-only artifact verification

Use `-verify-only` for KubeVirt or native bundles. It streams every exact
admitted artifact without creating disk images, running qemu/libvirt,
creating a VM, or writing/deleting S3 objects.

```sh
"$VESTA_RESTORE" -chain chain.json -s3-config s3.json \
  -keys-dir /secure/restore-keys -verify-only
```

This mode is mutually exclusive with `-output`, `-inspect-definition` and
controller restore worker mode. Offline `-objects-dir` input is also supported.
It checks the ordered chain, target and receipt membership, complete ciphertext
and plaintext byte counts/digests, authenticated decryption, KubeVirt extent
metadata/checkpoint continuity and each captured VM definition. Native mode
verifies all receipt-bound domain/checkpoint/manifest/disk artifacts; it does
not decode qcow2 disks or prove bootability. Reads use the same exact version/
If-Match conditions, fixed-size streaming buffers and HTTPS trust as restore.
No reconstruction scratch space proportional to disk size is needed.

Only complete success emits the versioned chain verification JSON with organization,
source VM, provider and ordered backup/reservation/plan/receipt bindings. It
contains no artifact contents or keys. Any corrupt/missing object, wrong key,
metadata mismatch, read/close failure or cancellation returns nonzero without
a successful result. This is verification of the supplied **trusted catalog
bundle**, not provenance for arbitrary S3 metadata, a fresh-VM restore/boot test,
or durable API verification history.

Use the CLI result as local evidence about the objects bound to the supplied
catalog bundle. Vesta records backend verification history through its own
admission and result acceptance. Verify the exact executable and its available
options with `vesta-restore -help` before relying on it in a recovery procedure.

## Offline recovery

An offline snapshot stores each object's exact accepted bytes beneath
`<snapshot-root>/<bucket>/<object-key>`. Preserve complete object keys rather
than flattening basenames. These transaction keys are unique per attempt;
download the version identified by its receipt when taking the snapshot.

```sh
"$VESTA_RESTORE" -chain chain.json -objects-dir /recovery/objects \
  -keys-dir /secure/restore-keys -output /restore/new-disks
```

Offline reads are restricted to the snapshot directory and use the same length
and hash verification as S3 reads.

## Boundary

The standalone `-output` mode produces raw disk images without changing a VM.
For target mapping decisions, inspect the selected backup's receipt-bound captured
definition into a **new private file** (it can contain cloud-init data):

```sh
"$VESTA_RESTORE" -chain chain.json -s3-config s3.json \
  -keys-dir /secure/restore-keys -inspect-definition /secure/recovered-vm.json
```

Inspection verifies the selected metadata, not all disk payloads. Missing VM
capture is refused; the command never substitutes a live VM definition.

The same executable also has controller-only `-worker` mode. The fresh restore
controller provisions new Filesystem/Block PVCs, projects private inputs and runs
the image-pinned Job. This mode writes filesystem `disk.img` files or raw block
devices directly; it is not an operator shortcut for writing existing disks.
The controller creates the new VM Halted only after verified worker completion.
Use the authenticated fresh-VM restore API or console to select the target and
supply explicit storage and network mappings. Review the restored VM before
starting the guest.

## Native libvirt bundles

The same command accepts native libvirt recovery bundles containing explicit
accepted `request`, `receipt`, and `push_result` members. Native S3 credentials
and per-backup key files use exactly the same protected formats above. The
native helper requires `/usr/bin/python3` and qemu-img **10.1.x**; no old
virtnbdbackup filename interpretation is used.

```sh
/usr/bin/vesta-restore -chain native-chain.json -s3-config s3.json \
  -keys-dir /secure/restore-keys -output /restore/new-native-recovery
```

Every metadata/image object is hash/length/version verified before reconstruction.
Downloaded plaintext resides in `members/`; private copied/rebased qcow2 layers
and final `<target>.raw` disks reside in `disks/`. Original input objects are never
modified. Native partial output is retained on any failure and must not be
consumed; do not retry onto the same existing directory. Successful stdout lists
each target, final path, size and SHA-256. Provision scratch space for all layers
and final raw images.

For native `-inspect-definition`, choose a new private `.xml` file. This verifies
the selected immutable `domain.xml`, including encrypted members, without
downloading disk payloads. The XML contains source paths/UUID/MACs and must **not**
be defined verbatim. Use the admitted native API/UI fresh-VM path for explicit
disk/network remapping and inactive-domain creation. The standalone command
never defines or starts a VM.
