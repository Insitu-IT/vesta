# Recover Linux files and VM disks

`vesta-restore` recovers encrypted Linux file archives and reconstructs verified raw disk images from the stored full backup
and its incremental extents. It uses the accepted transaction's exact object
keys, versions, sizes and SHA-256 hashes, and verifies ciphertext and plaintext
before reporting success. A changed extent replaces the corresponding disk
range; a zero extent clears that range.

Download `vesta-restore-linux-amd64` from the [matching GitHub release](https://github.com/Insitu-IT/vesta/releases), verify its signed checksum and run `chmod +x vesta-restore-linux-amd64`. Set `VESTA_RESTORE` to its path for the examples below. The same executable ships as `vesta-restore` in the native agent RPM and as `/vesta-restore` in the KubeVirt agent image. Native libvirt chains also require Python 3 and qemu-img 10.1.x on the recovery workstation.

Set `VESTA_RESTORE=/usr/bin/vesta-restore` on a host with the native agent package installed. Inside the agent image use `VESTA_RESTORE=/vesta-restore`. If you run the image as a restore container, override its entrypoint with `/vesta-restore` and mount the input files, trusted CA and a new output directory at the paths you pass. Keep encryption keys and S3 credentials on private read-only mounts.

## Linux file archives

Run `vesta-restore --version` to identify the executable. Run
`vesta-restore --file-archive-format` to report its file archive format.

Generate an age X25519 identity on the recovery workstation:

```sh
"$VESTA_RESTORE" files keygen --identity /secure/file-recovery.agekey
```

The command creates a new mode-0600 identity file and prints its public
recipient. `files recipient --identity /secure/file-recovery.agekey` prints
the same recipient later. Configure the backup host with the recipient
and store the identity separately from that host and the archive.

Keep the encrypted archive, the identity and the ciphertext SHA-256 from the
trusted backup record for offline recovery. The digest pins the archive to
that record because anyone with the public recipient can create an encrypted
archive.

```sh
"$VESTA_RESTORE" files verify --archive /offline/backup.age \
  --identity /secure/file-recovery.agekey --sha256 "$ARCHIVE_SHA256"
"$VESTA_RESTORE" files list --archive /offline/backup.age \
  --identity /secure/file-recovery.agekey --sha256 "$ARCHIVE_SHA256"
"$VESTA_RESTORE" files extract --archive /offline/backup.age \
  --identity /secure/file-recovery.agekey --sha256 "$ARCHIVE_SHA256" \
  --output /restore/new-tree --select reports
```

Pass selections as archive-relative paths without a trailing slash, such as
`--select reports`. Repeat the option for multiple paths or omit it to
extract all entries. A selected directory includes all its descendants.
Extraction publishes a new private directory after verifying the entire
archive. The output parent must exist and support atomic no-overwrite
rename. Set `TMPDIR` to a volume that can hold a temporary encrypted copy
of the archive and allow space for the recovered files at the destination.

To recover from S3, use the private HTTPS `s3.json` configuration described
below. Supply the object version if the storage service returned one:

```sh
"$VESTA_RESTORE" files verify --archive s3://file-backups/host/backup.age \
  --s3-config s3.json --s3-version-id "$ARCHIVE_VERSION" \
  --identity /secure/file-recovery.agekey --sha256 "$ARCHIVE_SHA256"
```

The same S3 flags apply to `files list` and `files extract`. S3 recovery
requires read access to the configured bucket and uses its configured HTTPS
trust. Offline and S3 recovery run without the Vesta console.

The format stores regular files and directories with ordinary file permission
bits and second-resolution modification times. Recovery gives the restoring
user access to every directory. It restores each file independently and
does not retain ownership, ACLs, extended attributes or hard-link relationships.
Symlinks, special files and mounts inside the source tree fail archive creation.

## Discover and recover directly from a versioned S3 bucket

The recovery workstation needs the standalone executable and a private
`s3.json` that authorizes read access to the original HTTPS endpoint and
bucket. Match the recorded region exactly. A blank historical VM region is
represented as `"region": ""` and signs requests for a custom endpoint with
`us-east-1`. The read identity needs `s3:ListBucketVersions` for the recovery
prefixes it will discover and `s3:GetObjectVersion` for data it will retrieve.
Restrict these permissions by prefix and object resource. The standalone
commands perform no S3 writes.

For signed VM backups, keep a recovery trust export independently of the
bucket. A Vesta key export containing that trust also works. The listing
provides verified backup names, completion times and backup IDs. A bucket
listing supplies no new trusted signing key.

```sh
"$VESTA_RESTORE" s3 list --s3-config /secure/s3.json \
  --trust /secure/recovery-trust.json

"$VESTA_RESTORE" s3 restore --s3-config /secure/s3.json \
  --backup "$BACKUP_ID" --kek-export /secure/recovery-keys.bin \
  --output /restore/new-disks
```

Signed listings return `items`, `issues` and `incomplete`. Follow `next_cursor`
with `--cursor` to see more entries. Use `--limit` to choose a smaller page.
An unavailable generation can still have a valid signed record. Choose a point
whose generation is available for recovery.

Use `--trust` on restore when the export predates embedded recovery trust.
For cleartext backups, use the separate `--trust` document and omit
`--kek-export`. The executable prompts for the key export passphrase on a
terminal without echo. In automation, provide `--passphrase-file` with an
owner-only file. Keep the passphrase, KEK export and S3 credentials in
separate custody. Vesta verifies and unwraps each member's key in memory.
Recovery supports full and incremental KubeVirt and native libvirt chains.
It writes verified raw images and does not create or start a VM.

Complete historical unsigned generations can be recovered into a new
isolated local directory with explicit acknowledgment. Their names and
times are historical metadata from the generation and S3. Historical native
records can display a source UUID when the VM name was never retained. A
historical `identity-only` entry lacks enough material to reconstruct a disk.

```sh
"$VESTA_RESTORE" s3 list --s3-config /secure/s3.json \
  --allow-unsigned-legacy

"$VESTA_RESTORE" s3 restore --s3-config /secure/s3.json \
  --allow-unsigned-legacy --backup "$BACKUP_ID" \
  --generation-key "$OBJECT_KEY" --version-id "$OBJECT_VERSION" \
  --kek-export /secure/historical-keys.bin --output /restore/isolated-disks
```

Use the reported object key and version for exact selection. Supply
`--trust /secure/recovery-trust.json`, a KEK export with embedded trust,
or `--installation-id "$SOURCE_INSTALLATION_ID" --org-id "$SOURCE_ORG_ID"`
from independent records. The reader checks that the generation matches that
identity and needs `s3:ListBucketVersions` for only the relevant signed point
name at `vesta-recovery/v1/<installation>/<org>/<backup>.json`. A retained
version or delete marker at that name prevents unsigned recovery. If the
reader cannot check the signed history, recovery stops.

With no independent scope, an older operator can still acknowledge isolated
recovery. The reader then needs permission to list versions under the full
`vesta-recovery/v1/` prefix and checks up to 65,536 entries. If that limit is
exceeded, supply independent source identity to use the exact-name check.
`--org-id` alone limits generation discovery. Historical payload receipts
that omitted a version must resolve to one retained version
by ETag and size before the actual ciphertext and plaintext are verified.
Allow enough available space for reconstructed disks and native scratch
files. Run old native recovery on a dedicated recovery workstation with the
supported patched image tools and verify the resulting images before use.

For managed Linux files, provide the host prefix that was configured on the
agent. S3 can list archived versions without an age identity. The listing's
file-set name and upload time come from the S3 object key and metadata. Use
the independent age identity to verify and extract the chosen version.

```sh
"$VESTA_RESTORE" s3 list --s3-config /secure/s3.json \
  --file-prefix linux-backup/host-a --set documents

"$VESTA_RESTORE" s3 restore --s3-config /secure/s3.json \
  --file-prefix linux-backup/host-a --set documents --backup "$BACKUP_ID" \
  --version-id "$OBJECT_VERSION" --identity /secure/file-recovery.agekey \
  --output /restore/new-files --select reports
```

Add `--sha256` with the ciphertext digest from a trusted backup receipt to
authenticate the chosen archive's origin. The age identity authenticates
decryption and archive integrity. Keep the recovery identity independent of
the bucket and backup host.

## VM chain inputs

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
`session_token` supports temporary credentials. Grant object read access only. The chain-file mode opens the exact
objects recorded in the supplied bundle.

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
