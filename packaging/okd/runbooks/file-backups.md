# Back up a Linux directory to S3

Use a file set to protect a directory of finished database dumps, configuration exports, or ordinary files. Vesta takes a full, client-side encrypted copy on each run. You can start it from **Backups** and schedule it alongside VM jobs. A Linux host can protect files on its own, or protect both files and libvirt VMs.

## Keep a recovery key

On a trusted Linux workstation, install the signed `vesta-restore-linux-amd64` download as `vesta-restore`. Pick a new private filename and run:

```sh
vesta-restore files keygen --identity ./exports-recovery.key
```

The command saves the private identity in that file and prints the public recipient beginning with `age1`. Give the source host the public recipient. Store the private identity somewhere you can reach after losing both the host and the console. Keep earlier identities while their backups are retained. To identify an older key, run `vesta-restore files recipient --identity ./exports-recovery.key`. Its fingerprint is the SHA-256 of the printed public recipient text without the final newline. Each completed receipt records the fingerprint used for that backup.

## Connect the host

1. Install the Enterprise Linux 9 or 10 RPM from [GitHub Releases](https://github.com/Insitu-IT/vesta/releases/latest). Choose `vesta-agent-files` for a file-only server, or `vesta-agent` for a libvirt host. Both install the same service and recovery command. On an enrolled libvirt host, keep its identity and add `VESTA_WORKLOADS=vm,files` to its agent environment.
2. Follow the [agent enrollment guide](first-configuration.md#5-enroll-the-agent-and-select-the-scope) to configure the Vesta API URL, agent credentials and mutual TLS. Copy the packaged `file-backups.json.example` to `/etc/vesta/file-backups.json`. Set its ownership so the service can read it and restrict access to the administrator and service account.
3. In that file, give each directory a short name, an absolute root and its public recipient. Set the HTTPS S3 endpoint, bucket, region, dedicated prefix and scoped upload credential. Enable versioning on the bucket. The agent needs permission to check versioning, conditionally create an object, inspect the object it wrote and abort an incomplete multipart upload. [Package configuration](../../rpm/README.files.md)
4. Give the service account read access to the directory. Start or restart `vesta-agent`. Its next heartbeat advertises the named sets. The console shows the name, host, destination and recipient fingerprint. The host keeps the local paths and storage credentials.

For a database, write a completed database-native dump into the directory. For files that change together, prepare a consistent export or filesystem snapshot first. A directory traversal can observe its files at different times. Use regular files and directories. Symbolic links and special files cause the job to stop. Use UTF-8 names without backslashes, up to 4,095 bytes per relative path and 128 path components. Very wide directories can reach the 16 MiB working limit for sorting names. Split a large directory into independent sets if needed. Allow space on the host for one encrypted archive. The package configuration sets the maximum archive size.

## Run it and check the result

Open **Backups → File backups**, pick the host and file set, check the destination, and choose **Run now**. The row shows the result or a reason the job stopped. Expand **Archive details** on a completed run to see its S3 location, object version and SHA-256. Save this receipt with your recovery records when you need to verify the exact point later.

In **Schedules → File backup schedules**, an administrator can name a schedule, select a set and enter a UTC cron expression. For example, `0 2 * * *` runs at 02:00 UTC each day. The schedule shows its next run and last success. Pausing or removing it leaves completed archives in S3. Set the retention and version-expiry policy on your bucket. If storage loses an upload response, the agent holds the staged encrypted bytes while it confirms the exact object version. Keep its journal and staging directory. Restore access to the original endpoint, region, bucket and prefix if they have changed.

## Recover a file on a clean workstation

Download the signed recovery executable. `vesta-restore --version` identifies its release and `vesta-restore --file-archive-format` identifies its file format. File recovery works on Linux amd64 with the recovery identity, a local encrypted archive or HTTPS access to S3, and a new output directory under a parent you control. It runs independently of the Vesta API and hypervisor.

Use the receipt's S3 URI, or use your S3 browser to find a backup by set name and object creation time under `<host-prefix>/managed-files/<set-name>/`. Save the bucket, prefix and a working read-only credential with your recovery identity. Supply read-only access in the private `s3.json` described in the [recovery reference](../../../agent/cmd/vnbui-restore/README.md#vm-chain-inputs). To list an archive:

```sh
vesta-restore files list --archive "$ARCHIVE_URI" --s3-config ./s3.json --identity ./exports-recovery.key
```

Select a relative path shown in the inventory. This example also pins the object version and ciphertext checksum from the saved receipt:

```sh
vesta-restore files extract --archive "$ARCHIVE_URI" --s3-config ./s3.json \
  --s3-version-id "$OBJECT_VERSION" --sha256 "$ARCHIVE_SHA256" \
  --identity ./exports-recovery.key --select database.dump --output ./recovered
```

Omit `--select` to restore the whole set. For a downloaded archive, pass its local filename as `--archive` and omit the S3 options. Use `files verify` to verify without extracting. Extraction needs temporary space for the encrypted archive and destination space for the selected files. It verifies the complete archive before publishing the output. File contents, ordinary permission bits and modification times are recovered. Reapply any site-specific ownership, ACLs and extended attributes.

For a file **inside a VM backup**, use the [VM and disk restore guide](restore.md). Those backups hold virtual disks and use their own recovery bundles.
