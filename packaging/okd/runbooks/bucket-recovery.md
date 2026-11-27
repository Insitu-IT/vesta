# Recover directly from S3

Choose your bucket, select a recovery point by name and time, and restore to a new destination. The bucket carries the recovery metadata. For encrypted VM backups, keep a recovery-key export and its passphrase outside the bucket. Linux file backups use their separate age identity.

## Prepare once

- Give a recovery workstation read access to the relevant bucket prefixes and retained object versions. Keep that credential independently of the source host and Vesta database.
- In Vesta, export the VM keys needed for the backups you intend to keep. Save the export and its passphrase separately. A new export includes the installation’s public recovery trust. You can also save the public trust file on its own, including for an unencrypted installation. Saving a trust file does not grant decryption access.
- When you rotate VM keys, keep earlier KEKs while their backups are retained. For Linux files, retain the private identity corresponding to each host’s configured public recipient. Test one actual recovery from a clean destination.

Vesta publishes readable, signed records for accepted VM recovery points. A record identifies the source installation, VM, recovery point and exact S3 generation. The generation contains the ordered requests, receipts and wrapped data keys. Older accepted generations can receive a signed record when the original database is available. Grant the installation permission to publish and read back the recovery metadata. A recovery workstation uses read-only storage access.

## Use a running or fresh console

Open **Recover from S3** and point the installation at the storage you want to recover from. Select the recovery trust for the source installation and import the matching VM keys when the data is encrypted. On a fresh installation, enroll the destination agent and confirm its normal TLS setup.

Under **Settings → Storage**, enter a dedicated S3 recovery reader. Give it permission to list the recovery prefixes and read the object versions you plan to restore. Scope it to the installations and backups this destination may read. A fresh recovery-only installation needs just this reader. If you use the installer, reference its Kubernetes Secret with `s3.recovery_secret` in your site manifest. [Site manifest](site-manifest.md)

Choose a recovery point, review its source and date, and select a compatible fresh destination. Review the storage and network mapping before starting a restored VM. A bucket listing allows you to find points. The signature against your saved trust, exact object identities and full data checks establish which bytes the recovery used.

## Use a standalone workstation

Download the signed `vesta-restore-linux-amd64` executable from [GitHub Releases](https://github.com/Insitu-IT/vesta/releases/latest). Use a trusted Linux workstation and a new output directory. Put read-only S3 connection details in a private `s3.json`. The [recovery reference](../../../agent/cmd/vnbui-restore/README.md#vm-chain-inputs) describes its fields.

List VM recovery points using the trust in your KEK export:

```sh
vesta-restore s3 list --s3-config ./s3.json --kek-export ./vm-keys.export
```

The list returns names, times and backup IDs in `items`. If it returns a `next_cursor`, pass it back with `--cursor` to see the next page. The `issues` field identifies entries the reader could not verify. Choose an available point. The tool prompts privately for the export passphrase when needed.

```sh
vesta-restore s3 restore --s3-config ./s3.json --backup "$BACKUP_ID" \
  --kek-export ./vm-keys.export --output ./recovered-disks
```

For an unencrypted VM, use `--trust ./recovery-trust.json` to verify the source. A native libvirt disk chain also requires the native restore tools described in the [recovery reference](../../../agent/cmd/vnbui-restore/README.md#native-libvirt-bundles). The standalone command writes disks into a fresh location. It leaves the choice of where and when to boot them to you.

For a Linux file set, use its host prefix to find its recovery points, then use the private age identity to select or extract the files. [Restore a file backup](file-backups.md#recover-a-file-on-a-clean-workstation)

## Recognize older points

Some earlier VM backups have a complete generation in S3 without a recovery signature. If the original database is gone, the standalone reader can recover a complete old generation to new, isolated disks when you explicitly accept its unverified origin with `--allow-unsigned-legacy`. Supply the matching keys for encrypted data and check the recovered VM or application in isolation. Keep an independent version or receipt when you have one.

For an exact historical lookup, use the independently saved trust file, a key export that contains trust, or source installation and organization IDs from independent records. Pass the IDs as `--installation-id` and `--org-id`. The reader checks for signed history at the exact source and backup name. A retained version or delete marker there blocks unsigned recovery. If you lack independent scope, the reader needs `s3:ListBucketVersions` under the entire `vesta-recovery/v1/` prefix and stops if it cannot establish absence within 65,536 entries.

A shorter historical chain listing can describe a backup without containing the object receipts or disk layout needed to reconstruct it. Look for the complete generation, a saved trusted chain bundle, or a matched database recovery copy. A record with a failed signature should be investigated before use.

S3 write and delete access can hide points or remove versions. Signatures identify a particular recovery point. Independent storage retention and a second protected copy help ensure that point remains available. [What an S3 reader can see](encryption-custody.md)
