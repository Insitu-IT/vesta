# What an S3 reader can see

For a VM backup with client-side encryption enabled, Vesta encrypts the disk bytes on the agent before upload. A reader with the bucket objects alone lacks the keys that decrypt those bytes. A VM capture made with encryption disabled stores disk contents and the captured definition in readable form. Linux file backups use their own public recovery recipient. The corresponding private identity can stay on a separate recovery workstation.

| Backup type | Visible to someone who can read the bucket | Protected content and independent recovery material |
| --- | --- | --- |
| KubeVirt VM | Object keys, sizes, versions, structural manifests, source and volume identifiers, checkpoints, extent layout and checksums | Disk payloads and the captured VM definition are encrypted. For independent recovery, keep the appropriate recovery trust and encryption keys. A saved chain bundle and its data keys are also supported. |
| Native libvirt VM | Object keys, sizes and versions. Publication and receipt metadata can include identifiers, checksums and wrapped data keys. | With encryption enabled, the native disk artifacts, domain XML, checkpoint XML and backup metadata artifacts are encrypted. The native restore reader uses the same independent custody for its recovery trust and keys. |
| Linux file set | Bucket, host prefix, file-set label, backup ID, archive size, object version and ciphertext checksum | Paths, file contents and the archive inventory are encrypted. Keep the separate age identity. Retain the receipt to identify the intended recovery point and recipient independently of who can write to the bucket. |

Bucket listings and operational manifests are sensitive inventory. A published plaintext checksum can identify a known file. Use neutral file-set labels when names themselves are sensitive.

## Keep the keys with their recovery copies

For encrypted VM captures, Vesta generates a fresh 256-bit data encryption key for each backup attempt. The agent streams AES-256-GCM-encrypted chunks to S3. The control plane wraps the data key with the selected key-encryption key. With local key management, the installation key protects stored key-encryption keys and service credentials in PostgreSQL. Some storage profiles include the wrapped data key in their generation manifest.

- **Recover a VM disk independently.** Give the workstation read access to the selected S3 versions and supply the matching independently kept KEK export. [Choose a recovery point in the bucket](bucket-recovery.md). The reader uses the generation’s object receipts and wrapped data keys. The standalone reader checks the recorded sizes and plaintext and ciphertext hashes as it reconstructs the disk. An exported chain bundle is a metadata-only alternative and requires its separate backup data keys. [VM recovery](restore.md)
- **Recover a Linux file independently.** Keep the private age identity and read-only storage credentials apart from the source host. The agent uses the public recipient for writing. The recovery tool verifies the complete encrypted archive before publishing the selected files. [File recovery](file-backups.md)
- **Back up the installation.** Keep a recoverable database copy and its corresponding installation key under separate access controls. A password-protected KEK export can recover the keys it contains. Those keys work with the matching wrapped data keys. Use the generated export passphrase, or choose a long passphrase of your own. Store it separately from the encrypted export. Test an older retained export with its original passphrase before replacing it.

## During a VM restore

An active or held restore may need its data keys and scoped S3 credentials again after a restart. The native agent keeps that state in its private journal. A KubeVirt restore also projects temporary credentials into its worker. Treat those journal volumes, temporary Kubernetes Secrets, and any copies of them as decryption credentials for the affected backup chain.

Restrict host and volume access to the restore service and its operators. Use restricted Kubernetes roles and protect persisted cluster Secrets and their backups. Collect the operation ID and status when asking for help. Keep raw journals, key files, credential-bearing manifests and database dumps out of support tickets. For a held operation, establish whether its worker can still run before retiring its credentials or reclaiming its journal. [Held backup review](held-backup-review.md)

## If storage or recovery material is exposed

Restrict the affected storage credentials and preserve object versions and access records. Establish separately who could read the bucket, who could change it, and which keys, exports or journals were accessible. Storage write or delete access can affect recovery availability even when encryption keeps the contents private.

Use the saved recovery trust to verify the bucket’s recovery records. A signed record identifies its installation and pins a particular generation and object versions. Earlier complete, unsigned generations can be recovered for inspection to a fresh local output when the operator accepts the unverified origin. These points carry recovery data, not authority to schedule, delete, or extend other backups. A trusted database copy and its matching installation key also allow a control-plane recovery.

If a recovery key or an export with its passphrase was exposed, issue new keys for future backups, rotate affected storage and service credentials, and review the retention of earlier copies. Rewrapping the installation database preserves existing backup data keys. Someone who already holds a vulnerable combination of earlier data and keys may retain access to those copies. [Installation key rotation](installation-key-rotation.md) · [Incident recovery](https://vestabackup.com/docs/recovery-incidents/)
