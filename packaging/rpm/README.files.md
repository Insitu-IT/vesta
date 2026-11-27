# Managed Linux file backup packages

Install `vesta-agent-files` on Linux hosts that only protect directories. Install
`vesta-agent` on KVM hosts. The KVM package protects VMs by default and accepts
`VESTA_WORKLOADS=vm,files` in `/etc/vesta/agent.env` to add local directory sets.
Both packages install the `vesta-agent` service and the `vesta-restore` command.
On mixed hosts, file backups remain available while libvirt is down. Restart
the agent after restoring libvirt if VM availability stays unavailable.

Copy `/etc/vesta/agent.env.example` to `/etc/vesta/agent.env` with owner-only
permissions. Set the Vesta URL, scoped registration key and orchestrator key.
File backup requires verified HTTPS, a client certificate for traffic in each
direction, API-key validation and heartbeat. Configure the CA that issued the
orchestrator server certificate if it is absent from the system trust store.
Managed file jobs use the enrolled agent leaf for both its HTTPS server and its client callbacks. The agent follows enrollment renewal on new TLS connections. Its verified heartbeat supplies the current controller certificate fingerprint. For an existing host, retain its enrollment and certificate journal.

Install `/etc/vesta/file-backups.json` with mode `0640` and group `vesta-agent`.
Use the actual group of the service account on installations that retained a
legacy account. The packaged `file-backups.json.example` shows its structure.
Each set specifies a stable lowercase name, an absolute directory and an age
X25519 public recipient. Grant the service account read and traverse access
to the declared directory and its contents. Generate and store the corresponding
age identity independently of both the source agent and the Vesta control
plane. Retain identities for as long as archives encrypted to them are kept.

Set an HTTPS S3 endpoint, bucket and dedicated nonempty prefix. Enable versioning
for the archive prefix and support conditional object creation. Scope the agent
credential to upload and inspect its own prefix. For AWS-compatible policies,
grant `s3:PutObject`, `s3:AbortMultipartUpload`, `s3:GetObject` and
`s3:GetObjectVersion` under the configured `managed-files/` subtree plus
`s3:GetBucketVersioning` on the bucket. Grant `s3:ListBucketVersions` on the same
bucket with `s3:prefix` restricted to the host's managed-files subtree.

```json
{
  "Effect": "Allow",
  "Action": "s3:ListBucketVersions",
  "Resource": "arn:aws:s3:::BACKUP_BUCKET",
  "Condition": {"StringLike": {"s3:prefix": "HOST_PREFIX/managed-files/*"}}
}
```

The agent checks the exact object-key prefix before uploading. AWS may return
403 for a missing key on HEAD, so an interrupted upload relies on the scoped
version listing to distinguish an unused key from a retained version or
delete marker. If the listing is denied, the job waits and the service log
identifies the grant to correct. The agent checks a retained version's encrypted
bytes before reporting completion and refuses to create a replacement for a
deleted key. The recovery-only credential can use `s3:GetObjectVersion` for a
known version without the writer's listing grant.

The agent uses the configured region, derives it from a regional AWS endpoint where possible, and otherwise defaults to `us-east-1`. An optional `s3_ca_file` names a local CA bundle for the S3 endpoint.
Apply a storage lifecycle rule to expire incomplete multipart uploads.

The agent creates one encrypted archive at a time in its private state directory. An unresolved S3 upload keeps its encrypted copy while other sets can proceed, so several staged copies can coexist during a storage outage.
By default, that directory is `file-backups` alongside the enrollment key, and
the encrypted archive limit is 32 GiB. Set `max_archive_bytes` to match the
available scratch space and the expected set sizes. An alternate state mount
configured using `VESTA_FILE_BACKUP_STATE` must be writable by the service.
For the files-only service, add the mount to `ReadWritePaths` in a systemd
drop-in. If the mixed service must read home directories, set
`ProtectHome=read-only` in a systemd drop-in.

Use `systemctl enable --now vesta-agent` to start the agent on a fresh host.
Restart an enrolled agent after editing the local declarations. Check the
service journal with `journalctl -u vesta-agent`. After a completed job, retain
the S3 URI, object version and ciphertext SHA-256 for standalone recovery.
If the catalog is unavailable, find archive versions in S3 under
`<prefix>/managed-files/<file-set>/<backup-id>/archive.age`. Use object version
timestamps to select the backup.
