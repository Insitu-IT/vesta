# Recover a file from your first VM backup

Start with a disposable KubeVirt VM and a separate restore namespace. The
[Community kit guide](../packaging/community/OKD.md) covers installation.
Follow [first configuration](../packaging/okd/runbooks/first-configuration.md)
until the agent is connected, the S3 bucket passes its connection test, and
you’ve saved the exported recovery key somewhere you can reach if the cluster is down.

1. **Record a known file in the source guest.** In a disposable Linux guest,
   run the commands below. Keep the hash in your own test notes outside the VM.

   ```sh
   printf 'before backup\n' > "$HOME/vesta-recovery-example.txt"
   sync
   sha256sum "$HOME/vesta-recovery-example.txt"
   ```

2. **Create the first restore point.** In the console select the test VM and
   request a full backup. Wait for the completed backup in its history and
   record its ID. If it enters a hold, use the reason and operation ID in
   [backup safety](../packaging/okd/runbooks/backup-safety.md).
3. **Make a second, recognizable point.** Change the file to
   `after backup`, flush it and record its new SHA-256. Request an incremental
   backup using the existing chain. Wait for completion and record that point.
4. **Restore the incremental point.** Choose a new VM name, new disks and an
   isolated destination network. Inspect disk coverage in the preview. Wait
   for the restore to finish, review the new Halted VM and boot it on that
   network. In the restored guest run `sha256sum "$HOME/vesta-recovery-example.txt"`
   and compare it to the second hash. Restoring the full point to a different
   target should reproduce the first hash.

Record the selected point, guest hash and provider/storage versions with your
result. The [restore manual](../packaging/okd/runbooks/restore.md) explains
disk selection, key custody, validation and offline raw-disk recovery.
