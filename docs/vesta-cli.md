# Use the Vesta operator CLI

Use `vesta-cli` to inspect an installation, track a backup, or run authorized API operations from a terminal. It works from a Linux amd64 workstation or job runner that can reach your Vesta API. The installation kit’s `./vesta` command handles cluster installation and site configuration. [Manage a site from its manifest](../packaging/okd/runbooks/site-manifest.md)

## Install the binary

Open the [matching GitHub release](https://github.com/Insitu-IT/vesta/releases) and download `vesta-cli-linux-amd64`, `SHA256SUMS`, its detached signature, and the release keyring. Follow the [download verification instructions](../QUICKSTART.md#verify-and-unpack-the-kit) and look for `OK` beside the CLI filename. You can transfer those files to a disconnected workstation.

Install the verified file in a directory on your `PATH`. These commands use a personal installation on Linux.

```sh
install -Dm755 vesta-cli-linux-amd64 "$HOME/.local/bin/vesta-cli"
vesta-cli version
vesta-cli doctor --offline
```

The offline report describes the API contract built into this CLI. `vesta-cli discover` lists the commands it understands. The release’s compliance download includes the CLI license, dependency inventory and notices.

## Connect to your installation

Set `VESTA_URL` to the HTTPS origin of **your Vesta API**, without `/api/v1`. For a site using a private certificate authority, set `VESTA_CA_FILE` to the path of its PEM bundle.

```sh
export VESTA_URL=https://api.vesta.example.org
```

If your site enables password sign-in, the CLI can prompt at the terminal and save the issued token in a private file. Replace `YOUR_USER` with your Vesta username.

```sh
session_dir="$HOME/.config/vesta-cli"
install -d -m 700 "$session_dir"
vesta-cli auth login --username YOUR_USER --password-prompt --token-out "$session_dir/operator.token"
export VESTA_TOKEN_FILE="$session_dir/operator.token"
vesta-cli auth whoami
```

For unattended use, point `VESTA_TOKEN_FILE` at the private token file provided for that site and role. Keep separate credentials for different API origins. Run `vesta-cli doctor` to check discovery and report which reads your identity can make.

## Work with Linux file backups

Use the same operator login as the console. List the sets enrolled by each host, inspect recent runs, or view schedules:

```sh
vesta-cli file-sets list
vesta-cli file-backups list
vesta-cli file-schedules list
```

For an immediate run, `vesta-cli file-backups run-now --help` shows how to pass the target and a saved request ID. Reuse that same ID after an interrupted response. The [file backup guide](../packaging/okd/runbooks/file-backups.md) covers the host configuration and independent recovery command.

## Find a VM or follow a backup

List one page of VMs. JSON is the default output.

```sh
vesta-cli agents list-vms --limit 20
```

When a backup request already exists, use its original request ID to see what happened. Set `REQUEST_ID` to the UUID recorded when the request was submitted.

```sh
vesta-cli backups explain --request-id "$REQUEST_ID"
vesta-cli backups wait --request-id "$REQUEST_ID" --until-status completed --deadline 5m --stream
```

The wait command emits newline-delimited JSON with `--stream`. Reaching the requested status tells you what the API observed. To verify recovery, restore a fresh copy and compare a known file from the guest. [Recover your first VM](first-recovery.md)

## Find a VM recovery point in S3

On the original installation, save its public recovery trust once and check when a backup’s signed record is ready. Here `source` and `recovery` are CLI profiles for your installations.

```sh
vesta-cli --profile source bucket-recovery trust --out-file ./source-trust.json
vesta-cli --profile source bucket-recovery readiness "$BACKUP_ID"
```

On the recovery installation, configure a read-only S3 account and import the matching keys for encrypted VMs. List recovery points, then use the backup ID from the list to inspect the disks and network mappings.

```sh
trust=$(cat ./source-trust.json)
vesta-cli --profile recovery bucket-recovery discover --trust "$trust"
vesta-cli --profile recovery bucket-recovery preview "$BACKUP_ID" --trust "$trust"
```

Use `bucket-recovery restore --help` to choose a fresh destination and supply the mappings from the preview. Save one request ID before starting and reuse it if the response is interrupted. A workstation without a running Vesta API can use the standalone `vesta-restore` executable. [Recover directly from S3](../packaging/okd/runbooks/bucket-recovery.md)

Use `vesta-cli COMMAND --help` for command-specific inputs and the [versioned API reference](https://vestabackup.com/docs/api/) for request and response fields. [Operate Vesta with an automation agent](operating-with-agents.md)
