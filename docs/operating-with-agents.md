# Operate Vesta with an automation agent

Start with the site, the work you want done, and a credential scoped to that work. An agent can inventory VMs, explain a delayed backup, or follow an existing request using structured output. It can also run the site's approved manifest through the installer from an operator workstation.

## Choose the command

| Task | Command | What it uses |
| --- | --- | --- |
| Plan, install or reconfigure a site | `./vesta` from the offline kit | A `vesta.json` manifest and the selected OpenShift context |
| Inspect VMs, backups, queues and operator requests | `vesta-cli` | Your site's HTTPS API and an operator identity |
| Reconstruct raw disks when the server is unavailable | `vesta-restore` | Saved backup-chain metadata, backup objects and any required recovery keys |

For a named Linux file set, discover the set and its advertised destination before requesting a backup. Follow the receipt to the completed recovery point. Keep the private recovery identity on the authorized recovery workstation. [File backup and recovery](../packaging/okd/runbooks/file-backups.md)

Keep tokens, kubeconfigs and recovery keys in the site's credential store. Give the runner the relevant file paths. Keep credentials and disk contents out of prompts, transcripts and issue reports. [Install the CLI and connect it to a site](vesta-cli.md)

## Inspect an existing site

With the API origin and token file supplied to the runner, start with these reads.

```sh
vesta-cli doctor --offline
vesta-cli doctor --deadline 30s
vesta-cli agents list-vms --limit 20
```

The offline report identifies the local client. The second command reads the deployment's advertised capabilities and reports the access it observed. Use the returned identifiers for subsequent reads. A list can be incomplete. When a wider inventory is needed, set explicit page and item limits and check the pagination result.

For a cluster-side health check, run `./vesta status` with the accepted site manifest. For a **fresh installation**, `./vesta plan` shows the selected images and stages, and `./vesta check` checks prerequisites before `./vesta install`. [Site manifest guide](../packaging/okd/runbooks/site-manifest.md)

## Track one requested change

For a command that needs an idempotency key, generate and save one **before** sending the request. Bind that ID to the target, action and parameters in your job record.

```sh
vesta-cli operator-recovery new-request-id --output id
```

If the connection drops after submission, inspect the original request before deciding what to do next. Set `REQUEST_ID` to its saved UUID.

```sh
vesta-cli operator-recovery operator-request-outcome "$REQUEST_ID"
vesta-cli backups explain --request-id "$REQUEST_ID"
```

A new UUID can submit a second operation. For an existing request, pass the saved ID to the supported recovery command. Supply `--yes` only for the specific high-impact action the site operator approved. For changes to a running installation, use the [reconfiguration procedure](../packaging/okd/runbooks/reconfiguration.md) and the transaction state it produces.

Report the site, request or backup ID, observed status and any remaining uncertainty. Use a bounded `backups wait` when requested. A completed backup and a verified restore are different observations. [Restore and check a fresh VM](first-recovery.md)

If the task calls for changing Vesta's source or documentation, follow the [contributor reading guide](../AGENTS.md).

For a bucket recovery, use `bucket-recovery discover` and `preview` with the source installation’s saved public trust. Report the selected point, destination and required disk or network mappings before starting a restore. Preserve the original request ID across retries. [CLI recovery commands](vesta-cli.md#find-a-vm-recovery-point-in-s3)
