# Install a native libvirt agent package

Use a native RPM supplied for your host's supported profile. [GitHub Releases](https://github.com/Insitu-IT/vesta/releases/latest) lists the available assets. The OKD kit includes the KubeVirt agent. If there is no matching native package for your host, ask in [GitHub Issues](https://github.com/Insitu-IT/vesta/issues) before installing.

This RPM installs the native libvirt agent, its systemd service, the raw-disk
restore command, and native staging/recovery helpers. It does not install the
backend/UI or configure storage, keys, authentication or scheduling for the site.

Consult the licence and notices for the exact RPM release you installed. The
RPM includes the full product licence and upstream dependency notices as
`%license` documents under `/usr/share/licenses/vesta-agent/`. Keep those notices
with redistributed packages.

## Host requirements and configuration

Use the native EL9 x86_64 package on a compatible libvirt host. Native push backup accepts libvirt **11.10.x or 12.7.x**, a running QEMU **10.1.x** domain and **qemu-img 10.1.x**. Package-manager dependency minimums alone cannot establish compatibility. The host also needs the libvirt QEMU driver and Python bindings, systemd, ACL and polkit support. Check the running domain and its backup and checkpoint interfaces before protecting important VMs.

Provision `/etc/vesta/agent.env` privately with the site's backend URL, serving
and client trust, scoped registration/authentication inputs and stable identity.
Do not copy credentials into shell arguments or logs. The agent's journal and
identity under `/var/lib/vesta` are recovery material; preserve them during updates.
Enrollment requires a scoped registration key from the running backend. Do not
disable TLS verification or give the agent unrestricted sudo to bypass setup.

## Install or update safely

Verify the package source/checksum and the site's signature policy before install.
Use the normal dependency-resolving package manager; do not force missing
dependencies. Use a package signed or otherwise authenticated according to your site's release policy. No libvirt/QEMU package or VM change is part of an agent-only update.

Before an important host update, pause new admissions and review active/uncertain
attempts. Retain a rollback package and current configuration/key/journal custody.
The agent service may be replaced/restarted during its package transaction; that
does not prove a previously started producer has stopped. Do not restart libvirt,
QEMU, VMs or the host to make the agent update complete.

For upgrades from the former package name, see the [RPM lifecycle guide](INSTALL_UNINSTALL_BEHAVIOR.md). Existing installations retain their backup and credential paths and service identity.

## Diagnostics and recovery

The host administrator can read ordinary service status and bounded logs:

```bash
systemctl status vesta-agent --no-pager
journalctl -u vesta-agent --since '1 hour ago' -n 200 --no-pager -o short-iso
```

New agent monitoring queries can use the `vesta_agent_` metric prefix. The agent exposes the same samples under the previous prefix for existing dashboards and alerts. Use one prefix per query.

Use the backend's System Health diagnostic download to correlate agent and
operation UUIDs. Raw logs may contain customer information; inspect/sanitize
them locally before sharing. Do not export environment, keys, VM XML or disks
as diagnostics. Never automatically send a report to a vendor endpoint.

For interrupted work, preserve the original attempt/journal and use the product's
same-attempt recovery. A missing job/journal or an expired retention period is not
cleanup authority. Never sweep checkpoints, abort unidentified jobs, remove source
disks or clear a database hold to force progress. Independent VM-changing clients
must retain their operations. If writer termination remains uncertain, keep the
attempt held and escalate; a VM shutdown is a separately reviewed last resort.

`vesta-restore -h` describes the installed offline restore/verification command.
It reconstructs into a new output directory and does not replace an existing VM.
Keep source, accepted backups and key custody intact until the fresh target has
been independently validated.

## Supply and support responsibilities

The RPM ships `supply-contract.json` under its RPM documentation directory.
Its `native-rpm` profile lists the supplied agent, restore command and embedded libraries separately from the host packages you maintain. Check the package inventory, supported libvirt/QEMU dependencies, license and upstream notices for the RPM you receive. Retain those notices if you redistribute the package.
