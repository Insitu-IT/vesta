# Vesta Agent RPM lifecycle

## Fresh install

The RPM creates the `vesta-agent` service account and installs
`vesta-agent.service`, `/usr/bin/vesta-restore`, optional native staging
tools, and the configuration example at `/etc/vesta/agent.env.example`.
The agent is initially disabled. Write `/etc/vesta/agent.env` with the
site settings before running `systemctl enable --now vesta-agent`.
New installations store their default key, backup and restore directories
under `/var/lib/vesta`. Optional file logs use `/var/log/vesta/agent.log`.

## Upgrade from the previous RPM name

Install the new `vesta-agent` RPM with DNF. In the same transaction DNF
replaces the previous agent RPM. The agent keeps the existing
service UID/GID, directories, keys and backup journals so recovery paths
continue to resolve. The package copies the previous environment file to
`/etc/vesta/agent.env` when the destination does not already exist
and carries across systemd drop-ins. Review local overrides that name
the old binary or service. Continue administering the new unit with
`systemctl status vesta-agent` and read its logs with
`journalctl -u vesta-agent`. Existing journal entries remain under the
former unit.

The agent's active and enabled states carry over independently.
When an existing optional native staging broker is configured, the
package retains its mounted storage and socket paths. Its active and
enabled states also carry over independently. The package never
enables or starts a broker on a fresh installation.

Existing libvirt and QEMU permissions and existing protected workloads keep
their identities. Before upgrading, pause new admissions, review active
and uncertain attempts, and retain a copy of the environment file, keys
and journals. See [installation and recovery](README.customer.md).

## Remove

`dnf remove vesta-agent` disables and stops the packaged services, removes
the packaged code and templates, and deletes the new default registration
key at `/var/lib/vesta/agent.key`. Site configuration, service identities,
backup files and journals remain available for recovery. Review credential
and backup retention separately according to your site's policy.

## Verify package lifecycle

On a disposable supported EL9 host, run
`sudo ./test-rpm-cycles.sh /path/to/vesta-agent.rpm` for a fresh cycle.
Pass the previous agent RPM as the second argument to exercise
the upgrade and retention of existing state.
