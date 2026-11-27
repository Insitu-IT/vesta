# Release notes

## 6.2.0

- Back up named Linux directories to a versioned S3 bucket from the console. Start a job now, schedule it in UTC and check the last successful recovery point.
- Install the file-only agent on Enterprise Linux 9 or 10, or add file sets to an enrolled libvirt host.
- Use the versioned standalone recovery tool to list, verify or extract a file using an independently held recovery key. Existing VM recovery commands remain available.
- Browse recovery points in S3, verify their source, and restore to a fresh destination. Encrypted VMs use separately held recovery keys. New recovery-key exports support generated passphrases, and earlier exports use their original passphrase.

[Set up your first file backup](packaging/okd/runbooks/file-backups.md) · [Upgrade an installation](packaging/community/UPGRADES.md)

## 6.1.1

Backup progress keeps each size with its unit on narrow screens. In Hebrew, the transferred size and total stay in order as the backup runs. Thanks to [@bfs2021](https://github.com/bfs2021) for [PR #8](https://github.com/Insitu-IT/vesta/pull/8).

Native libvirt agents now have separate EL9 and EL10 x86_64 RPMs for the existing supported virtualization stack. [Host requirements](packaging/community/installation-requirements.md)

## 6.1.0

Vesta’s first Community release includes the offline installation kit, native `vesta-agent` RPM, standalone disk recovery tool and workstation CLI. Use the manifest launcher for installation and scoped cluster checks. The console and operator API explain which backup mode is available for the selected VM and its disks. Eligible sites that cross the registration trigger receive a free two-year license for one installation.

[Release notes and signed downloads](https://github.com/Insitu-IT/vesta/releases/tag/v6.1.0) · [Matching Community source](https://github.com/Insitu-IT/vesta/tree/v6.1.0) · [Installation requirements](packaging/community/installation-requirements.md)

The [release channel](https://github.com/Insitu-IT/vesta/releases) lists published updates. Before updating a running installation, keep its accepted manifest and the matching kit. [Component versions, upgrades and rollback](packaging/community/UPGRADES.md)
