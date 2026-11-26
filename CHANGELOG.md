# Release notes

## 6.1.1

Backup progress keeps each size with its unit on narrow screens. In Hebrew, the transferred size and total stay in order as the backup runs. Thanks to [@bfs2021](https://github.com/bfs2021) for [PR #8](https://github.com/Insitu-IT/vesta/pull/8).

Native libvirt agents now have separate EL9 and EL10 x86_64 RPMs for the existing supported virtualization stack. [Host requirements](packaging/community/installation-requirements.md)

## 6.1.0

Vesta’s first Community release includes the offline installation kit, native `vesta-agent` RPM, standalone disk recovery tool and workstation CLI. Use the manifest launcher for installation and scoped cluster checks. The console and operator API explain which backup mode is available for the selected VM and its disks. Eligible sites that cross the registration trigger receive a free two-year license for one installation.

[Release notes and signed downloads](https://github.com/Insitu-IT/vesta/releases/tag/v6.1.0) · [Matching Community source](https://github.com/Insitu-IT/vesta/tree/v6.1.0) · [Installation requirements](packaging/community/installation-requirements.md)

The [release channel](https://github.com/Insitu-IT/vesta/releases) lists published updates. Before updating a running installation, keep its accepted manifest and the matching kit. [Component versions, upgrades and rollback](packaging/community/UPGRADES.md)
