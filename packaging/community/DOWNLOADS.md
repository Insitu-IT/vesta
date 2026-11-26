# Download Vesta

Open [GitHub Releases](https://github.com/Insitu-IT/vesta/releases/latest) and expand **Assets**.

- **OpenShift Virtualization or OKD** — download the prebuilt installation kit for your architecture. It contains the API, web console, KubeVirt agent and their container images.
- **Native libvirt** — select the `vesta-agent` RPM built for your host distribution and architecture.
- **Operate an existing site from a workstation or job runner** — download `vesta-cli-linux-amd64`. [Install and use the operator CLI](../../docs/vesta-cli.md).
- **Recover disks without an installation** — download `vesta-restore-linux-amd64` for a trusted Linux amd64 workstation. It is the same executable supplied with the agent. [Recover a raw disk](../okd/runbooks/restore.md#native-raw-disk-recovery).
- **Verify a download** — get the checksum list, detached signature and release verification keyring from the same release. Confirm the signing fingerprint with your administrator on first use.

The [quickstart](../../QUICKSTART.md) walks through verification and installation. You can take the kit into an air-gapped site. The version tag lets you browse the matching Community backup product source. The operator CLI ships as a binary. The compliance download carries its license and dependency notices alongside the software inventories and third-party material for the kit.
