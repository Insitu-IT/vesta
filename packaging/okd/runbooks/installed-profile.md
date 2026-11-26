# Installation profiles

The Community control plane includes the web console and API. Connect KubeVirt agents for OpenShift Virtualization or OKD, and native agents for libvirt hosts. Operators can use local accounts or OpenID Connect single sign-on. Agents authenticate independently.

For a new installation, decide where the database and backup data will live. The release assets identify the available database profiles. [Customer-managed PostgreSQL](customer-postgresql.md) · [Bundled PostgreSQL](postgresql.md)

## Installed namespaces and resource names

The starter manifest uses `vesta` for the application namespace and `vesta-agent` for the agent namespace. You choose the source namespaces to protect, permitted restore destinations and durable storage.

Keep your accepted manifest with your recovery records. When updating a site, reuse its established resource names, agent identity, journals and keys. Let the installer read those values from that manifest. [Install Vesta](installation.md) · [Update an existing site](upgrade-recovery.md)

## Licenses

Review or import your license in **Settings → Licensing**. Your ability to restore a backup continues through a licensing reminder or a renewal. [Using a license](licensing.md)
