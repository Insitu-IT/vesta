# Install the control plane

[Verify the prebuilt release](https://vestabackup.com/docs/console/) on your operator workstation. The kit includes the images and an executable launcher. Run `./vesta init` in the extracted directory and edit the generated `vesta.json` for your cluster.

## Run the installation

```sh
./vesta check
./vesta import-images
./vesta install
./vesta status
```

Use `./vesta plan` for an offline view of the selected images and deployment stages. You can point any manifest command at your saved site file, for example `./vesta check --manifest /private/vesta/site.json`. Your registry, cluster access, Secrets and trust must already be available. [Prepare your site](https://vestabackup.com/docs/install/)

The installation brings up the API and console. Complete [first configuration](first-configuration.md) to connect storage and an agent. For a site using a separately managed database, follow [customer-managed PostgreSQL](customer-postgresql.md). For a running site, use [upgrades and rollback](upgrade-recovery.md).

Back up a disposable VM and [restore a fresh copy](restore.md) to check your installation before scheduling other workloads.
