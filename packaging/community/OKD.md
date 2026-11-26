# Install on OKD or OpenShift

The Community kit installs the Vesta API, web console and KubeVirt agent. The images travel with the kit so a disconnected cluster can use its own registry. A customer-managed PostgreSQL service and S3-compatible bucket can stay inside your network.

Start with [installation requirements](installation-requirements.md) for the database, virtualization APIs, machine architecture and storage allocations in the kit.

## Prepare your site

Use an operator workstation with Python 3.11 or later and an authenticated `oc` session. For an image import you also need `skopeo` and credentials for a cluster-reachable registry. Your platform team supplies the namespaces, storage classes, HTTPS names, TLS credentials and namespace Secrets. The [database guide](../okd/runbooks/customer-postgresql.md) explains the owner and runtime database roles. Check the release's database profile before provisioning a database.

## Install from one manifest

[Verify the kit and unpack it](../../QUICKSTART.md). Run the following in its root directory.

```sh
./vesta init
```

Edit `vesta.json`. Set your cluster context, destination registry, site routing and Secret references. Put credentials in the referenced Secrets. Use `./vesta plan` to inspect what the installer will use without connecting to a cluster.

```sh
./vesta check
./vesta import-images
./vesta install
```

The installer checks cluster prerequisites and resource conflicts before applying the manifest. Import the bundled images once for each destination registry. Keep a private copy of the accepted manifest for maintenance and recovery.

## Connect the first agent

When you can sign in, use the same manifest with `./vesta configure` to configure your S3 destination, optional OpenID Connect provider and enrolled KubeVirt agent. [First configuration](../okd/runbooks/first-configuration.md) covers credentials, key custody and the first heartbeat. Use `./vesta status` to check the site, then [restore a known file](../../docs/first-recovery.md).
