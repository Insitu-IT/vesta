# What comes with your installation

The release manifest and `install/supply-contract.json` list the supplied images and identify them by digest. Use the files from the same [GitHub release](https://github.com/Insitu-IT/vesta/releases/latest) as your runtime kit. Its source archive, third-party source and notices, and software bill of materials describe what the release contains.

| Component | Who provides it |
|---|---|
| Vesta API, web console and KubeVirt agent | The Community OKD kit includes the three prebuilt images, their embedded dependencies, the installer and database migrations. |
| PostgreSQL | With the Community `customer-postgresql` profile, you provide and operate PostgreSQL, configure its certificates and roles, and arrange database backup and recovery. A kit explicitly marked `full` additionally supplies a PostgreSQL image. |
| Cluster and storage | You provide compatible OKD, KubeVirt/CDI, persistent storage, an S3-compatible bucket and any identity provider you use. |
| Native libvirt agent | Native packages are a separate delivery. Check the release assets for your platform before planning a host installation. The OKD archive contains the KubeVirt agent. |

See [database preparation](customer-postgresql.md), [installation](installation.md) and the [first configuration guide](first-configuration.md) for the site inputs. Keep the signed checksums, manifest, sources and notices with the release when taking it offline. Third-party components retain their own terms.
