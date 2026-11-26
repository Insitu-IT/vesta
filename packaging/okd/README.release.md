# Install Vesta

This offline kit contains the Vesta API, web console, KubeVirt agent and a launcher for your operator workstation. The release page identifies the architecture and database profile. You can take the archive and its signed verification files into an air-gapped network.

## Set up a site

1. Verify the downloaded archive against the signed checksum list, then extract it into a private directory.
2. In the extracted directory, run `./vesta verify` and `./vesta init`.
3. Edit `vesta.json` with your cluster context, registry, namespaces, service hostnames, storage and Secret references. The operator workstation needs Python 3.11 or later and an authenticated `oc` session. Use `skopeo` to import images into your site's registry.
4. Run `./vesta check`. Resolve any reported prerequisite, then run `./vesta import-images` and `./vesta install`. You can skip the import when your registry already serves the exact images shown by `./vesta plan`.
5. Open your console and sign in. Use `./vesta configure` to connect the storage, optional OpenID Connect provider and enrolled KubeVirt agent in the manifest. Run `./vesta status` to check the installation.

The local manual `runbooks/site-manifest.md` explains each field and the applicable database and enrollment steps. Your platform team supplies cluster access, DNS, TLS trust, a storage class, the named Secrets and an S3-compatible bucket. The customer-managed database profile uses the PostgreSQL service you supply.

## Try a recovery

Select a disposable VM and write a file you can recognize. Back it up, restore a fresh copy and compare the file before scheduling protection for production workloads. From the root of the offline kit, open `runbooks/first-configuration.md` to connect your first agent and `runbooks/fresh-vm-restore.md` to recover a VM. [First configuration](https://vestabackup.com/docs/manuals/first-configuration/) · [First recovery](https://vestabackup.com/docs/first-recovery/)

## Maintain the site

Keep your accepted manifest and recovery keys in separate approved custody. `./vesta --help` lists the available operations. Provide a different manifest with `--manifest PATH` after a command. Use the local `runbooks/reconfiguration.md` for site changes and `runbooks/upgrade-recovery.md` for an upgrade or rollback. For a native libvirt host, install the separate `vesta-agent` RPM from the matching [GitHub release](https://github.com/Insitu-IT/vesta/releases).
