# Install Vesta and recover your first VM

Start with the prebuilt Linux amd64 kit and a disposable VM. For an existing site, follow [Upgrades and rollback](packaging/community/UPGRADES.md).

## Verify and unpack the kit

Open the [latest release](https://github.com/Insitu-IT/vesta/releases/latest). Download the OKD kit, `SHA256SUMS`, `SHA256SUMS.asc` and the `.gpg` keyring into an empty directory. On your first installation, confirm the signing key fingerprint with your administrator.

```sh
gpgv --keyring "$PWD"/vesta-release-*.gpg SHA256SUMS.asc SHA256SUMS &&
  sha256sum --check --ignore-missing SHA256SUMS
```

Look for a good signature and `OK` beside the installation kit. Extract it to a private directory.

```sh
mkdir -m 700 vesta-install
tar -xzf ./*-okd-amd64.tar.gz -C vesta-install
cd vesta-install
./vesta verify
./vesta init
```

## Describe your site and install

Edit the generated `vesta.json`. Enter your cluster context, registry, namespaces, hostnames and the names of the site Secrets. Your operator workstation needs Python 3.11 or later and an authenticated `oc` session. Use [Install on OKD or OpenShift](packaging/community/OKD.md) to prepare the storage, database and TLS inputs for your site.

```sh
./vesta check
./vesta import-images
./vesta install
```

The kit carries the application images with it. Skip the image import if the exact images are already in your registry. The launcher discovers `vesta.json` in the current directory. To use another copy, pass its path, for example `./vesta check --manifest /private/vesta/site.json`.

## Connect a workload and try recovery

Open the console at your configured HTTPS address. After the API is ready, use `./vesta configure` for your configured storage, SSO and enrolled agent, then `./vesta status` to check the installation. [Connect storage and agents](packaging/okd/runbooks/first-configuration.md)

Choose a disposable VM, back it up and restore a fresh copy. Compare a known file from the guest before scheduling protection for production workloads. [Recover your first VM](docs/first-recovery.md)
