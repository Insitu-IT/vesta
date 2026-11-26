# Check your installation

From the extracted kit, run the check against the manifest you will install.

```sh
./vesta check
```

The command checks the cluster context, required Secrets and keys, storage classes, selected APIs, resource conflicts and permission to create the planned objects. Resolve any reported failure and repeat the check. To see the planned resources without contacting the cluster, run `./vesta plan`.

For KubeVirt, capture the platform's backup capability report when assessing a new cluster or storage configuration.

```sh
./vesta preflight --output-dir /private/vesta/preflight
```

After installation, `./vesta status` reports service readiness. A [first recovery](https://vestabackup.com/docs/first-recovery/) demonstrates that your VM, encryption key and storage work together.
