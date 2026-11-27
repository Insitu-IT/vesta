# Connect storage, sign-in and agents

Use the same `vesta.json` that installed the control plane. The [site manifest guide](site-manifest.md) shows the supported fields and Secret keys. You can do the following tasks in the console when working interactively.

## 1 Sign in and check the installation

Open the configured console HTTPS address and sign in with an installation administrator account. **System Health** shows the API and database status. The API host also serves a local reference for your release, including when the site is disconnected.

## 2 Configure S3

Create a bucket or choose a dedicated prefix for Vesta. Grant the site's storage identity the necessary access to that location. Set the S3 endpoint, bucket, prefix, region and Secret name in the manifest. On the operator workstation run:

```sh
./vesta configure
```

The launcher tests access to the configured bucket. In the console you can also use **Settings → S3 Storage**. Store recovery credentials outside the cluster, protect earlier object versions as required by your retention policy and keep your encryption recovery keys separately.

## 3 Configure authentication

For single sign-on, register the Vesta client with your OpenID Connect provider. Its callback is `/api/v1/auth/oidc/callback` on the actual Vesta sign-in origin. Set your issuer, client, role mapping and Secret reference in the manifest, then run `./vesta configure`. Open a separate browser session and verify the intended user's access and logout. Keep a working local recovery account.

## 4 Establish encryption recovery custody

Open **Settings → Encryption**. Create a backup encryption key and export a password-protected recovery copy. Store the exported file and its password in separate approved custody. Use **Verify saved export** and record the recovery location with your administrator. The installation encryption key that protects stored credentials and the backup encryption key have different jobs. Keep recovery copies of both.

With client-side encryption enabled, data is encrypted before it reaches S3. Your storage provider does not receive your recovery key. Verify a recovery with a disposable VM before protecting important workloads.

## 5 Enroll the agent and select the scope

For KubeVirt, choose the workloads to protect and the allowed restore destinations in `vesta.json`. Create a one-use registration key in **Settings → API Keys** or use:

```sh
./vesta agent-key --output /private/vesta/registration-key
```

Deliver the key to the agent's registration Secret. Preserve the stable agent identity, shared secret and keystore. Run `./vesta configure` to bring up the enrolled KubeVirt agent and check its heartbeat. For a libvirt host, follow the [native agent guide](https://vestabackup.com/docs/manuals/native-agent/).

## 6 Accept the installation with disposable data

Run `./vesta status` and open **Agents**. Check the expected host and its most recent heartbeat. On **Virtual Machines**, select a disposable guest, run a backup, and [restore a fresh copy](https://vestabackup.com/docs/first-recovery/). Confirm the file you wrote is present.

## 7 Enable schedules and retention

Once you have verified a recovery, create a schedule for the workloads you intend to protect. Select retention for the recovery points you need. Review the first scheduled backup and its eligibility for verification. [Daily operations](operations.md)

For a recovery copy of VM keys, save the export and its passphrase in separate places. [What the bucket contains and which keys to keep](encryption-custody.md)
