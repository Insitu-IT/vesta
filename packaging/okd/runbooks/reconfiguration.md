# Change site configuration

Use the accepted site manifest and the Vesta kit for your running release. Make a private copy as the desired `vesta.json`; edit the hostnames, source namespaces or restore destinations you intend to change. Keep the established installation and agent identities, database roles, keys and journal storage.

## Plan the change

From the directory holding your desired manifest, call the kit launcher. For example, when it is in the current directory:

```sh
./vesta reconfigure plan --previous /private/vesta/accepted.json --state /private/vesta/change
```

Use a new private state directory for each change. Inspect the proposed resource and access changes. Prepare both old and new DNS names, TLS trust and any SSO callback addresses before a hostname change. Back up the accepted manifest, keys and recovery information.

## Apply and verify

Pause new backup admissions and wait for current work to drain. Record your schedule and maintenance settings. Then apply the reviewed plan.

```sh
./vesta reconfigure apply --state /private/vesta/change --quiesced --custody-confirmed --external-ready
```

The confirmations refer to the running site and the external preparations you have completed. Check sign-in, TLS, storage, the agent heartbeat, source inventory and restore access at the expected names. Save the verified manifest as the new accepted copy.

```sh
./vesta reconfigure accept --state /private/vesta/change --quiesced --paths-verified
```

Resume admissions and schedules after acceptance. The application can restart during a configuration change.

## Roll back this change

While work is quiesced, roll back the latest applied transaction and verify the original paths before resuming. Vesta checks the site's revision, the affected objects and the identities of namespaces whose access it would restore. If another change has since been accepted, start with that later transaction. Repeating a verified rollback leaves the site as it is.

```sh
./vesta reconfigure rollback --state /private/vesta/change --quiesced
```

For a software version change, follow [Upgrades and rollback](upgrade-recovery.md).
