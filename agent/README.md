# Connect an agent

Choose the agent for the platform that runs your VMs. Each host needs its own enrollment identity, verified HTTPS to the Vesta API, access to its workloads and durable storage for its journal.

## Linux directories

Use the file-only RPM on an Enterprise Linux host, or enable file sets on an enrolled libvirt host. The service advertises locally named directories and uploads encrypted archives directly to S3. [Connect a file set](../packaging/okd/runbooks/file-backups.md)

## OpenShift Virtualization and OKD

The [prebuilt kit](../packaging/community/OKD.md) includes the KubeVirt agent image. Set the agent mode, source namespaces, restore destinations and journal storage in your site manifest. Use the [first configuration guide](../packaging/okd/runbooks/first-configuration.md) to enroll the agent and verify its first heartbeat.

## Native libvirt on Linux

Choose the x86_64 RPM for your host’s Enterprise Linux major version. Look for `.el9.` or `.el10.` in the filename. Download that single RPM, verify it with the signed checksums and install it on the libvirt host. [GitHub Releases](https://github.com/Insitu-IT/vesta/releases/latest) · [Virtualization requirements](../packaging/community/installation-requirements.md)

```sh
sudo dnf install ./vesta-agent-[0-9]*.rpm
```

[Configure the native agent](https://vestabackup.com/docs/manuals/native-agent/). After enrollment, check the service and its recent messages.

```sh
systemctl status vesta-agent
journalctl -u vesta-agent -n 50
```

In the console, open **Agents** and check the recent authenticated heartbeat. Open **Virtual Machines**, select a disposable guest with the storage you intend to protect and [test a recovery](../docs/first-recovery.md).
