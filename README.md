![Vesta Backup](branding/vesta/readme-mark.png)

# Back up your virtual machines with Vesta

Protect virtual machines on OpenShift Virtualization, OKD and native libvirt hosts. On compatible VM and storage configurations, Vesta sends full and incremental backups to the S3-compatible storage you choose. With client-side encryption, the data is encrypted before it reaches the bucket and the recovery keys stay with you.

Run the control plane on your own infrastructure, including in an air-gapped network. The Community edition includes single sign-on for operators and mutual TLS for agents. The [Community license](https://vestabackup.com/docs/legal/terms/) lets you study, modify and redistribute the covered code. Your ability to recover must never depend on your license status.

## Make your first recovery

Try the [interactive console demo](https://vestabackup.com/#recovery-demo), or see [what Vesta can back up and restore](docs/faq.md). The [Vesta documentation](https://vestabackup.com/docs/) walks through installation and day-to-day operation.

1. [Install Vesta](QUICKSTART.md) from the prebuilt [GitHub release](https://github.com/Insitu-IT/vesta/releases/latest).
2. [Connect your bucket and enroll an agent](packaging/okd/runbooks/first-configuration.md). Choose a disposable VM and write a file you can recognize.
3. [Back up the VM and restore a fresh copy](docs/first-recovery.md). Open the restored file and compare it with the original. Then schedule backups for the workloads you want to protect.

## Work with an existing installation

| I want to… | Guide |
|---|---|
| Check whether my storage and VM can use incrementals | [Storage compatibility](packaging/community/storage-compatibility.md) |
| Size a cluster and check its installed APIs | [Installation requirements](packaging/community/installation-requirements.md) |
| Understand the data path and recovery without the console | [Backup and recovery architecture](packaging/community/backup-and-recovery.md) |
| Plan recovery time and bucket growth | [Sizing and recovery time](packaging/community/sizing-and-recovery-time.md) |
| Recover when an agent, bucket or the control plane fails | [Incident recovery](packaging/community/recovery-incidents.md) |
| Connect an OpenShift, OKD or libvirt host | [VM agents](agent/README.md) |
| Schedule a backup or investigate a delay | [Daily operations](packaging/okd/runbooks/operations.md) |
| Restore a VM or recover individual disks | [Restore guide](packaging/okd/runbooks/restore.md) |
| Inspect VMs or follow a backup from the terminal | [Vesta operator CLI](docs/vesta-cli.md) |
| Operate a site with an automation agent | [Agent operating guide](docs/operating-with-agents.md) |
| Connect my own tools | [Using the API](docs/operator-api.md) |
| Update an installation | [Upgrades and rollback](packaging/community/UPGRADES.md) |

Explore the [roadmap](ROADMAP.md), report a problem in [GitHub Issues](https://github.com/Insitu-IT/vesta/issues), or [contribute a change](CONTRIBUTING.md).
