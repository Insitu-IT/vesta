# Frequently asked questions

## Does Vesta back up bare-metal servers?

Vesta can protect selected directories on a supported Linux server and the VMs on a libvirt host. Rebuilding a physical server from a whole-machine image needs a separate recovery plan.

## Can I restore a single file?

Yes. For a [Linux file backup](../packaging/okd/runbooks/file-backups.md), list the archive and extract just the file you need with `vesta-restore`. For a VM backup, restore a fresh copy of the VM on an isolated network and copy the file out. You can also recover a disk and mount its filesystem read-only on a trusted machine. You choose the file in the recovered filesystem. Vesta has no built-in file picker. [Restore a VM or disk](../packaging/okd/runbooks/restore.md)

## Can I back up folders on my laptop?

The enrolled Linux service can back up named directories on supported Enterprise Linux hosts. It runs on a schedule and needs access to your Vesta installation and S3 storage. Windows and macOS desktop backup clients are outside the current release. [Linux file backups](../packaging/okd/runbooks/file-backups.md)

## Does Vesta work with VMware, Nutanix AHV or Hyper-V?

Vesta supports KubeVirt and native libvirt/KVM. It has no backup agent for VMware vSphere, Nutanix AHV or Microsoft Hyper-V.

## Will an older OpenShift or OKD cluster work?

It depends on the virtualization features your cluster provides. Vesta needs VM backup, changed-block tracking and export support. Run the Vesta preflight for one VM to see what’s available on your cluster. [Check your VM and storage](../packaging/community/storage-compatibility.md)

## Does Vesta back up an entire OpenShift cluster, including all PVCs and etcd?

No. Vesta protects VMs and their selected persistent disks. Use a separate cluster backup for etcd and a backup tool for application PVCs that aren’t attached to a VM. A cluster without virtualization has no guest VMs for the KubeVirt agent to protect.

## Can one console manage both libvirt/KVM and KubeVirt VMs?

Yes. Enroll the native libvirt agents and the KubeVirt agent with the same Vesta installation. You’ll see their VMs in one console and can schedule backups for both. [Connect your agents](../agent/README.md)

## Can the console stay at headquarters while agents run at branches?

Yes, with a routed connection such as a site-to-site VPN. The branch agent must reach the Vesta API, and the API must be able to reach the agent to start jobs. Use mutual TLS between them. Backup data goes directly from the agent to its S3 bucket. Try a backup and restore over your link to see how long each takes. [Network and storage requirements](../packaging/community/installation-requirements.md)

## What happens when my two-year free license expires?

Your backups, schedules and restores keep working. The console shows a reminder. If your installation still needs a free license, renew it in the portal and import the new file in **Settings → License**. [Renew a free license](../REGISTRATION.md#renew-a-free-license)

## Can someone who can read my bucket read my backups?

Encrypted VM disks need separately held keys. Linux file archives need their private recovery identity. A bucket reader can still see object sizes and names, and VM manifests can expose details such as volume identifiers and changed disk ranges. [What an S3 reader can see](../packaging/okd/runbooks/encryption-custody.md)

## Can I recover by pointing Vesta at my S3 bucket?

Yes. Browse the recovery points in the bucket, choose one and restore to a fresh destination. VM backups with encryption need the matching keys. The public recovery trust identifies signed points from your installation. Linux files use their separate private age identity. [Recover directly from S3](../packaging/okd/runbooks/bucket-recovery.md)
