# Customer OKD preflight

Read-only environment discovery for the supported KubeVirt backup path. Requires
Bash, `jq`, and an authenticated `oc` on the customer's own host. These scripts do
not install, update, restart, back up, or restore anything. `oc auth can-i` submits
access reviews only; it does not create the resources whose permissions it checks.

## Collect an explicitly scoped report

Run from the directory containing these scripts, choosing the context and each
workload namespace explicitly:

```bash
umask 077
bash customer-preflight.sh \
  --context customer-context \
  --namespace backup-pilot \
  --vm pilot-vm \
  --output /private/reports/customer-preflight
```

The output directory must not exist; its parent must exist. The collector creates
it with mode 0700 and private files. Without `--output`, it creates a new
timestamped preflight directory in the current directory. Prefer a private
location outside the installation kit. `--oc-bin /absolute/path/to/oc` selects a specific
client; omitting `--context` uses the current context without switching it.

Repeat `--namespace` or `--vm` as needed. VM names apply in each selected namespace;
omitting `--vm` includes all VMs there. PVC/DataVolume and quota projections remain
namespace-wide, including template-created and scratch resources. Installation
facts such as nodes, operators, KubeVirt/HCO, storage classes and APIs are queried
cluster-wide. Bound-PV output is filtered to the selected namespaces. No other
workload namespaces are collected.

## Handle the report privately

Only allowlisted projections are saved: no Secret objects, kubeconfig, credentials,
cloud-init content, raw VM/domain definitions, PV handles, or raw server errors.
Reports still contain private inventory names, UIDs, labels, network references
and capacity information. Review every file before sharing. Do not commit reports,
attach them to public issues, or copy them into the portable kit.

S3/SSO credentials and customer-specific configuration are intentionally not
collected; configure those at the customer site. Permissions describe the current
`oc` identity, not the future agent ServiceAccount. Failed/denied queries are
reported as missing evidence; they do not justify a compatibility fallback.

## Interpret offline

```bash
bash customer-preflight-gates.sh /private/reports/customer-preflight
bash customer-preflight-scope.sh /private/reports/customer-preflight
```

Both commands only read the report and print JSON. Keep `umask 077` if redirecting
their output. The gates summary checks observed HCO/KubeVirt backup configuration
and the agent's exact served APIs: `backup.kubevirt.io/v1alpha1` for
backup/tracker and `export.kubevirt.io/v1beta1` for export. A CRD serving only
another version fails this prerequisite; no older-version fallback is implied.
The scope summary evaluates observed namespace/VM labels against rendered CBT
selectors, lists missing requested VMs, and reports each nominated VM's
observed VMI UID, phase, and CBT state when the VMI query succeeds.

`OK` means a query succeeded. `PASS` means only the stated configuration check
matched; `SELECTED` means only an observed label-selector match. An `Enabled`
VMI CBT state is observed runtime status, not proof of global pilot-only scope,
provider correctness, backup/restore success, supported-version qualification,
or customer acceptance.
`UNKNOWN`, `EMPTY`, `DENIED`, and `FAIL` need investigation; they are not passes.
An absent VMI is reported as `ABSENT`, and a present VMI without a CBT state
as `UNREPORTED`; neither is an active-CBT pass.

Scripts locate companion scripts beside themselves, so the directory can be
copied intact to a customer host without a source checkout or development tools.
