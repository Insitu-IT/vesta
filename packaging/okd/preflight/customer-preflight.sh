#!/usr/bin/env bash
# Read-only operator discovery. Does not establish backup/restore acceptance.
set -euo pipefail
umask 077

usage() {
  echo 'Usage: bash customer-preflight.sh --namespace NAME [--namespace NAME ...] [--vm NAME ...] [--context NAME] [--oc-bin ABSOLUTE_PATH] [--output NEW_DIRECTORY]'
  echo 'Requires authenticated oc and jq. --vm limits VM/VMI detail; names apply in each selected namespace.'
  echo 'Without --vm, collects inventory for all VMs in the selected namespaces.'
}
namespaces=() vms=()
context='' output='' oc_binary='' target_vm=''
while (($#)); do
  case "$1" in
    --namespace|--vm|--target-vm|--context|--oc-bin|--output)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --namespace) namespaces+=("$2");;
        --vm) vms+=("$2");;
        --target-vm) target_vm=$2;;
        --context) context=$2;;
        --oc-bin) oc_binary=$2;;
        --output) output=$2;;
      esac
      shift 2;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
((${#namespaces[@]})) || { usage >&2; exit 2; }
if [[ -n "$target_vm" ]]; then
  (("${#namespaces[@]}" == 1 && "${#vms[@]}" == 0)) || { usage >&2; exit 2; }
  vms=("$target_vm")
fi
for name in "${namespaces[@]}" "${vms[@]}"; do
  [[ "$name" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || { echo 'Invalid resource name' >&2; exit 2; }
done
if [[ -z "$oc_binary" ]]; then
  oc_binary=$(command -v oc) || { echo 'oc is required' >&2; exit 2; }
else
  [[ "$oc_binary" == /* && -x "$oc_binary" ]] || { echo '--oc-bin must be an executable absolute path' >&2; exit 2; }
fi
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 2; }
oc_cmd=("$oc_binary" --request-timeout=20s)
[[ -z "$context" ]] || oc_cmd+=(--context "$context")
if [[ -z "$output" ]]; then
  output=$(mktemp -d ./vnbui-customer-preflight.XXXXXXXX)
else
  mkdir -m 700 -- "$output" || { echo 'Output must be a new directory with an existing parent' >&2; exit 2; }
fi
vm_json=$(printf '%s\n' "${vms[@]}" | jq -Rsc 'split("\n")|map(select(length>0))')
ns_json=$(printf '%s\n' "${namespaces[@]}" | jq -Rsc 'split("\n")|map(select(length>0))')
jq -n --arg collected_at "$(date -u +%FT%TZ)" --argjson namespaces "$ns_json" --argjson vms "$vm_json" \
  '{schema:1,collected_at:$collected_at,namespaces:$namespaces,requested_vms:$vms,mode:"read-only discovery",warning:"OK means query succeeded, not prerequisite or product acceptance. UNKNOWN means evidence unavailable; EMPTY means no objects returned. Review inventory names before sharing."}' > "$output/report.json"

# Do not persist raw objects or raw server errors: only allowlisted projections.
collect() {
  local label=$1 filter=$2 raw filtered kind
  shift 2
  printf 'Checking %s\n' "$label" >&2
  if ! raw=$("${oc_cmd[@]}" "$@" 2>/dev/null); then
    jq -n --arg check "$label" '{check:$check,status:"UNKNOWN",reason:"Command failed: access denied, API unavailable, connectivity, or timeout. No raw error retained."}' > "$output/$label.json"
    return
  fi
  if [[ -n "$target_vm" && ( "$label" == "${namespaces[0]}-vms" || "$label" == "${namespaces[0]}-vmis" ) ]]; then
    if [[ -z "$raw" ]]; then
      raw='{"items":[]}'
    else
      kind=VirtualMachine
      [[ "$label" != "${namespaces[0]}-vmis" ]] || kind=VirtualMachineInstance
      raw=$(printf '%s' "$raw" | jq -c --arg kind "$kind" --arg vm "$target_vm" --arg ns "${namespaces[0]}" '
        if type == "object" and .apiVersion == "kubevirt.io/v1" and
          .kind == $kind and .metadata.name == $vm and .metadata.namespace == $ns
        then {items:[.]} else error("Unexpected resource shape") end' 2>/dev/null) || raw=''
    fi
    # jq on an empty stream succeeds, so make an unexpected object fail projection.
    [[ -n "$raw" ]] || raw='null'
  fi
  if ! filtered=$(printf '%s' "$raw" | jq --argjson vms "$vm_json" --argjson namespaces "$ns_json" "$filter" 2>/dev/null); then
    jq -n --arg check "$label" '{check:$check,status:"UNKNOWN",reason:"Unexpected response shape"}' > "$output/$label.json"
    return
  fi
  printf '%s' "$filtered" | jq --arg check "$label" '{check:$check,status:(if .==[] then "EMPTY" else "OK" end),data:.}' > "$output/$label.json"
}

collect_platform_configuration() {
  collect kubevirt '[.items[]|{namespace:.metadata.namespace,name:.metadata.name,version:.status.observedKubeVirtVersion,phase:.status.phase,conditions:[.status.conditions[]?|{type,status,reason}],feature_gates:.spec.configuration.developerConfiguration.featureGates,incremental_backup_rendered:((.spec.configuration.developerConfiguration.featureGates // [])|index("IncrementalBackup") != null),utility_volumes_rendered:((.spec.configuration.developerConfiguration.featureGates // [])|index("UtilityVolumes") != null),vm_state_storage_class:.spec.configuration.vmStateStorageClass,changed_block_tracking_selectors:.spec.configuration.changedBlockTrackingLabelSelectors,workload_update_methods:.spec.workloadUpdateStrategy.workloadUpdateMethods}]' get kubevirts.kubevirt.io -A -o json
  collect hco '[.items[]|{api_version:.apiVersion,namespace:.metadata.namespace,name:.metadata.name,versions:.status.versions,conditions:[.status.conditions[]?|{type,status,reason}],feature_gates:.spec.featureGates,incremental_backup_requested:(any(.spec.featureGates[]?;((.name // ""|ascii_downcase)=="incrementalbackup") and ((.state // "Enabled"|ascii_downcase)=="enabled"))),vm_state_storage_class:.spec.storage.vmStateStorageClass,changed_block_tracking_selectors:.spec.virtualization.changedBlockTrackingLabelSelectors}]' get hyperconvergeds.v1.hco.kubevirt.io -A -o json
}

if [[ -n "$target_vm" ]]; then
  ns=${namespaces[0]}
  collect_platform_configuration
  collect "$ns-namespace" '{name:.metadata.name,labels:(.metadata.labels // {})}' get namespace "$ns" -o json
  collect "$ns-vms" '[.items[]|{name:.metadata.name,uid:.metadata.uid,deleting:(.metadata.deletionTimestamp != null),labels:(.metadata.labels // {})}]' \
    get virtualmachines.kubevirt.io "$target_vm" -n "$ns" --ignore-not-found -o json
  collect "$ns-vmis" '[.items[]|{name:.metadata.name,uid:.metadata.uid,phase:.status.phase,node_assigned:((.status.nodeName | type) == "string" and (.status.nodeName | length) > 0),availability_conditions:[.status.conditions[]?|select(.type=="Ready" or .type=="Paused")|{type,status}],deleting:(.metadata.deletionTimestamp != null),changed_block_tracking:{state:.status.changedBlockTracking.state},owners:[.metadata.ownerReferences[]?|select(.controller==true)|{api_version:.apiVersion,kind,name,uid}],disks:[.spec.domain.devices.disks[]?|.name],volumes:[.spec.volumes[]?|{name,source_kinds:(keys-["name"]),pvc:.persistentVolumeClaim.claimName,data_volume:.dataVolume.name}] }]' \
    get virtualmachineinstances.kubevirt.io "$target_vm" -n "$ns" --ignore-not-found -o json

  collect served-api-versions '[.groups[].versions[].groupVersion]' get --raw /apis
  collect served-backup-api '{group_version:.groupVersion, resources:[.resources[]|{name,kind,namespaced}]}' get --raw /apis/backup.kubevirt.io/v1alpha1
  collect served-export-api '{group_version:.groupVersion, resources:[.resources[]|{name,kind,namespaced}]}' get --raw /apis/export.kubevirt.io/v1beta1
  exit 0
fi

collect client-version '{client:.clientVersion.gitVersion,server:.openshiftVersion,kubernetes:.serverVersion.gitVersion}' version -o json
collect platform '[.items[]|{name:.metadata.name,version:.status.desired.version,conditions:[.status.conditions[]?|{type,status,reason}]}]' get clusterversions.config.openshift.io -o json
collect operators '[.items[]|{name:.metadata.name,versions:.status.versions,conditions:[.status.conditions[]?|{type,status,reason}]}]' get clusteroperators.config.openshift.io -o json
collect nodes '[.items[]|{name:.metadata.name,roles:((.metadata.labels // {})|keys|map(select(startswith("node-role.kubernetes.io/")))),kubelet:.status.nodeInfo.kubeletVersion,architecture:.status.nodeInfo.architecture,allocatable:.status.allocatable,conditions:[.status.conditions[]?|{type,status,reason}]}]' get nodes -o json
collect pools '[.items[]|{name:.metadata.name,machines:.status.machineCount,ready:.status.readyMachineCount,conditions:[.status.conditions[]?|{type,status,reason}]}]' get machineconfigpools.machineconfiguration.openshift.io -o json
collect_platform_configuration
collect cdi '[.items[]|{name:.metadata.name,version:.status.observedVersion,phase:.status.phase,conditions:[.status.conditions[]?|{type,status,reason}]}]' get cdis.cdi.kubevirt.io -o json
collect virtualization-subscriptions '[.items[]|select((.spec.name // ""|test("kubevirt|hyperconverged|hco|virtualization|cdi|odf|ocs|ceph|data.foundation";"i")) or (.metadata.name|test("kubevirt|hyperconverged|hco|virtualization|cdi|odf|ocs|ceph|data.foundation";"i")))|{namespace:.metadata.namespace,name:.metadata.name,package:.spec.name,channel:.spec.channel,catalog_source:.spec.source,catalog_namespace:.spec.sourceNamespace,installed_csv:.status.installedCSV,current_csv:.status.currentCSV,conditions:[.status.conditions[]?|{type,status,reason}]}]' get subscriptions.operators.coreos.com -A -o json
collect virtualization-csvs '[.items[]|select((.metadata.name|test("kubevirt|hyperconverged|hco|virtualization|cdi|odf|ocs|ceph|data.foundation";"i")) or (.spec.displayName // ""|test("kubevirt|hyperconverged|hco|virtualization|cdi|odf|ocs|ceph|data.foundation";"i")))|{namespace:.metadata.namespace,name:.metadata.name,version:.spec.version,phase:.status.phase,reason:.status.reason}]' get clusterserviceversions.operators.coreos.com -A -o json
collect relevant-apis '[.items[]|select(.spec.group|test("kubevirt.io$|cdi.kubevirt.io$|snapshot.storage.k8s.io$|ceph.rook.io$|odf.openshift.io$|ocs.openshift.io$"))|{name:.metadata.name,group:.spec.group,kind:.spec.names.kind,versions:[.spec.versions[]|{name,served,storage}]}]' get customresourcedefinitions.apiextensions.k8s.io -o json
collect storage-classes '[.items[]|{name:.metadata.name,provisioner,default:(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] // "false"),volumeBindingMode,reclaimPolicy,allowVolumeExpansion}]' get storageclasses.storage.k8s.io -o json
collect bound-pvs '[.items[]|select((.spec.claimRef.namespace // "") as $ns | $namespaces | index($ns))|{name:.metadata.name,claim_namespace:.spec.claimRef.namespace,claim_name:.spec.claimRef.name,claim_uid:.spec.claimRef.uid,storage_class:.spec.storageClassName,volume_mode:.spec.volumeMode,capacity:.spec.capacity.storage,phase:.status.phase,csi_driver:.spec.csi.driver,source_kinds:(.spec|keys-["accessModes","capacity","claimRef","mountOptions","nodeAffinity","persistentVolumeReclaimPolicy","storageClassName","volumeMode"])}]' get persistentvolumes -o json
collect storage-profiles '[.items[]|{name:.metadata.name,configured_claim_property_sets:[.spec.claimPropertySets[]?|{access_modes:.accessModes,volume_mode:.volumeMode}],effective_claim_property_sets:[.status.claimPropertySets[]?|{access_modes:.accessModes,volume_mode:.volumeMode}],configured_clone_strategy:.spec.cloneStrategy,effective_clone_strategy:.status.cloneStrategy,storage_class:.status.storageClass,provisioner:.status.provisioner,snapshot_class:.status.snapshotClass}]' get storageprofiles.cdi.kubevirt.io -o json
collect csi-drivers '[.items[]|{name:.metadata.name,attachRequired:.spec.attachRequired,fsGroupPolicy:.spec.fsGroupPolicy,volumeLifecycleModes:.spec.volumeLifecycleModes}]' get csidrivers.storage.k8s.io -o json
collect snapshot-classes '[.items[]|{name:.metadata.name,driver,deletionPolicy}]' get volumesnapshotclasses.snapshot.storage.k8s.io -o json
collect ceph-clusters '[.items[]|{namespace:.metadata.namespace,name:.metadata.name,state:.status.state,phase:.status.phase,health:(.status.ceph.health|if type=="string" then . else null end),health_checked_at:.status.ceph.lastChecked,capacity_bytes:{available:.status.ceph.capacity.bytesAvailable,total:.status.ceph.capacity.bytesTotal,used:.status.ceph.capacity.bytesUsed},version:.status.version.version,conditions:[.status.conditions[]?|{type,status,reason}]}]' get cephclusters.ceph.rook.io -A -o json

for ns in "${namespaces[@]}"; do
  collect "$ns-namespace" '{name:.metadata.name,labels:(.metadata.labels // {})}' get namespace "$ns" -o json
  collect "$ns-vms" '[.items[]|select(($vms|length)==0 or (.metadata.name as $n|$vms|index($n)))|{name:.metadata.name,uid:.metadata.uid,labels:(.metadata.labels // {}),run_strategy:.spec.runStrategy,running:.spec.running,conditions:[.status.conditions[]?|{type,status,reason}],cpu:.spec.template.spec.domain.cpu,memory:.spec.template.spec.domain.memory,resources:.spec.template.spec.domain.resources,disks:[.spec.template.spec.domain.devices.disks[]?|{name,bootOrder,disk,lun,cdrom}],interfaces:[.spec.template.spec.domain.devices.interfaces[]?|{name,model,masquerade,bridge,binding}],networks:[.spec.template.spec.networks[]?|{name,pod,multus}],volumes:[.spec.template.spec.volumes[]?|{name,source_kinds:(keys-["name"]),pvc:.persistentVolumeClaim.claimName,data_volume:.dataVolume.name}],data_volume_templates:[.spec.dataVolumeTemplates[]?|{name:.metadata.name,storage_class:(.spec.storage.storageClassName // .spec.pvc.storageClassName),volume_mode:(.spec.storage.volumeMode // .spec.pvc.volumeMode),requested_storage:(.spec.storage.resources.requests.storage // .spec.pvc.resources.requests.storage)}]}]' get virtualmachines.kubevirt.io -n "$ns" -o json
  collect "$ns-vmis" '[.items[]|select(($vms|length)==0 or (.metadata.name as $n|$vms|index($n)))|{name:.metadata.name,uid:.metadata.uid,phase:.status.phase,node:.status.nodeName,conditions:[.status.conditions[]?|{type,status,reason}],changed_block_tracking:.status.changedBlockTracking,guest_agent_reported:([.status.conditions[]?|select(.type=="AgentConnected" and .status=="True")]|length>0)}]' get virtualmachineinstances.kubevirt.io -n "$ns" -o json
  # PVC/DV inventories stay namespace-wide: template-created and scratch names may
  # not match the VM name. Only storage facts are retained (never import sources).
  collect "$ns-pvcs" '[.items[]|{name:.metadata.name,uid:.metadata.uid,volume_name:.spec.volumeName,storage_class:.spec.storageClassName,volume_mode:.spec.volumeMode,access_modes:.spec.accessModes,requested:.spec.resources.requests.storage,capacity:.status.capacity.storage,phase:.status.phase}]' get persistentvolumeclaims -n "$ns" -o json
  collect "$ns-data-volumes" '[.items[]|{name:.metadata.name,uid:.metadata.uid,phase:.status.phase,conditions:[.status.conditions[]?|{type,status,reason}]}]' get datavolumes.cdi.kubevirt.io -n "$ns" -o json
  collect "$ns-quotas" '[.items[]|{name:.metadata.name,hard:.status.hard,used:.status.used}]' get resourcequotas -n "$ns" -o json
  collect "$ns-limits" '[.items[]|{name:.metadata.name,limits:.spec.limits}]' get limitranges -n "$ns" -o json
  for resource in virtualmachinebackups.backup.kubevirt.io virtualmachinebackuptrackers.backup.kubevirt.io virtualmachineexports.export.kubevirt.io virtualmachineinstancemigrations.kubevirt.io; do
    collect "$ns-$resource" '[.items[]|{name:.metadata.name,uid:.metadata.uid,phase:.status.phase,conditions:[.status.conditions[]?|{type,status,reason}]}]' get "$resource" -n "$ns" -o json
  done
  for permission in 'get virtualmachines.kubevirt.io' 'get persistentvolumeclaims' 'get virtualmachinebackups.backup.kubevirt.io' 'create jobs.batch' 'create persistentvolumeclaims' 'create virtualmachines.kubevirt.io'; do
    read -r verb resource <<< "$permission"
    # SelfSubjectAccessReview only. This does not create the queried resource.
    answer='' status=UNKNOWN
    if answer=$("${oc_cmd[@]}" auth can-i "$verb" "$resource" -n "$ns" 2>/dev/null); then
      case "$answer" in
        yes) status=ALLOWED;;
        no) status=DENIED;;
      esac
    elif [[ "$answer" == no ]]; then
      status=DENIED
    fi
    jq -n --arg verb "$verb" --arg resource "$resource" --arg status "$status" \
      '{identity:"current oc user; not future agent ServiceAccount",verb:$verb,resource:$resource,status:$status}' > "$output/$ns-permission-$verb-$resource.json"
  done
done
jq -s '[.[]|select(.status=="UNKNOWN" or .status=="DENIED")|{check,resource,verb,status,reason}]' "$output/"*.json > "$output/unavailable-checks.txt"
echo "Report saved to $output"
echo 'Review filenames and JSON before sharing. UNKNOWN/DENIED entries are missing evidence, not a product compatibility verdict.'
