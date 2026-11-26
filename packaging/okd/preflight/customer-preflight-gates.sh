#!/usr/bin/env bash
# Offline interpretation of the private, allowlisted customer-preflight report.
# This never runs oc or reads raw Secrets; PASS is configuration evidence only.
set -euo pipefail

if (($# != 1)) || [[ ! -d "$1" ]]; then
  echo 'Usage: bash customer-preflight-gates.sh REPORT_DIRECTORY' >&2
  exit 2
fi
report_dir=$1
if [[ -f "$report_dir/served-api-versions.json" ]]; then
  api_args=(--argjson apis '[]'
    --slurpfile discovery "$report_dir/served-api-versions.json"
    --slurpfile backup "$report_dir/served-backup-api.json"
    --slurpfile export_api "$report_dir/served-export-api.json")
else
  api_args=(--slurpfile apis "$report_dir/relevant-apis.json"
    --argjson discovery '[]' --argjson backup '[]' --argjson export_api '[]')
fi
for name in report hco kubevirt; do
  [[ -f "$report_dir/$name.json" ]] || {
    echo "Missing $name.json in report directory" >&2
    exit 2
  }
done
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 2; }

jq -n \
  --slurpfile report "$report_dir/report.json" \
  --slurpfile hco "$report_dir/hco.json" \
  --slurpfile kubevirt "$report_dir/kubevirt.json" \
  "${api_args[@]}" '
  def singleton_gate($r; $value; $expected):
    if $r.status == "UNKNOWN" then "UNKNOWN"
    elif $r.status == "EMPTY" then "FAIL"
    elif $r.status != "OK" or (($r.data | type) != "array") then "UNKNOWN"
    elif ($r.data | length) != 1 then "UNKNOWN"
    elif $value == null then "UNKNOWN"
    elif $value == $expected then "PASS" else "FAIL" end;
  def api_gate($r; $kind; $group; $version):
    if $r.status == "UNKNOWN" then "UNKNOWN"
    elif $r.status == "EMPTY" then "FAIL"
    elif $r.status != "OK" or (($r.data | type) != "array") then "UNKNOWN"
    elif any($r.data[];
      .kind == $kind and .group == $group and
      any(.versions[]?; .name == $version and .served == true)) then "PASS"
    else "FAIL" end;
  def discovery_gate($group; $version; $name; $kind; $api):
    ($group + "/" + $version) as $group_version |
    if $api.status == "OK" and $api.data.group_version == $group_version and
       ($api.data.resources | type) == "array" then
      if any($api.data.resources[];
             .name == $name and .kind == $kind and .namespaced == true)
      then "PASS" else "FAIL" end
    elif ($discovery[0].status == "OK" or $discovery[0].status == "EMPTY") and
         ($discovery[0].data | type) == "array" and
         ($discovery[0].data | index($group_version)) == null
    then "FAIL" else "UNKNOWN" end;
  def served_gate($kind; $name; $group; $version; $api):
    if ($discovery | length) > 0 then discovery_gate($group; $version; $name; $kind; $api)
    else api_gate($apis[0]; $kind; $group; $version) end;
  def cbt_selector_gate($r; $selectors):
    if $r.status == "UNKNOWN" then "UNKNOWN"
    elif $r.status == "EMPTY" then "FAIL"
    elif $r.status != "OK" or (($r.data | type) != "array") then "UNKNOWN"
    elif ($r.data | length) != 1 then "UNKNOWN"
    else
      if $selectors == null then "FAIL"
      elif ($selectors | type) != "object" then "UNKNOWN"
      elif any([$selectors.namespaceLabelSelector,
                $selectors.virtualMachineLabelSelector][];
        type == "object" and
        (((.matchLabels // {}) | type == "object" and length > 0) or
         ((.matchExpressions // []) | type == "array" and length > 0)))
      then "PASS"
      else "FAIL" end
    end;
  def cbt_selector_match_gate($requested; $rendered):
    if $requested.status != "OK" or $rendered.status != "OK" then "UNKNOWN"
    elif (($requested.data | type) != "array") or
         (($rendered.data | type) != "array") then "UNKNOWN"
    elif ($requested.data | length) != 1 or ($rendered.data | length) != 1
      then "UNKNOWN"
    elif $requested.data[0].changed_block_tracking_selectors == null or
         $rendered.data[0].changed_block_tracking_selectors == null
      then "UNKNOWN"
    elif $requested.data[0].changed_block_tracking_selectors ==
         $rendered.data[0].changed_block_tracking_selectors
      then "PASS"
    else "FAIL" end;
  if ($report | length) != 1 or $report[0].schema != 1 then
    error("Unsupported or malformed report schema")
  else
    {
      hco_v1: singleton_gate($hco[0]; $hco[0].data[0].api_version; "hco.kubevirt.io/v1"),
      incremental_backup_requested: singleton_gate($hco[0]; $hco[0].data[0].incremental_backup_requested; true),
      cbt_selector_configured: cbt_selector_gate($hco[0]; $hco[0].data[0].changed_block_tracking_selectors),
      cbt_selector_rendered: cbt_selector_gate($kubevirt[0]; $kubevirt[0].data[0].changed_block_tracking_selectors),
      cbt_selector_request_render_match: cbt_selector_match_gate($hco[0]; $kubevirt[0]),
      incremental_backup_rendered: singleton_gate($kubevirt[0]; $kubevirt[0].data[0].incremental_backup_rendered; true),
      utility_volumes_rendered: singleton_gate($kubevirt[0]; $kubevirt[0].data[0].utility_volumes_rendered; true),
      backup_api_served: served_gate("VirtualMachineBackup"; "virtualmachinebackups"; "backup.kubevirt.io"; "v1alpha1"; $backup[0]),
      tracker_api_served: served_gate("VirtualMachineBackupTracker"; "virtualmachinebackuptrackers"; "backup.kubevirt.io"; "v1alpha1"; $backup[0]),
      export_api_served: served_gate("VirtualMachineExport"; "virtualmachineexports"; "export.kubevirt.io"; "v1beta1"; $export_api[0])
    } as $gates |
    {
      schema: 1,
      kind: "HCO v1 backup configuration gates only",
      collected_at: $report[0].collected_at,
      gates: $gates,
      configuration_result:
        (if any($gates[]; . == "FAIL") then "FAIL"
         elif any($gates[]; . == "UNKNOWN") then "UNKNOWN"
         else "PASS" end),
      warning: "PASS confirms nonempty HCO, rendered KubeVirt CBT selectors, exact equality of their reported objects, and the agent-required served backup/tracker v1alpha1 and export v1beta1 APIs. It does not prove pilot-only scope, VMI CBT Enabled, scratch sizing, Ceph RBD backup, restore, platform support policy or customer acceptance. UNKNOWN is not a pass."
    }
  end
'
