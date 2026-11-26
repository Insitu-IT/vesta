#!/usr/bin/env bash
# Synthetic, offline controls for the HCO v1 summary. Never calls oc.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
fixture_dir=$(mktemp -d /tmp/vnbui-preflight-gates-test.XXXXXXXX)
trap 'rm -r -- "$fixture_dir"' EXIT

jq -n '{schema:1,collected_at:"2026-09-28T00:00:00Z"}' > "$fixture_dir/report.json"
jq -n '{status:"OK",data:[{
  incremental_backup_rendered:true,
  utility_volumes_rendered:true,
  changed_block_tracking_selectors:{namespaceLabelSelector:{matchLabels:{cbt:""}}}
}]}' > "$fixture_dir/kubevirt.json"
write_apis() {
  jq -n --arg backup "$1" --arg tracker "$2" --arg export "$3" '{status:"OK",data:[
    {kind:"VirtualMachineBackup",group:"backup.kubevirt.io",versions:[{name:$backup,served:true}]},
    {kind:"VirtualMachineBackupTracker",group:"backup.kubevirt.io",versions:[{name:$tracker,served:true}]},
    {kind:"VirtualMachineExport",group:"export.kubevirt.io",versions:[{name:$export,served:true}]}
  ]}' > "$fixture_dir/relevant-apis.json"
}
write_apis v1alpha1 v1alpha1 v1beta1

check_selector() {
  local expected=$1 expected_match=$2 expected_result=$3 selector=$4
  jq -n --argjson selector "$selector" '{
    status:"OK",data:[{
      api_version:"hco.kubevirt.io/v1",
      incremental_backup_requested:true,
      changed_block_tracking_selectors:$selector
    }]
  }' > "$fixture_dir/hco.json"
  bash "$script_dir/customer-preflight-gates.sh" "$fixture_dir" |
    jq -e --arg expected "$expected" --arg expected_match "$expected_match" --arg expected_result "$expected_result" '
      .gates.cbt_selector_configured == $expected and
      .gates.cbt_selector_rendered == "PASS" and
      .gates.cbt_selector_request_render_match == $expected_match and
      .configuration_result == $expected_result and
      ([.gates | to_entries[] | select(.key != "cbt_selector_configured" and .key != "cbt_selector_request_render_match") | .value] | all(. == "PASS"))
    ' > /dev/null
}

check_selector FAIL UNKNOWN FAIL null
check_selector FAIL FAIL FAIL '{}'
check_selector FAIL FAIL FAIL '{"namespaceLabelSelector":{}}'
check_selector PASS PASS PASS '{"namespaceLabelSelector":{"matchLabels":{"cbt":""}}}'
check_selector PASS FAIL FAIL '{"virtualMachineLabelSelector":{"matchExpressions":[{"key":"cbt","operator":"In","values":["true"]}]}}'

# A served but different API version does not satisfy the agent's fixed GVR.
for mismatch in backup tracker export; do
  case "$mismatch" in
    backup) write_apis v1 v1alpha1 v1beta1; gate=backup_api_served;;
    tracker) write_apis v1alpha1 v1 v1beta1; gate=tracker_api_served;;
    export) write_apis v1alpha1 v1alpha1 v1alpha1; gate=export_api_served;;
  esac
  bash "$script_dir/customer-preflight-gates.sh" "$fixture_dir" |
    jq -e --arg gate "$gate" '.gates[$gate] == "FAIL" and .configuration_result == "FAIL"' > /dev/null
done
write_apis v1alpha1 v1alpha1 v1beta1

jq -n '{status:"OK",data:[{
  incremental_backup_rendered:true,
  utility_volumes_rendered:true,
  changed_block_tracking_selectors:null
}]}' > "$fixture_dir/kubevirt.json"
bash "$script_dir/customer-preflight-gates.sh" "$fixture_dir" |
  jq -e '.gates.cbt_selector_configured == "PASS" and .gates.cbt_selector_rendered == "FAIL" and .gates.cbt_selector_request_render_match == "UNKNOWN" and .configuration_result == "FAIL"' > /dev/null

jq -n '{status:"UNKNOWN",reason:"no HCO API"}' > "$fixture_dir/hco.json"
bash "$script_dir/customer-preflight-gates.sh" "$fixture_dir" |
  jq -e '.gates.cbt_selector_configured == "UNKNOWN" and .gates.cbt_selector_rendered == "FAIL" and .gates.cbt_selector_request_render_match == "UNKNOWN" and .configuration_result == "FAIL"' > /dev/null

echo 'customer-preflight-gates selector and API-version controls: PASS'
