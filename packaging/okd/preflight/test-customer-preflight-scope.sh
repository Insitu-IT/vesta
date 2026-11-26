#!/usr/bin/env bash
# Synthetic offline controls; does not call oc.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
fixture_dir=$(mktemp -d /tmp/vnbui-preflight-scope-test.XXXXXXXX)
trap 'rm -r -- "$fixture_dir"' EXIT

jq -n '{schema:1,namespaces:["pilot"],requested_vms:["vm-a","vm-b","missing"]}' > "$fixture_dir/report.json"
jq -n '{status:"OK",data:[{
  changed_block_tracking_selectors:{
    namespaceLabelSelector:{matchLabels:{cbt:"true"}},
    virtualMachineLabelSelector:{matchExpressions:[
      {key:"tier",operator:"In",values:["pilot"]}
    ]}
  }
}]}' > "$fixture_dir/kubevirt.json"
jq -n '{status:"OK",data:{name:"pilot",labels:{cbt:"false"}}}' > "$fixture_dir/pilot-namespace.json"
jq -n '{status:"OK",data:[
  {name:"vm-a",labels:{tier:"pilot"}},
  {name:"vm-b",labels:{tier:"other"}}
]}' > "$fixture_dir/pilot-vms.json"
jq -n '{status:"OK",data:[
  {name:"vm-a",uid:"vmi-a",phase:"Running",changed_block_tracking:{state:"Enabled"}},
  {name:"vm-b",uid:"vmi-b",phase:"Running",changed_block_tracking:{state:"Disabled"}}
]}' > "$fixture_dir/pilot-vmis.json"

bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0] |
    .selected_vms[0].namespace_selector == "NO_MATCH" and
    .selected_vms[0].vm_selector == "MATCH" and
    .selected_vms[0].nominated_vm_selector_result == "SELECTED" and
    .selected_vms[0].vmi_cbt_state == "Enabled" and
    .selected_vms[0].vmi_uid == "vmi-a" and
    .selected_vms[1].vmi_cbt_state == "Disabled" and
    .selected_vms[1].nominated_vm_selector_result == "NOT_SELECTED" and
    .missing_requested_vms == ["missing"]' >/dev/null

jq -n '{status:"UNKNOWN"}' > "$fixture_dir/pilot-vmis.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    all(.[]; .vmi_cbt_state == "UNKNOWN")' >/dev/null
jq -n '{status:"OK",data:[]}' > "$fixture_dir/pilot-vmis.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    all(.[]; .vmi_cbt_state == "ABSENT")' >/dev/null
jq -n '{status:"OK",data:[{name:"vm-a",uid:"vmi-a",phase:"Running"}]}' > "$fixture_dir/pilot-vmis.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    .[0].vmi_cbt_state == "UNREPORTED" and
    .[1].vmi_cbt_state == "ABSENT"' >/dev/null
jq -n '{status:"OK",data:[
  {name:"vm-a",uid:"vmi-a",phase:"Running",changed_block_tracking:{state:"Enabled"}},
  {name:"vm-b",uid:"vmi-b",phase:"Running",changed_block_tracking:{state:"Disabled"}}
]}' > "$fixture_dir/pilot-vmis.json"

jq -n '{status:"OK",data:{name:"pilot",labels:{cbt:"true"}}}' > "$fixture_dir/pilot-namespace.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    all(.[]; .namespace_selector == "MATCH" and
             .nominated_vm_selector_result == "SELECTED")' >/dev/null

jq -n '{status:"UNKNOWN"}' > "$fixture_dir/kubevirt.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    all(.[]; .nominated_vm_selector_result == "UNKNOWN")' >/dev/null

jq -n '{status:"OK",data:[{
  changed_block_tracking_selectors:{
    virtualMachineLabelSelector:{matchExpressions:[
      {key:"tier",operator:"Bogus",values:["pilot"]}
    ]}
  }
}]}' > "$fixture_dir/kubevirt.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    all(.[]; .vm_selector == "UNKNOWN" and
             .nominated_vm_selector_result == "UNKNOWN")' >/dev/null

jq -n '{status:"OK",data:{name:"pilot",labels:{cbt:"false"}}}' > "$fixture_dir/pilot-namespace.json"
jq -n '{status:"OK",data:[
  {name:"vm-a",labels:{tier:"pilot"}},
  {name:"vm-b",labels:{tier:"other"}},
  {name:"vm-c",labels:{}}
]}' > "$fixture_dir/pilot-vms.json"
jq -n '{status:"OK",data:[{
  changed_block_tracking_selectors:{
    virtualMachineLabelSelector:{matchExpressions:[
      {key:"tier",operator:"NotIn",values:["other"]}
    ]}
  }
}]}' > "$fixture_dir/kubevirt.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    map(.vm_selector) == ["MATCH","NO_MATCH","MATCH"]' >/dev/null

jq -n '{status:"OK",data:[{
  changed_block_tracking_selectors:{
    virtualMachineLabelSelector:{matchExpressions:[
      {key:"tier",operator:"Exists"}
    ]}
  }
}]}' > "$fixture_dir/kubevirt.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    map(.vm_selector) == ["MATCH","MATCH","NO_MATCH"]' >/dev/null

jq -n '{status:"OK",data:[{
  changed_block_tracking_selectors:{
    virtualMachineLabelSelector:{matchExpressions:[
      {key:"tier",operator:"DoesNotExist"}
    ]}
  }
}]}' > "$fixture_dir/kubevirt.json"
bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" |
  jq -e '.namespaces[0].selected_vms |
    map(.vm_selector) == ["NO_MATCH","NO_MATCH","MATCH"]' >/dev/null

jq -n '{schema:1,namespaces:["pilot","../escaped"],requested_vms:[]}' > "$fixture_dir/report.json"
if bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" >/dev/null 2>&1; then
  echo 'Invalid namespace was accepted' >&2
  exit 1
fi
jq -n '{schema:1,namespaces:["pilot","pilot"],requested_vms:[]}' > "$fixture_dir/report.json"
if bash "$script_dir/customer-preflight-scope.sh" "$fixture_dir" >/dev/null 2>&1; then
  echo 'Duplicate namespace was accepted' >&2
  exit 1
fi

echo 'customer-preflight-scope synthetic controls: PASS'
