#!/usr/bin/env bash
# Offline, read-only interpretation of nominated VM labels against rendered CBT selectors.
set -euo pipefail

if (($# != 1)) || [[ ! -d "$1" ]]; then
  echo 'Usage: bash customer-preflight-scope.sh REPORT_DIRECTORY' >&2
  exit 2
fi
report_dir=$1
command -v jq >/dev/null
[[ -f "$report_dir/report.json" && -f "$report_dir/kubevirt.json" ]] || {
  echo 'Missing report.json or kubevirt.json' >&2
  exit 2
}

namespaces=$(jq -er '
  select(.schema == 1 and (.namespaces | type) == "array" and
         (.namespaces | length) > 0) |
  .namespaces as $names |
  if any($names[]; if type != "string" then true
                   else test("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$") | not end) or
     (($names | unique | length) != ($names | length))
  then error("Invalid or duplicate namespace in report")
  else $names[] end' "$report_dir/report.json")

{
  while IFS= read -r ns; do
    [[ -f "$report_dir/$ns-namespace.json" &&
       -f "$report_dir/$ns-vms.json" &&
       -f "$report_dir/$ns-vmis.json" ]] || {
      echo "Missing namespace, VM or VMI projection for $ns" >&2
      exit 2
    }
    jq -n --arg namespace "$ns" --slurpfile report "$report_dir/report.json" --slurpfile kubevirt "$report_dir/kubevirt.json" --slurpfile nsdata "$report_dir/$ns-namespace.json" --slurpfile vms "$report_dir/$ns-vms.json" --slurpfile vmis "$report_dir/$ns-vmis.json" '
      def expr_match($e; $labels):
        if ($e | type) != "object" or ($e.key | type) != "string" or
           ($e.operator | type) != "string" or
           (($e | keys) - ["key","operator","values"] | length) != 0
        then null
        elif $e.operator == "In" or $e.operator == "NotIn" then
          if ($e.values | type) != "array" or
             ($e.values | length) == 0 or
             any($e.values[]; type != "string") then null
          elif $e.operator == "In" then
            ($labels | has($e.key)) and
            (($e.values | index($labels[$e.key])) != null)
          else
            (($labels | has($e.key)) | not) or
            (($e.values | index($labels[$e.key])) == null)
          end
        elif $e.operator == "Exists" or $e.operator == "DoesNotExist" then
          if ($e.values != null and ($e.values | type) != "array") or
             (($e.values // []) | length) != 0 then null
          elif $e.operator == "Exists" then $labels | has($e.key)
          else ($labels | has($e.key)) | not end
        else null end;
      def selector_match($selector; $labels):
        if $selector == null then "ABSENT"
        elif ($selector | type) != "object" or ($labels | type) != "object" or
             (($selector | keys) - ["matchLabels","matchExpressions"] | length) != 0 or
             (($selector.matchLabels // {}) | type) != "object" or
             (($selector.matchExpressions // []) | type) != "array"
        then "UNKNOWN"
        else
          ([($selector.matchLabels // {} | to_entries[] |
              if (.value | type) != "string" then null
              else $labels[.key] == .value end),
            ($selector.matchExpressions // [] | .[] | expr_match(.; $labels))]) as $checks |
          if any($checks[]; . == false) then "NO_MATCH"
          elif any($checks[]; . == null) then "UNKNOWN"
          else "MATCH" end
        end;
      ($kubevirt[0].status == "OK" and
       ($kubevirt[0].data | type) == "array" and
       ($kubevirt[0].data | length) == 1) as $kv_ok |
      (if $kv_ok then $kubevirt[0].data[0].changed_block_tracking_selectors
       else null end) as $selectors |
      ($nsdata[0] | if .status == "OK" then .data.labels else null end) as $nslabels |
      ($vms[0] | if .status == "OK" and (.data | type) == "array"
                 then .data else [] end) as $vmdata |
      ($vmis[0] | if .status == "OK" and (.data | type) == "array"
                  then .data else null end) as $vmidata |
      {
        namespace: $namespace,
        namespace_query: $nsdata[0].status,
        vm_query: $vms[0].status,
        vmi_query: $vmis[0].status,
        selected_vms: [
          $vmdata[] |
          . as $vm |
          ($vmidata | if . == null then null
                      else map(select(.name == $vm.name)) | .[0] end) as $vmi |
          (if $kv_ok then selector_match($selectors.namespaceLabelSelector; $nslabels)
           else "UNKNOWN" end) as $ns_match |
          (if $kv_ok then selector_match($selectors.virtualMachineLabelSelector; $vm.labels)
           else "UNKNOWN" end) as $vm_match |
          {
            name: $vm.name,
            vmi_uid: ($vmi.uid // null),
            vmi_phase: ($vmi.phase // null),
            vmi_cbt_state:
              (if $vmidata == null then "UNKNOWN"
               elif $vmi == null then "ABSENT"
               elif ($vmi.changed_block_tracking.state | type) == "string"
               then $vmi.changed_block_tracking.state
               else "UNREPORTED" end),
            namespace_selector: $ns_match,
            vm_selector: $vm_match,
            nominated_vm_selector_result:
              (if $ns_match == "MATCH" or $vm_match == "MATCH" then "SELECTED"
               elif $ns_match == "UNKNOWN" or $vm_match == "UNKNOWN" then "UNKNOWN"
               else "NOT_SELECTED" end)
          }
        ],
        missing_requested_vms:
          (($report[0].requested_vms // []) -
           [$vmdata[] | .name])
      }'
  done <<< "$namespaces"
} | jq -s '{
  schema: 1,
  kind: "rendered CBT label-selector configuration scope",
  namespaces: .,
  warning: "SELECTED is only a label-selector match for an observed VM in a queried namespace. VMI CBT state is the observed VMI status, not proof of a successful backup or restore. Neither field proves post-restart eligibility, global pilot-only scope, or customer acceptance. UNKNOWN is not a pass."
}'
