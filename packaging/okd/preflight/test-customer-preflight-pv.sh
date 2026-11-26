#!/usr/bin/env bash
# Synthetic control for the exact bound-PV projection embedded in the collector.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
line=$(grep '^collect bound-pvs ' "$script_dir/customer-preflight.sh")
[[ "$line" == *" get persistentvolumes -o json" ]] || exit 1
filter=${line#*\'}
filter=${filter%%\'*}

jq -n '{
  items: [
    {metadata:{name:"pv-rbd"},spec:{
      claimRef:{namespace:"pilot",name:"disk",uid:"uid-1"},
      storageClassName:"ocs-rbd",volumeMode:"Block",capacity:{storage:"10Gi"},
      csi:{driver:"rbd.csi.ceph.com",volumeHandle:"PRIVATE-HANDLE",
           nodeStageSecretRef:{name:"PRIVATE-SECRET"}}
    },status:{phase:"Bound"}},
    {metadata:{name:"pv-foreign"},spec:{
      claimRef:{namespace:"other",name:"disk",uid:"uid-2"},
      csi:{driver:"other",volumeHandle:"PRIVATE-HANDLE"}
    },status:{phase:"Bound"}},
    {metadata:{name:"pv-unclaimed"},spec:{csi:{driver:"other"}}}
  ]
}' |
  jq --argjson namespaces '["pilot"]' "$filter" |
  jq -e '
    length == 1 and
    .[0] == {
      name:"pv-rbd",claim_namespace:"pilot",claim_name:"disk",
      claim_uid:"uid-1",storage_class:"ocs-rbd",volume_mode:"Block",
      capacity:"10Gi",phase:"Bound",csi_driver:"rbd.csi.ceph.com",
      source_kinds:["csi"]
    } and
    (tostring | contains("PRIVATE") | not)
  ' >/dev/null

echo 'customer-preflight bound-PV projection: PASS'
