"""Build the allowlisted readiness summary for one nominated KubeVirt VM."""

import json
import re
import shlex
import subprocess


STORAGE_GUIDE = "https://vestabackup.com/docs/storage-compatibility/"
ACTIONS = {
    "vm_absent": "Check that the named VM exists in the requested namespace.",
    "vm_unknown": "Verify that the selected context can read the named VM.",
    "backup_api_unavailable": "Ask the platform administrator to expose VirtualMachineBackup at backup.kubevirt.io/v1alpha1.",
    "tracker_api_unavailable": "Ask the platform administrator to expose VirtualMachineBackupTracker at backup.kubevirt.io/v1alpha1.",
    "export_api_unavailable": "Ask the platform administrator to expose VirtualMachineExport at export.kubevirt.io/v1beta1.",
    "api_evidence_unknown": "Verify that the selected context can discover the KubeVirt backup and export APIs.",
    "hco_unavailable": "Ask the platform administrator to check the HyperConverged v1 installation.",
    "kubevirt_unavailable": "Ask the platform administrator to check the installed KubeVirt resource.",
    "gate_evidence_unknown": "Review the HyperConverged and KubeVirt configuration with the platform administrator.",
    "incremental_backup_not_enabled": "Ask the platform administrator to check the requested and rendered IncrementalBackup gate.",
    "utility_volumes_not_enabled": "Ask the platform administrator to check the rendered UtilityVolumes gate.",
    "cbt_selector_missing": "Review the requested and rendered changed-block tracking (CBT) selectors with the platform administrator.",
    "cbt_selector_configuration_mismatch": "Check why the requested and rendered CBT selectors differ.",
    "cbt_selector_not_matched": "Review the namespace and VM labels against the rendered CBT selectors.",
    "cbt_selector_unknown": "Confirm the intended CBT selector match using the current namespace and VM labels.",
    "vmi_absent": "Check CBT again while the named VM is running.",
    "vmi_unknown": "Verify that the selected context can read the named VirtualMachineInstance.",
    "vmi_owner_unknown": "Confirm that the running VM instance belongs to the current VM.",
    "vmi_health_unknown": "Refresh the instance’s Ready and Paused conditions before checking its backup readiness.",
    "vmi_not_ready": "Review the instance’s Ready condition and node assignment before retrying the backup check.",
    "vmi_paused": "Review the cause of the paused instance and its storage health before retrying the backup check.",
    "vmi_not_running": "Check CBT again when the VM instance is running.",
    "cbt_pending": "Wait for CBT initialization, then rerun this check.",
    "cbt_disabled": "Review the VM's CBT configuration and any required lifecycle change with the platform administrator.",
    "cbt_state_unknown": "Check the running VM instance's reported CBT status.",
}
API_CODES = {
    "backup_api_served": "backup_api_unavailable",
    "tracker_api_served": "tracker_api_unavailable",
    "export_api_served": "export_api_unavailable",
}
GATE_CODES = {
    "hco_v1": "hco_unavailable",
    "incremental_backup_requested": "incremental_backup_not_enabled",
    "incremental_backup_rendered": "incremental_backup_not_enabled",
    "utility_volumes_rendered": "utility_volumes_not_enabled",
    "cbt_selector_configured": "cbt_selector_missing",
    "cbt_selector_rendered": "cbt_selector_missing",
    "cbt_selector_request_render_match": "cbt_selector_configuration_mismatch",
}
PROVISIONED_VOLUME = {
    "persistentVolumeClaim": "pvc",
    "dataVolume": "data_volume",
}
EPHEMERAL_VOLUME = {
    "cloudInitConfigDrive",
    "cloudInitNoCloud",
    "configMap",
    "containerDisk",
    "downwardAPI",
    "secret",
    "serviceAccount",
    "sysprep",
}
GROUP_API = "groupsnapshot.storage.k8s.io"
GROUP_RESOURCES = {
    ("volumegroupsnapshots", "VolumeGroupSnapshot", True),
    ("volumegroupsnapshotcontents", "VolumeGroupSnapshotContent", False),
    ("volumegroupsnapshotclasses", "VolumeGroupSnapshotClass", False),
}
DNS_LABEL = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
RESOURCE_NAME = re.compile(rf"{DNS_LABEL}(?:\.{DNS_LABEL})*")
LABEL_VALUE = re.compile(r"[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?")


def single_resource(report):
    data = report.get("data")
    if report.get("status") == "OK" and isinstance(data, list) and len(data) == 1:
        return data[0]
    return None


def read_projection(directory, name):
    return json.loads((directory / f"{name}.json").read_text())


def cluster_read(context, *args):
    try:
        response = subprocess.run(
            ["oc", "--request-timeout=20s", "--context", context, *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=25,
        )
        document = json.loads(response.stdout)
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        return {}
    return document if isinstance(document, dict) else {}


def object_field(document, field):
    value = document.get(field)
    return value if isinstance(value, dict) else {}


def records(document, field):
    value = document.get(field)
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    return []


def disk_claims(vmi):
    """Identify the actual persistent disks on the observed instance."""
    disks = vmi["disks"]
    volumes = vmi["volumes"]
    if (
        not all(isinstance(disk, str) for disk in disks)
        or len(set(disks)) != len(disks)
        or len({volume["name"] for volume in volumes}) != len(volumes)
    ):
        return None

    claims = set()
    mapped = set()
    for volume in volumes:
        name = volume["name"]
        sources = volume["source_kinds"]
        if len(sources) != 1:
            return None
        source = sources[0]
        if source in PROVISIONED_VOLUME:
            claim = volume[PROVISIONED_VOLUME[source]]
            if (
                name not in disks
                or not isinstance(claim, str)
                or not RESOURCE_NAME.fullmatch(claim)
            ):
                return None
            if claim in claims:
                return None
            claims.add(claim)
        elif source not in EPHEMERAL_VOLUME:
            return None
        mapped.add(name)
    return claims if set(disks) <= mapped else None


def claim_driver(context, namespace, claim):
    pvc = cluster_read(
        context, "get", "persistentvolumeclaim", claim, "-n", namespace, "-o", "json"
    )
    identity = object_field(pvc, "metadata")
    bound = object_field(pvc, "spec").get("volumeName")
    uid = identity.get("uid")
    if (
        pvc.get("apiVersion") != "v1"
        or pvc.get("kind") != "PersistentVolumeClaim"
        or identity.get("namespace") != namespace
        or identity.get("name") != claim
        or not isinstance(uid, str)
        or not uid
        or identity.get("deletionTimestamp")
        or object_field(pvc, "status").get("phase") != "Bound"
        or not isinstance(bound, str)
        or not RESOURCE_NAME.fullmatch(bound)
    ):
        return None
    pv = cluster_read(context, "get", "persistentvolume", bound, "-o", "json")
    spec = object_field(pv, "spec")
    claim_ref = object_field(spec, "claimRef")
    driver = object_field(spec, "csi").get("driver")
    if (
        pv.get("apiVersion") == "v1"
        and pv.get("kind") == "PersistentVolume"
        and object_field(pv, "metadata").get("name") == bound
        and not object_field(pv, "metadata").get("deletionTimestamp")
        and object_field(pv, "status").get("phase") == "Bound"
        and claim_ref.get("namespace") == namespace
        and claim_ref.get("name") == claim
        and claim_ref.get("uid") == uid
        and isinstance(driver, str)
        and driver
    ):
        return driver
    return None


def matching_group_class(context, versions, driver):
    for group_version in versions:
        if not isinstance(group_version, str) or not re.fullmatch(
            re.escape(GROUP_API) + r"/v[0-9]+(?:(?:alpha|beta)[0-9]+)?", group_version
        ):
            continue
        path = f"/apis/{group_version}"
        api = cluster_read(context, "get", "--raw", path)
        if api.get("groupVersion") != group_version:
            continue
        resources = {
            (item.get("name"), item.get("kind"), item.get("namespaced"))
            for item in records(api, "resources")
            if isinstance(item.get("name"), str)
            and isinstance(item.get("kind"), str)
            and type(item.get("namespaced")) is bool
        }
        if not GROUP_RESOURCES <= resources:
            continue
        classes = cluster_read(
            context, "get", "--raw", path + "/volumegroupsnapshotclasses"
        )
        if (
            classes.get("apiVersion") != group_version
            or classes.get("kind") != "VolumeGroupSnapshotClassList"
        ):
            continue
        if any(
            cls.get("driver") == driver
            and object_field(cls, "metadata").get("name")
            and not object_field(cls, "metadata").get("deletionTimestamp")
            for cls in records(classes, "items")
        ):
            return True
    return False


def group_snapshot(context, namespace, vmi, report):
    claims = disk_claims(vmi)
    if claims is None:
        return "not_observed"
    if len(claims) < 2:
        return "not_applicable"
    versions = report.get("data", [])
    if report.get("status") != "OK" or not any(
        isinstance(version, str) and version.startswith(GROUP_API + "/")
        for version in versions
    ):
        return "not_observed"

    driver = None
    for claim in sorted(claims):
        observed_driver = claim_driver(context, namespace, claim)
        if not observed_driver or driver not in (None, observed_driver):
            return "not_observed"
        driver = observed_driver
    return (
        "candidate"
        if matching_group_class(context, versions, driver)
        else "not_observed"
    )


def availability_finding(vmi):
    conditions = {}
    for condition in vmi.get("availability_conditions", []):
        name, status = condition.get("type"), condition.get("status")
        if name in conditions or status not in {"True", "False", "Unknown"}:
            return "vmi_health_unknown", "unknown"
        conditions[name] = status
    if conditions.get("Paused") == "True":
        return "vmi_paused", "action_required"
    if vmi.get("node_assigned") is False or conditions.get("Ready") == "False":
        return "vmi_not_ready", "action_required"
    if vmi.get("node_assigned") is not True or conditions.get("Ready") != "True" or conditions.get("Paused") == "Unknown":
        return "vmi_health_unknown", "unknown"
    return None


def evaluate(directory, context, namespace, vm_name, gates, scope):
    findings = {}

    def add(code, status):
        findings[code] = status

    def report_gates(codes, unknown, *observed):
        for gate in observed or codes:
            result = gates.get(gate)
            if result == "FAIL":
                add(codes[gate], "action_required")
            elif result != "PASS":
                add(unknown, "unknown")

    def report_platform_gates(*names):
        report_gates(GATE_CODES, "gate_evidence_unknown", *names)

    report_gates(API_CODES, "api_evidence_unknown")
    report_platform_gates("hco_v1")
    if gates.get("hco_v1") == "PASS":
        report_platform_gates("incremental_backup_requested", "cbt_selector_configured")
    kubevirt = read_projection(directory, "kubevirt")
    if kubevirt["status"] == "EMPTY":
        add("kubevirt_unavailable", "action_required")
    elif single_resource(kubevirt):
        report_platform_gates(
            "incremental_backup_rendered",
            "utility_volumes_rendered",
            "cbt_selector_rendered",
        )
        if all(
            gates.get(key) == "PASS"
            for key in ("cbt_selector_configured", "cbt_selector_rendered")
        ):
            report_platform_gates("cbt_selector_request_render_match")
    else:
        add("gate_evidence_unknown", "unknown")

    vm_report = read_projection(directory, f"{namespace}-vms")
    vmi_report = read_projection(directory, f"{namespace}-vmis")
    vm = single_resource(vm_report)
    vmi = single_resource(vmi_report)
    scope_vm = next(
        (
            item
            for item in scope["namespaces"][0]["selected_vms"]
            if item["name"] == vm_name
        ),
        {},
    )
    group = "not_observed"
    if vm_report["status"] == "EMPTY":
        add("vm_absent", "action_required")
    elif not vm or not vm["uid"] or vm["deleting"]:
        add("vm_unknown", "unknown")
    else:
        if vmi_report["status"] == "EMPTY":
            add("vmi_absent", "action_required")
        elif not vmi or not vmi["uid"] or vmi["deleting"]:
            add("vmi_unknown", "unknown")
        elif vmi["owners"] != [
            {
                "api_version": "kubevirt.io/v1",
                "kind": "VirtualMachine",
                "name": vm_name,
                "uid": vm["uid"],
            }
        ]:
            add("vmi_owner_unknown", "unknown")
        elif vmi["phase"] is None:
            add("vmi_unknown", "unknown")
        elif vmi["phase"] != "Running":
            add("vmi_not_running", "action_required")
        elif finding := availability_finding(vmi):
            add(*finding)
        else:
            selector = scope_vm.get("nominated_vm_selector_result")
            if gates.get("cbt_selector_rendered") == "PASS":
                if selector == "NOT_SELECTED":
                    add("cbt_selector_not_matched", "action_required")
                elif selector != "SELECTED":
                    add("cbt_selector_unknown", "unknown")
            cbt = scope_vm.get("vmi_cbt_state")
            if cbt in ("Initializing", "Pending", "PendingRestart"):
                add("cbt_pending", "action_required")
            elif cbt == "Disabled":
                add("cbt_disabled", "action_required")
            elif cbt != "Enabled":
                add("cbt_state_unknown", "unknown")
            group = group_snapshot(
                context,
                namespace,
                vmi,
                read_projection(directory, "served-api-versions"),
            )

    status = "ready"
    if "action_required" in findings.values():
        status = "action_required"
    elif findings:
        status = "unknown"
    return {
        "schema": 1,
        "kind": "vesta-vm-readiness",
        "status": status,
        "findings": [
            {"code": code, "status": state} for code, state in findings.items()
        ],
        "checkpoint": "not_checked",
        "group_snapshot": group,
    }


def valid_label_key(key):
    prefix, separator, name = key.rpartition("/")
    return (
        len(name) <= 63
        and LABEL_VALUE.fullmatch(name)
        and (not separator or (len(prefix) <= 253 and RESOURCE_NAME.fullmatch(prefix)))
    )


def selector_preview(directory, context, namespace, vm_name, gates):
    if gates.get("cbt_selector_request_render_match") != "PASS":
        return None
    kubevirt = single_resource(read_projection(directory, "kubevirt"))
    selectors = object_field(kubevirt, "changed_block_tracking_selectors")
    if selectors.get("namespaceLabelSelector") is not None:
        return None
    vm_selector = object_field(selectors, "virtualMachineLabelSelector")
    if set(vm_selector) != {"matchLabels"}:
        return None
    required = object_field(vm_selector, "matchLabels")
    vm = single_resource(read_projection(directory, f"{namespace}-vms"))
    labels = vm.get("labels")
    if not isinstance(labels, dict) or any(
        not valid_label_key(key)
        or not isinstance(value, str)
        or len(value) > 63
        or (value and not LABEL_VALUE.fullmatch(value))
        or (key in labels and labels[key] != value)
        for key, value in required.items()
    ):
        return None
    additions = [
        f"{key}={value}" for key, value in sorted(required.items()) if key not in labels
    ]
    if not additions:
        return None
    return shlex.join(
        [
            "oc",
            "--context",
            context,
            "-n",
            namespace,
            "label",
            "vm",
            vm_name,
            *additions,
            "--dry-run=server",
            "-o",
            "name",
        ]
    )


def print_summary(summary, preview=None):
    print("KubeVirt VM readiness: " + summary["status"].replace("_", " "), flush=True)
    for finding in summary["findings"]:
        print(ACTIONS[finding["code"]], flush=True)
    if preview:
        print(
            "Preview the required VM label change with a server-side dry run:",
            flush=True,
        )
        print(preview, flush=True)
    if summary["findings"]:
        print(STORAGE_GUIDE + "#check-changed-block-tracking", flush=True)
    if summary["group_snapshot"] == "candidate":
        print(
            "The observed disks are a group-snapshot candidate. Qualify this driver and workload with your platform administrator.",
            flush=True,
        )
        print(STORAGE_GUIDE + "#multiple-disks-and-group-snapshots", flush=True)
