#!/usr/bin/env python3
"""Operator-run, bounded site reconfiguration with durable verified rollback.

No migrations, credentials, identities, database objects or storage are changed.
Keep the private transaction directory until external acceptance and custody.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import socket
import ssl
import urllib.request
import uuid
sys.dont_write_bytecode = True
from render import render, validate, write_kustomize, installed_profile, resource_prefix, kube_name
import reconcile_inputs

MUTABLE = {"ui_host", "api_host", "source_namespaces", "selected_namespaces", "restore_namespaces", "appearance", "ui_aliases", "licensing", "kube_api_qps", "kube_api_burst", "kubevirt_transfer_profile", "agent_key_rotation_ttl_hours"}
TLS_KEYS = {"backend_tls", "trust"}
REVISION_ANNOTATION = "backup.insitu.co.il/site-configuration-revision"


def public_route_paths(config):
    for host in (config["ui_host"], *config.get("ui_aliases", [])):
        yield host, ("/", "/api/v1/version")
    yield config["api_host"], ("/health", "/ready")


def probe(config, ca_file=None):
    """Actual hostname validation, CA-verified TLS and public HTTP readiness."""
    context = ssl.create_default_context(cafile=ca_file)
    for host, paths in public_route_paths(config):
        if not socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
            raise ValueError("Endpoint DNS did not resolve")
        for path in paths:
            with urllib.request.urlopen("https://" + host + path, context=context, timeout=15) as response:
                if response.status != 200:
                    raise ValueError("Endpoint HTTP readiness failed")
                # Bounded read exercises the response without logging its body.
                response.read(65536)


def changed(previous, proposed):
    validate(previous)
    validate(proposed)
    if resource_prefix(previous) != resource_prefix(proposed):
        raise ValueError("Installed resource_prefix cannot change during reconfiguration")
    if installed_profile(previous) != installed_profile(proposed):
        raise ValueError("Installed edition and operating profile cannot change during reconfiguration")
    for key in set(previous) | set(proposed):
        if previous.get(key) == proposed.get(key) or key in {"edition", "operating_profile", "resource_prefix"}:
            continue
        if key == "secrets":
            if any(previous[key][n] != proposed[key][n] for n in previous[key] if n not in TLS_KEYS):
                raise ValueError("Credential and identity inputs are immutable during reconfiguration")
        elif key not in MUTABLE:
            raise ValueError("Unsupported reconfiguration field: " + key)
    if previous["ui_host"] != proposed["ui_host"] and not {previous["ui_host"], *previous.get("ui_aliases", [])} <= set(proposed.get("ui_aliases", [])):
        raise ValueError("Changing the UI primary requires retaining its old primary and aliases in ui_aliases")
    if ({k: v for k, v in previous.items() if k not in {"edition", "operating_profile", "resource_prefix"}}
            == {k: v for k, v in proposed.items() if k not in {"edition", "operating_profile", "resource_prefix"}}):
        raise ValueError("No configuration changes")


def route_suffix(route):
    # Each component's alias must remain discoverable when only the other
    # public hostname changes in an intervening accepted transaction.
    identity = [route["metadata"]["namespace"], route["metadata"]["name"], route["spec"]["host"]]
    return hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:10]


def key(item):
    return (item["kind"], item["metadata"]["namespace"], item["metadata"]["name"])


def call(oc, *args, value=None):
    result = subprocess.run([*reconcile_inputs.oc_arguments(oc), *args], input=None if value is None else json.dumps(value),
                            text=True, capture_output=True, check=True)
    return result.stdout


def get(oc, item):
    kind, ns, name = key(item)
    raw = call(oc, "-n", ns, "get", kind, name, "--ignore-not-found", "-o", "json")
    return json.loads(raw) if raw.strip() else None


def subset(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and subset(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(
            subset(left, right) for left, right in zip(expected, actual)
        )
    return expected == actual


def normalize_empty_annotations(item):
    """Kubernetes omits empty ObjectMeta annotations on replacement."""
    result = copy.deepcopy(item)
    metadata = [result.get("metadata", {})]
    if result.get("kind") == "Deployment":
        metadata.append(result.get("spec", {}).get("template", {}).get("metadata", {}))
    for fields in metadata:
        if fields.get("annotations") == {}:
            fields.pop("annotations")
    return result


def configuration_matches(expected, actual):
    # Existing transaction snapshots can retain annotations={} after removing
    # client-owned markers. Keep subset strict everywhere else.
    return subset(normalize_empty_annotations(expected), normalize_empty_annotations(actual))


# Only these Deployment lists support additive site configuration. Workload
# containers remain an exact named set; arbitrary sidecars are not adopted.
ADDITIVE_LISTS = {"env": "name", "volumes": "name", "volumeMounts": "mountPath"}


def named_entries(values, field):
    if not isinstance(values, list) or any(not isinstance(v, dict) or not isinstance(v.get(field), str) for v in values):
        raise ValueError("Unsupported Deployment named-list shape")
    result = {value[field]: value for value in values}
    if len(result) != len(values):
        raise ValueError("Duplicate Deployment named-list identity")
    return result


def deployment_matches(expected, actual, path=()):
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(
            # The API omits this one documented VolumeMount default. Do not
            # generalize to false fields whose Kubernetes default is true,
            # such as automountServiceAccountToken.
            (k == "readOnly" and v is False and k not in actual
             and len(path) >= 2 and path[-2] == "volumeMounts")
            or (k in actual and deployment_matches(v, actual[k], path + (k,)))
            for k, v in expected.items()
        )
    if isinstance(expected, list) and path and path[-1] in {*ADDITIVE_LISTS, "containers", "initContainers"}:
        field = ADDITIVE_LISTS.get(path[-1], "name")
        left, right = named_entries(expected, field), named_entries(actual, field)
        if path[-1] in {"containers", "initContainers"} and set(left) != set(right):
            return False
        return all(name in right and deployment_matches(value, right[name], path + (name,)) for name, value in left.items())
    return subset(expected, actual)


def merge_deployment(before, proposed, actual, path=()):
    """Apply only reviewed renderer changes; retain actual unowned additions."""
    if before == proposed:
        return copy.deepcopy(actual)
    if isinstance(before, dict) and isinstance(proposed, dict) and isinstance(actual, dict):
        result = copy.deepcopy(actual)
        for name in set(before) - set(proposed):
            result.pop(name, None)
        for name, value in proposed.items():
            if name in before:
                result[name] = merge_deployment(before[name], value, actual[name], path + (name,))
            elif name in actual:
                if not subset(value, actual[name]):
                    raise ValueError("New renderer field collides with site configuration")
            else:
                result[name] = copy.deepcopy(value)
        return result
    if isinstance(before, list) and isinstance(proposed, list) and path and path[-1] in {*ADDITIVE_LISTS, "containers", "initContainers"}:
        field = ADDITIVE_LISTS.get(path[-1], "name")
        old, new, live = (named_entries(values, field) for values in (before, proposed, actual))
        merged = {}
        for name, value in new.items():
            if name in old:
                merged[name] = merge_deployment(old[name], value, live[name], path + (name,))
            elif name in live:
                if not subset(value, live[name]):
                    raise ValueError("New renderer list member collides with site configuration")
                merged[name] = copy.deepcopy(live[name])
            else:
                merged[name] = copy.deepcopy(value)
        # Retain actual ordering and every site entry outside the owned set.
        result = [merged.pop(value[field]) if value[field] in merged else copy.deepcopy(value)
                  for value in actual if value[field] not in old or value[field] in new]
        result.extend(merged.values())
        return result
    return copy.deepcopy(proposed)


def update_frontend_redirect(target, previous, proposed):
    if previous["ui_host"] == proposed["ui_host"] or target["metadata"]["name"] != kube_name(previous, "backend"):
        return
    containers = target["spec"]["template"]["spec"]["containers"]
    backend = next(container for container in containers if container["name"] == "backend")
    for variable in backend.get("env", []):
        if variable["name"] != "FRONTEND_URL":
            continue
        value = variable.get("value")
        if value == "/":
            continue
        old, new = "https://" + previous["ui_host"], "https://" + proposed["ui_host"]
        if value not in {old, old + "/"}:
            raise ValueError("FRONTEND_URL must be a relative '/' or the old literal UI origin before hostname reconfiguration; external references/custom paths require administrator adoption")
        variable["value"] = new + ("/" if value.endswith("/") else "")


def clean(item):
    result = copy.deepcopy(item)
    result.pop("status", None)
    metadata = result["metadata"]
    result["metadata"] = {k: v for k, v in metadata.items() if k in {"name", "namespace", "labels", "annotations"}}
    for name in ("kubectl.kubernetes.io/last-applied-configuration", reconcile_inputs.ANNOTATION):
        result["metadata"].get("annotations", {}).pop(name, None)
    if result["kind"] == "Deployment":
        result["metadata"].get("annotations", {}).pop("deployment.kubernetes.io/revision", None)
        result.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {}).pop(reconcile_inputs.ANNOTATION, None)
    return normalize_empty_annotations(result)


def save(path, state):
    temporary = path / "transaction.tmp"
    with temporary.open("w") as stream:
        json.dump(state, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path / "transaction.json")


def resources(config, include_agent=True):
    stages = ("api", "agent") if include_agent else ("api",)
    return [item for stage in stages for item in render(config, stage)["items"]]


def revision_deployment(config):
    return ("Deployment", config["namespace"], kube_name(config, "backend"))


def revision(item):
    return item["metadata"].get("annotations", {}).get(REVISION_ANNOTATION)


def namespace_uid(oc, namespace):
    uid = call(oc, "get", "namespace", namespace, "-o", "jsonpath={.metadata.uid}").strip()
    if not uid:
        raise ValueError("Missing namespace identity for " + namespace)
    return uid


def plan(previous, proposed, path, oc, ca_file=None, *, include_agent=True, launcher_target=None):
    changed(previous, proposed)
    path.mkdir(mode=0o700)
    # Persist both coordinated configs and reviewable Kustomize overlays. No Secret values.
    for name, config in (("previous", previous), ("proposed", proposed)):
        (path / (name + ".json")).write_text(json.dumps(config, indent=2))
    for stage in (("api", "agent") if include_agent else ("api",)):
        write_kustomize(proposed, stage, path / stage)
        call(oc, "kustomize", str(path / stage))
    previous_items = resources(previous, include_agent)
    proposed_items = resources(proposed, include_agent)
    old = {key(item): item for item in previous_items}
    desired = {key(item): item for item in proposed_items}
    # PVCs and agent accounts never belong to this transaction. Adding source
    # scopes requires scratch PVCs provisioned independently before planning.
    for identity, item in desired.items():
        if identity not in old and item["kind"] == "PersistentVolumeClaim":
            actual = get(oc, item)
            if actual is None or not subset(item["spec"], actual.get("spec", {})):
                raise ValueError("Preprovision matching scratch PVC before scope expansion")
    changes, removals, prerequisites = [], [], []
    for identity, item in desired.items():
        before = old.get(identity)
        marker = identity == revision_deployment(previous)
        if before == item and not marker:
            continue
        if item["kind"] in {"PersistentVolumeClaim", "Service"}:
            continue
        if item["kind"] == "ServiceAccount":
            # Only a newly added restore destination may create its worker SA.
            # Existing/agent accounts are never replaced or reset.
            if before is not None or item["metadata"]["name"] != kube_name(proposed, "restore-worker"):
                continue
            existing = get(oc, item)
            if existing is not None:
                if not restore_account_matches(item, existing):
                    raise ValueError("Existing restore-worker ServiceAccount is unrelated, terminating or controller-owned")
                prerequisites.append({"expected": copy.deepcopy(item), "uid": existing["metadata"]["uid"]})
                continue
        actual = get(oc, before or item)
        if before and item["kind"] == "Route" and (actual is None or not subset(before, actual)):
            # Later transactions locate the retained route from the last accepted config.
            previous_suffix = route_suffix(before)
            before = copy.deepcopy(before)
            before["metadata"]["name"] += "-" + previous_suffix
            actual = get(oc, before)
        matches = deployment_matches if item["kind"] == "Deployment" else subset
        if before and (actual is None or not matches(before, actual)):
            raise ValueError("Live resource does not match previous site configuration: " + "/".join(identity))
        if not before and actual is not None:
            raise ValueError("Refusing an existing untracked resource")
        target = merge_deployment(before, item, clean(actual)) if item["kind"] == "Deployment" and actual is not None else copy.deepcopy(item)
        if marker:
            # Every transaction, including disjoint scope changes, claims the
            # same Deployment. This top-level annotation leaves its pod template intact.
            if (revision(actual) or "").startswith("rolling-back/"):
                raise ValueError("Finish the current rollback before planning a new configuration")
            target["metadata"].setdefault("annotations", {})[REVISION_ANNOTATION] = uuid.uuid4().hex
        if item["kind"] == "Deployment":
            update_frontend_redirect(target, previous, proposed)
        if item["kind"] == "Route":
            # The existing Routes and old DNS remain available through acceptance.
            target["metadata"]["name"] += "-" + route_suffix(item)
            if get(oc, target) is not None:
                raise ValueError("Candidate Route already exists")
            actual = None
        entry = {"desired": target, "before": clean(actual) if actual else None,
                 "uid": actual["metadata"]["uid"] if actual else None}
        if marker:
            changes.insert(0, entry)
        else:
            changes.append(entry)
    for identity, before in old.items():
        if identity not in desired and before["kind"] == "RoleBinding":
            actual = get(oc, before)
            if actual is None or not subset(before, actual):
                raise ValueError("Removed binding is stale or missing")
            removals.append({"before": clean(actual), "uid": actual["metadata"]["uid"], "attempted": False})
    inputs = {}
    deployment_inputs = previous_items + proposed_items
    deployment_inputs += [item for entry in changes for item in (entry["before"], entry["desired"]) if item]
    for item in deployment_inputs:
        if item["kind"] == "Deployment":
            namespace = item["metadata"]["namespace"]
            versions = reconcile_inputs.source_versions(oc, namespace, reconcile_inputs.source_refs(item))
            for name, version in versions.items():
                # ConfigMaps are intentionally updated by this transaction.
                if name.startswith("secret/"):
                    inputs[namespace + "/" + name] = version
    state = {"status": "planned", "changes": changes, "removals": removals, "secret_inputs": inputs, "prerequisites": prerequisites,
             "previous": previous, "proposed": proposed, "ca_file": ca_file}
    state["binding_namespaces"] = {
        ns: namespace_uid(oc, ns) for ns in sorted({key(entry["before"])[1] for entry in removals})
    }
    if launcher_target is not None:
        state["launcher_target"] = launcher_target
    if not include_agent:
        state["include_agent"] = False
    save(path, state)
    return state


def restore_account_matches(expected, actual):
    metadata = actual.get("metadata", {})
    return (subset(expected, actual) and not metadata.get("deletionTimestamp")
            and not metadata.get("ownerReferences"))


def check_prerequisites(state, oc):
    for namespace, uid in state.get("binding_namespaces", {}).items():
        if namespace_uid(oc, namespace) != uid:
            raise ValueError("Namespace identity changed; refusing to restore or remove its binding")
    for entry in state.get("prerequisites", []):
        actual = assert_identity(oc, entry["expected"], entry["uid"])
        if not restore_account_matches(entry["expected"], actual):
            raise ValueError("Restore-worker ServiceAccount prerequisite changed")


def assert_identity(oc, item, uid):
    actual = get(oc, item)
    if (uid is None and actual is not None) or (uid is not None and (actual is None or actual["metadata"]["uid"] != uid)):
        raise ValueError("Resource identity changed; refusing mutation")
    return actual


def apply_object(oc, item, uid=None, *, expected=None):
    actual = assert_identity(oc, item, uid)
    payload = copy.deepcopy(item)
    if actual is not None:
        # Conditional replacement fails if another writer replaces or updates
        # the resource between identity validation and the API mutation.
        if expected is not None and clean(actual) != normalize_empty_annotations(expected):
            raise ValueError("Resource configuration changed before replacement")
        payload["metadata"].update(uid=uid, resourceVersion=actual["metadata"]["resourceVersion"])
        response = call(oc, "replace", "-f", "-", "-o", "json", value=payload)
    else:
        response = call(oc, "create", "-f", "-", "-o", "json", value=payload)
    return json.loads(response)


def delete_object(oc, item, uid, *, expected=None):
    # DeleteOptions carries a server-side UID precondition; never delete a replacement.
    kind, ns, name = key(item)
    actual = assert_identity(oc, item, uid)
    if actual is None:
        return
    preconditions = {"uid": uid}
    if expected is not None:
        if clean(actual) != normalize_empty_annotations(expected):
            raise ValueError("Resource configuration changed before deletion")
        preconditions["resourceVersion"] = actual["metadata"]["resourceVersion"]
    api = item["apiVersion"]
    # oc delete --raw sends DeleteOptions rather than a racy name-only deletion.
    plural = {"RoleBinding": "rolebindings", "Role": "roles", "ServiceAccount": "serviceaccounts", "Route": "routes", "ConfigMap": "configmaps"}[kind]
    prefix = "/api/v1" if api == "v1" else "/apis/" + api
    call(oc, "delete", "--raw", f"{prefix}/namespaces/{ns}/{plural}/{name}", "-f", "-",
         value={"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": preconditions})


def verify(state, oc, rollback=False):
    check_prerequisites(state, oc)
    config = state["previous" if rollback else "proposed"]
    for item in resources(config, state.get("include_agent", True)):
        if item["kind"] != "Deployment":
            continue
        _, ns, name = key(item)
        if reconcile_inputs.run(oc, ns, name, True, "10m") != 0:
            raise ValueError("Input reconciliation did not become current")
    entries = [entry["before"] if rollback else entry["desired"] for entry in state["changes"]]
    entries += [entry["before"] for entry in state["removals"]] if rollback else []
    for expected in entries:
        if expected and not configuration_matches(expected, get(oc, expected) or {}):
            raise ValueError("Coordinated configuration verification failed")
    for entry in state["removals"] if not rollback else []:
        if get(oc, entry["before"]) is not None:
            raise ValueError("Removed namespace permission remains")
    probe(config, state.get("ca_file"))
    if not rollback:
        # Old paths must continue working throughout the acceptance window.
        probe(state["previous"], state.get("ca_file"))


def rollback_preflight(state, oc):
    """Check the whole rollback before restoring any workload or granting access."""
    check_prerequisites(state, oc)
    complete = state["status"] in {"accepted", "awaiting-external-verification"}
    anchor = revision_deployment(state["previous"])
    anchor_entry = next((entry for entry in state["changes"] if key(entry["desired"]) == anchor), None)
    # Older journals have no revision. Never allow them across a newer
    # transaction that has acquired the site.
    marker_object = {"kind": anchor[0], "metadata": {"namespace": anchor[1], "name": anchor[2]}}
    actual = get(oc, marker_object)
    current = revision(actual) if actual else None
    target_revision = revision(anchor_entry["desired"]) if anchor_entry else None
    allowed = {target_revision}
    if anchor_entry and not complete:
        allowed.add(revision(anchor_entry["before"]))
        if target_revision:
            allowed.add("rolling-back/" + target_revision)
    if actual is None or current not in allowed:
        raise ValueError("Rollback incomplete; the site configuration revision was superseded")
    anchor_observation = clean(actual)

    for entry in state["changes"]:
        actual = get(oc, entry["desired"])
        before = entry["before"]
        if actual is None:
            if before or (complete and entry.get("created_uid")):
                raise ValueError("Rollback incomplete; a planned resource is missing")
            continue
        if actual["metadata"].get("deletionTimestamp") or (
                not before and actual["metadata"].get("ownerReferences")):
            raise ValueError("Rollback incomplete; resource ownership or deletion state changed")
        expected_uid = entry["uid"] if before else entry.get("created_uid")
        if expected_uid is not None and actual["metadata"]["uid"] != expected_uid:
            raise ValueError("Rollback incomplete; resource identity changed")
        if (entry is anchor_entry and target_revision
                and revision(actual) == "rolling-back/" + target_revision):
            prior = clean(actual)
            old_revision = revision(before)
            if old_revision is None:
                prior["metadata"]["annotations"].pop(REVISION_ANNOTATION)
            else:
                prior["metadata"]["annotations"][REVISION_ANNOTATION] = old_revision
            if normalize_empty_annotations(prior) == normalize_empty_annotations(before):
                continue  # Only the rollback claim remains after independent recovery.
            actual["metadata"]["annotations"][REVISION_ANNOTATION] = target_revision
        if before and not complete and clean(actual) == normalize_empty_annotations(before):
            continue  # Request failed before changing this object, or it was already restored.
        if not entry.get("attempted"):
            raise ValueError("Rollback incomplete; an unmodified resource changed")
        if "applied" in entry:
            matches = clean(actual) == entry["applied"]
        else:
            matches = configuration_matches(entry["desired"], actual)
        if not matches:
            raise ValueError("Rollback incomplete; applied configuration has changed")
    for entry in state["removals"]:
        actual = get(oc, entry["before"])
        if actual is None:
            if entry.get("attempted") is False:
                raise ValueError("Rollback incomplete; a binding vanished before its removal was attempted")
        elif (complete or actual["metadata"].get("ownerReferences") or actual["metadata"].get("deletionTimestamp")
              or actual["metadata"]["uid"] != entry.get("restored_uid", entry["uid"])
              or clean(actual) != normalize_empty_annotations(entry["before"])):
            raise ValueError("Rollback incomplete; namespace binding identity or configuration changed")
    return anchor_entry if target_revision else None, anchor_observation


def rollback(state, path, oc):
    if state["status"] == "rolled-back-verified":
        return
    if state["status"] not in {"applying", "awaiting-external-verification", "accepted", "rolling-back", "rollback-incomplete"}:
        raise ValueError("Rollback requires a previously attempted transaction")
    anchor, observed = rollback_preflight(state, oc)
    state["status"] = "rolling-back"
    save(path, state)
    claim = None
    if anchor and anchor.get("attempted"):
        target_revision = revision(anchor["desired"])
        if revision(observed) == target_revision:
            locked = copy.deepcopy(observed)
            locked["metadata"]["annotations"][REVISION_ANNOTATION] = "rolling-back/" + target_revision
            claim = clean(apply_object(oc, locked, anchor["uid"], expected=observed))
        elif revision(observed) == "rolling-back/" + target_revision:
            claim = observed
    failures = []
    for entry in reversed(state["changes"]):
        if not entry.get("attempted") or entry is anchor:
            continue
        try:
            actual = get(oc, entry["desired"])
            if entry["before"]:
                actual = assert_identity(oc, entry["before"], entry["uid"])
                if clean(actual) != normalize_empty_annotations(entry["before"]):
                    if not configuration_matches(entry["desired"], actual):
                        raise ValueError("Resource drifted during rollback")
                    apply_object(oc, entry["before"], entry["uid"], expected=entry.get("applied", clean(actual)))
            elif actual is not None:
                # A lost create response cannot justify deleting an unknown UID.
                # Continue restoring independent prior resources before stopping.
                if not entry.get("created_uid"):
                    raise ValueError("Uncertain created resource identity")
                if not configuration_matches(entry["desired"], actual):
                    raise ValueError("Created resource drifted during rollback")
                delete_object(oc, entry["desired"], entry["created_uid"], expected=entry.get("applied", clean(actual)))
                if get(oc, entry["desired"]) is not None:
                    raise ValueError("Created resource deletion is incomplete")
        except Exception as exc:
            failures.append(type(exc).__name__)
    for entry in state["removals"]:
        try:
            actual = get(oc, entry["before"])
            if actual is None:
                if entry.get("attempted") is False:
                    raise ValueError("Binding was not removed by this transaction")
                namespace = key(entry["before"])[1]
                expected_namespace = state.get("binding_namespaces", {}).get(namespace)
                if expected_namespace and namespace_uid(oc, namespace) != expected_namespace:
                    raise ValueError("Namespace identity changed during rollback")
                restored = apply_object(oc, entry["before"])
                entry["restored_uid"] = restored["metadata"]["uid"]
                save(path, state)
            elif (actual["metadata"]["uid"] != entry.get("restored_uid", entry["uid"])
                  or clean(actual) != normalize_empty_annotations(entry["before"])):
                raise ValueError("Removed binding identity was replaced")
        except Exception as exc:
            failures.append(type(exc).__name__)
    try:
        if claim is not None:
            restored = copy.deepcopy(anchor["before"])
            if failures:
                # Restore the backend along with other independent workloads,
                # retaining the revision until outstanding identities are resolved.
                restored["metadata"].setdefault("annotations", {})[REVISION_ANNOTATION] = revision(claim)
            apply_object(oc, restored, anchor["uid"], expected=claim)
        verify(state, oc, rollback=True)
    except Exception as exc:
        failures.append(type(exc).__name__)
    state["status"] = "rollback-incomplete" if failures else "rolled-back-verified"
    save(path, state)
    if failures:
        raise ValueError("Rollback incomplete; prior resources were restored where identities permitted; inspect private transaction and keep dispatch fenced")


def apply(state, path, oc):
    if state["status"] != "planned":
        raise ValueError("Transaction already attempted; use rollback")
    # Check the entire coordinated set before the first mutation.
    check_prerequisites(state, oc)
    for entry in state["changes"]:
        actual = assert_identity(oc, entry["desired"], entry["uid"])
        if actual and clean(actual) != normalize_empty_annotations(entry["before"]):
            raise ValueError("Planned resource configuration is stale")
    for entry in state["removals"]:
        actual = assert_identity(oc, entry["before"], entry["uid"])
        if clean(actual) != normalize_empty_annotations(entry["before"]):
            raise ValueError("Planned namespace binding is stale")
    for identity, expected in state.get("secret_inputs", {}).items():
        namespace, kind, name = identity.split("/", 2)
        current = reconcile_inputs.source_versions(oc, namespace, [(kind, name)])
        if current[kind + "/" + name] != expected:
            raise ValueError("Secret input metadata changed after planning")
    probe(state["previous"], state.get("ca_file"))
    for hostname in [state["proposed"]["ui_host"], state["proposed"]["api_host"], *state["proposed"].get("ui_aliases", [])]:
        socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    state["status"] = "applying"
    save(path, state)
    try:
        for entry in state["changes"]:
            entry["attempted"] = True
            save(path, state)
            applied = apply_object(oc, entry["desired"], entry["uid"], expected=entry["before"])
            entry["applied"] = clean(applied)
            if entry["uid"] is None:
                entry["created_uid"] = applied["metadata"]["uid"]
            save(path, state)
        for entry in state["removals"]:
            entry["attempted"] = True
            save(path, state)
            delete_object(oc, entry["before"], entry["uid"], expected=entry["before"])
        verify(state, oc)
        state["status"] = "awaiting-external-verification"
        save(path, state)
    except BaseException:
        rollback(state, path, oc)
        raise


def accept(state, path, oc):
    if state["status"] != "awaiting-external-verification":
        raise ValueError("Acceptance requires successful apply")
    rollback_preflight(state, oc)
    try:
        verify(state, oc)
        state["status"] = "accepted"
        save(path, state)
    except BaseException:
        rollback(state, path, oc)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "rollback", "accept"))
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--oc", default="oc")
    parser.add_argument("--ca-file", help="local PEM CA bundle for verified endpoint probes; otherwise system trust")
    parser.add_argument("--quiesced", action="store_true")
    parser.add_argument("--external-ready", action="store_true", help="DNS, dual-name certificates/trust and SSO prepared")
    parser.add_argument("--paths-verified", action="store_true", help="new and old UI/API, login/SSO and authenticated agent path verified")
    args = parser.parse_args()
    try:
        if args.action == "plan":
            if not args.previous or not args.config:
                raise ValueError("plan requires --previous and --config")
            state = plan(json.loads(args.previous.read_text()), json.loads(args.config.read_text()), args.state, args.oc, args.ca_file)
        else:
            if not args.quiesced:
                raise ValueError("Fence dispatch and review active work; --quiesced required")
            state = json.loads((args.state / "transaction.json").read_text())
            if "launcher_target" in state:
                raise ValueError("Resume this manifest transaction with the vesta launcher")
            if args.action == "apply":
                if not args.external_ready:
                    raise ValueError("Prepare DNS/TLS/trust/SSO before --external-ready")
                apply(state, args.state, args.oc)
            elif args.action == "rollback":
                rollback(state, args.state, args.oc)
            else:
                if state["status"] != "awaiting-external-verification" or not args.paths_verified:
                    raise ValueError("accept requires successful apply and --paths-verified")
                accept(state, args.state, args.oc)
        print("Reconfiguration: " + state["status"])
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print("Reconfiguration stopped: " + detail + "; inspect private state; verify rollback before resuming dispatch.", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
