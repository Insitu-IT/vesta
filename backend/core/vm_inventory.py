"""Identity-preserving, atomic inventory updates. Never delete historical VMs."""

from datetime import datetime
from fastapi import HTTPException
from models import Agent, VM


def identity_fields(vm):
    return {
        key: getattr(vm, key)
        for key in (
            "provider",
            "namespace",
            "vm_uid",
            "vmi_uid",
            "inventory_present",
            "last_observed_at",
            "absent_since",
            "replaces_vm_id",
        )
    }


def legacy_event_vm(db, agent_id, name):
    """Name-only libvirt events cannot address historical or KubeVirt rows."""
    candidates = [
        vm
        for vm in db.query(VM)
        .filter(
            VM.agent_id == agent_id, VM.name == name, VM.inventory_present.is_(True)
        )
        .all()
        if (vm.provider or (vm.vm_metadata or {}).get("provider", "libvirt"))
        == "libvirt"
    ]
    return candidates[0] if len(candidates) == 1 else None


def sync_inventory(db, agent, payload):
    entries = payload.get("vms")
    complete = payload.get("complete", False)
    if not isinstance(entries, list) or type(complete) is not bool:
        raise HTTPException(422, "Inventory requires vms array and boolean complete")
    inventory_namespaces = payload.get("source_namespaces")
    scope = (agent.metrics or {}).get("scope")
    if scope is not None:
        from core.agent_scope import namespace_list

        inventory_namespaces = namespace_list(inventory_namespaces)
        if not set(inventory_namespaces) <= set(scope.get("source_namespaces") or []):
            raise HTTPException(
                422, "Inventory scope exceeds installed namespace ceiling"
            )
    normalized = []
    identities = set()
    names = set()
    for item in entries:
        if not isinstance(item, dict):
            raise HTTPException(422, "Inventory entry must be an object")
        meta = item.get("metadata") or {}
        if not isinstance(meta, dict):
            raise HTTPException(422, "Inventory metadata must be an object")
        provider = item.get("provider") or meta.get("provider") or "libvirt"
        ns = item.get("namespace") or meta.get("namespace") or ""
        uid = item.get("vm_uid") or (
            item.get("uuid") if provider != "kubevirt" else None
        )
        name = item.get("name")
        if not all(
            isinstance(x, str) and x for x in (provider, uid, name)
        ) or not isinstance(ns, str):
            raise HTTPException(
                422,
                "Inventory requires name and stable VM identity; upgrade legacy KubeVirt agent",
            )
        if (
            provider == "kubevirt"
            and inventory_namespaces is not None
            and ns not in inventory_namespaces
        ):
            raise HTTPException(
                422, "Inventory entry outside completed namespace scope"
            )
        if provider == "kubevirt" and not ns:
            raise HTTPException(422, "KubeVirt inventory requires namespace")
        if any(
            len(value) > maximum
            for value, maximum in ((provider, 32), (ns, 255), (uid, 36), (name, 255))
        ):
            raise HTTPException(422, "Inventory identity exceeds supported length")
        if (
            not isinstance(item.get("state", "unknown"), str)
            or len(item.get("state", "unknown")) > 20
        ):
            raise HTTPException(422, "Invalid VM state")
        if not isinstance(item.get("disks", []), list) or any(
            not isinstance(disk, dict) for disk in item.get("disks", [])
        ):
            raise HTTPException(422, "Invalid VM disks")
        for field in ("memory_kb", "vcpu_count"):
            if item.get(field) is not None and (
                type(item[field]) is not int or item[field] < 0
            ):
                raise HTTPException(422, "Invalid VM resource quantity")
        if (item.get("memory_kb") or 0) >= 2**63 or (
            item.get("vcpu_count") or 0
        ) >= 2**31:
            raise HTTPException(422, "VM resource quantity exceeds supported range")
        vmi_uid = item.get("vmi_uid") or None
        if vmi_uid is not None and (not isinstance(vmi_uid, str) or len(vmi_uid) > 64):
            raise HTTPException(422, "Invalid VMI UID")
        key = (provider, ns, uid)
        named = (provider, ns, name)
        if key in identities or named in names:
            raise HTTPException(422, "Duplicate inventory identity or namespace/name")
        identities.add(key)
        names.add(named)
        normalized.append((item, meta, key, vmi_uid))

    # Serialize complete snapshots with partial updates on the same agent.
    db.query(Agent).filter(Agent.id == agent.id).with_for_update().one()
    rows = db.query(VM).filter(VM.agent_id == agent.id).all()
    by_identity = {(v.provider, v.namespace, v.vm_uid): v for v in rows if v.vm_uid}
    now = datetime.utcnow()
    seen = set()
    for item, meta, key, vmi_uid in normalized:
        provider, ns, uid = key
        vm = by_identity.get(key)
        if vm is None and provider == "libvirt":
            # Libvirt's UUID already was stable. KubeVirt's legacy uuid was a VMI UID.
            legacy = [
                v
                for v in rows
                if not v.provider
                and v.uuid == uid
                and (v.vm_metadata or {}).get("provider") != "kubevirt"
            ]
            if len(legacy) == 1:
                vm = legacy[0]
        is_new = vm is None
        if is_new:
            vm = VM(agent_id=agent.id, name=item["name"])
            db.add(vm)
            rows.append(vm)
        vm.provider, vm.namespace, vm.vm_uid = key
        vm.vmi_uid = vmi_uid
        vm.name = item["name"]
        vm.uuid = uid
        vm.state = item.get("state", "unknown")
        # Legacy and current agents use zero for unavailable KubeVirt memory.
        # No valid guest has zero RAM. Keep the public observation nullable.
        vm.memory_kb = item.get("memory_kb")
        if provider == "kubevirt" and not vm.memory_kb:
            vm.memory_kb = None
        vm.vcpu_count = item.get("vcpu_count")
        vm.disks = item.get("disks", [])
        vm.vm_metadata = meta
        vm.inventory_present = True
        vm.last_observed_at = now
        vm.absent_since = None
        seen.add(vm)
        # A replacement explicitly observed at the same address retires the prior
        # row even in a partial batch. References stay on that historical row.
        predecessors = []
        for old in rows:
            old_provider = old.provider or (old.vm_metadata or {}).get(
                "provider", "libvirt"
            )
            old_ns = (
                old.namespace
                if old.namespace is not None
                else (old.vm_metadata or {}).get("namespace", "")
            )
            if (
                old is not vm
                and old.name == vm.name
                and (old_provider, old_ns) == (provider, ns)
            ):
                if old.id:
                    predecessors.append(old)
                old.inventory_present = False
                old.absent_since = old.absent_since or now
        if is_new and predecessors:
            # Empty complete snapshots retire predecessors before recreation.
            # Presence therefore cannot decide attribution. Prefer the latest
            # observed incarnation, with creation time and ID as stable ties.
            # Missing observation time on legacy rows falls back to creation.
            vm.replaces_vm_id = max(
                predecessors,
                key=lambda old: (
                    old.last_observed_at or old.created_at or datetime.min,
                    old.created_at or datetime.min,
                    old.id,
                ),
            ).id
    if complete:
        for vm in rows:
            if (
                vm.provider == "kubevirt"
                and inventory_namespaces is not None
                and vm.namespace not in inventory_namespaces
            ):
                continue
            if vm not in seen:
                vm.inventory_present = False
                vm.absent_since = vm.absent_since or now
    db.commit()
    return len(normalized)
