"""Session-local mutations for the public evaluator journey."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

from config import settings
from models import DemoSession

from .executor import (
    DemoExecutionError,
    backup_plan,
    restore_plan,
    retry_upload_plan,
)


class DemoJourneyError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class DemoJourney:
    """Mutate only the JSON document owned by one demo session."""

    def __init__(self, session: DemoSession, db):
        self.session = session
        self.db = db
        self.state = deepcopy(session.state)

    def _save(self) -> None:
        self.session.state = self.state
        self.db.commit()
        self.db.refresh(self.session)

    def _find(self, collection: str, item_id: str) -> dict:
        for item in self.state[collection]:
            if item["id"] == item_id:
                return item
        raise DemoJourneyError(
            f"{collection.upper()}_NOT_FOUND",
            f"No demo {collection[:-1]} has id {item_id!r}.",
        )

    def _activity(
        self, action: str, resource_type: str, resource_id: str, **details
    ) -> None:
        self.state["activity"].insert(
            0,
            {
                "id": str(uuid4()),
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "created_at": _now(),
                "details": {**details, "simulated": True},
                "simulated": True,
            },
        )
        del self.state["activity"][settings.demo_max_activity :]

    def _require_capacity(self, collection: str, maximum: int) -> None:
        if len(self.state[collection]) >= maximum:
            raise DemoJourneyError(
                "DEMO_QUOTA_EXCEEDED",
                f"This demo session has reached its {collection} limit ({maximum}). Reset the demo to continue.",
            )

    @staticmethod
    def _rule_matches(vm: dict, rule: dict) -> bool:
        field = rule["field"]
        if field == "metadata.environment":
            actual = vm.get("metadata", {}).get("environment")
        else:
            actual = vm.get(field)
        expected = rule["value"]
        operation = rule.get("op", "eq")
        if operation == "eq":
            return actual == expected
        if operation == "neq":
            return actual != expected
        if operation == "in":
            return actual in expected
        raise DemoJourneyError(
            "GROUP_RULE_UNSUPPORTED",
            f"Demo group preview does not support operator {operation!r}.",
        )

    def preview_group(self, rules: list[dict], rules_match: str) -> list[dict]:
        if not rules:
            raise DemoJourneyError("GROUP_RULE_REQUIRED", "Provide at least one rule.")
        if rules_match not in {"all", "any"}:
            raise DemoJourneyError(
                "GROUP_MATCH_INVALID", "rules_match must be all or any."
            )
        predicate = all if rules_match == "all" else any
        return [
            vm
            for vm in self.state["vms"]
            if predicate(self._rule_matches(vm, rule) for rule in rules)
        ]

    def create_group(self, name: str, rules: list[dict], rules_match: str) -> dict:
        self._require_capacity("groups", settings.demo_max_groups)
        members = self.preview_group(rules, rules_match)
        group = {
            "id": str(uuid4()),
            "name": name,
            "group_type": "dynamic",
            "rules": rules,
            "rules_match": rules_match,
            "member_count": len(members),
            "simulated": True,
        }
        self.state["groups"].append(group)
        self._activity("group_created", "group", group["id"], name=name)
        self._save()
        return group

    def update_group(
        self, group_id: str, name: str, rules: list[dict], rules_match: str
    ) -> dict:
        group = self._find("groups", group_id)
        members = self.preview_group(rules, rules_match)
        group.update(
            name=name,
            group_type="dynamic",
            rules=rules,
            rules_match=rules_match,
            member_count=len(members),
            simulated=True,
        )
        group.pop("vm_ids", None)
        self._activity("group_updated", "group", group_id, name=name)
        self._save()
        return group

    def _group_members(self, group: dict) -> list[dict]:
        by_id = {vm["id"]: vm for vm in self.state["vms"]}
        members = [by_id[item] for item in group.get("vm_ids", []) if item in by_id]
        if group.get("rules"):
            dynamic = self.preview_group(
                group["rules"], group.get("rules_match", "all")
            )
            seen = {vm["id"] for vm in members}
            members.extend(vm for vm in dynamic if vm["id"] not in seen)
        return members

    def create_schedule(self, payload: dict) -> dict:
        self._require_capacity("schedules", settings.demo_max_schedules)
        target_id = payload.get("vm_id") or payload.get("vm_group_id")
        if bool(payload.get("vm_id")) == bool(payload.get("vm_group_id")):
            raise DemoJourneyError(
                "SCHEDULE_TARGET_INVALID", "Choose exactly one VM or group target."
            )
        collection = "vms" if payload.get("vm_id") else "groups"
        self._find(collection, target_id)
        schedule = {
            "id": str(uuid4()),
            **payload,
            "simulated": True,
        }
        self.state["schedules"].append(schedule)
        self._activity(
            "schedule_created", "schedule", schedule["id"], name=schedule["name"]
        )
        self._save()
        return schedule

    def run_schedule(self, schedule_id: str) -> dict:
        schedule = self._find("schedules", schedule_id)
        if not schedule.get("enabled"):
            raise DemoJourneyError(
                "SCHEDULE_DISABLED", "Enable this demo schedule before running it."
            )
        if schedule.get("vm_id"):
            vm = self._find("vms", schedule["vm_id"])
        else:
            group = self._find("groups", schedule["vm_group_id"])
            members = self._group_members(group)
            if not members:
                raise DemoJourneyError(
                    "SCHEDULE_TARGET_EMPTY", "The demo group contains no VMs."
                )
            vm = members[0]
        return self.create_backup(vm["id"], schedule["backup_type"], "success")

    def create_backup(self, vm_id: str, backup_type: str, scenario: str) -> dict:
        self._require_capacity("backups", settings.demo_max_backups)
        vm = self._find("vms", vm_id)
        completed = [
            item
            for item in self.state["backups"]
            if item["vm_id"] == vm_id and item["status"] == "completed"
        ]
        operation_id = str(uuid4())
        try:
            events = backup_plan(
                operation_id,
                backup_type,
                supports_incremental=bool(
                    vm.get("metadata", {}).get("supports_incremental")
                ),
                has_completed_parent=bool(completed),
                scenario=scenario,
            )
        except DemoExecutionError as exc:
            raise DemoJourneyError(exc.code, str(exc)) from exc
        final = events[-1]
        parent = completed[-1] if backup_type == "incremental" and completed else None
        backup = {
            "id": operation_id,
            "vm_id": vm_id,
            "vm_name": vm["name"],
            "backup_type": backup_type,
            "status": final.status,
            "progress": final.progress,
            "parent_backup_id": parent["id"] if parent else None,
            "chain_id": parent["chain_id"] if parent else operation_id,
            "chain_position": parent["chain_position"] + 1 if parent else 0,
            "created_at": _now(),
            "completed_at": _now() if final.status == "completed" else None,
            "error_message": final.message if final.status == "upload_failed" else None,
            "events": [event.as_dict() for event in events],
            "simulated": True,
        }
        self.state["backups"].insert(0, backup)
        self._activity(
            f"backup_{final.status}", "backup", operation_id, vm_name=vm["name"]
        )
        self._save()
        return backup

    def retry_backup(self, backup_id: str) -> dict:
        backup = self._find("backups", backup_id)
        if backup["status"] != "upload_failed":
            raise DemoJourneyError(
                "UPLOAD_NOT_RETRIABLE",
                "Only an upload-failed demo backup can be retried.",
            )
        events = retry_upload_plan()
        backup.update(
            status="completed",
            progress=100,
            completed_at=_now(),
            error_message=None,
            events=[event.as_dict() for event in events],
        )
        self._activity("backup_retry_completed", "backup", backup_id)
        self._save()
        return backup

    def create_restore(self, backup_id: str) -> dict:
        self._require_capacity("restores", settings.demo_max_restores)
        backup = self._find("backups", backup_id)
        try:
            events = restore_plan(backup_status=backup["status"])
        except DemoExecutionError as exc:
            raise DemoJourneyError(exc.code, str(exc)) from exc
        restore = {
            "id": str(uuid4()),
            "backup_id": backup_id,
            "target_vm_id": backup["vm_id"],
            "status": events[-1].status,
            "progress": events[-1].progress,
            "created_at": _now(),
            "completed_at": _now(),
            "events": [event.as_dict() for event in events],
            "message": "No VM or disk was changed.",
            "simulated": True,
        }
        self.state["restores"].insert(0, restore)
        self._activity("restore_completed", "restore", restore["id"])
        self._save()
        return restore
