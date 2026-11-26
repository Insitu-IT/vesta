"""Persist the KubeVirt publication/checkpoint contract on every status path."""


def apply_checkpoint_state(backup, data, status):
    tags = dict(backup.tags or {})
    if "checkpoint_committed" in data:
        tags["checkpoint_required"] = True
        tags["checkpoint_committed"] = data["checkpoint_committed"] is True
    if tags.get("checkpoint_required"):
        if data.get("s3_location"):
            backup.storage_path = data["s3_location"]
        if status == "completed" and not tags.get("checkpoint_committed"):
            status = "cleanup_required"
            tags["error"] = (
                "S3 publication has no committed checkpoint; cleanup required"
            )
        tags["cleanup_required"] = status == "cleanup_required"
        if status in ("failed", "cleanup_required"):
            backup.completed_at = None
    backup.tags = tags
    return status
