"""Catalog controls for legacy records without accepted recovery authority."""

LEGACY_RECOVERY_REFUSAL = (
    "This backup has no accepted catalog lineage for managed recovery. "
    "Use an independently saved trusted catalog and its matching recovery "
    "tools, configuration and keys."
)


def legacy_s3_unverified(backup):
    return getattr(backup, "unverified_legacy_s3", False) is True


def recorded_legacy_local_path(backup):
    """Only explicit unencrypted local custody can use the old local path."""
    path = getattr(backup, "storage_path", None) or ""
    tags = getattr(backup, "tags", None) or {}
    if (
        legacy_s3_unverified(backup)
        or not path.startswith("file:///")
        or len(path) <= len("file:///")
        or getattr(backup, "backup_type", "full") != "full"
        or getattr(backup, "parent_backup_id", None)
        or getattr(backup, "encryption_key_id", None)
        or getattr(backup, "wrapped_dek", None)
        or tags.get("encrypted")
    ):
        return None
    return path.removeprefix("file://")
