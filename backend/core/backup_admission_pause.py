"""Read-only pause projection; PostgreSQL remains reservation authority."""

import json

from core.installation_config import read_configuration
from models import SettingV3


def new_backup_admission_paused(db):
    rows = read_configuration(db, SettingV3, "backup.admission_pause")
    if not rows:
        return False
    try:
        value = json.loads(rows[0].value) if len(rows) == 1 else None
        if (
            type(value) is not dict
            or set(value) != {"schema", "revision", "paused"}
            or type(value["schema"]) is not int
            or value["schema"] != 1
            or type(value["revision"]) is not int
            or not 0 < value["revision"] < 2**63
            or type(value["paused"]) is not bool
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Backup admission pause policy unavailable") from None
    return value["paused"]
