"""Transfer sizing negotiation for new attempts, never mutable upload authority."""

import os

from core.s3_ownership import StorageOwnershipError
from core.storage_wire import TRANSFER_PROFILE_32

CAPABILITY = "kubevirt_transfer_profiles"


def select_transfer_profile(agent):
    desired = os.getenv("KUBEVIRT_TRANSFER_PROFILE", TRANSFER_PROFILE_32)
    if desired not in ("legacy", TRANSFER_PROFILE_32):
        raise StorageOwnershipError("Unsupported installation transfer profile")
    if agent is None:
        raise StorageOwnershipError("Source agent is unavailable")
    capabilities = agent.capabilities or {}
    if type(capabilities) is not dict:
        raise StorageOwnershipError("Invalid agent transfer capabilities")
    profiles = capabilities.get(CAPABILITY, [])
    if (
        type(profiles) is not list
        or len(profiles) > 8
        or any(type(p) is not str for p in profiles)
        or len(set(profiles)) != len(profiles)
    ):
        raise StorageOwnershipError("Invalid agent transfer capabilities")
    if (
        desired == TRANSFER_PROFILE_32
        and capabilities.get("provider") == "kubevirt"
        and TRANSFER_PROFILE_32 in profiles
    ):
        return TRANSFER_PROFILE_32
    return None


def refreshed_capabilities(previous, reported):
    # Heartbeats used to merge all keys. A downgrade must not retain an
    # advertisement that the current binary no longer sends or understands.
    result = dict(previous or {})
    result.pop(CAPABILITY, None)
    result.pop("kubevirt_native_disk_profiles", None)
    result.pop("kubevirt_restore_profiles", None)
    result.pop("storage_admission_used_percent", None)
    result.update(reported)
    return result
