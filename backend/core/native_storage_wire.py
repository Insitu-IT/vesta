"""Closed native file-set envelope; parsing never grants filesystem authority.

This is a separate representation, not a reinterpretation of KubeVirt volumes.
Current push checkpoints and explicitly accepted parents are required.
"""

import hmac
from typing import Any, Literal

from pydantic import Field, model_validator

from core.native_storage import build_artifacts, validate_source
from core.storage_wire import (
    Encryption,
    Parent,
    Profile,
    Target,
    WireModel,
    plan_digest,
)
from core.storage_semantics import UUID, validate_target


class NativeArtifact(WireModel):
    artifact_id: str
    disk_id: str | None
    role: str
    key: str = Field(min_length=1, max_length=1024)
    plaintext_min: int = Field(ge=0, le=2**63 - 1)
    plaintext_max: int = Field(ge=0, le=2**63 - 1)
    ciphertext_min: int = Field(ge=0, le=2**63 - 1)
    ciphertext_max: int = Field(ge=0, le=2**63 - 1)


class NativePlan(WireModel):
    attempt_id: str
    capability_profile: Profile
    provider: Literal["libvirt"]
    source: dict[str, Any]
    backup_type: Literal["full", "incremental"]
    parent: Parent | None
    exclusions: list[str] = Field(max_length=128)
    target: Target
    credential_ref: Literal["installation/storage.s3"]
    encryption: Encryption
    artifacts: list[NativeArtifact] = Field(min_length=1, max_length=4096)
    checksum_policy: Literal["sha256-parts-receipt-v2"]


class NativeTransactionRequest(WireModel):
    protocol: Literal["vnbui-storage-transaction/1"]
    org_id: str
    agent_id: str
    backup_id: str
    reservation_id: str
    plan_sha256: str
    plan: NativePlan

    @model_validator(mode="after")
    def bound_plan(self):
        def require(ok):
            if not ok:
                raise ValueError("Invalid native transaction binding")

        for value in (self.org_id, self.agent_id, self.backup_id, self.reservation_id):
            require(UUID.fullmatch(value) is not None)
        p = self.plan
        s = validate_source(p.source)
        require(self.agent_id == s["agent_id"])
        require(self.reservation_id == p.attempt_id == s["inventory"]["attempt_id"])
        require(self.backup_id == s["inventory"]["backup_id"])
        require(s["inventory"]["checkpoint"] == "vnbui-" + p.attempt_id)
        require(s["inventory"]["job_id"] == "vnbui-native-" + p.attempt_id)
        require((p.backup_type == "full") == (p.parent is None))
        if p.parent is not None:
            parent = p.parent
            for value in (
                parent.backup_id,
                parent.root_backup_id,
                parent.generation_id,
            ):
                require(UUID.fullmatch(value) is not None)
            require(
                parent.backup_id != self.backup_id
                and parent.root_backup_id != self.backup_id
            )
            require(parent.tracker_uid == s["inventory"]["domain_uuid"])
            import re

            require(re.fullmatch(r"[0-9a-f]{64}", parent.receipt_sha256) is not None)
            require(
                parent.checkpoint.startswith("vnbui-")
                and UUID.fullmatch(parent.checkpoint[6:]) is not None
            )
        require(p.exclusions == sorted(set(p.exclusions)))
        selected = {d["target"] for d in s["inventory"]["disks"]}
        import re

        require(
            all(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", x)
                and x not in selected
                for x in p.exclusions
            )
        )
        validate_target(p.target, require)
        expected = build_artifacts(
            s,
            self.org_id,
            self.backup_id,
            self.reservation_id,
            p.encryption.model_dump(),
        )
        require([a.model_dump() for a in p.artifacts] == expected)
        require(len(self.model_dump_json().encode()) <= 4 * 1024 * 1024)
        require(
            hmac.compare_digest(
                self.plan_sha256.encode(), plan_digest(p.model_dump()).encode()
            )
        )
        return self
