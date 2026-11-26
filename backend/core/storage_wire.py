"""Strict transaction/1 KubeVirt envelope, separate from legacy requests.

Parsing is not publication authority. The agent currently holds activation;
receipt verification and checkpoint publication remain separate release work.
"""

import hashlib
import hmac
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

PROTOCOL = "vnbui-storage-transaction/1"
TRANSFER_PROFILE_32 = "kubevirt-32m/1"
Profile = Literal[
    "checksum-enforced/1", "consumer-verified/1", "db-rooted-consumer-verified/1"
]


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class DiskMapping(WireModel):
    disk_name: str
    device: str
    bus: str
    serial: str | None


class Volume(WireModel):
    name: str
    pvc_name: str
    pvc_uid: str
    pvc_resource_version: str
    capacity_bytes: int = Field(gt=0, le=2**63 - 1)
    mapping: DiskMapping


class Source(WireModel):
    schema: Literal[1] = Field(...)
    agent_id: str
    vm_id: str
    vm_uid: str
    vmi_uid: str | None
    namespace: str
    volumes: list[Volume] = Field(min_length=1, max_length=256)


class NativeDiskSource(Source):
    schema: Literal[2] = Field(...)
    native_volumes: list[Volume] = Field(min_length=1, max_length=256)


class Parent(WireModel):
    backup_id: str
    root_backup_id: str
    receipt_sha256: str
    generation_id: str
    tracker_uid: str
    checkpoint: str


class Target(WireModel):
    endpoint: str
    bucket: str
    region: str
    configuration_prefix: str


class Encryption(WireModel):
    format: str
    key_ref: str | None


class Artifact(WireModel):
    volume_id: str
    role: str
    key: str = Field(min_length=1, max_length=1024)
    plaintext_min: int = Field(ge=0, le=2**63 - 1)
    plaintext_max: int = Field(ge=0, le=2**63 - 1)
    ciphertext_min: int = Field(ge=0, le=2**63 - 1)
    ciphertext_max: int = Field(ge=0, le=2**63 - 1)


class Plan(WireModel):
    attempt_id: str
    capability_profile: Profile
    source: NativeDiskSource | Source
    provider: Literal["kubevirt"]
    vm_name: str
    backup_type: Literal["full", "incremental"]
    exclusions: list[str] = Field(max_length=256)
    parent: Parent | None
    target: Target
    credential_ref: str
    encryption: Encryption
    artifacts: list[Artifact] = Field(min_length=1, max_length=4096)
    checksum_policy: Literal["sha256-parts-receipt-v2"]


class CapabilityEvidenceRef(WireModel):
    id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    revision: int = Field(gt=0, le=2**63 - 1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    adapter: Literal["vnbui-callback-provider/1"]
    wire: Literal["vnbui-storage-transaction/1"]


class QualifiedPlan(Plan):
    # An explicit unmounted successor; the old representation remains unchanged.
    evidence_schema: int = Field(ge=1, le=1)
    capability_evidence: CapabilityEvidenceRef


class CapabilityEvidenceRefV2(CapabilityEvidenceRef):
    schema: int = Field(ge=2, le=2)


class QualifiedPlanV2(Plan):
    evidence_schema: int = Field(ge=2, le=2)
    capability_evidence: CapabilityEvidenceRefV2


class TransferPlan(Plan):
    # Separate representation keeps absent fields and legacy plan digests intact.
    transfer_profile: Literal["kubevirt-32m/1"]


class TransferQualifiedPlan(QualifiedPlan, TransferPlan):
    pass


class TransferQualifiedPlanV2(QualifiedPlanV2, TransferPlan):
    pass


def plan_digest(plan):
    return hashlib.sha256(
        json.dumps(
            plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


class TransactionRequest(WireModel):
    protocol: Literal["vnbui-storage-transaction/1"]
    org_id: str
    agent_id: str
    backup_id: str
    reservation_id: str
    plan_sha256: str
    plan: (
        TransferQualifiedPlanV2
        | TransferQualifiedPlan
        | TransferPlan
        | QualifiedPlanV2
        | QualifiedPlan
        | Plan
    )

    @model_validator(mode="after")
    def bound_plan(self):
        from core.storage_semantics import validate_semantics

        validate_semantics(self)
        if self.agent_id != self.plan.source.agent_id:
            raise ValueError("Agent binding mismatch")
        if not hmac.compare_digest(
            self.plan_sha256.encode(), plan_digest(self.plan.model_dump()).encode()
        ):
            raise ValueError("Plan digest mismatch")
        return self


def validate_transaction(value):
    """Explicit representation selection, never fallback after failed decoding."""
    if (
        type(value) is dict
        and type(value.get("plan")) is dict
        and value["plan"].get("provider") == "libvirt"
    ):
        from core.native_storage_wire import NativeTransactionRequest

        return NativeTransactionRequest.model_validate(value).model_dump()
    return TransactionRequest.model_validate(value).model_dump()


def decode_request(body: bytes):
    """Reject duplicate keys, non-integer schema/counts and unknown versions."""
    if len(body) > 4 * 1024 * 1024:
        raise ValueError("Storage request exceeds bound")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate storage request field")
            result[key] = value
        return result

    value = json.loads(body, object_pairs_hook=unique_pairs)
    # Literal[1] also accepts bool/float in Pydantic; the wire does not.
    if (
        type(value) is not dict
        or type(value.get("plan")) is not dict
        or type(value["plan"].get("source")) is not dict
        or type(value["plan"]["source"].get("schema")) is not int
    ):
        raise ValueError("Invalid source schema")
    return TransactionRequest.model_validate(value)
