"""Builder functions for backend→agent request dicts.

These are the single source of truth for the shape of every dict the backend
sends to the agent. Both the executors and the contract tests import these,
so any drift between backend and agent models is caught automatically.

No ORM, no async, no side effects — just pure dict construction.
"""

from typing import Optional, List


def build_backup_request(
    backup_id: str,
    vm_name: str,
    backup_type: str,
    output_path: str,
    compression: Optional[str] = None,
    exclude_disks: Optional[List[str]] = None,
    workers: Optional[int] = None,
    encryption_type: Optional[str] = None,
    encryption_key: Optional[str] = None,
    parent_path: Optional[str] = None,
    include_raw: bool = False,
    vm_namespace: Optional[str] = None,
    vm_uid: Optional[str] = None,
) -> dict:
    """Build agent BackupRequest dict (backup_executor.py:209-236)."""
    request = {
        "backup_id": backup_id,
        "vm_name": vm_name,
        "backup_type": backup_type,
        "output_path": output_path,
        "compression": compression,
        "include_disks": None,
        "exclude_disks": exclude_disks,
        "workers": workers,
        "parent_path": parent_path,
        "include_raw": include_raw,
    }
    if encryption_type:
        request["encryption_type"] = encryption_type
        request["encryption_key"] = encryption_key
    if vm_namespace is not None:
        request["vm_namespace"] = vm_namespace
    if vm_uid is not None:
        request["vm_uid"] = vm_uid
    return request


def build_restore_request(
    restore_id: str,
    backup_path: str,
    restore_path: str,
    selected_disks: Optional[List[str]] = None,
    target_name: Optional[str] = None,
    until_checkpoint: Optional[str] = None,
    auto_define: bool = False,
    adjust_config: bool = False,
    encryption_type: Optional[str] = None,
    encryption_key: Optional[str] = None,
    encryption_key_hash: Optional[str] = None,
) -> dict:
    """Build agent RestoreRequest dict for local restore (restore_executor.py:163-233)."""
    request = {
        "restore_id": restore_id,
        "backup_path": backup_path,
        "restore_path": restore_path,
        "action": "restore",
        "selected_disks": selected_disks,
        "target_name": target_name,
        "until_checkpoint": until_checkpoint,
        "auto_define": auto_define,
        "adjust_config": adjust_config,
    }
    if encryption_type:
        request["encryption_type"] = encryption_type
        request["encryption_key"] = encryption_key
        request["encryption_key_hash"] = encryption_key_hash
    return request


def build_s3_restore_request(
    restore_id: str,
    restore_path: str,
    s3_config: dict,
    chain_members: List[dict],
    selected_disks: Optional[List[str]] = None,
    target_name: Optional[str] = None,
    until_checkpoint: Optional[str] = None,
    auto_define: bool = False,
    adjust_config: bool = False,
) -> dict:
    """Build agent RestoreRequest dict for S3 chain restore (restore_executor.py:346-365)."""
    return {
        "restore_id": restore_id,
        "backup_path": "",  # Not used for S3 restores
        "restore_path": restore_path,
        "action": "restore",
        "selected_disks": selected_disks,
        "target_name": target_name,
        "until_checkpoint": until_checkpoint,
        "auto_define": auto_define,
        "adjust_config": adjust_config,
        "source": "s3",
        "s3_config": s3_config,
        "chain_members": chain_members,
    }


def build_s3_config(
    endpoint: Optional[str],
    bucket: str,
    region: Optional[str],
    access_key: str,
    secret_key: str,
) -> dict:
    """Build s3_config dict for agent (restore_executor.py:357-363)."""
    return {
        "endpoint": endpoint or None,
        "bucket": bucket,
        "region": region or "us-east-1",
        "access_key": access_key,
        "secret_key": secret_key,
    }


def build_chain_member(
    backup_id: str,
    s3_prefix: str,
    chain_position: Optional[int],
    encryption_key: Optional[str] = None,
    encryption_type: Optional[str] = None,
) -> dict:
    """Build a single chain member dict (restore_executor.py:321-335)."""
    member = {
        "backup_id": backup_id,
        "s3_prefix": s3_prefix,
        "chain_position": chain_position,
    }
    if encryption_key:
        member["encryption_key"] = encryption_key
        member["encryption_type"] = encryption_type
    return member


def build_heartbeat_response(
    agent_id: str,
    timestamp: str,
    config: Optional[dict],
) -> dict:
    """Retain the nullable compatibility field without delivering S3 credentials."""
    return {
        "status": "ok",
        "timestamp": timestamp,
        "agent_id": agent_id,
        "config": config or {},
        "s3_config": None,
    }
