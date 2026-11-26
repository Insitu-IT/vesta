"""
Real restore execution via agents
Replaces mock restore simulation in routers/restores.py
"""

import asyncio
import base64
import hashlib
import httpx
import logging
import os
from datetime import datetime
from typing import Optional, Dict, Tuple
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Backup, Restore, VM, Agent, Organization, OrganizationDefault, User
from config import settings
from core.agent_http import AgentHTTP
from core.task_lifetime import DispatchLifetime, owned_dispatch
from core.tenant_context import TenantContext, commercial_mode, _validate_user_id

logger = logging.getLogger(__name__)


class RestoreAdmissionError(RuntimeError):
    """No credential or remote authority is granted by a refused worker."""


def admit_restore(db, restore_id, org_id, actor_id, phase):
    """Refresh and lock persisted manual authority; never borrow worker authority."""

    def locked(model, **fields):
        return (
            db.query(model)
            .filter_by(**fields)
            .populate_existing()
            .with_for_update(nowait=True)
            .one_or_none()
        )

    if not commercial_mode():
        assignment = db.get(OrganizationDefault, "oss", populate_existing=True)
        if assignment is None or assignment.org_id != org_id:
            raise RestoreAdmissionError("Restore admission refused")
    org = locked(Organization, id=org_id)
    actor = locked(User, id=actor_id, org_id=org_id)
    if (
        org is None
        or org.enabled is not True
        or actor is None
        or actor.is_active is not True
        or actor.role not in {"admin", "operator"}
    ):
        raise RestoreAdmissionError("Restore admission refused")
    restore = locked(Restore, id=restore_id, org_id=org_id)
    if restore is None or restore.created_by != actor_id or restore.status != phase:
        raise RestoreAdmissionError("Restore admission refused")
    backup = locked(Backup, id=restore.backup_id, org_id=org_id)
    if backup is None or backup.status != "completed":
        raise RestoreAdmissionError("Restore admission refused")
    vm = locked(VM, id=backup.vm_id, org_id=org_id)
    if vm is None or (restore.restore_to_original and restore.target_vm_id != vm.id):
        raise RestoreAdmissionError("Restore admission refused")
    if restore.target_vm_id and not restore.restore_to_original:
        raise RestoreAdmissionError("Restore admission refused")
    agent = locked(Agent, id=vm.agent_id, org_id=org_id)
    if agent is None or agent.status != "online":
        raise RestoreAdmissionError("Restore admission refused")
    kubevirt_plan = getattr(restore, "kubevirt_plan", None)
    if kubevirt_plan and kubevirt_plan.get("bundle"):
        from core.kubevirt_restore import require_restore_capability

        require_restore_capability(agent, kubevirt_plan["bundle"])
    return restore, backup, vm, agent


class RestoreExecutor:
    """
    Orchestrates enrolled restores over authenticated agent transport.
    """

    def __init__(self):
        self.dispatch_lifetime = DispatchLifetime()
        self._shutdown_complete = False
        # Configure HTTP client (reuse same mTLS config as backup_executor)
        client_config = {"timeout": 30.0}

        agent_ca_cert = os.getenv("AGENT_CA_CERT")
        client_cert = os.getenv("ORCHESTRATOR_CLIENT_CERT")
        client_key = os.getenv("ORCHESTRATOR_CLIENT_KEY")

        if agent_ca_cert:
            client_config["verify"] = agent_ca_cert
        else:
            agent_verify_ssl = os.getenv("AGENT_VERIFY_SSL", "true").lower() == "true"
            client_config["verify"] = agent_verify_ssl

        if client_cert and client_key:
            client_config["cert"] = (client_cert, client_key)

        self.http_client = AgentHTTP(**client_config)
        self.monitoring_tasks = {}  # restore_id -> asyncio.Task
        self.agent_tls_enabled = (
            os.getenv("AGENT_TLS_ENABLED", "false").lower() == "true"
        )

    def configure_mtls_from_db(self, db):
        """Load mTLS certs from secrets_v3 if env vars not set.

        Called from app startup after DB is available.
        """
        if os.getenv("ORCHESTRATOR_CLIENT_CERT"):
            return

        try:
            from core.settings_service import SettingsService
            from core.pki import is_ca_initialized
            import tempfile

            if not is_ca_initialized(db):
                return

            svc = SettingsService(db)
            ca_cert_pem = svc.get("pki.ca_cert")
            backend_cert_pem = svc.get_secret("pki.backend_cert")
            backend_key_pem = svc.get_secret("pki.backend_key")

            if not all([ca_cert_pem, backend_cert_pem, backend_key_pem]):
                return

            cert_dir = tempfile.mkdtemp(prefix="vnbui-mtls-")
            ca_path = os.path.join(cert_dir, "ca.crt")
            cert_path = os.path.join(cert_dir, "client.crt")
            key_path = os.path.join(cert_dir, "client.key")

            with open(ca_path, "w") as f:
                f.write(ca_cert_pem)
            with open(cert_path, "w") as f:
                f.write(backend_cert_pem)
            with open(key_path, "w") as f:
                f.write(backend_key_pem)
            os.chmod(key_path, 0o600)

            self.http_client = AgentHTTP(
                timeout=30.0,
                verify=ca_path,
                cert=(cert_path, key_path),
            )
            self.agent_tls_enabled = True
            logger.info("mTLS enabled for restore agent communication (loaded from DB)")
        except Exception as e:
            logger.warning(f"Failed to load mTLS certs from DB: {e}")

    @owned_dispatch
    async def execute_restore(self, restore_id: str, org_id=None, actor_id=None):
        # Delivery without explicit provenance is held, never guessed from an
        # ambient worker/platform context or a similarly named identity.
        for value in (restore_id, org_id, actor_id):
            _validate_user_id(value)
        with TenantContext(org_id, actor_id):
            return await self._execute_restore_scoped(restore_id, org_id, actor_id)

    async def _execute_restore_scoped(self, restore_id, org_id, actor_id):
        """
        Execute restore via agent

        Flow:
        1. Load restore, backup, and VM details
        2. Check backup is encrypted - get key if so
        3. Find agent for VM's host
        4. Send restore command to agent
        5. Start monitoring task
        """
        db = SessionLocal()
        try:
            recorded = (
                db.query(Restore).filter_by(id=restore_id, org_id=org_id).one_or_none()
            )
            if recorded is not None and (
                getattr(recorded, "kubevirt_plan", None)
                or getattr(recorded, "native_plan", None)
            ):
                return await self._execute_fresh_restore(
                    db, restore_id, org_id, actor_id
                )
            restore, backup, vm, agent = admit_restore(
                db, restore_id, org_id, actor_id, "pending"
            )
            source_binding = (backup.id, vm.id, agent.id)
            # A durable conservative claim precedes even key resolution. Lost
            # commit acknowledgement cannot cause a second producer on restart.
            restore.status = "dispatching"
            db.commit()
            restore, backup, vm, agent = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            if (backup.id, vm.id, agent.id) != source_binding:
                raise RestoreAdmissionError("Restore source changed during admission")
            # Do not hold synchronous row locks across awaited KMS/network I/O:
            # another ASGI request could block this same event loop.
            db.commit()

            # Determine restore source: S3 chain or local file
            is_s3_restore = backup.storage_path and backup.storage_path.startswith(
                "s3://"
            )

            if is_s3_restore and backup.chain_id:
                # S3 restore: resolve full chain and send to agent
                agent_request = await self._build_s3_restore_request(
                    restore, backup, db
                )
                if agent_request is None:
                    # _build_s3_restore_request already set restore.status = "failed"
                    return {"status": "held"}
            else:
                # Local restore (existing behavior)
                if backup.storage_path and backup.storage_path.startswith("file://"):
                    backup_path = backup.storage_path.replace("file://", "")
                else:
                    backup_path = f"/var/lib/vnbui/backups/{backup.id}"

                # Resolve encryption config if backup was encrypted
                from core.agent_requests import build_restore_request

                enc_type = None
                enc_key = None
                enc_hash = None

                if backup.tags and backup.tags.get("encrypted"):
                    dek = None
                    encryption_type = backup.tags.get("encryption_type", "aes-256-gcm")

                    # Try envelope encryption first (v3.1+ backups)
                    if backup.encryption_key_id and backup.wrapped_dek:
                        try:
                            from core.kms import get_kms_provider

                            kms = get_kms_provider()
                            wrapped_dek_bytes = base64.b64decode(backup.wrapped_dek)
                            dek = await kms.unwrap_dek(
                                wrapped_dek_bytes, backup.encryption_key_id
                            )
                            logger.info(
                                f"Restore {restore.id}: unwrapped DEK via KMS (KEK={backup.encryption_key_id})"
                            )
                        except Exception:
                            logger.error("Restore key resolution failed")
                            restore.status = "failed"
                            restore.error_message = "Restore key resolution failed"
                            db.commit()
                            return {"status": "held"}

                    # Fallback: legacy env var mode (pre-envelope backups)
                    if dek is None:
                        encryption_key = os.getenv("ENCRYPTION_KEY", "")
                        if not encryption_key:
                            logger.error(
                                "Cannot restore encrypted backup: no KMS key and ENCRYPTION_KEY not set"
                            )
                            restore.status = "failed"
                            restore.error_message = "Cannot restore encrypted backup: encryption key not available"
                            db.commit()
                            return {"status": "held"}

                        encryption_key_hash = backup.tags.get("encryption_key_hash")
                        if encryption_key_hash:
                            actual_hash = hashlib.sha256(
                                encryption_key.encode()
                            ).hexdigest()[:16]
                            if actual_hash != encryption_key_hash:
                                logger.error(
                                    f"Encryption key mismatch for backup {backup.id}: "
                                    f"expected {encryption_key_hash}, got {actual_hash}"
                                )
                                restore.status = "failed"
                                restore.error_message = (
                                    "Encryption key does not match the key used for this backup. "
                                    "The backup may require a different encryption key."
                                )
                                db.commit()
                                return {"status": "held"}

                        # Legacy key is passed as-is (not base64-encoded raw bytes)
                        enc_type = encryption_type
                        enc_key = encryption_key
                        enc_hash = encryption_key_hash
                        logger.info(f"Restore {restore.id} using legacy encryption key")
                        dek = None  # Signal that we already set encryption fields

                    # Set encryption fields for envelope-encrypted backups
                    if dek is not None:
                        enc_type = encryption_type
                        enc_key = base64.b64encode(dek).decode()
                        enc_hash = backup.tags.get("encryption_key_hash")
                        logger.info(
                            f"Restore {restore.id} will decrypt with envelope encryption"
                        )

                agent_request = build_restore_request(
                    restore_id=restore.id,
                    backup_path=backup_path,
                    restore_path=restore.target_vm_name
                    or f"/var/lib/vnbui/restores/{restore.id}",
                    selected_disks=restore.selected_disks or None,
                    target_name=(
                        restore.target_vm_name
                        if not restore.restore_to_original
                        else None
                    ),
                    until_checkpoint=restore.until_checkpoint,
                    auto_define=restore.auto_define,
                    adjust_config=restore.adjust_config,
                    encryption_type=enc_type,
                    encryption_key=enc_key,
                    encryption_key_hash=enc_hash,
                )

            # Send to agent
            restore, backup, vm, agent = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            if (backup.id, vm.id, agent.id) != source_binding:
                raise RestoreAdmissionError("Restore source changed before send")
            agent_url = self._get_agent_url(agent)
            db.commit()
            response, _ = await self._send_restore_command(agent_url, agent_request)

            if not response:
                # A transport failure is not evidence the agent did not start.
                db.rollback()
                logger.error(
                    "Restore dispatch outcome uncertain; reconciliation required"
                )
                return {"status": "held"}

            # Mark as running
            restore, backup, vm, agent = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            if (backup.id, vm.id, agent.id) != source_binding:
                raise RestoreAdmissionError("Restore source changed after send")
            restore.status = "running"
            restore.started_at = datetime.utcnow()
            restore.progress = 0
            db.commit()

            logger.info(f"Started restore {restore_id} on agent {agent.hostname}")

            # Start monitoring task
            task = asyncio.create_task(
                self.monitor_restore(restore_id, agent_url, org_id, actor_id)
            )
            self.monitoring_tasks[restore_id] = task

        except Exception:
            db.rollback()
            logger.warning("Restore worker refused or uncertain; no automatic replay")
            return {"status": "held"}
        finally:
            db.close()

    async def _execute_fresh_restore(self, db, restore_id, org_id, actor_id):
        recorded = (
            db.query(Restore).filter_by(id=restore_id, org_id=org_id).one_or_none()
        )
        if recorded is None or recorded.status not in {
            "pending",
            "dispatching",
            "running",
        }:
            raise RestoreAdmissionError("Restore is not resumable")
        if recorded.native_plan:
            from core import native_restore as restore_profile
        else:
            from core import kubevirt_restore as restore_profile
        phase = recorded.status
        restore, backup, vm, agent = admit_restore(
            db, restore_id, org_id, actor_id, phase
        )
        source_binding = (backup.id, vm.id, agent.id)
        plan = restore.kubevirt_plan or restore.native_plan
        if plan["agent_id"] != agent.id or plan["org_id"] != org_id:
            raise RestoreAdmissionError("Restore plan owner changed")
        url = self._get_agent_url(agent)
        if (
            not url.startswith("https://")
            or not settings.orchestrator_to_agent_key
            or self.http_client._configuration.get("verify", True) is False
        ):
            raise RestoreAdmissionError(
                "Fresh restore requires verified authenticated agent HTTPS"
            )
        if phase != "running":
            restore.status = "dispatching"
            db.commit()
            # Recheck the human, selected catalog and key state immediately
            # before granting custody; idempotent resend retains the same plan.
            restore, _, _, current_agent = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            if self._get_agent_url(current_agent) != url:
                raise RestoreAdmissionError("Restore target transport changed")
            request = restore_profile.hydrate_request(db, restore)
            db.commit()
            response, refusal = await self._send_restore_command(url, request)
            del request
            if response is None:
                if refusal == "prejournal_target_reserved":
                    # The authenticated agent rejected this exact destination
                    # before writing a journal. A missing/failed HTTP response
                    # is never enough to enter this branch.
                    restore, backup, vm, agent = admit_restore(
                        db, restore_id, org_id, actor_id, "dispatching"
                    )
                    if (backup.id, vm.id, agent.id) != source_binding:
                        raise RestoreAdmissionError(
                            "Restore source changed after pre-journal refusal"
                        )
                    if self._get_agent_url(agent) != url:
                        raise RestoreAdmissionError(
                            "Restore agent transport changed after pre-journal refusal"
                        )
                    restore.status = "failed"
                    restore.error_message = (
                        "Fresh restore target is reserved by an agent journal; "
                        "choose new VM and PVC names"
                    )
                    restore.completed_at = datetime.utcnow()
                    db.commit()
                    return  # Proven pre-journal refusal is a known terminal failure.
                # An unconfirmed send retains exact-plan custody for /resume.
                return {"status": "held"}
            restore, _, _, _ = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            restore_profile.apply_progress(restore, response)
            if restore.started_at is None:
                restore.started_at = datetime.utcnow()
            if restore.status == "completed":
                restore.completed_at = datetime.utcnow()
            db.commit()
        else:
            db.commit()
        if restore.status == "running" and restore_id not in self.monitoring_tasks:
            task = asyncio.create_task(
                self.monitor_restore(restore_id, url, org_id, actor_id)
            )
            self.monitoring_tasks[restore_id] = task

    def _get_agent_url(self, agent: Agent) -> str:
        """Get agent API URL with optional TLS support"""
        host = agent.ip_address or agent.hostname
        port = agent.port or 8090
        scheme = "https" if self.agent_tls_enabled else "http"
        return f"{scheme}://{host}:{port}"

    def _get_agent_headers(self) -> Dict[str, str]:
        """Get headers for agent requests including authentication"""
        headers = {}
        if settings.orchestrator_to_agent_key:
            headers["X-Orchestrator-Key"] = settings.orchestrator_to_agent_key
        return headers

    async def _build_s3_restore_request(
        self, restore: Restore, backup: Backup, db: Session
    ) -> Optional[Dict]:
        """Build agent restore request for S3-stored chain backups.

        Resolves the full chain up to the requested backup, unwraps each
        member's DEK, and packages everything for the agent.

        Returns agent_request dict, or None if an error occurred (restore
        status is set to failed in that case).
        """
        from core.backup_service import BackupService
        from core.settings_service import SettingsService

        backup_svc = BackupService(db)
        chain = backup_svc.get_chain(backup.chain_id)

        if not chain:
            restore.status = "failed"
            restore.error_message = "No chain backups found for S3 restore"
            db.commit()
            return None

        s3_config = SettingsService(db).get_s3_config()
        if not s3_config:
            restore.status = "failed"
            restore.error_message = "S3 storage not configured"
            db.commit()
            return None

        prefix = s3_config.get("prefix", "backups").strip("/")

        # Build chain members up to the requested backup's position
        chain_members = []
        for cb in chain:
            if cb.chain_position is not None and backup.chain_position is not None:
                if cb.chain_position > backup.chain_position:
                    continue  # Only include up to the requested backup

            from core.agent_requests import build_chain_member

            enc_key = None
            enc_type_str = None

            # Unwrap each member's DEK if encrypted
            if cb.encryption_key_id and cb.wrapped_dek:
                try:
                    from core.kms import get_kms_provider

                    kms = get_kms_provider()
                    wrapped_dek_bytes = base64.b64decode(cb.wrapped_dek)
                    dek = await kms.unwrap_dek(wrapped_dek_bytes, cb.encryption_key_id)
                    enc_key = base64.b64encode(dek).decode()
                    enc_type_str = (cb.tags or {}).get("encryption_type", "aes-256-gcm")
                except Exception as e:
                    logger.error(f"Failed to unwrap DEK for chain member {cb.id}: {e}")
                    restore.status = "failed"
                    restore.error_message = (
                        f"Failed to unwrap encryption key for backup {cb.id}: {e}"
                    )
                    db.commit()
                    return None

            member = build_chain_member(
                backup_id=cb.id,
                s3_prefix=f"{prefix}/{cb.id}/",
                chain_position=cb.chain_position,
                encryption_key=enc_key,
                encryption_type=enc_type_str,
            )
            chain_members.append(member)

        # Build the S3 restore request — agent handles download + assembly
        from core.agent_requests import build_s3_restore_request, build_s3_config

        return build_s3_restore_request(
            restore_id=restore.id,
            restore_path=restore.target_vm_name
            or f"/var/lib/vnbui/restores/{restore.id}",
            s3_config=build_s3_config(
                endpoint=s3_config.get("endpoint"),
                bucket=s3_config["bucket"],
                region=s3_config.get("region", "us-east-1"),
                access_key=s3_config["access_key"],
                secret_key=s3_config["secret_key"],
            ),
            chain_members=chain_members,
            selected_disks=restore.selected_disks or None,
            target_name=(
                restore.target_vm_name if not restore.restore_to_original else None
            ),
            until_checkpoint=restore.until_checkpoint,
            auto_define=restore.auto_define,
            adjust_config=restore.adjust_config,
        )

    async def _send_restore_command(
        self, agent_url: str, request: Dict
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Send once; no provider body/request material escapes on failure."""
        try:
            response = await self.http_client.post(
                f"{agent_url}/api/restores",
                json=request,
                headers=self._get_agent_headers(),
            )
            if response.status_code == 409 and "kubevirt" in request:
                try:
                    submitted = request["kubevirt"]
                    target = submitted["target"]
                    proof = response.json()
                    expected = {
                        "code": "prejournal_target_reserved",
                        "restore_id": submitted["restore_id"],
                        "target_vm_name": target["vm_name"],
                        "target_pvc_names": sorted(
                            disk["pvc_name"] for disk in target["disks"]
                        ),
                        "journal_created": False,
                    }
                    if (
                        response.headers.get("cache-control") == "no-store"
                        and len(response.content) <= 2048
                        and type(proof) is dict
                        and set(proof) == set(expected)
                        and type(proof.get("journal_created")) is bool
                        and proof == expected
                    ):
                        return None, "prejournal_target_reserved"
                except (KeyError, TypeError, ValueError):
                    pass
            response.raise_for_status()
            if "kubevirt" in request and response.status_code != 202:
                return None, "Fresh restore did not receive an accepted acknowledgement"
            return response.json(), None
        except httpx.HTTPStatusError as e:
            detail = f"HTTP {e.response.status_code}"
            logger.warning("Restore command refused; outcome requires reconciliation")
            return None, detail
        except Exception:
            logger.warning("Restore command outcome uncertain")
            return None, "Restore command outcome uncertain"

    async def monitor_restore(self, restore_id: str, agent_url: str, org_id, actor_id):
        """
        Monitor restore progress by polling agent
        """
        db = SessionLocal()
        try:
            while True:
                await asyncio.sleep(5)  # Poll every 5 seconds

                try:
                    restore, _, _, agent = admit_restore(
                        db, restore_id, org_id, actor_id, "running"
                    )
                except RestoreAdmissionError:
                    db.rollback()
                    break
                if self._get_agent_url(agent) != agent_url:
                    db.rollback()
                    break
                db.commit()

                # Get status from agent
                try:
                    response = await self.http_client.get(
                        f"{agent_url}/api/restores/{restore_id}",
                        headers=self._get_agent_headers(),
                    )
                    response.raise_for_status()
                    status_data = response.json()
                except Exception:
                    db.rollback()
                    logger.warning("Restore status unavailable")
                    continue

                # Update from agent response
                restore, _, _, agent = admit_restore(
                    db, restore_id, org_id, actor_id, "running"
                )
                if self._get_agent_url(agent) != agent_url:
                    db.rollback()
                    break
                if getattr(restore, "kubevirt_plan", None):
                    from core.kubevirt_restore import apply_progress

                    apply_progress(restore, status_data)
                elif getattr(restore, "native_plan", None):
                    from core.native_restore import apply_progress

                    apply_progress(restore, status_data)
                else:
                    new_status = status_data.get("status", restore.status)
                    restore.status = new_status
                    restore.progress = status_data.get(
                        "progress_percent", restore.progress
                    )
                    error_msg = status_data.get("error_message")
                    if error_msg:
                        restore.error_message = error_msg

                db.commit()

                # Check if completed or failed
                if restore.status in ["completed", "failed", "cleanup_required"]:
                    if restore.status == "completed":
                        restore.completed_at = datetime.utcnow()
                        logger.info(f"Restore {restore_id} completed")
                    else:
                        logger.error(
                            f"Restore {restore_id} failed: {restore.error_message}"
                        )

                    db.commit()
                    break

        except Exception as e:
            logger.exception(f"Error monitoring restore {restore_id}: {e}")
        finally:
            db.close()
            if self.monitoring_tasks.get(restore_id) is asyncio.current_task():
                del self.monitoring_tasks[restore_id]

    def close_admission(self):
        self.dispatch_lifetime.close_admission()

    def start(self):
        if self.dispatch_lifetime.closed:
            if not self._shutdown_complete:
                raise RuntimeError("Restore executor shutdown remains unresolved")
            self.__init__()

    async def cleanup(self):
        """Cleanup resources"""
        from core.task_lifetime import drain_monitors

        self.close_admission()
        await self.dispatch_lifetime.drain()
        await drain_monitors(self.monitoring_tasks)
        await self.http_client.aclose()
        self._shutdown_complete = True


# Global instance
restore_executor = RestoreExecutor()
