"""
Real restore execution via agents
Replaces mock restore simulation in routers/restores.py
"""

import asyncio
import httpx
import logging
import os
from datetime import datetime
from typing import Optional, Dict, Tuple

from database import SessionLocal
from models import Backup, Restore, VM, Agent, Organization, OrganizationDefault, User
from config import settings
from core.file_agent_http import AgentPeer, FileAgentHTTP
from core.vm_agent_peer import AgentPeerUnavailable, vm_agent_peer
from core.task_lifetime import DispatchLifetime, owned_dispatch, run_owned_worker
from core.tenant_context import TenantContext, commercial_mode, _validate_user_id

from core.legacy_recovery import (
    LEGACY_RECOVERY_REFUSAL,
    legacy_s3_unverified,
    recorded_legacy_local_path,
)

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
    if getattr(restore, "s3_recovery", None):
        from core import bucket_recovery

        plan = restore.native_plan or restore.kubevirt_plan
        if (
            not bucket_recovery.recovery_admin(actor)
            or restore.backup_id is not None
            or restore.restore_to_original
            or restore.target_vm_id is not None
            or not plan
            or plan["org_id"] != org_id
            or plan["restore_id"] != restore.id
        ):
            raise RestoreAdmissionError("S3 recovery admission refused")
        agent = bucket_recovery.destination(
            db,
            org_id,
            plan["agent_id"],
            restore.s3_recovery["point"]["provider"],
            plan["bundle"],
            plan["target"],
            lock=True,
            check_existing=False,
        )
        return restore, None, None, agent
    backup = locked(Backup, id=restore.backup_id, org_id=org_id)
    if backup is None or backup.status != "completed":
        raise RestoreAdmissionError("Restore admission refused")
    if legacy_s3_unverified(backup):
        raise RestoreAdmissionError(LEGACY_RECOVERY_REFUSAL)
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
        self.monitoring_tasks = {}
        self.agent_tls_enabled = (
            os.getenv("AGENT_TLS_ENABLED", "false").lower() == "true"
        )
        client_cert = os.getenv("ORCHESTRATOR_CLIENT_CERT")
        client_key = os.getenv("ORCHESTRATOR_CLIENT_KEY")
        ca = os.getenv("AGENT_CA_CERT")
        verify = ca or os.getenv("AGENT_VERIFY_SSL", "true").lower() == "true"
        self.http_client = (
            FileAgentHTTP(
                ca=ca, certificate=(client_cert, client_key), max_response_bytes=262144
            )
            if client_cert and client_key and verify
            else None
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

            self.http_client = FileAgentHTTP(
                ca=ca_path, certificate=(cert_path, key_path), max_response_bytes=262144
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
            if recorded_legacy_local_path(backup) is None:
                raise RestoreAdmissionError(LEGACY_RECOVERY_REFUSAL)
            peer = self._agent_peer(db, agent)
            self._transport()
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

            # Legacy local recovery has no authority to unwrap a catalog key
            # or to obtain S3 credentials. The fresh plans above use retained
            # and revalidated DB-rooted receipts for these actions.
            backup_path = recorded_legacy_local_path(backup)
            if backup_path is None:
                raise RestoreAdmissionError(LEGACY_RECOVERY_REFUSAL)
            from core.agent_requests import build_restore_request

            agent_request = build_restore_request(
                restore_id=restore.id,
                backup_path=backup_path,
                restore_path=restore.target_vm_name
                or f"/var/lib/vnbui/restores/{restore.id}",
                selected_disks=restore.selected_disks or None,
                target_name=(
                    restore.target_vm_name if not restore.restore_to_original else None
                ),
                until_checkpoint=restore.until_checkpoint,
                auto_define=restore.auto_define,
                adjust_config=restore.adjust_config,
            )

            # Send to agent
            restore, backup, vm, agent = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            if (backup.id, vm.id, agent.id) != source_binding:
                raise RestoreAdmissionError("Restore source changed before send")
            if self._agent_peer(db, agent) != peer:
                raise RestoreAdmissionError("Restore target transport changed")
            db.commit()
            response, _ = await self._send_restore_command(
                peer,
                agent_request,
                recheck=self._peer_recheck(restore_id, org_id, actor_id, peer),
            )

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
            if (backup.id, vm.id, agent.id) != source_binding or self._agent_peer(
                db, agent
            ) != peer:
                raise RestoreAdmissionError("Restore source changed after send")
            restore.status = "running"
            restore.started_at = datetime.utcnow()
            restore.progress = 0
            db.commit()

            logger.info(f"Started restore {restore_id} on agent {agent.hostname}")

            # Start monitoring task
            task = asyncio.create_task(
                self.monitor_restore(restore_id, peer, org_id, actor_id)
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
        source_binding = (restore.backup_id, vm.id if vm else None, agent.id)
        plan = restore.kubevirt_plan or restore.native_plan
        if plan["agent_id"] != agent.id or plan["org_id"] != org_id:
            raise RestoreAdmissionError("Restore plan owner changed")
        peer = self._agent_peer(db, agent)
        self._transport()
        if phase != "running":
            restore.status = "dispatching"
            db.commit()
            recovery_material = None
            if getattr(restore, "s3_recovery", None):
                from core import bucket_recovery

                def load_material():
                    with TenantContext(org_id, actor_id), SessionLocal() as scoped:
                        current = (
                            scoped.query(Restore)
                            .filter_by(id=restore_id, org_id=org_id)
                            .one()
                        )
                        return bucket_recovery.check_point(scoped, current)

                recovery_material = await run_owned_worker(load_material)
            # Recheck local authority after the independent bucket read and
            # before unwrapping a DEK or delivering repository credentials.
            restore, _, _, current_agent = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            if self._agent_peer(db, current_agent) != peer:
                raise RestoreAdmissionError("Restore target transport changed")
            if recovery_material is None:
                request = restore_profile.hydrate_request(db, restore)
            else:
                request = bucket_recovery.hydrate_request(
                    db, restore, recovery_material
                )
                del recovery_material
            db.commit()
            response, refusal = await self._send_restore_command(
                peer,
                request,
                recheck=self._peer_recheck(restore_id, org_id, actor_id, peer),
            )
            del request
            if response is None:
                if refusal == "prejournal_target_reserved":
                    # The authenticated agent rejected this exact destination
                    # before writing a journal. A missing/failed HTTP response
                    # is never enough to enter this branch.
                    restore, backup, vm, agent = admit_restore(
                        db, restore_id, org_id, actor_id, "dispatching"
                    )
                    if (
                        restore.backup_id,
                        vm.id if vm else None,
                        agent.id,
                    ) != source_binding:
                        raise RestoreAdmissionError(
                            "Restore source changed after pre-journal refusal"
                        )
                    if self._agent_peer(db, agent) != peer:
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
            restore, _, _, current_agent = admit_restore(
                db, restore_id, org_id, actor_id, "dispatching"
            )
            if self._agent_peer(db, current_agent) != peer:
                raise RestoreAdmissionError("Restore target transport changed")
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
                self.monitor_restore(restore_id, peer, org_id, actor_id)
            )
            self.monitoring_tasks[restore_id] = task

    @staticmethod
    def _agent_peer(db, agent):
        try:
            return vm_agent_peer(db, agent)
        except AgentPeerUnavailable as exc:
            raise RestoreAdmissionError(str(exc)) from None

    def _transport(self):
        if (
            not self.agent_tls_enabled
            or not isinstance(self.http_client, FileAgentHTTP)
            or not settings.orchestrator_to_agent_key
        ):
            raise RestoreAdmissionError(
                "Restore requires configured enrolled agent HTTPS"
            )
        return self.http_client

    @staticmethod
    def _get_agent_headers(peer):
        return {
            "X-Orchestrator-Key": settings.orchestrator_to_agent_key,
            "X-Vesta-Agent-ID": peer.agent_id,
        }

    def _peer_recheck(self, restore_id, org_id, actor_id, peer):
        def recheck():
            with TenantContext(org_id, actor_id), SessionLocal() as db:
                _, _, _, agent = admit_restore(
                    db, restore_id, org_id, actor_id, "dispatching"
                )
                if self._agent_peer(db, agent) != peer:
                    raise RestoreAdmissionError(
                        "Restore target transport changed before request"
                    )

        async def verified():
            await run_owned_worker(recheck)

        return verified

    async def _send_restore_command(
        self, peer: AgentPeer, request: Dict, *, recheck=None
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Send once to a revalidated TLS peer; redact all remote failure bodies."""
        try:
            response = await self._transport().post(
                peer,
                "/api/restores",
                json=request,
                headers=self._get_agent_headers(peer),
                recheck=recheck,
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

    async def monitor_restore(self, restore_id: str, peer: AgentPeer, org_id, actor_id):
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
                    if self._agent_peer(db, agent) != peer:
                        raise RestoreAdmissionError("Restore monitor peer changed")
                except RestoreAdmissionError:
                    db.rollback()
                    break
                db.commit()

                # Get status from agent
                try:
                    response = await self._transport().get(
                        peer,
                        f"/api/restores/{restore_id}",
                        headers=self._get_agent_headers(peer),
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
                if self._agent_peer(db, agent) != peer:
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
        if self.http_client is not None:
            await self.http_client.aclose()
        self._shutdown_complete = True


# Global instance
restore_executor = RestoreExecutor()
