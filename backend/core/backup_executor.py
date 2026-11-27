"""
Real backup execution via agents
Replaces mock simulate_backup_execution
"""

import asyncio
import httpx
import json
import logging
import os
import threading
from datetime import datetime
from typing import Optional, Dict, Tuple
from urllib.parse import urlsplit
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Backup, Agent, VM
from config import settings
from core.realtime import emit_backup_event
from core.agent_http import AgentHTTP
from core.file_agent_http import FileAgentHTTP
from core.task_lifetime import DispatchLifetime, owned_dispatch, run_owned_worker

logger = logging.getLogger(__name__)


class BackupExecutor:
    """
    Orchestrates actual virtnbdbackup execution via agents
    """

    def __init__(self):
        self.dispatch_lifetime = DispatchLifetime()
        self._shutdown_complete = False
        # Configure HTTP client with optional mTLS
        client_config = {"timeout": 30.0}

        # Check for mTLS configuration
        agent_ca_cert = os.getenv("AGENT_CA_CERT")  # CA to verify agent certs
        client_cert = os.getenv("ORCHESTRATOR_CLIENT_CERT")  # Client cert for mTLS
        client_key = os.getenv("ORCHESTRATOR_CLIENT_KEY")  # Client key for mTLS

        if agent_ca_cert:
            client_config["verify"] = agent_ca_cert
        else:
            # Disable SSL verification for agents (development only)
            agent_verify_ssl = os.getenv("AGENT_VERIFY_SSL", "true").lower() == "true"
            client_config["verify"] = agent_verify_ssl

        if client_cert and client_key:
            client_config["cert"] = (client_cert, client_key)
            logger.info("mTLS enabled for agent communication")

        self.file_agent_http = (
            FileAgentHTTP(ca=agent_ca_cert, certificate=(client_cert, client_key))
            if client_cert and client_key
            else None
        )
        self.http_client = AgentHTTP(**client_config)
        self.agent_verify_ssl = client_config.get("verify", True) is not False
        self.monitoring_tasks = {}  # backup_id -> asyncio.Task

        # Check if TLS is enabled for agents
        self.agent_tls_enabled = (
            os.getenv("AGENT_TLS_ENABLED", "false").lower() == "true"
        )

    def configure_mtls_from_db(self, db):
        """Load mTLS certs from secrets_v3 if env vars not set.

        Called from app startup after DB is available.
        Writes certs to temp files and reconfigures the HTTP client.
        """
        if os.getenv("ORCHESTRATOR_CLIENT_CERT"):
            return  # Already configured via env

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

            # Write to temp files for httpx
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

            # Reconfigure HTTP client
            self.http_client = AgentHTTP(
                timeout=30.0,
                verify=ca_path,
                cert=(cert_path, key_path),
            )
            self.file_agent_http = FileAgentHTTP(
                ca=ca_path, certificate=(cert_path, key_path)
            )
            self.agent_tls_enabled = True
            self.agent_verify_ssl = True
            logger.info("mTLS enabled for agent communication (loaded from DB)")
        except Exception as e:
            logger.warning(f"Failed to load mTLS certs from DB: {e}")

    @owned_dispatch
    async def execute_backup(self, backup_id: str):
        """Rebind background work to its persisted human, never ambient HTTP state."""
        from core.tenant_context import TenantContext

        # Starlette background tasks run after request middleware has released
        # its ContextVars. This trusted read locates original authority only;
        # every actual dispatch/write runs in tenant scope and is re-admitted.
        original = await run_owned_worker(
            self._read_original_backup_authority, backup_id
        )
        if original[0] == "held":
            return {"status": "held", "reason": original[1]}
        _, org_id, actor_id = original

        with TenantContext(org_id, actor_id):
            # Supported admission already owns its own worker/session. Do not
            # perform the preliminary provider lookup on the serving loop.
            provider = await run_owned_worker(self._read_supported_provider, backup_id)
            if provider is not None:
                return await self._execute_supported_in_worker(backup_id, provider)
            return await self._execute_backup_scoped(backup_id)

    def _read_original_backup_authority(self, backup_id):
        from core.backup_authority import HumanAuthority, read_authority
        from core.tenant_context import PlatformContext

        with PlatformContext(), SessionLocal() as bootstrap:
            original = bootstrap.query(Backup).filter(Backup.id == backup_id).first()
            if original is None:
                return "held", "original_backup_missing"
            try:
                authority = read_authority(original)
            except ValueError:
                return "held", "original_authority_unavailable"
            if not isinstance(authority, HumanAuthority):
                return "held", "scheduler_execution_dormant"
            return "human", original.org_id, authority.user_id

    def _read_supported_provider(self, backup_id):
        with SessionLocal() as db:
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            if backup is None or backup.authority_kind == "scheduler":
                return None
            vm = db.query(VM).filter(VM.id == backup.vm_id).first()
            if vm is None or vm.inventory_present is False:
                return None
            return vm.provider if vm.provider in {"kubevirt", "libvirt"} else None

    async def _execute_backup_scoped(self, backup_id: str):
        """
        Execute backup via agent

        Flow:
        1. Load backup and VM details
        2. Check storage space
        3. Find agent for VM's host
        4. Send backup command to agent
        5. Start monitoring task
        """
        db = SessionLocal()
        supported_transaction = False
        try:
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            if not backup:
                logger.error(f"Backup {backup_id} not found")
                return

            if backup.authority_kind == "scheduler":
                return {"status": "held", "reason": "scheduler_execution_dormant"}
            vm = db.query(VM).filter(VM.id == backup.vm_id).first()
            if not vm or vm.inventory_present is False:
                error = "VM not found or absent from inventory"
                logger.error(error)
                backup.status = "failed"
                backup.tags = backup.tags or {}
                backup.tags["error"] = error
                db.commit()
                await emit_backup_event(
                    backup_id=backup_id, status="failed", error=error
                )
                return

            if vm.provider == "kubevirt":
                supported_transaction = True
                # Admission uses the synchronous SQLAlchemy engine. It can
                # wait on owner/capacity locks, so keep the whole transaction
                # and its verified agent send off the serving event loop. A
                # fresh session lives only in that worker thread.
                db.close()
                return await self._execute_supported_in_worker(backup_id, "kubevirt")

            if vm.provider == "libvirt":
                supported_transaction = True
                db.close()
                return await self._execute_supported_in_worker(backup_id, "libvirt")

            # Unsupported or historical VM provider values have no live
            # producer admission. Preserve existing custody for reconciliation.
            return {"status": "held", "reason": "unsupported_backup_provider"}

        except Exception as e:
            db.rollback()
            if supported_transaction:
                logger.warning(
                    "Supported backup %s held after dispatch isolation failure",
                    backup_id,
                    exc_info=True,
                )
                return {
                    "status": "held",
                    "reason": "transaction_admission_or_recovery_required",
                }
            logger.exception(f"Error executing backup {backup_id}: {e}")
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            if backup:
                backup.status = "failed"
                backup.tags = backup.tags or {}
                backup.tags["error"] = str(e)
                db.commit()
        finally:
            db.close()

    async def _execute_supported_in_worker(self, backup_id, provider):
        """Isolate sync DB admission without moving dispatch-lifetime ownership."""
        from core.tenant_context import TenantContext, identity

        org_id, actor_id, platform = identity()
        if not org_id or not actor_id or platform:
            raise RuntimeError("Original human authority is required")
        cancelled = threading.Event()

        def run():
            with TenantContext(org_id, actor_id), SessionLocal() as db:
                operation = (
                    self._execute_kubevirt
                    if provider == "kubevirt"
                    else self._execute_native
                )
                return asyncio.run(operation(db, backup_id, cancellation=cancelled))

        return await run_owned_worker(run, on_cancel=cancelled.set)

    async def _post_certified_vm_backup(
        self, db, agent_id, org_id, request, *, cancellation=None
    ):
        from core.s3_ownership import StorageOwnershipError
        from core.vm_agent_peer import vm_agent_peer

        headers = self._get_agent_headers()
        if (
            not self.agent_tls_enabled
            or not self.agent_verify_ssl
            or not headers
            or self.file_agent_http is None
        ):
            raise StorageOwnershipError(
                "Verified authenticated VM transport unavailable"
            )

        def current_peer():
            if cancellation is not None and cancellation.is_set():
                raise StorageOwnershipError("Dispatch continuation cancelled")
            agent = (
                db.query(Agent)
                .filter_by(id=agent_id, org_id=org_id)
                .populate_existing()
                .one_or_none()
            )
            if agent is None or agent.status != "online":
                raise StorageOwnershipError("Transaction agent unavailable")
            return vm_agent_peer(db, agent)

        peer = current_peer()

        async def recheck():
            if current_peer() != peer:
                raise StorageOwnershipError("Enrolled VM agent identity changed")
            return peer

        return await self.file_agent_http.post(
            peer,
            "/api/backups",
            headers={**headers, "X-Vesta-Agent-ID": peer.agent_id},
            json=request,
            recheck=recheck,
        )

    async def send_storage_transaction(self, agent_id, request):
        """Send an already admitted transaction; never grant lifecycle authority.

        Manual dispatch and the organization scheduler own their admission and
        capacity locks. This transport returns only the exact durable 202 ACK.
        An exception leaves their existing custody intact for reconciliation.
        """
        from core.s3_ownership import StorageOwnershipError

        plan = request.get("plan", {})
        headers = self._get_agent_headers()
        if (
            request.get("agent_id") != agent_id
            or plan.get("provider") != "kubevirt"
            or plan.get("capability_profile") != "db-rooted-consumer-verified/1"
            or not plan.get("target", {}).get("region")
            or not self.agent_tls_enabled
            or not self.agent_verify_ssl
            or not headers
        ):
            raise StorageOwnershipError("Verified transaction transport unavailable")
        with SessionLocal() as db:
            response = await self._post_certified_vm_backup(
                db, agent_id, request["org_id"], request
            )
        expected = dict(
            status="accepted",
            backup_id=request["backup_id"],
            reservation_id=request["reservation_id"],
            plan_sha256=request["plan_sha256"],
        )
        if response.status_code != 202 or response.json() != expected:
            raise StorageOwnershipError(
                "Transaction admission was not acknowledged; custody retained"
            )
        return expected

    async def _execute_kubevirt(self, db, backup_id, *, cancellation=None):
        """Dispatch the supported manual transaction, never infer completion.

        The agent owns its persisted runner after admission. Lost HTTP replies
        retain both DB custody and agent recovery; legacy progress polling and
        the outer failed-job handler must not invalidate that live transaction.
        """
        from core.backup_capacity import reserve_capacity
        from core.s3_ownership import StorageOwnershipError
        from core.settings_service import SettingsService
        from core.storage_dispatch import dispatch_kubevirt, read_target

        try:
            target = read_target(SettingsService(db))
            if target["capability_profile"] != "db-rooted-consumer-verified/1":
                raise StorageOwnershipError(
                    "Manual execution requires the DB-rooted storage profile"
                )
            if not target["region"]:
                raise StorageOwnershipError(
                    "Manual execution requires an explicit S3 signing region"
                )
            if (
                not self.agent_tls_enabled
                or not self.agent_verify_ssl
                or not self._get_agent_headers()
            ):
                raise StorageOwnershipError(
                    "Manual execution requires verified agent HTTPS and orchestrator authentication"
                )

            # Capacity is a separate durable transaction, before producer
            # custody. It validates the original initiating human, not a worker.
            db.rollback()
            reserve_capacity(SessionLocal, backup_id)

            async def send_if_live(agent_id, request):
                if cancellation is not None and cancellation.is_set():
                    raise StorageOwnershipError("Dispatch continuation cancelled")
                return await self.send_storage_transaction(agent_id, request)

            result = await dispatch_kubevirt(db, backup_id, send_if_live)
            # Publication may already have completed while the HTTP reply was
            # in flight. Only advance pending -> running under a fresh row lock.
            current = (
                db.query(Backup)
                .filter_by(id=backup_id)
                .populate_existing()
                .with_for_update()
                .one()
            )
            if current.status == "pending":
                current.status = "running"
                db.commit()
            return result
        except Exception as failure:
            db.rollback()
            try:
                from core.backup_unreserved import close_unreserved

                return close_unreserved(SessionLocal, backup_id)
            except Exception:
                # A failed reservation call is not proof that its commit failed.
                # Reserved or uncertain records retain the existing custody path.
                pass
            # A source-selection refusal can occur after capacity was reserved
            # but before its first durable publication. The capacity trigger
            # independently refuses this transition once effect custody exists.
            # Requiring no publication at all is stricter still: a lost send
            # acknowledgement or committed dispatch always remains held.
            try:
                from core.backup_capacity import release_never_effect
                from models import S3Publication, StorageLineageGeneration

                def fail_unstarted(session):
                    original = (
                        session.query(Backup)
                        .filter(Backup.id == backup_id)
                        .populate_existing()
                        .with_for_update()
                        .one()
                    )
                    if (
                        original.status != "pending"
                        or original.capacity_state != "released"
                        or not original.capacity_release
                        or original.capacity_release.get("reason")
                        != "never_effect_admitted"
                        or session.query(S3Publication.id)
                        .filter(S3Publication.backup_id == backup_id)
                        .first()
                        or session.query(StorageLineageGeneration.id)
                        .filter(StorageLineageGeneration.backup_id == backup_id)
                        .first()
                    ):
                        raise StorageOwnershipError(
                            "Durable producer custody requires held reconciliation"
                        )
                    original.status = "failed"
                    original.tags = dict(
                        original.tags or {}, error="pre_dispatch_refused"
                    )

                release = release_never_effect(
                    SessionLocal, backup_id, before_commit=fail_unstarted
                )
                if release["disposition"] != "committed_custody":
                    raise StorageOwnershipError(
                        "No-effect terminal transition was not committed"
                    )
            except Exception:
                logger.warning(
                    "KubeVirt transaction %s held; original custody retained",
                    backup_id,
                    exc_info=True,
                )
                return {
                    "status": "held",
                    "reason": "transaction_admission_or_recovery_required",
                }
            logger.warning(
                "KubeVirt transaction %s failed before durable producer custody: %s",
                backup_id,
                failure,
            )
            return {
                "status": "failed",
                "reason": "pre_dispatch_no_effect",
            }

    async def send_native_job(self, agent_id, request):
        """Verified native intent transport, shared by human and scheduler paths."""
        from core.native_inventory import digest
        from core.s3_ownership import StorageOwnershipError

        intent = request.get("intent", {})
        headers = self._get_agent_headers()
        if (
            request.get("protocol") != "vnbui-native-job/1"
            or intent.get("agent_id") != agent_id
            or request.get("intent_sha256") != digest(intent)
            or not self.agent_tls_enabled
            or not self.agent_verify_ssl
            or not headers
        ):
            raise StorageOwnershipError("Verified native transport unavailable")
        with SessionLocal() as db:
            response = await self._post_certified_vm_backup(
                db, agent_id, intent["org_id"], request
            )
        expected = dict(
            status="accepted",
            backup_id=intent["backup_id"],
            attempt_id=intent["attempt_id"],
            intent_sha256=request["intent_sha256"],
        )
        if response.status_code != 202 or response.json() != expected:
            raise StorageOwnershipError("Native intent acknowledgment unavailable")
        return expected

    async def _execute_native(self, db, backup_id, *, cancellation=None):
        """Start only the immutable native push intent; never legacy polling.

        The agent retains an uninterrupted producer observation or an uncertain
        attempt. HTTP timeout never authorizes relaunch, cancellation or cleanup.
        """
        from core.backup_capacity import reserve_capacity
        from core.native_inventory import digest
        from core.native_job import prepare_job
        from core.s3_ownership import StorageOwnershipError
        from core.settings_service import SettingsService
        from core.storage_dispatch import read_target

        try:
            target = read_target(SettingsService(db))
            headers = self._get_agent_headers()
            if (
                target["capability_profile"] != "db-rooted-consumer-verified/1"
                or not target["region"]
                or not self.agent_tls_enabled
                or not self.agent_verify_ssl
                or not headers
            ):
                raise StorageOwnershipError(
                    "Native push requires supported storage and verified authenticated HTTPS"
                )
            db.rollback()
            reserve_capacity(SessionLocal, backup_id)
            intent = prepare_job(db, backup_id)
            # A fresh admission after the durable boundary rechecks source and
            # original actor. It cannot allocate a second producer attempt.
            if prepare_job(db, backup_id) != intent:
                raise StorageOwnershipError("Native producer intent changed")
            request = dict(
                protocol="vnbui-native-job/1",
                intent=intent,
                intent_sha256=digest(intent),
            )
            db.rollback()
            if cancellation is not None and cancellation.is_set():
                raise StorageOwnershipError("Dispatch continuation cancelled")
            expected = await self.send_native_job(intent["agent_id"], request)
            current = (
                db.query(Backup)
                .filter_by(id=backup_id)
                .populate_existing()
                .with_for_update()
                .one()
            )
            if current.status == "pending":
                current.status = "running"
                db.commit()
            return expected
        except Exception:
            db.rollback()
            try:
                from core.backup_unreserved import close_unreserved

                return close_unreserved(SessionLocal, backup_id)
            except Exception:
                pass
            logger.warning(
                "Native transaction %s held; original custody retained",
                backup_id,
                exc_info=True,
            )
            return dict(status="held", reason="native_admission_or_recovery_required")

    async def execute_backup_and_wait(self, backup_id: str):
        """Own monitor lifetime for an application-loop scheduler/queue task.

        Dispatch alone starts a child task. Keep this loop alive through any
        backup-to-upload handoff; cancellation still propagates to its child.
        No recovery or second dispatch is inferred from a missing monitor.
        """
        await self.execute_backup(backup_id)
        while task := self.monitoring_tasks.get(backup_id):
            if task.get_loop() is not asyncio.get_running_loop():
                raise RuntimeError("Backup monitor belongs to another event loop")
            try:
                await task
            finally:
                if self.monitoring_tasks.get(backup_id) is task:
                    del self.monitoring_tasks[backup_id]

    def has_authenticated_agent_transport(self):
        return (
            self.agent_tls_enabled
            and self.agent_verify_ssl
            and self.file_agent_http is not None
            and bool(self._get_agent_headers())
        )

    def _get_agent_url(self, agent: Agent) -> str:
        """
        Get agent API URL with optional TLS support
        """
        # Use agent's ip_address if available, fallback to hostname
        host = agent.ip_address or agent.hostname
        port = agent.port or 8090

        # Use HTTPS if TLS is enabled
        scheme = "https" if self.agent_tls_enabled else "http"

        return f"{scheme}://{host}:{port}"

    def _get_agent_headers(self) -> Dict[str, str]:
        """Get headers for agent requests including authentication"""
        headers = {}
        if settings.orchestrator_to_agent_key:
            headers["X-Orchestrator-Key"] = settings.orchestrator_to_agent_key
        return headers

    async def _send_backup_command(
        self, agent_url: str, request: Dict
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Send backup command to agent. Returns (result, error_detail).

        On success: (response_json, None). On failure: (None, detail) where detail
        captures the agent's actual HTTP status + body (e.g. "HTTP 403: Invalid
        orchestrator key") or the transport error. Surfacing the real reason is the
        #38 product-quality fix: a 403 orchestrator-key mismatch previously collapsed
        into an opaque "Failed to send backup command" and read as a generic failure
        for ~110 days before ops-it had to diagnose it host-side.
        """
        headers = self._get_agent_headers()
        if (headers or request.get("encryption_key")) and (
            not self.agent_tls_enabled
            or not self.agent_verify_ssl
            or urlsplit(agent_url).scheme != "https"
        ):
            return None, "Verified agent HTTPS is required for credentials"
        try:
            response = await self.http_client.post(
                f"{agent_url}/api/backups",
                json=request,
                headers=headers,
            )
            response.raise_for_status()
            return response.json(), None
        except httpx.HTTPStatusError as e:
            body = (e.response.text or "").strip()[:500]
            detail = f"HTTP {e.response.status_code}" + (f": {body}" if body else "")
            logger.error(f"Backup command to {agent_url} rejected ({detail})")
            return None, detail
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"
            logger.error(f"Failed to send backup command to {agent_url}: {detail}")
            return None, detail

    async def monitor_backup(self, binding):
        """Poll with fresh scoped admission on both sides of the HTTP await."""
        from core.backup_monitor import MonitorBinding, admit, progress_observation
        from core.tenant_context import TenantContext

        if not isinstance(binding, MonitorBinding):
            return
        try:
            while True:
                await asyncio.sleep(5)
                if self.dispatch_lifetime.closed:
                    break
                with TenantContext(binding.org_id, binding.actor_id):
                    with SessionLocal() as db:
                        admit(db, binding, self._get_agent_url)
                        db.rollback()
                # No ORM session or row lock crosses network or event awaits.
                try:
                    response = await self.http_client.get(
                        f"{binding.endpoint}/api/backups/{binding.backup_id}",
                        headers=self._get_agent_headers(),
                    )
                    response.raise_for_status()
                    data = response.json()
                except Exception:
                    logger.warning("Backup status unavailable; custody retained")
                    continue
                if self.dispatch_lifetime.closed:
                    break
                with TenantContext(binding.org_id, binding.actor_id):
                    with SessionLocal() as db:
                        backup = admit(db, binding, self._get_agent_url)
                        event = progress_observation(backup, data)
                        if event is None:
                            db.rollback()
                            logger.info(
                                "Terminal observation requires authoritative reconciliation"
                            )
                            break
                        db.commit()
                with TenantContext(binding.org_id, binding.actor_id):
                    await emit_backup_event(**event)
                if event["status"] == "cleanup_required":
                    break
        except Exception:
            logger.warning("Backup monitor refused; custody retained")
        finally:
            if self.monitoring_tasks.get(binding.backup_id) is asyncio.current_task():
                del self.monitoring_tasks[binding.backup_id]

    def _is_s3_configured(self, db) -> bool:
        """Non-secret routing hint only; never destination/credential authority."""
        from core.settings_service import SettingsService

        cfg = SettingsService(db).get_many(("storage.type", "storage.s3.bucket"))
        return cfg["storage.type"] == "s3" and bool(cfg["storage.s3.bucket"])

    async def _handoff_local_upload(self, db, backup):
        """Commit local evidence before inspecting a separate first-upload handoff."""
        backup_id, org_id, actor_id = (
            backup.id,
            backup.org_id,
            backup.initiating_user_id,
        )
        db.commit()
        return await self.execute_upload(
            backup_id, org_id=org_id, initiating_user_id=actor_id, origin="first_upload"
        )

    @owned_dispatch
    async def execute_upload(
        self, backup_id: str, *, org_id=None, initiating_user_id=None, origin=None
    ):
        """Scoped upload admission, not permission to replay a path-only command.

        D05 must provide the native file-set first-dispatch interface; D07 must
        provide exact-attempt recovery. Neither upload_failed nor local completion
        supplies either authority. The KubeVirt transaction uploader is separate.
        """
        from core.tenant_context import TenantContext
        from core.upload_retry import _identifier, inspect_upload_handoff

        if origin not in {"first_upload", "automatic_retry"} or not all(
            _identifier(value) for value in (backup_id, org_id, initiating_user_id)
        ):
            return {"status": "held", "reason": "delivery_provenance_required"}
        with TenantContext(org_id):
            db = SessionLocal()
            try:
                reason = inspect_upload_handoff(
                    db, backup_id, org_id, initiating_user_id, origin
                )
                return {"status": "held", "reason": reason}
            except Exception:
                # Lock conflicts/database failure are not permission to send and
                # must not overwrite the original provider/native error evidence.
                return {"status": "held", "reason": "upload_admission_unavailable"}
            finally:
                try:
                    db.rollback()
                finally:
                    db.close()

    async def _upload_chain_manifest(self, backup: Backup, db: Session):
        """Upload chain manifest JSON to S3 after backup completion.

        The manifest captures the full chain state so a greenfield restore
        (fresh install + S3 access + exported KEKs) can reconstruct everything
        without a database.
        """
        if not backup.chain_id:
            return

        try:
            from core.settings_service import SettingsService
            from core.backup_service import BackupService

            svc = SettingsService(db)
            s3_config = svc.get_s3_config()
            if not s3_config:
                return

            backup_svc = BackupService(db)
            chain = backup_svc.get_chain(backup.chain_id)
            if not chain:
                return

            vm_name = backup_svc.get_vm_name(backup.vm_id) or backup.vm_id
            source_vm = db.query(VM).filter(VM.id == backup.vm_id).one()
            prefix = s3_config.get("prefix", "backups").strip("/")
            bucket = s3_config["bucket"]

            manifest = {
                "version": 1,
                "chain_id": backup.chain_id,
                "vm_name": vm_name,
                "vm_identity": {
                    "agent_id": source_vm.agent_id,
                    "provider": source_vm.provider,
                    "namespace": source_vm.namespace,
                    "vm_uid": source_vm.vm_uid,
                },
                "updated_at": datetime.utcnow().isoformat() + "Z",
                "backups": [],
            }

            for cb in chain:
                if cb.status != "completed" or (
                    (cb.tags or {}).get("checkpoint_required")
                    and not (cb.tags or {}).get("checkpoint_committed")
                ):
                    continue
                entry = {
                    "backup_id": cb.id,
                    "backup_type": cb.backup_type,
                    "chain_position": cb.chain_position,
                    "s3_prefix": f"{prefix}/{cb.id}/",
                    "size_bytes": cb.size_bytes,
                    "created_at": (
                        cb.created_at.isoformat() + "Z" if cb.created_at else None
                    ),
                    "completed_at": (
                        cb.completed_at.isoformat() + "Z" if cb.completed_at else None
                    ),
                }
                if cb.encryption_key_id:
                    entry["encryption_key_id"] = cb.encryption_key_id
                if cb.wrapped_dek:
                    entry["wrapped_dek"] = cb.wrapped_dek
                manifest["backups"].append(entry)

            import boto3

            s3 = boto3.client(
                "s3",
                endpoint_url=s3_config.get("endpoint") or None,
                aws_access_key_id=s3_config.get("access_key"),
                aws_secret_access_key=s3_config.get("secret_key"),
                region_name=s3_config.get("region", "us-east-1"),
            )

            manifest_key = f"{prefix}/manifests/{vm_name}/{backup.chain_id}.json"
            s3.put_object(
                Bucket=bucket,
                Key=manifest_key,
                Body=json.dumps(manifest, indent=2),
                ContentType="application/json",
            )
            logger.info(f"Uploaded chain manifest to s3://{bucket}/{manifest_key}")

        except ImportError:
            logger.debug("boto3 not installed, skipping manifest upload")
        except Exception as e:
            # Manifest upload failure is non-fatal
            logger.warning(
                f"Failed to upload chain manifest for backup {backup.id}: {e}"
            )

    @owned_dispatch
    async def stop_backup(self, backup_id: str):
        """
        Stop a running backup

        Sends stop command to agent
        """
        db = SessionLocal()
        try:
            backup = db.query(Backup).filter(Backup.id == backup_id).first()
            if not backup:
                return

            if backup.status not in ["running", "pending"]:
                return  # Already stopped

            vm = db.query(VM).filter(VM.id == backup.vm_id).first()
            agent = db.query(Agent).filter(Agent.id == vm.agent_id).first()

            if not agent:
                return

            # Send stop command to agent
            agent_url = self._get_agent_url(agent)
            try:
                response = await self.http_client.delete(
                    f"{agent_url}/api/backups/{backup_id}",
                    headers=self._get_agent_headers(),
                )
                response.raise_for_status()
            except Exception as e:
                logger.error(f"Failed to stop backup on agent: {e}")
                raise

            # Update status
            backup.status = "cancelled"
            db.commit()

            # Cancel monitoring task
            if backup_id in self.monitoring_tasks:
                self.monitoring_tasks[backup_id].cancel()

        finally:
            db.close()

    def close_admission(self):
        self.dispatch_lifetime.close_admission()

    def start(self):
        if self.dispatch_lifetime.closed:
            if not self._shutdown_complete:
                raise RuntimeError("Backup executor shutdown remains unresolved")
            self.__init__()

    async def cleanup(self):
        """
        Cleanup resources
        """
        from core.task_lifetime import drain_monitors

        self.close_admission()
        await self.dispatch_lifetime.drain()
        await drain_monitors(self.monitoring_tasks)

        # Close HTTP client
        await self.http_client.aclose()
        self._shutdown_complete = True


# Global instance
backup_executor = BackupExecutor()
