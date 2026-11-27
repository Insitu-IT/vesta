"""Manifest-based installation and administration for a single Vesta site."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import getpass
from http.client import IncompleteRead
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener
from uuid import UUID, uuid4

import check_fresh_target
import kit
import postgres
import render
import reconfigure
import vm_readiness

INSTALL_ROUTE_TIMEOUT = 180
INSTALL_ROUTE_REQUEST_TIMEOUT = 15
INSTALL_ROUTE_READ_LIMIT = 65536
INSTALL_ROUTE_POLL_LIMIT = 8


UPGRADE_TARGET = ("6.2.0", "managed_file_backups")
UPGRADE_SOURCES = {"6.1.0": "backup_admission_pause", "6.1.1": "backup_admission_pause"}
RUNTIME_OBSERVATION = """
import json
from sqlalchemy import create_engine, text
from config import settings
from core.postgres_profile import connection_parameters
from core.schema_parity import assert_schema_current
from core.tenant_database import assert_non_bypass_role
from version import __version__

url, parameters = connection_parameters(settings.database_url)
with create_engine(url, connect_args=parameters, hide_parameters=True).connect() as db:
    db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
    db.execute(text("SET LOCAL statement_timeout = '15s'"))
    assert_non_bypass_role(db)
    db.execute(text("SELECT set_config('app.platform_admin','true',true)"))
    database, role = db.execute(text("SELECT current_database(), current_user")).one()
    revision = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    installation = db.execute(text(
        "SELECT installation_id FROM storage_configuration_clock WHERE slot=1"
    )).scalar_one()
    assert_schema_current(db)
print(json.dumps(dict(version=__version__, revision=revision, database=database,
                      role=role, installation_id=installation)))
"""


class SiteError(ValueError):
    """A safe diagnostic with no credential or response body."""


def object_fields(value, name, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) <= set(
        required
    ) | set(optional):
        raise SiteError(f"Review the {name} fields in the manifest reference")
    return value


def nonempty(value, name):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(c) < 32 for c in value)
    ):
        raise SiteError(f"{name} requires a nonempty string")
    return value


def read_json(path):
    def unique_fields(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise SiteError("JSON contains a repeated field")
        return result

    return json.loads(path.read_text(), object_pairs_hook=unique_fields)


def private_output(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")


def https(value, name, *, allow_path=False):
    url = urlsplit(nonempty(value, name))
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username is not None
        or url.query
        or url.fragment
        or (not allow_path and url.path not in ("", "/"))
    ):
        raise SiteError(
            f"{name} requires an HTTPS URL without credentials, a query or a fragment"
        )
    return value.rstrip("/")


def release_metadata(root):
    if not (root / "manifest.json").is_file():
        raise SiteError("Run vesta from an extracted offline kit")
    manifest = read_json(root / "manifest.json")
    if (
        manifest.get("kind") != "release"
        or manifest.get("metadata", {}).get("site_launcher") != 1
    ):
        raise SiteError("This offline kit lacks the manifest launcher receipt")
    return manifest["metadata"]


def secret_ref(value, service):
    name = nonempty(value, f"{service}.secret")
    if len(name) > 253 or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", name):
        raise SiteError(f"{service}.secret requires a Kubernetes Secret name")
    return name


def integration_settings(document):
    integrations = {}
    if "s3" in document:
        s3 = object_fields(
            document["s3"],
            "s3",
            ("endpoint", "bucket", "region", "prefix"),
            ("secret", "recovery_secret"),
        )
        endpoint = "" if s3["endpoint"] == "" else https(s3["endpoint"], "s3.endpoint")
        prefix = nonempty(s3["prefix"], "s3.prefix")
        if any(part in ("", ".", "..") for part in prefix.split("/")):
            raise SiteError("s3.prefix requires a dedicated relative object prefix")
        fields = {
            "storage.type": "s3",
            "storage.s3.endpoint": endpoint,
            "storage.s3.bucket": nonempty(s3["bucket"], "s3.bucket"),
            "storage.s3.region": nonempty(s3["region"], "s3.region"),
            "storage.s3.prefix": prefix,
        }
        if "secret" in s3:
            integrations["s3"] = (
                fields,
                secret_ref(s3["secret"], "s3"),
                {
                    "storage.s3.access_key": "access_key",
                    "storage.s3.secret_key": "secret_key",
                },
            )
        if "recovery_secret" in s3:
            integrations["s3-recovery"] = (
                {} if "secret" in s3 else fields,
                secret_ref(s3["recovery_secret"], "s3 recovery"),
                {
                    "storage.s3.recovery_access_key": "access_key",
                    "storage.s3.recovery_secret_key": "secret_key",
                },
            )
        if not integrations:
            raise SiteError("s3 requires a writer secret or a separate recovery_secret")
    if "oidc" in document:
        oidc = object_fields(
            document["oidc"],
            "oidc",
            ("issuer", "client_id", "secret"),
            ("scopes", "role_claim", "admin_values", "operator_values"),
        )
        scopes = " ".join(
            dict.fromkeys(
                nonempty(
                    oidc.get("scopes", "openid profile email"), "oidc.scopes"
                ).split()
            )
        )
        if "openid" not in scopes.split():
            raise SiteError("OIDC scopes must include openid")
        values = {
            key: oidc.get(key, "")
            for key in ("role_claim", "admin_values", "operator_values")
        }
        for key, value in values.items():
            if value != "":
                nonempty(value, f"oidc.{key}")
        if (values["admin_values"] or values["operator_values"]) and not values[
            "role_claim"
        ]:
            raise SiteError("OIDC group mapping requires role_claim")
        fields = {
            "oidc.enabled": True,
            "oidc.issuer": https(oidc["issuer"], "oidc.issuer", allow_path=True),
            "oidc.client_id": nonempty(oidc["client_id"], "oidc.client_id"),
            "oidc.scopes": scopes,
            "oidc.default_role": "viewer",
            **{f"oidc.{key}": value for key, value in values.items()},
        }
        integrations["oidc"] = (
            fields,
            secret_ref(oidc["secret"], "oidc"),
            {
                "oidc.client_secret": "client_secret",
            },
        )
    return integrations


class Site:
    def __init__(self, root, manifest):
        self.root = root
        self.manifest = manifest
        self.metadata = release_metadata(root)
        value = object_fields(
            read_json(manifest),
            "top-level",
            ("schema", "context", "registry", "site", "agent"),
            ("postgres", "ca_file", "s3", "oidc"),
        )
        if value["schema"] != "vesta-site/1":
            raise SiteError("Expected manifest schema vesta-site/1")
        self.context = nonempty(value["context"], "context")
        self.registry = nonempty(value["registry"], "registry")
        if not re.fullmatch(
            r"[a-z0-9][a-z0-9.:-]*/[a-z0-9]+(?:[-_./][a-z0-9]+)*", self.registry
        ):
            raise SiteError("registry requires a registry host and repository prefix")
        if self.context == "REPLACE" or self.registry == "registry.example.org/vesta":
            raise SiteError("Replace the example cluster context and registry prefix")
        self.oc = ["oc", "--context", self.context]
        self.images = {
            name: f"{self.registry}/{name}@{digest}"
            for name, digest in kit.image_digests(self.metadata).items()
        }
        self.config = dict(value["site"]) if isinstance(value["site"], dict) else {}
        if "images" in self.config:
            raise SiteError("Image digests come from the kit and its registry prefix")
        self.config["images"] = {
            key: self.images[key] for key in ("backend", "frontend", "agent")
        }
        try:
            self.profile = render.selected_delivery_profile(self.config)
            render.validate(self.config)
        except ValueError as error:
            raise SiteError(str(error)) from None
        self.agent = value["agent"]
        if self.agent not in ("kubevirt", "external"):
            raise SiteError("agent requires kubevirt or external")
        self.postgres = value.get("postgres")
        if self.postgres is not None:
            if (
                self.profile != "full"
                or not isinstance(self.postgres, dict)
                or "image" in self.postgres
            ):
                raise SiteError(
                    "Dedicated PostgreSQL requires the full kit and inherits its pinned image"
                )
            self.postgres = {**self.postgres, "image": self.images["postgres"]}
            try:
                postgres.validate(self.postgres)
            except ValueError as error:
                raise SiteError(str(error)) from None
        self.integrations = integration_settings(value)
        self.namespace = self.config["namespace"]
        self.agent_namespace = self.config.get(
            "agent_namespace", self.config["vm_namespace"]
        )
        self.agent_id = self.config.get(
            "agent_id",
            render.kube_name(self.config, f"kubevirt-{self.config['vm_namespace']}"),
        )
        self.ca_file = (
            (manifest.parent / nonempty(value["ca_file"], "ca_file"))
            if "ca_file" in value
            else None
        )
        self.names = self.config["secrets"]

    def verify(self):
        kit.verify(self.root, local_site_manifest=True)

    def kubectl(self, *args, label, missing=False):
        try:
            result = subprocess.run(
                [*self.oc, *args], check=True, capture_output=True, text=True
            )
        except subprocess.CalledProcessError:
            raise SiteError(
                f"OpenShift check failed ({label}). Verify context, permissions and site inputs"
            ) from None
        if not missing and not result.stdout.strip() and args[0] == "get":
            raise SiteError(f"OpenShift returned no object ({label})")
        return result.stdout

    def resource(self, namespace, kind, name):
        label = f"{namespace}/{kind}/{name}"
        output = self.kubectl(
            "-n",
            namespace,
            "get",
            kind,
            name,
            "--ignore-not-found",
            "-o",
            "json",
            label=label,
            missing=True,
        )
        return json.loads(output) if output.strip() else None

    def secret(self, namespace, name, keys):
        record = self.resource(namespace, "secret", name)
        try:
            if record is None:
                raise KeyError(name)
            values = {
                key: base64.b64decode(record["data"][key], validate=True).decode()
                for key in keys
            }
            if not all(values.values()):
                raise ValueError("empty Secret field")
            return values
        except (KeyError, ValueError, TypeError):
            raise SiteError(
                f"Secret {namespace}/{name} requires nonempty keys: {', '.join(keys)}"
            ) from None

    def control_secrets(self):
        app_inputs = {
            "database_owner": ("DATABASE_URL",),
            "database_runtime": ("DATABASE_URL",),
            "application": (
                "JWT_SECRET",
                render.application_key_name(self.config),
                "ORCHESTRATOR_TO_AGENT_KEY",
            ),
            "admin": ("password",),
            "backend_tls": ("tls.crt", "tls.key"),
            "trust": ("ca.crt",),
        }
        for name, keys in app_inputs.items():
            values = self.secret(self.namespace, self.names[name], keys)
            if "DATABASE_URL" in values:
                database = urlsplit(values["DATABASE_URL"])
                modes = parse_qs(database.query, keep_blank_values=True).get("sslmode")
                if (
                    database.scheme
                    not in {"postgres", "postgresql", "postgresql+psycopg2"}
                    or not database.hostname
                    or (modes is not None and modes != ["verify-full"])
                ):
                    raise SiteError(
                        f"{self.names[name]} requires a TCP PostgreSQL URL with verified TLS"
                    )
        serving_trust = self.config.get("agent_serving_trust_config_map")
        if serving_trust:
            resource = self.resource(self.namespace, "configmap", serving_trust)
            if not resource or not (resource.get("data") or {}).get("agent-serving-trust.json"):
                raise SiteError("Agent serving trust ConfigMap requires agent-serving-trust.json")
        if self.postgres:
            self.secret(
                self.namespace,
                self.postgres["bootstrap_secret"],
                ("POSTGRES_PASSWORD", "OWNER_PASSWORD", "RUNTIME_PASSWORD"),
            )
            self.secret(
                self.namespace, self.postgres["tls_secret"], ("tls.crt", "tls.key")
            )
        if self.config["mtls"] is not None:
            self.secret(
                self.namespace, self.config["mtls"]["backend_client_ca"], ("ca.crt",)
            )
            self.secret(
                self.namespace,
                self.config["mtls"]["backend_client_tls"],
                ("tls.crt", "tls.key"),
            )

    def agent_secrets(self, *, registration=False):
        self.secret(
            self.agent_namespace, self.names["agent_tls"], ("tls.crt", "tls.key")
        )
        self.secret(self.agent_namespace, self.names["trust"], ("ca.crt",))
        if self.config["mtls"] is not None:
            self.secret(
                self.agent_namespace,
                self.config["mtls"]["agent_client_ca"],
                ("ca.crt",),
            )
        if registration:
            agent = self.secret(
                self.agent_namespace,
                self.names["agent_registration"],
                ("REGISTRATION_KEY", "KEYSTORE_IDENTITY", "ORCHESTRATOR_API_KEY"),
            )
            application = self.secret(
                self.namespace,
                self.names["application"],
                ("ORCHESTRATOR_TO_AGENT_KEY",),
            )
            if (
                agent["ORCHESTRATOR_API_KEY"]
                != application["ORCHESTRATOR_TO_AGENT_KEY"]
            ):
                raise SiteError("KubeVirt agent and application shared keys differ")

    def agent_apis(self):
        for endpoint, expected in {
            "/apis/backup.kubevirt.io/v1alpha1": {
                "virtualmachinebackups",
                "virtualmachinebackuptrackers",
            },
            "/apis/export.kubevirt.io/v1beta1": {"virtualmachineexports"},
        }.items():
            found = json.loads(self.kubectl("get", "--raw", endpoint, label=endpoint))
            if not expected <= {entry["name"] for entry in found["resources"]}:
                raise SiteError(f"Required KubeVirt APIs are missing ({endpoint})")

    def prepare(self, stage, destination):
        if stage == "postgres":
            postgres.write_kustomize(self.config, self.postgres, destination)
        else:
            render.write_kustomize(self.config, stage, destination)

    def apply(self, stage, directory, *, dry_run):
        args = (
            ("create", "--save-config", "--dry-run=server")
            if dry_run
            else ("create", "--save-config")
        )
        self.kubectl(
            *args,
            "-k",
            str(directory),
            label=f"{'server dry-run' if dry_run else 'apply'} {stage}",
        )

    def wait(self, stage):
        name = render.kube_name
        if stage == "postgres":
            for condition in ("create", "condition=Ready"):
                self.kubectl(
                    "-n",
                    self.namespace,
                    "wait",
                    f"--for={condition}",
                    f"pod/{name(self.config, 'postgres')}-0",
                    "--timeout=10m",
                    label=f"PostgreSQL {condition}",
                )
        elif stage == "migrate":
            self.kubectl(
                "-n",
                self.namespace,
                "wait",
                "--for=condition=complete",
                f"job/{name(self.config, 'fresh-schema')}",
                "--timeout=30m",
                label="fresh database migration",
            )
        else:
            namespace, components = (
                (self.namespace, ("backend", "frontend"))
                if stage == "api"
                else (self.agent_namespace, ("agent",))
            )
            for component in components:
                self.kubectl(
                    "-n",
                    namespace,
                    "rollout",
                    "status",
                    f"deployment/{name(self.config, component)}",
                    "--timeout=10m",
                    label=f"{component} rollout",
                )

    def plan(self):
        return {
            "context": self.context,
            "profile": self.profile,
            "application_namespace": self.namespace,
            "ui": "https://" + self.config["ui_host"],
            "api": "https://" + self.config["api_host"],
            "images": self.images,
            "install_order": [
                *(["postgres"] if self.postgres else []),
                "migrate",
                "api",
            ],
            "configure": list(self.integrations)
            + (["agent"] if self.agent == "kubevirt" else []),
            "agent": self.agent_id if self.agent == "kubevirt" else "external",
        }

    def _deployed_image(self, component, namespace, *, ready=False):
        name = render.kube_name(self.config, component)
        resource = self.resource(namespace, "deployment", name)
        if resource is None:
            if ready:
                raise SiteError("An installed backend Deployment is required to observe an upgrade")
            return None
        metadata, spec = resource.get("metadata", {}), resource.get("spec", {})
        status = resource.get("status", {})
        replicas = spec.get("replicas", 1)
        if ready and (
            not replicas
            or metadata.get("generation") != status.get("observedGeneration")
            or status.get("updatedReplicas") != replicas
            or status.get("readyReplicas") != replicas
        ):
            raise SiteError("Allow the installed backend Deployment to finish rolling out before observing an upgrade")
        entries = spec.get("template", {}).get("spec", {}).get("containers", [])
        container = next((entry for entry in entries if entry.get("name") == component), None)
        if container is None:
            raise SiteError(f"The deployed {component} workload does not match the accepted site manifest")
        if ready:
            runtime_binding = next(
                (entry.get("valueFrom", {}).get("secretKeyRef") for entry in container.get("env", [])
                 if entry.get("name") == "DATABASE_URL"),
                None,
            )
            if not isinstance(runtime_binding, dict) or (
                runtime_binding.get("name"), runtime_binding.get("key")
            ) != (self.names["database_runtime"], "DATABASE_URL"):
                raise SiteError("The running backend database Secret differs from the accepted site manifest")
        return container.get("image")

    def upgrade_plan(self):
        """Read the selected site's running schema using its regular runtime login."""
        target, self.oc = cluster_access(self.context)
        self.check_api_route()
        backend = self._deployed_image("backend", self.namespace, ready=True)
        result = self.kubectl(
            "--request-timeout=45s", "-n", self.namespace,
            "exec", "deployment/" + render.kube_name(self.config, "backend"), "-c", "backend",
            "--", "python", "-c", RUNTIME_OBSERVATION,
            label="read installed product version and PostgreSQL schema",
        )
        try:
            observed = object_fields(
                json.loads(result), "runtime observation",
                ("version", "revision", "database", "role", "installation_id"),
            )
            identity = UUID(observed["installation_id"])
            if identity.int == 0 or str(identity) != observed["installation_id"]:
                raise ValueError("invalid installation identity")
        except (TypeError, ValueError, AttributeError):
            raise SiteError("The backend returned an invalid upgrade observation") from None
        if (observed["database"], observed["role"]) != (
            self.config["database"], self.config["runtime_role"]
        ):
            raise SiteError("The running database or runtime role differs from the site manifest")

        version, revision = observed["version"], observed["revision"]
        stages = []
        if (version, revision) == UPGRADE_TARGET:
            frontend = self._deployed_image("frontend", self.namespace)
            if (backend, frontend) != (self.images["backend"], self.images["frontend"]):
                stages.append("api")
            if self.agent == "kubevirt" and self._deployed_image("agent", self.agent_namespace) != self.images["agent"]:
                stages.append("agent")
        elif isinstance(version, str) and UPGRADE_SOURCES.get(version) == revision and revision:
            stages = ["upgrade", "api"]
            if self.agent == "kubevirt":
                stages.append("agent")
        else:
            raise SiteError("The installed Vesta release and database schema do not have a reviewed transition in this kit")
        return {
            "schema": "vesta-upgrade-plan/1",
            "status": "review_required" if stages else "already_current",
            "target": target,
            "namespace": self.namespace,
            "observed": observed,
            "destination": {"version": UPGRADE_TARGET[0], "revision": UPGRADE_TARGET[1]},
            "stages": stages,
            "images": {
                name: self.images[name]
                for name in ("backend", "frontend", "agent")
                if name != "agent" or self.agent == "kubevirt"
            },
            "agent_management": self.agent,
        }

    def prepare_reviewed_upgrade(self, destination):
        if destination.resolve().is_relative_to(self.root):
            raise SiteError("Keep upgrade targets outside the extracted kit")
        plan = self.upgrade_plan()
        destination.mkdir(mode=0o700)
        try:
            # A setgid parent can add an inherited mode bit at mkdir time.
            destination.chmod(0o700)
            for stage in plan["stages"]:
                if stage == "upgrade":
                    config = {**self.config, "upgrade_installation_id": plan["observed"]["installation_id"]}
                    render.write_kustomize(config, stage, destination / stage)
                else:
                    self.prepare(stage, destination / stage)
            with private_output(destination / "upgrade-plan.json") as stream:
                json.dump(plan, stream, indent=2)
                stream.write("\n")
        except BaseException:
            shutil.rmtree(destination)
            raise
        return plan

    def check_fresh(self, directory, preflight_output=None):
        stages = self.plan()["install_order"]
        collisions = check_fresh_target.planned_resources(self.config, self.postgres)
        if self.agent == "external":
            # The legacy check describes all portable stages, including an optional agent.
            collisions = {
                ns: refs for ns, refs in collisions.items() if ns == self.namespace
            }
        for namespace, references in collisions.items():
            self.kubectl(
                "get",
                "namespace",
                namespace,
                "-o",
                "name",
                label=f"namespace {namespace}",
            )
            found = self.kubectl(
                "-n",
                namespace,
                "get",
                *references,
                "--ignore-not-found",
                "-o",
                "name",
                label=f"fresh resource names in {namespace}",
            )
            if found.strip():
                raise SiteError(
                    f"Existing Vesta resources in {namespace}. Use status or the upgrade/recovery guide"
                )
        self.control_secrets()
        if preflight_output is not None and self.agent != "kubevirt":
            raise SiteError("A KubeVirt preflight report requires agent: kubevirt")
        classes = set()
        if self.postgres:
            classes.add(self.postgres["storage_class"])
        if self.agent == "kubevirt":
            self.run_fresh_preflight(preflight_output)
            self.agent_secrets()
            classes.update(
                self.config[key]
                for key in ("journal_storage_class", "scratch_storage_class")
            )
        for storage_class in sorted(classes):
            self.kubectl(
                "get",
                "storageclass",
                storage_class,
                "-o",
                "name",
                label=f"storage class {storage_class}",
            )
        for stage in [*stages, *(["agent"] if self.agent == "kubevirt" else [])]:
            self.prepare(stage, directory / stage)
            self.apply(stage, directory / stage, dry_run=True)
        print(
            "Fresh target, input Secret keys, storage classes and server dry-runs passed",
            flush=True,
        )
        return stages

    def run_fresh_preflight(self, output):
        if output is not None:
            self.preflight(output)
            return
        spool = Path(tempfile.mkdtemp(prefix="vesta-preflight-"))
        self.preflight(spool / "report", show_path=False)
        shutil.rmtree(spool)

    def preflight(self, output, *, show_path=True, target_vm=None):
        if self.agent != "kubevirt":
            raise SiteError("Detailed preflight requires agent: kubevirt")
        if output.resolve().is_relative_to(self.root):
            raise SiteError("Keep the preflight report outside the extracted kit")
        if not all(shutil.which(tool) for tool in ("bash", "oc", "jq")):
            raise SiteError("Detailed preflight requires Bash, oc and jq")
        scripts = self.root / "install/preflight"
        args = ["--context", self.context, "--output", str(output)]
        namespaces = self.config.get("source_namespaces", [self.config["vm_namespace"]])
        if target_vm is None:
            for namespace in namespaces:
                args.extend(("--namespace", namespace))
        else:
            namespace, vm = target_vm
            args.extend(("--namespace", namespace, "--target-vm", vm))
        try:
            subprocess.run(
                ["bash", scripts / "customer-preflight.sh", *args],
                check=True,
                capture_output=True,
                timeout=240,
            )
            summaries = {}
            for report in ("gates", "scope"):
                result = subprocess.run(
                    ["bash", scripts / f"customer-preflight-{report}.sh", output],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                summaries[report] = json.loads(result.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            detail = (
                f" Review the report or output path {output}."
                if show_path
                else " Check cluster access or retain a private report."
            )
            raise SiteError(
                "KubeVirt preflight could not complete." + detail
            ) from None
        for report, summary in summaries.items():
            with private_output(output / f"vesta-{report}.json") as stream:
                json.dump(summary, stream, indent=2)
                stream.write("\n")
        if target_vm is not None:
            summary = vm_readiness.evaluate(
                output,
                self.context,
                *target_vm,
                summaries["gates"]["gates"],
                summaries["scope"],
            )
            with private_output(output / "vesta-readiness.json") as stream:
                json.dump(summary, stream, indent=2)
                stream.write("\n")
            preview = None
            if any(
                finding["code"] == "cbt_selector_not_matched"
                for finding in summary["findings"]
            ):
                preview = vm_readiness.selector_preview(
                    output, self.context, *target_vm, summaries["gates"]["gates"]
                )
            vm_readiness.print_summary(summary, preview)
            if show_path:
                print(f"Private report saved to {output}", flush=True)
            return summary["status"] == "ready"
        if summaries["gates"]["configuration_result"] != "PASS":
            raise SiteError(
                f"KubeVirt configuration gates did not pass. Review {output / 'vesta-gates.json'}"
            )
        print(
            "KubeVirt HCO configuration, rendered CBT selectors and served API gates passed",
            flush=True,
        )
        if show_path:
            print(f"Review scope and runtime CBT evidence in {output}", flush=True)

    def preflight_vm(self, target, output):
        namespace, sep, vm = target.partition("/")
        if not sep or not vm_readiness.RESOURCE_NAME.fullmatch(vm) or len(vm) > 253:
            raise SiteError("Use --vm NAMESPACE/VM")
        namespaces = self.config.get("source_namespaces", [self.config["vm_namespace"]])
        if namespace not in namespaces:
            raise SiteError(
                "The VM namespace must be a source namespace in the site manifest"
            )
        if output is not None:
            return self.preflight(output, target_vm=(namespace, vm))
        with tempfile.TemporaryDirectory(prefix="vesta-preflight-") as spool:
            return self.preflight(
                Path(spool) / "report", target_vm=(namespace, vm), show_path=False
            )

    def check_api_route(self):
        expected = next(
            item
            for item in render.render(self.config, "api")["items"]
            if item["kind"] == "Route"
            and item["metadata"]["name"] == render.kube_name(self.config, "backend")
        )
        name = expected["metadata"]["name"]
        for route_name in (name, name + "-" + reconfigure.route_suffix(expected)):
            route = self.resource(self.namespace, "route", route_name)
            if (
                route
                and route.get("spec", {}).get("host") == self.config["api_host"]
                and route["spec"].get("to", {}).get("name") == name
            ):
                return
        raise SiteError(
            "The configured API hostname does not match the selected cluster's backend Route"
        )

    def verify_routes(self):
        try:
            reconfigure.probe(self.config, self.ca_file)
        except (OSError, ValueError) as error:
            raise SiteError(
                "Application routes failed readiness. Check DNS, HTTPS trust and backend readiness"
            ) from error

    def verify_install_routes(self):
        """Allow the ingress data plane to catch up with completed rollouts."""
        try:
            context = ssl.create_default_context(cafile=self.ca_file)
        except (OSError, ValueError):
            raise SiteError(
                "Cannot load HTTPS trust for the application routes. Check the site CA file"
            ) from None
        client = build_opener(HTTPSHandler(context=context), NoRedirect())
        urls = [
            "https://" + host + path
            for host, paths in reconfigure.public_route_paths(self.config)
            for path in paths
        ]
        deadline = time.monotonic() + INSTALL_ROUTE_TIMEOUT
        pause = 2
        last_pending = []
        while True:
            pending = []
            for url in urls:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    detail = ", ".join(pending or last_pending) or url
                    raise SiteError(
                        f"Application routes did not become ready within {INSTALL_ROUTE_TIMEOUT}s: "
                        f"{detail}. Check ingress and use ./vesta status once the routes are ready"
                    )
                result = install_route_retry_reason(
                    client, url, timeout=min(remaining, INSTALL_ROUTE_REQUEST_TIMEOUT)
                )
                if result:
                    pending.append(f"{url} ({result})")
            if not pending:
                if last_pending:
                    print(
                        "Application HTTPS routes are ready after ingress convergence",
                        flush=True,
                    )
                return
            if pending != last_pending:
                print(
                    "Waiting for application HTTPS routes: " + ", ".join(pending),
                    flush=True,
                )
            last_pending = pending
            time.sleep(min(pause, max(0, deadline - time.monotonic())))
            pause = min(2 * pause, INSTALL_ROUTE_POLL_LIMIT)

    def agent_items(self):
        return [
            (
                item,
                self.resource(
                    item["metadata"]["namespace"],
                    item["kind"],
                    item["metadata"]["name"],
                ),
            )
            for item in render.render(self.config, "agent")["items"]
        ]

    def agent_plan(self, directory):
        items = self.agent_items()
        if all(actual is None for _, actual in items):
            self.agent_apis()
            self.agent_secrets(registration=True)
            self.prepare("agent", directory)
            self.apply("agent", directory, dry_run=True)
            return True
        for expected, actual in items:
            if not actual:
                raise SiteError(
                    "Agent stage is incomplete. Preserve its journal and follow the recovery guide"
                )
            match = (
                reconfigure.deployment_matches
                if expected["kind"] == "Deployment"
                else reconfigure.configuration_matches
            )
            if not match(expected, actual):
                raise SiteError(
                    "Agent resources differ from this manifest. Follow the upgrade/reconfiguration guide"
                )
        return False

    def settings_plan(self, api, refresh_credentials):
        if not self.integrations:
            return {}
        snapshot = api.request("GET", "/settings/v3")
        if not snapshot["encryption_configured"]:
            raise SiteError(
                "Application encryption is required to configure credentials"
            )
        patch = {}
        for name, (settings, secret, field_mapping) in self.integrations.items():
            changes = {
                key: value
                for key, value in settings.items()
                if snapshot["settings"].get(key) != value
            }
            if (
                name in {"s3", "s3-recovery"}
                and changes
                and (
                    snapshot["settings"].get("storage.s3.bucket")
                    or snapshot["settings"].get("storage.type") != "s3"
                )
            ):
                raise SiteError(
                    "Existing S3 endpoint, bucket, region or prefix differs. Review a storage migration before changing it"
                )
            new_oidc_client = name == "oidc" and bool(
                changes.keys() & {"oidc.issuer", "oidc.client_id"}
            )
            if (
                refresh_credentials
                or new_oidc_client
                or any(
                    not snapshot["secrets"][key]["configured"] for key in field_mapping
                )
            ):
                values = self.secret(self.namespace, secret, field_mapping.values())
                changes.update(
                    {key: values[field] for key, field in field_mapping.items()}
                )
            patch.update(changes)
        return patch

    def configure(self, api, directory, refresh_credentials):
        new_agent = self.agent == "kubevirt" and self.agent_plan(directory / "agent")
        patch = self.settings_plan(api, refresh_credentials)
        if patch:
            api.request("PUT", "/settings/v3", patch)
            print("Site settings saved", flush=True)
        else:
            print("Managed site settings already match", flush=True)
        if "s3" in self.integrations:
            api.request("POST", "/settings/test-s3", {})
            print("S3 bucket connection check passed", flush=True)
        if "oidc" in self.integrations:
            print(
                "OIDC settings saved or already matched. Verify sign-in, MFA and roles in a separate browser session",
                flush=True,
            )
        if self.agent == "kubevirt":
            if new_agent:
                self.apply("agent", directory / "agent", dry_run=False)
            self.wait("agent")
            self.wait_heartbeat(api)
            print(
                f"Agent {self.agent_id} has a recent authenticated heartbeat",
                flush=True,
            )

    def wait_heartbeat(self, api):
        # Registration itself timestamps the row. Only a later observation
        # from the same identity demonstrates that the running agent is checking in.
        deadline = time.monotonic() + 300
        previous = None
        while time.monotonic() < deadline:
            for entry in api.request("GET", "/agents"):
                if entry["hostname"] != self.agent_id or not entry.get("last_heartbeat"):
                    continue
                observed = datetime.fromisoformat(entry["last_heartbeat"].replace("Z", "+00:00"))
                if observed.tzinfo is None:
                    observed = observed.replace(tzinfo=timezone.utc)
                identity = entry["id"]
                age = datetime.now(timezone.utc) - observed
                if (previous and previous[0] == identity and observed > previous[1]
                        and timedelta(seconds=-30) <= age <= timedelta(seconds=120)):
                    return
                previous = (identity, observed)
            time.sleep(5)
        raise SiteError("Agent rollout completed but no new heartbeat arrived for the enrolled identity")

    def status(self):
        print(f"Target context {self.context}, namespace {self.namespace}", flush=True)
        self.wait("api")
        self.verify_routes()
        print("API/UI workloads and HTTPS routes are ready", flush=True)
        if self.agent == "kubevirt":
            self.wait("agent")
            print(
                "KubeVirt agent Deployment is ready. Configure checks its authenticated heartbeat",
                flush=True,
            )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def install_route_retry_reason(client, url, *, timeout):
    """Read a public route with verified TLS, or report a retryable ingress condition."""
    try:
        with client.open(Request(url), timeout=timeout) as response:
            if response.status != 200:
                raise SiteError(
                    f"{url} returned HTTP {response.status}. Expected HTTP 200"
                )
            body = response.read(INSTALL_ROUTE_READ_LIMIT)
            advertised = response.getheader("Content-Length")
            if advertised is not None:
                try:
                    length = int(advertised)
                    if length < 0:
                        raise ValueError
                except ValueError:
                    raise SiteError(
                        f"{url} returned an invalid Content-Length"
                    ) from None
                if len(body) < min(length, INSTALL_ROUTE_READ_LIMIT):
                    return "HTTPS response ended early"
    except IncompleteRead:
        return "HTTPS response ended early"
    except HTTPError as exc:
        exc.close()
        if exc.code == 503:
            return "HTTP 503"
        raise SiteError(f"{url} returned HTTP {exc.code}. Expected HTTP 200") from None
    except OSError as exc:
        cause = exc.reason if isinstance(exc, URLError) else exc
        if isinstance(cause, ssl.SSLCertVerificationError):
            raise SiteError(
                f"{url} failed TLS certificate verification. Check the site CA and route hostname"
            ) from None
        if isinstance(cause, ssl.SSLEOFError) or (
            isinstance(cause, ssl.SSLError)
            and getattr(cause, "reason", None) == "UNEXPECTED_EOF_WHILE_READING"
        ):
            return "TLS connection closed before readiness"
        if isinstance(cause, ConnectionResetError):
            return "connection reset"
        if isinstance(cause, ConnectionRefusedError):
            return "connection refused"
        if isinstance(cause, TimeoutError):
            return "HTTPS request timed out"
        state = (
            "DNS lookup failed"
            if isinstance(cause, socket.gaierror)
            else "HTTPS request failed"
        )
        raise SiteError(
            f"{state} for {url}. Check DNS, route admission and HTTPS configuration"
        ) from None
    return None


class AdminAPI:
    def __init__(self, site, username):
        if not sys.stdin.isatty():
            raise SiteError(
                "An interactive terminal is required for the local administrator password"
            )
        site.check_api_route()
        self.origin = "https://" + site.config["api_host"] + "/api/v1"
        self.client = build_opener(
            HTTPSHandler(context=ssl.create_default_context(cafile=site.ca_file)),
            NoRedirect(),
        )
        self.token = self._request(
            "POST",
            "/auth/login",
            urlencode(
                {
                    "username": username or site.config["admin_username"],
                    "password": getpass.getpass("Vesta local administrator password: "),
                }
            ).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )["access_token"]

    def _request(self, method, path, payload, headers):
        request = Request(
            self.origin + path, data=payload, headers=headers, method=method
        )
        try:
            with self.client.open(request, timeout=30) as response:
                return json.load(response)
        except HTTPError as error:
            raise SiteError(
                f"Vesta {method} {path} returned HTTP {error.code}"
            ) from None
        except (URLError, TimeoutError, ValueError):
            raise SiteError(
                f"Vesta {method} {path} failed. Check the API hostname, trust and readiness"
            ) from None

    def request(self, method, path, value=None, request_id=None):
        headers = {
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json",
        }
        if request_id is not None:
            headers["Idempotency-Key"] = request_id
        return self._request(
            method,
            path,
            json.dumps(value).encode() if value is not None else None,
            headers,
        )


def issue_agent_key(api, hostname, output):
    if len(hostname) > 255 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", hostname):
        raise SiteError("Supply the exact technical hostname configured on the agent")
    if any(agent["hostname"] == hostname for agent in api.request("GET", "/agents")):
        raise SiteError(
            "This agent is already enrolled. Follow its key rotation or recovery procedure"
        )
    keys = api.request("GET", "/registration-keys")["items"]
    if any(key["agent_hostname"] == hostname and key["is_valid"] for key in keys):
        raise SiteError(
            "An active key already exists for this agent. Review its custody or revoke it before issuing another"
        )
    request_id = str(uuid4())
    with private_output(output) as stream:
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        try:
            result = api.request(
                "POST",
                "/registration-keys",
                {
                    "name": f"Agent enrollment for {hostname}",
                    "agent_hostname": hostname,
                    "max_uses": 1,
                    "expires_at": expires.isoformat(),
                },
                request_id=request_id,
            )
            stream.write(result["api_key"] + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        except (SiteError, OSError, KeyError):
            raise SiteError(
                f"Agent key operation {request_id} did not complete. Review API key custody before retrying"
            ) from None
    print(f"Wrote one-use registration key to {output}. It expires in one hour")


def initialize(root, manifest):
    metadata = release_metadata(root)
    config = read_json(root / "install/config.example.json")
    del config["images"]
    config["selected_namespaces"] = []
    document = {
        "schema": "vesta-site/1",
        "context": "REPLACE",
        "registry": "registry.example.org/vesta",
        "agent": "kubevirt",
        "site": config,
    }
    if metadata.get("delivery_profile", "full") == "full":
        database = read_json(root / "install/postgres.example.json")
        del database["image"]
        document["postgres"] = database
    with private_output(manifest) as stream:
        json.dump(document, stream, indent=2)
        stream.write("\n")
    print(f"Created {manifest}. Edit the site inputs before running plan or check")


def add_reconfiguration_commands(commands):
    command = commands.add_parser(
        "reconfigure", help="plan, apply, accept or roll back a reviewed change"
    )
    actions = command.add_subparsers(dest="change", required=True)
    plan = actions.add_parser(
        "plan", help="compare the accepted site with the desired manifest"
    )
    plan.add_argument("--previous", type=Path, required=True, help="accepted manifest")
    plan.add_argument(
        "--manifest",
        type=Path,
        default=Path("vesta.json"),
        help="desired manifest (default: vesta.json)",
    )
    for action in ("apply", "accept", "rollback"):
        step = actions.add_parser(action)
        step.add_argument(
            "--quiesced",
            action="store_true",
            required=True,
            help="confirm dispatch is fenced and work is settled",
        )
        if action == "apply":
            step.add_argument(
                "--custody-confirmed",
                action="store_true",
                required=True,
                help="confirm durable custody of accepted configuration and recovery material",
            )
            step.add_argument(
                "--external-ready",
                action="store_true",
                required=True,
                help="confirm old/new DNS, TLS, trust and SSO preparation",
            )
        if action == "accept":
            step.add_argument(
                "--paths-verified",
                action="store_true",
                required=True,
                help="confirm both paths, authentication and agent access",
            )
    for action in actions.choices.values():
        action.add_argument(
            "--state",
            type=Path,
            required=True,
            help="private transaction directory outside the kit",
        )


def cluster_access(context):
    base = ["oc", "--context", nonempty(context, "context")]
    result = subprocess.run(
        [*base, "whoami", "--show-server"], capture_output=True, text=True, check=True
    )
    server = https(result.stdout.strip(), "OpenShift API server")
    return {"context": context, "server": server}, [*base, "--server", server]


def run_reconfiguration(root, args):
    path = args.state
    if path.resolve().is_relative_to(root):
        raise SiteError("Keep transaction state outside the extracted kit")
    if args.change == "plan":
        previous = Site(root, args.previous)
        proposed = Site(root, args.manifest)
        if any(
            getattr(previous, name) != getattr(proposed, name)
            for name in ("context", "registry", "agent", "postgres", "integrations")
        ):
            raise SiteError(
                "A reconfiguration transaction requires the same cluster context, registry, agent mode, database and integration settings"
            )
        target, oc = cluster_access(proposed.context)
        state = reconfigure.plan(
            previous.config,
            proposed.config,
            path,
            oc,
            str(proposed.ca_file.resolve()) if proposed.ca_file else None,
            include_agent=proposed.agent == "kubevirt",
            launcher_target=target,
        )
    else:
        if (
            not stat.S_ISDIR(path.lstat().st_mode)
            or stat.S_IMODE(path.stat().st_mode) & 0o077
        ):
            raise SiteError("Use the private mode-0700 directory created at plan time")
        journal = path / "transaction.json"
        if not stat.S_ISREG(journal.lstat().st_mode):
            raise SiteError("Transaction journal must be an ordinary file")
        state = read_json(journal)
        accepted_target = state.get("launcher_target")
        if not isinstance(accepted_target, dict) or set(accepted_target) != {
            "context",
            "server",
        }:
            raise SiteError("Open a launcher-created reconfiguration transaction")
        target, oc = cluster_access(accepted_target["context"])
        if accepted_target != target:
            raise SiteError("The cluster context now points to a different API server")
        if args.change == "rollback" and state["status"] == "planned":
            raise SiteError("This transaction has not been applied")
        getattr(reconfigure, args.change)(state, path, oc)
    print(f"Reconfiguration: {state['status']}", flush=True)



def add_upgrade_commands(commands):
    command = commands.add_parser("upgrade", help="observe and prepare the reviewed release transition")
    actions = command.add_subparsers(dest="change", required=True)
    actions.add_parser("plan", help="observe the installed version and database schema")
    prepare = actions.add_parser("prepare", help="write reviewed targets for the observed site")
    prepare.add_argument("--output-dir", type=Path, required=True)
    for step in actions.choices.values():
        step.add_argument(
            "--manifest", type=Path, default=Path("vesta.json"),
            help="accepted site manifest (default: vesta.json)",
        )

def main(root):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    actions = {
        "init": "write an editable starter manifest",
        "verify": "verify the extracted kit files",
        "plan": "validate the manifest and show the stages offline",
        "check": "run read-only checks and server-side dry-runs for a fresh installation",
        "preflight": "collect and evaluate detailed KubeVirt preflight evidence",
        "import-images": "copy the kit images into the site registry",
        "install": "install a fresh Vesta API/UI and optionally PostgreSQL",
        "configure": "apply selected S3/OIDC settings and deploy an enrolled KubeVirt agent",
        "status": "check application and agent Deployment readiness",
        "agent-key": "issue a scoped one-use enrollment key to a private file",
        "prepare-upgrade": "render application and agent targets for upgrade review",
    }
    for command, help_text in actions.items():
        subcommand = commands.add_parser(command, help=help_text)
        if command != "verify":
            subcommand.add_argument(
                "--manifest",
                type=Path,
                default=Path("vesta.json"),
                help="site manifest (default: vesta.json in the current directory)",
            )
        if command in ("configure", "agent-key"):
            subcommand.add_argument(
                "--username", help="local admin login (default: site.admin_username)"
            )
        if command == "configure":
            subcommand.add_argument(
                "--refresh-credentials",
                action="store_true",
                help="replace configured S3/OIDC credentials from the referenced Secrets",
            )
        if command == "agent-key":
            subcommand.add_argument(
                "--hostname",
                help="exact technical agent hostname (default: configured KubeVirt agent ID)",
            )
            subcommand.add_argument(
                "--output",
                required=True,
                type=Path,
                help="new private file for the one-time credential",
            )
        if command in ("preflight", "prepare-upgrade"):
            subcommand.add_argument(
                "--output-dir",
                type=Path,
                required=command == "prepare-upgrade",
                help="new private output directory outside the kit",
            )
        if command == "preflight":
            subcommand.add_argument(
                "--vm",
                metavar="NAMESPACE/VM",
                help="check one VM in a manifest source namespace",
            )
        if command in ("check", "install"):
            subcommand.add_argument(
                "--preflight-output",
                type=Path,
                help="retain the KubeVirt preflight report in a new private directory",
            )
    add_reconfiguration_commands(commands)
    add_upgrade_commands(commands)
    args = parser.parse_args()
    try:
        if args.command == "reconfigure":
            try:
                run_reconfiguration(root, args)
            except (
                ValueError,
                subprocess.CalledProcessError,
                KeyboardInterrupt,
            ) as error:
                detail = (
                    str(error)
                    if isinstance(error, ValueError)
                    else type(error).__name__
                )
                raise SiteError(
                    f"Reconfiguration stopped ({detail}). Inspect private state and keep dispatch fenced if already applied"
                ) from None
            return 0
        if args.command == "init":
            if (
                args.manifest.resolve().is_relative_to(root)
                and args.manifest.absolute() != root / "vesta.json"
            ):
                raise SiteError(
                    "Write the site manifest outside the kit or to its root vesta.json"
                )
            initialize(root, args.manifest)
            return 0
        if args.command == "verify":
            kit.verify(root, local_site_manifest=True)
            print("Kit file inventory and checksums verified")
            return 0
        site = Site(root, args.manifest)
        if args.command == "plan":
            print(json.dumps(site.plan(), indent=2))
        elif args.command == "upgrade":
            site.verify()
            if args.change == "plan":
                print(json.dumps(site.upgrade_plan(), indent=2))
            else:
                plan = site.prepare_reviewed_upgrade(args.output_dir)
                if plan["stages"]:
                    print("Prepared the observed upgrade targets for review. See upgrade-plan.json for the order.")
                else:
                    print("The site already uses the target release and schema. No rollout targets were generated.")
        elif args.command == "import-images":
            site.verify()
            if not shutil.which("skopeo"):
                raise SiteError(
                    "Install skopeo on the operator workstation to import images"
                )
            kit.import_images(site.root / "images", site.registry)
            print("Release images imported with their pinned digests")
        elif args.command == "preflight":
            if args.vm is not None:
                return 0 if site.preflight_vm(args.vm, args.output_dir) else 2
            if args.output_dir is None:
                raise SiteError("Broad preflight requires --output-dir")
            site.preflight(args.output_dir)
        elif args.command == "prepare-upgrade":
            if args.output_dir.resolve().is_relative_to(root):
                raise SiteError("Keep upgrade targets outside the extracted kit")
            args.output_dir.mkdir(mode=0o700)
            for stage in ("api", "agent") if site.agent == "kubevirt" else ("api",):
                site.prepare(stage, args.output_dir / stage)
            print(
                "Rendered upgrade targets for review. Follow the kit upgrade and recovery guide for the observed schema"
            )
        elif args.command == "status":
            site.status()
        elif args.command == "agent-key":
            if args.output.resolve().is_relative_to(root):
                raise SiteError("Keep registration key files outside the extracted kit")
            if site.agent == "external" and args.hostname is None:
                raise SiteError("--hostname is required for an external agent")
            issue_agent_key(
                AdminAPI(site, args.username),
                args.hostname or site.agent_id,
                args.output,
            )
        else:
            if not shutil.which("oc"):
                raise SiteError("Install oc on the operator workstation")
            with tempfile.TemporaryDirectory(prefix="vesta-site-") as working:
                directory = Path(working)
                if args.command == "configure":
                    site.configure(
                        AdminAPI(site, args.username),
                        directory,
                        args.refresh_credentials,
                    )
                else:
                    if args.command == "install":
                        site.verify()
                    stages = site.check_fresh(directory, args.preflight_output)
                    if args.command == "install":
                        for stage in stages:
                            print(f"Installing {stage}", flush=True)
                            site.apply(stage, directory / stage, dry_run=False)
                            site.wait(stage)
                        site.verify_install_routes()
                        print(
                            f"Sign in at https://{site.config['ui_host']}. See the first-configuration guide before admitting backups"
                        )
    except SiteError as error:
        print(f"Vesta: {error}", file=sys.stderr)
        return 2
    except FileNotFoundError as error:
        print(
            f"Vesta: required file or tool missing: {error.filename}", file=sys.stderr
        )
        return 2
    except FileExistsError:
        print("Vesta: output already exists", file=sys.stderr)
        return 2
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError):
        print(
            "Vesta: invalid manifest, kit or operation input. Review runbooks/site-manifest.md",
            file=sys.stderr,
        )
        return 2
    return 0
