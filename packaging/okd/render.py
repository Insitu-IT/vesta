#!/usr/bin/env python3
"""Offline renderer: separate fresh migration, API and namespaced agent stages.

Customer namespaces and Secrets are precreated. Output contains references only.
There is no cluster connection, default registry, latest tag or implicit apply.
"""

import argparse
import hashlib
from functools import partial
import json
import math
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

STAGES = ("migrate", "restore-grants", "upgrade", "rollback-schema", "api", "agent")
BASE_ROOT = Path(__file__).resolve().parent / "kustomize" / "base"

NAME = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
IMAGE = r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}"
SECRETS = {
    "database_owner",
    "database_runtime",
    "application",
    "admin",
    "backend_tls",
    "agent_tls",
    "agent_registration",
    "trust",
}


OPERATION_BUDGET_DEFAULTS = {
    "time_coefficient": 3,
    "no_progress_coefficient": 3,
    "observation_coefficient": 3,
    "scratch_coefficient": 1.2,
    "bootstrap_bytes_per_second": 8388608,
    "preparation_estimate_seconds": 180,
    "control_estimate_seconds": 60,
}


def operation_budget(c):
    raw = c.get("operation_budget", {})
    if type(raw) is not dict or set(raw) - set(OPERATION_BUDGET_DEFAULTS):
        raise ValueError(
            "operation_budget requires documented estimate/coefficient fields"
        )
    result = {**OPERATION_BUDGET_DEFAULTS, **raw}
    for key, maximum in (
        ("time_coefficient", 100),
        ("no_progress_coefficient", 100),
        ("observation_coefficient", 100),
        ("scratch_coefficient", 4),
    ):
        value = result[key]
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or not 1 <= value <= maximum
        ):
            raise ValueError(
                f"operation_budget.{key} requires a finite coefficient from 1 to {maximum}"
            )
    for key, maximum in (
        ("bootstrap_bytes_per_second", 2**40),
        ("preparation_estimate_seconds", 86400),
        ("control_estimate_seconds", 3600),
    ):
        if type(result[key]) is not int or not 1 <= result[key] <= maximum:
            raise ValueError(
                f"operation_budget.{key} requires a positive bounded integer"
            )
    return result


def source_health_probes(c):
    probes = c.get("source_health_probes", [])
    if type(probes) is not list or len(probes) > 128:
        raise ValueError(
            "source_health_probes requires at most 128 namespace/VM endpoints"
        )
    seen = set()
    for probe in probes:
        if (
            type(probe) is not dict
            or set(probe) != {"namespace", "vm_name", "url"}
            or type(probe["namespace"]) is not str
            or not re.fullmatch(NAME, probe["namespace"])
            or type(probe["vm_name"]) is not str
            or not re.fullmatch(
                r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?", probe["vm_name"]
            )
            or type(probe["url"]) is not str
            or len(probe["url"]) > 2048
        ):
            raise ValueError(
                "source_health_probes requires namespace, vm_name and a credential-free HTTP(S) URL"
            )
        try:
            u = urlsplit(probe["url"])
            valid = (
                u.scheme in {"http", "https"}
                and u.hostname
                and not (
                    u.username is not None
                    or u.password is not None
                    or "?" in probe["url"]
                    or "#" in probe["url"]
                )
            )
            _ = u.port
        except ValueError:
            valid = False
        binding = (probe["namespace"], probe["vm_name"])
        if not valid or binding in seen or any(ord(c) < 33 for c in probe["url"]):
            raise ValueError(
                "source_health_probes requires unique, credential-free HTTP(S) endpoints without queries or fragments"
            )
        seen.add(binding)
    if len(json.dumps(probes)) > 65536:
        raise ValueError("source_health_probes exceeds its configuration bound")
    return probes


def resource_prefix(c):
    """Missing naming configuration retains the pre-Vesta installation contract."""
    prefix = c.get("resource_prefix", "vnbui")
    if type(prefix) is not str or prefix not in {"vnbui", "vesta"}:
        raise ValueError("resource_prefix must be vesta or vnbui")
    return prefix


def kube_name(c, suffix):
    return resource_prefix(c) + "-" + suffix


def installed_profile(c):
    """Normalize only installed configuration, never a license file."""
    edition = c.get("edition", "community")
    if type(edition) is not str or edition not in {"community", "commercial"}:
        raise ValueError("edition must be community or commercial")
    profile = c.get("operating_profile")
    if profile is None and "operating_profile" not in c and edition == "community":
        profile = {"auth_mode": "single_organization", "enabled_modules": []}
    if type(profile) is not dict or set(profile) != {"auth_mode", "enabled_modules"}:
        raise ValueError(
            "An explicit operating_profile requires auth_mode and enabled_modules"
        )
    mode, modules = profile["auth_mode"], profile["enabled_modules"]
    if type(mode) is not str or mode not in {
        "single_organization",
        "multi_organization",
    }:
        raise ValueError("Invalid operating_profile auth_mode")
    if (
        type(modules) is not list
        or any(type(item) is not str for item in modules)
        or len(modules) != len(set(modules))
        or not set(modules) <= {"multi_tenancy", "billing_api", "white_labeling"}
    ):
        raise ValueError("Unsupported operating_profile enabled_modules")
    if edition == "community" and (mode != "single_organization" or modules):
        raise ValueError(
            "Community requires single_organization and no commercial modules"
        )
    if (mode == "multi_organization") != ("multi_tenancy" in modules):
        raise ValueError("multi_organization requires configured multi_tenancy")
    return {"edition": edition, "auth_mode": mode, "enabled_modules": sorted(modules)}


def compatible_image_env(setting):
    # Existing release images still read the legacy variable. Kubernetes expands
    # each alias from the immediately preceding canonical value or Secret reference.
    name = setting["name"]
    legacy = "VNBUI_" + name.removeprefix("VESTA_")
    return [setting, env(legacy, f"$({name})")]


def profile_environment(c):
    profile = installed_profile(c)
    return (
        [env("VESTA_DELIVERY_PROFILE", "customer-postgresql")]
        if c.get("delivery_profile") == "customer-postgresql"
        else []
    ) + [
        *compatible_image_env(env("VESTA_EDITION", profile["edition"])),
        *compatible_image_env(env("VESTA_AUTH_MODE", profile["auth_mode"])),
        *compatible_image_env(
            env("VESTA_ENABLED_MODULES", json.dumps(profile["enabled_modules"], separators=(",", ":")))
        ),
    ]


def bundled_delivery_profile():
    """Bind extracted installer behavior to its declared, checksum-bound profile.

    This checks only small profile/installer inputs. Operators must independently
    run kit.verify and authenticate the received archive checksum before use;
    mutable local manifests are not signatures.
    """
    install = Path(__file__).absolute().parent
    if install.name != "install":
        return None
    root = install.parent
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Extracted installer requires its release manifest")
    manifest = json.loads(manifest_path.read_text())
    metadata = manifest.get("metadata", {})
    profile = metadata.get("delivery_profile")
    if profile is None:
        return None  # Legacy profile-less release behavior remains full.
    if (
        manifest.get("kind") != "release"
        or manifest.get("schema") != "vnbui-portable-kit/1"
        or not isinstance(profile, str)
        or profile not in {"full", "customer-postgresql"}
    ):
        raise ValueError("Invalid bundled release delivery profile")
    for name in (
        "install/render.py",
        "install/config.example.json",
        "images/manifest.json",
    ):
        path = root / name
        if any(
            (root.joinpath(*Path(name).parts[:index])).is_symlink()
            for index in range(1, len(Path(name).parts) + 1)
        ):
            raise ValueError("Bundled profile inputs must be regular files")
        if not path.is_file() or hashlib.sha256(
            path.read_bytes()
        ).hexdigest() != manifest.get("files", {}).get(name):
            raise ValueError(
                "Bundled installer/profile checksum mismatch; verify the kit"
            )
    example = json.loads((install / "config.example.json").read_text())
    nested = json.loads((root / "images/manifest.json").read_text())
    expected = {"backend", "frontend", "agent"} | (
        {"postgres"} if profile == "full" else set()
    )
    if (
        example.get("delivery_profile") != profile
        or nested.get("metadata", {}).get("delivery_profile") != profile
        or nested.get("metadata", {}).get("images") != metadata.get("images")
        or set(metadata.get("images", {})) != expected
        or metadata.get("supply_contract", {}).get("profile") != profile
        or nested.get("metadata", {}).get("supply_contract", {}).get("profile")
        != profile
    ):
        raise ValueError("Bundled installer/profile receipt mismatch")
    return profile


def selected_delivery_profile(config):
    bundled = bundled_delivery_profile()
    explicit = config.get("delivery_profile")
    if "delivery_profile" in config and (
        not isinstance(explicit, str) or explicit not in {"full", "customer-postgresql"}
    ):
        raise ValueError("delivery_profile must be full or customer-postgresql")
    if bundled is not None and explicit is not None and explicit != bundled:
        raise ValueError("Site delivery_profile contradicts the bundled release")
    return bundled or explicit or "full"


def validate(c):
    fields = {
        "namespace",
        "vm_namespace",
        "restore_namespaces",
        "ui_host",
        "api_host",
        "images",
        "secrets",
        "mtls",
        "database",
        "runtime_role",
        "journal_storage_class",
        "journal_size",
        "scratch_storage_class",
        "scratch_size",
        "scratch_access_mode",
        "admin_username",
        "resources",
    }
    if (
        type(c) is not dict
        or not fields <= set(c)
        or set(c)
        - fields
        - {
            "apm_enabled",
            "agent_namespace",
            "source_namespaces",
            "selected_namespaces",
            "agent_id",
            "agent_serving_trust_config_map",
            "agent_display_name",
            "appearance",
            "max_concurrent_backups",
            "ui_aliases",
            "edition",
            "operating_profile",
            "licensing",
            "resource_prefix",
            "application_key_name",
            "kubevirt_native_backup_ttl_seconds",
            "kubevirt_transaction_timeout_seconds",
            "kube_api_qps",
            "kube_api_burst",
            "kubevirt_transfer_profile",
            "operation_budget",
            "source_health_probes",
            "rollback_schema_revision",
            "upgrade_installation_id",
            "agent_key_rotation_ttl_hours",
            "delivery_profile",
        }
    ):
        raise ValueError("Use exactly the fields in config.example.json")
    serving_trust = c.get("agent_serving_trust_config_map")
    if serving_trust is not None and (
        not isinstance(serving_trust, str)
        or len(serving_trust) > 253
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in serving_trust.split(".")
        )
    ):
        raise ValueError("agent_serving_trust_config_map requires an existing ConfigMap name")
    profile = selected_delivery_profile(c)
    if bundled_delivery_profile() is not None:
        c["delivery_profile"] = profile
    rotation_hours = c.get("agent_key_rotation_ttl_hours", 24)
    if type(rotation_hours) is not int or not 1 <= rotation_hours <= 168:
        raise ValueError(
            "agent_key_rotation_ttl_hours requires an integer from 1 to 168"
        )
    operation_budget(c)
    source_health_probes(c)
    upgrade_installation_id = c.get("upgrade_installation_id")
    if upgrade_installation_id is not None and (
        not isinstance(upgrade_installation_id, str)
        or upgrade_installation_id == "00000000-0000-0000-0000-000000000000"
        or not re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", upgrade_installation_id
        )
    ):
        raise ValueError("upgrade_installation_id must match the observed installation UUID")
    rollback_revision = c.get("rollback_schema_revision", "backup_admission_pause")
    if type(rollback_revision) is not str or rollback_revision not in {
        "backup_verification",
        "storage_upload_progress",
        "verification_budget",
        "operator_requests",
        "backup_admission_pause",
    }:
        raise ValueError(
            "rollback_schema_revision must match a reviewed predecessor schema"
        )
    installed_profile(c)
    resource_prefix(c)
    if application_key_name(c) not in {"VESTA_ENCRYPTION_KEY", "VNBUI_ENCRYPTION_KEY"}:
        raise ValueError("Unknown application Secret encryption key name")
    qps, burst = c.get("kube_api_qps", 50), c.get("kube_api_burst", 100)
    if type(qps) is not int or not 1 <= qps <= 200:
        raise ValueError("kube_api_qps requires an integer from 1 to 200")
    if type(burst) is not int or not qps <= burst <= 400:
        raise ValueError("kube_api_burst requires an integer between QPS and 400")
    if c.get("kubevirt_transfer_profile", "kubevirt-32m/1") not in (
        "legacy",
        "kubevirt-32m/1",
    ):
        raise ValueError("kubevirt_transfer_profile requires legacy or kubevirt-32m/1")
    native_ttl = c.get("kubevirt_native_backup_ttl_seconds", 36000)
    transaction_timeout = c.get("kubevirt_transaction_timeout_seconds", 0)
    if type(native_ttl) is not int or not 3600 <= native_ttl <= 2592000:
        raise ValueError(
            "kubevirt_native_backup_ttl_seconds requires an integer from 3600 to 2592000"
        )
    if (
        type(transaction_timeout) is not int
        or not 0 <= transaction_timeout <= native_ttl
    ):
        raise ValueError(
            "kubevirt_transaction_timeout_seconds requires an integer from 0 to the native backup TTL"
        )
    if c.get("licensing") is not None:
        licensing = c["licensing"]
        if (
            type(licensing) is not dict
            or set(licensing) != {"config_map"}
            or not isinstance(licensing["config_map"], str)
            or len(licensing["config_map"]) > 63
            or not re.fullmatch(NAME, licensing["config_map"])
        ):
            raise ValueError(
                "Use the local public-key ConfigMap projection from license_keys.py"
            )
    if type(c.get("apm_enabled", False)) is not bool:
        raise ValueError("apm_enabled must be a boolean")
    concurrency = c.get("max_concurrent_backups", 1)
    if type(concurrency) is not int or not 1 <= concurrency <= 16:
        raise ValueError("max_concurrent_backups requires an integer from 1 to 16")
    if c.get("scratch_access_mode") == "ReadWriteOnce" and concurrency != 1:
        raise ValueError("ReadWriteOnce scratch requires max_concurrent_backups=1")
    if c.get("appearance") is not None:
        appearance = c["appearance"]
        if (
            not isinstance(appearance, dict)
            or set(appearance) != {"config_map", "items"}
            or not isinstance(appearance["config_map"], str)
            or not re.fullmatch(NAME, appearance["config_map"])
        ):
            raise ValueError("Use the appearance projection generated by appearance.py")
        entries = appearance["items"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 512:
            raise ValueError("Invalid appearance projection size")
        paths = set()
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"key", "path"}
                or not isinstance(entry["key"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", entry["key"])
            ):
                raise ValueError("Invalid appearance projection key")
            path = entry["path"]
            if (
                not isinstance(path, str)
                or not re.fullmatch(
                    r"(?:config\.json|packs/[a-z0-9]+(?:-[a-z0-9]+)*/[0-9]+\.[0-9]+\.[0-9]+/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+)",
                    path,
                )
                or {".", ".."} & set(path.split("/"))
                or not (path == "config.json" or path.startswith("packs/"))
            ):
                raise ValueError("Invalid appearance projection path")
            if path in paths:
                raise ValueError("Duplicate appearance projection")
            paths.add(path)
        if "config.json" not in paths:
            raise ValueError("Appearance projection must include config.json")
    agentns, sources, selected = agent_scope(c)
    for label, values in (
        ("source_namespaces", sources),
        ("selected_namespaces", selected),
    ):
        if (
            not isinstance(values, list)
            or not (0 if label == "selected_namespaces" else 1) <= len(values) <= 32
            or len(set(values)) != len(values)
            or any(not isinstance(n, str) or not re.fullmatch(NAME, n) for n in values)
        ):
            raise ValueError(label + " requires 1 to 32 distinct explicit namespaces")
    if not set(selected) <= set(sources):
        raise ValueError("selected_namespaces must be a subset of source_namespaces")
    if not isinstance(agentns, str) or not re.fullmatch(NAME, agentns):
        raise ValueError("Invalid agent_namespace")
    if not isinstance(c.get("agent_id", "legacy"), str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", c.get("agent_id", "legacy")
    ):
        raise ValueError("Invalid stable agent_id")
    if (
        not isinstance(c.get("agent_display_name", "KubeVirt agent 1"), str)
        or not 1 <= len(c.get("agent_display_name", "KubeVirt agent 1")) <= 128
    ):
        raise ValueError("Invalid agent_display_name")
    scopes = c["restore_namespaces"]
    if (
        not isinstance(scopes, list)
        or not 1 <= len(scopes) <= 32
        or any(not isinstance(ns, str) or not re.fullmatch(NAME, ns) for ns in scopes)
        or len(set(scopes)) != len(scopes)
    ):
        raise ValueError(
            "restore_namespaces requires 1 to 32 distinct explicit namespace names"
        )
    if "agent_namespace" in c and agentns in set(sources) | set(scopes):
        raise ValueError(
            "Explicit agent_namespace must be separate from source and restore namespaces"
        )
    for key in (
        "namespace",
        "vm_namespace",
        "journal_storage_class",
        "scratch_storage_class",
    ):
        if not isinstance(c[key], str) or not re.fullmatch(NAME, c[key]):
            raise ValueError(f"Invalid explicit Kubernetes name: {key}")
    for key in ("api_host", "ui_host"):
        if (
            not isinstance(c[key], str)
            or len(c[key]) > 253
            or len(c[key].split(".")) < 2
            or any(not re.fullmatch(NAME, part) for part in c[key].split("."))
        ):
            raise ValueError(f"Invalid route hostname: {key}")
    aliases = c.get("ui_aliases", [])
    if (
        not isinstance(aliases, list)
        or len(aliases) > 16
        or any(
            not isinstance(host, str)
            or len(host) > 253
            or len(host.split(".")) < 2
            or any(not re.fullmatch(NAME, part) for part in host.split("."))
            for host in aliases
        )
        or len(set(aliases)) != len(aliases)
        or c["ui_host"] in aliases
        or c["api_host"] in aliases
    ):
        raise ValueError(
            "ui_aliases requires up to 16 distinct explicit UI hostname origins, excluding primary UI/API hosts"
        )
    if c["api_host"] == c["ui_host"]:
        raise ValueError("UI edge and API passthrough Routes require distinct hosts")
    if c["namespace"] in set(sources) | set(scopes) | {agentns}:
        raise ValueError(
            "Application namespace must be separate from protected and restore namespaces; "
            "agent Job/Secret permissions must not reach application credentials"
        )
    if set(c["images"]) != {"backend", "frontend", "agent"} or any(
        not isinstance(v, str) or not re.fullmatch(IMAGE, v)
        for v in c["images"].values()
    ):
        raise ValueError(
            "All three images must be registry references pinned by sha256 digest"
        )
    if (
        set(c["secrets"]) != SECRETS
        or any(
            not isinstance(v, str) or not re.fullmatch(NAME, v)
            for v in c["secrets"].values()
        )
        or len(set(c["secrets"].values())) != len(SECRETS)
    ):
        raise ValueError("Provide eight distinct Secret names, not their contents")
    mtls = c["mtls"]
    if mtls is not None:
        expected = {
            "backend_client_ca",
            "backend_client_tls",
            "agent_client_ca",
        }
        if (
            not isinstance(mtls, dict)
            or set(mtls) != expected
            or any(
                not isinstance(value, str) or not re.fullmatch(NAME, value)
                for value in mtls.values()
            )
            or len(set(mtls.values())) != len(expected)
            or set(mtls.values()) & set(c["secrets"].values())
        ):
            raise ValueError("mTLS requires three distinct site Secret names")
    for key in ("database", "runtime_role", "admin_username"):
        if not isinstance(c[key], str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_-]{0,62}", c[key]
        ):
            raise ValueError(f"Invalid installation identity: {key}")
    for key in ("journal_size", "scratch_size"):
        if not isinstance(c[key], str) or not re.fullmatch(
            r"[1-9][0-9]*(Mi|Gi|Ti)", c[key]
        ):
            raise ValueError(f"Positive explicit storage quantity required: {key}")
    if c["scratch_access_mode"] not in {"ReadWriteOnce", "ReadWriteMany"}:
        raise ValueError("Explicit supported scratch access mode required")
    if set(c["resources"]) != {"backend", "frontend", "agent", "migration"}:
        raise ValueError("Resource budgets required for all four components")
    for value in c["resources"].values():
        if type(value) is not dict or set(value) != {"requests", "limits"}:
            raise ValueError("Each component requires resource requests and limits")
        for budget in value.values():
            if (
                type(budget) is not dict
                or set(budget) != {"cpu", "memory"}
                or any(
                    not isinstance(v, str)
                    or not re.fullmatch(r"[1-9][0-9]*(m|Mi|Gi)?", v)
                    for v in budget.values()
                )
            ):
                raise ValueError("Positive CPU and memory budgets required")


def agent_scope(c):
    """Old site files retain their exact namespace and technical identity."""
    sources = c.get("source_namespaces", [c["vm_namespace"]])
    return (
        c.get("agent_namespace", c["vm_namespace"]),
        sources,
        c.get("selected_namespaces", sources),
    )


def obj(kind, name, ns, body=None, api="v1", part_of="vnbui"):
    return {
        "apiVersion": api,
        "kind": kind,
        "metadata": {
            "name": name,
            "namespace": ns,
            "labels": {"app.kubernetes.io/part-of": part_of},
        },
        **(body or {}),
    }


def env(name, value):
    return {"name": name, "value": value}


def application_key_name(c):
    # Older accepted manifests refer to the original key in their existing Secret.
    return c.get("application_key_name", "VNBUI_ENCRYPTION_KEY")


def secret_env(c, name, secret, *, source_key=None):
    return {
        "name": name,
        "valueFrom": {"secretKeyRef": {"name": c["secrets"][secret], "key": source_key or name}},
    }


def mount(name, path, **extra):
    return {"name": name, "mountPath": path, "readOnly": True, **extra}


def secret_volume(c, name, secret):
    return {
        "name": name,
        "secret": {"secretName": c["secrets"][secret], "defaultMode": 0o440},
    }


def mtls_volume(c, name, secret):
    return {
        "name": name,
        "secret": {"secretName": c["mtls"][secret], "defaultMode": 0o440},
    }


def container(c, component, port=None):
    result = {
        "name": component,
        "image": c["images"]["backend" if component == "migration" else component],
        "imagePullPolicy": "IfNotPresent",
        "resources": c["resources"][component],
        "securityContext": {
            "runAsNonRoot": True,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": [mount("tmp", "/tmp", readOnly=False)],
    }
    if port:
        result["ports"] = [
            {
                "name": "http" if component == "frontend" else "https",
                "containerPort": port,
            }
        ]
        for kind, path in (
            ("livenessProbe", "/health"),
            (
                "readinessProbe",
                (
                    "/ready"
                    if component == "backend"
                    else "/health/ready" if component == "agent" else "/health"
                ),
            ),
        ):
            result[kind] = {
                "httpGet": {
                    "path": path,
                    "port": port,
                    "scheme": "HTTP" if component == "frontend" else "HTTPS",
                },
                "periodSeconds": 15,
                "initialDelaySeconds": 30,
            }
    return result


def pod(c, component, item, volumes, sa=None):
    return {
        "metadata": {
            "labels": {
                "app": kube_name(c, component),
                "app.kubernetes.io/part-of": resource_prefix(c),
            }
        },
        "spec": {
            "automountServiceAccountToken": bool(sa),
            **({"serviceAccountName": sa} if sa else {}),
            "securityContext": {
                "runAsNonRoot": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [item],
            "volumes": [{"name": "tmp", "emptyDir": {}}, *volumes],
        },
    }


def deployment(c, component, template, ns):
    return obj(
        "Deployment",
        kube_name(c, component),
        ns,
        {
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app": kube_name(c, component)}},
                "template": template,
            }
        },
        "apps/v1",
        part_of=resource_prefix(c),
    )


def service(c, component, ns, port):
    return obj(
        "Service",
        kube_name(c, component),
        ns,
        {
            "spec": {
                "selector": {"app": kube_name(c, component)},
                "ports": [
                    {
                        "name": "http" if component == "frontend" else "https",
                        "port": port,
                        "targetPort": port,
                    }
                ],
            }
        },
        part_of=resource_prefix(c),
    )


def nginx(c):
    return """pid /tmp/nginx.pid;
events { worker_connections 1024; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /dev/stdout;
  error_log /dev/stderr;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  map $http_upgrade $connection_upgrade { default upgrade; '' close; }
  server {
    listen 8080;
    root /usr/share/nginx/html;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    location = /health { return 200 'healthy\\n'; }
    location = /metrics { return 404; }
    location ^~ /metrics/ { return 404; }
    location /apm/ { return 404; }
    location ^~ /appearance/ {
      root /etc;
      try_files /vesta$uri /vnbui$uri =404;
      autoindex off;
      add_header Cache-Control "no-store";
      add_header X-Content-Type-Options "nosniff" always;
      add_header Content-Security-Policy "default-src 'none'; style-src 'none'; sandbox" always;
    }
    location /assets/ { try_files $uri =404; }
    location /locales/ { try_files $uri =404; }
    location = /api { return 404; }
    location / { try_files $uri $uri/ /index.html; }
    location ~ ^/(api/|ws) {
      proxy_pass https://BACKEND;
      proxy_ssl_verify on;
      proxy_ssl_trusted_certificate /trust/ca.crt;
      proxy_ssl_server_name on;
      proxy_ssl_name APIHOST;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_read_timeout 3600;
    }
    location ~* \\.map$ { return 404; }
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
      try_files $uri =404;
      expires 1y;
      add_header Cache-Control "public, immutable";
    }
  }
}
""".replace("BACKEND", f"{kube_name(c, 'backend')}.{c['namespace']}.svc:8000").replace(
        "APIHOST", c["api_host"]
    )


def render(c, stage, *, structural=False):
    validate(c)
    ns, items = c["namespace"], []
    make = partial(obj, part_of=resource_prefix(c))
    vmns, sources, selected = agent_scope(c)
    if stage in {"migrate", "restore-grants", "upgrade", "rollback-schema"}:
        operation, job_name = {
            "migrate": ("--fresh", "fresh-schema"),
            "restore-grants": ("--restored", "restore-grants"),
            "upgrade": ("--upgrade-managed-files", "upgrade-managed-files"),
            "rollback-schema": ("--rollback-managed-files", "rollback-managed-files"),
        }[stage]
        item = container(c, "migration")
        item["command"] = [
            "python",
            "-m",
            "core.portable_install",
            operation,
            "--database",
            c["database"],
            "--runtime-role",
            c["runtime_role"],
        ]
        if stage == "rollback-schema" and c.get("rollback_schema_revision", "backup_admission_pause") != "backup_admission_pause":
            raise ValueError("Managed file rollback supports backup_admission_pause only")
        if stage in {"upgrade", "rollback-schema"}:
            installation = c.get("upgrade_installation_id")
            if installation is None and not structural:
                raise ValueError("An observed upgrade_installation_id is required")
            item["command"] += ["--installation-id", installation or "observed-uuid-required"]
        item["env"] = [
            secret_env(c, "DATABASE_URL", "database_owner"),
            env("PYTHONDONTWRITEBYTECODE", "1"),
            env("PGSSLMODE", "verify-full"),
            env("PGSSLROOTCERT", "/trust/ca.crt"),
            *profile_environment(c),
        ]
        item["volumeMounts"] += [mount("trust", "/trust")]
        template = pod(c, "migration", item, [secret_volume(c, "trust", "trust")])
        template["spec"]["restartPolicy"] = "Never"
        items.append(
            make(
                "Job",
                kube_name(c, job_name),
                ns,
                {
                    "spec": {
                        "backoffLimit": 0,
                        "activeDeadlineSeconds": 1800,
                        "template": template,
                    }
                },
                "batch/v1",
            )
        )
    elif stage == "api":
        item = container(c, "backend", 8000)
        item["env"] = [
            *profile_environment(c),
            secret_env(c, "DATABASE_URL", "database_runtime"),
            secret_env(c, "JWT_SECRET", "application"),
            *compatible_image_env(
                secret_env(c, "VESTA_ENCRYPTION_KEY", "application", source_key=application_key_name(c))
            ),
            secret_env(c, "ORCHESTRATOR_TO_AGENT_KEY", "application"),
            *[
                env(k, v)
                for k, v in {
                    "ENVIRONMENT": "production",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "USE_REAL_BACKUP_EXECUTOR": "true",
                    "AGENT_TLS_ENABLED": "true",
                    "AGENT_VERIFY_SSL": "true",
                    "ENABLE_ENCRYPTION": "true",
                    "REQUIRE_MTLS": "true" if c["mtls"] else "false",
                    "ALLOWED_ORIGINS": ",".join(
                        "https://" + host
                        for host in [c["ui_host"], *c.get("ui_aliases", [])]
                    ),
                    "INITIAL_ADMIN_USERNAME": c["admin_username"],
                    "INITIAL_ADMIN_PASSWORD_FILE": "/admin/password",
                    "BACKEND_TLS_CERT_FILE": "/tls/tls.crt",
                    "BACKEND_TLS_KEY_FILE": "/tls/tls.key",
                    "AGENT_CA_CERT": "/trust/ca.crt",
                    "AGENT_KEY_ROTATION_TTL_HOURS": str(
                        c.get("agent_key_rotation_ttl_hours", 24)
                    ),
                }.items()
            ],
        ]
        item["volumeMounts"] += [
            mount("tls", "/tls"),
            mount("trust", "/trust"),
            mount("admin", "/admin"),
        ]
        if c["mtls"]:
            item["env"] += [
                env("BACKEND_TLS_CLIENT_CA_FILE", "/client-ca/ca.crt"),
                env("ORCHESTRATOR_CLIENT_CERT", "/client-tls/tls.crt"),
                env("ORCHESTRATOR_CLIENT_KEY", "/client-tls/tls.key"),
            ]
            item["volumeMounts"] += [
                mount("client-ca", "/client-ca"),
                mount("client-tls", "/client-tls"),
            ]
        serving_trust = c.get("agent_serving_trust_config_map")
        if serving_trust:
            item["env"].append(env(
                "VESTA_AGENT_SERVING_TRUST_FILE", "/agent-serving-trust/agent-serving-trust.json"
            ))
            item["volumeMounts"].append(mount("agent-serving-trust", "/agent-serving-trust"))
        item["env"] += [
            env("OPERATION_" + key.upper(), str(value))
            for key, value in operation_budget(c).items()
        ]
        # A passthrough Route cannot filter HTTP paths at the router. Do not
        # expose installation-wide telemetry through this public listener.
        item["env"] += [
            env("METRICS_ENABLED", "false"),
            env("STORAGE_CAPABILITY_PROFILE", "db-rooted-consumer-verified/1"),
            env(
                "KUBEVIRT_TRANSFER_PROFILE",
                c.get("kubevirt_transfer_profile", "kubevirt-32m/1"),
            ),
        ]
        item["env"] += [
            env("AWS_CA_BUNDLE", "/trust/ca.crt"),
            env("SSL_CERT_FILE", "/trust/ca.crt"),
        ]
        item["env"] += [
            env("PGSSLMODE", "verify-full"),
            env("PGSSLROOTCERT", "/trust/ca.crt"),
        ]
        if resource_prefix(c) != "vnbui":
            item["env"].append(env("KUBEVIRT_RESOURCE_PREFIX", resource_prefix(c)))
        template = pod(
            c,
            "backend",
            item,
            [
                secret_volume(c, "tls", "backend_tls"),
                secret_volume(c, "trust", "trust"),
                secret_volume(c, "admin", "admin"),
                *(
                    [{
                        "name": "agent-serving-trust",
                        "configMap": {
                            "name": serving_trust,
                            "defaultMode": 0o444,
                            "items": [{"key": "agent-serving-trust.json", "path": "agent-serving-trust.json"}],
                        },
                    }] if serving_trust else []
                ),
                *(
                    [
                        mtls_volume(c, "client-ca", "backend_client_ca"),
                        mtls_volume(c, "client-tls", "backend_client_tls"),
                    ]
                    if c["mtls"]
                    else []
                ),
            ],
        )
        items += [
            deployment(c, "backend", template, ns),
            service(c, "backend", ns, 8000),
        ]
        item = container(c, "frontend", 8080)
        # Skip the upstream image's configuration-mutating entrypoint.
        item["command"] = ["nginx", "-g", "daemon off;"]
        item["volumeMounts"] += [
            mount("nginx", "/etc/nginx/nginx.conf", subPath="nginx.conf"),
            mount(
                "nginx",
                "/usr/share/nginx/html/site-config.json",
                subPath="site-config.json",
            ),
            mount("trust", "/trust"),
        ]
        template = pod(
            c,
            "frontend",
            item,
            [
                {"name": "nginx", "configMap": {"name": kube_name(c, "frontend")}},
                secret_volume(c, "trust", "trust"),
            ],
        )
        items += [
            make(
                "ConfigMap",
                kube_name(c, "frontend"),
                ns,
                {
                    "data": {
                        "nginx.conf": nginx(c),
                        "site-config.json": json.dumps(
                            {"apm": {"enabled": c.get("apm_enabled", False)}},
                            separators=(",", ":"),
                        ),
                    }
                },
            ),
            deployment(c, "frontend", template, ns),
            service(c, "frontend", ns, 8080),
        ]
        for component, host, termination in (
            ("frontend", c["ui_host"], "edge"),
            ("backend", c["api_host"], "passthrough"),
        ):
            items.append(
                make(
                    "Route",
                    kube_name(c, component),
                    ns,
                    {
                        "spec": {
                            "host": host,
                            "to": {"kind": "Service", "name": kube_name(c, component)},
                            "port": {
                                "targetPort": (
                                    "http" if component == "frontend" else "https"
                                )
                            },
                            "tls": {
                                "termination": termination,
                                "insecureEdgeTerminationPolicy": "Redirect",
                            },
                        }
                    },
                    "route.openshift.io/v1",
                )
            )
    elif stage == "agent":
        read, change = ["get", "list", "watch"], [
            "get",
            "list",
            "watch",
            "create",
            "delete",
        ]
        rules = [
            {"apiGroups": [group], "resources": resources, "verbs": verbs}
            for group, resources, verbs in (
                ("kubevirt.io", ["virtualmachines"], read),
                ("kubevirt.io", ["virtualmachineinstances"], read),
                (
                    "backup.kubevirt.io",
                    ["virtualmachinebackups", "virtualmachinebackuptrackers"],
                    change + ["patch", "update"],
                ),
                ("export.kubevirt.io", ["virtualmachineexports"], change),
                ("", ["persistentvolumeclaims", "secrets"], change),
                ("", ["services", "configmaps"], read),
                ("", ["pods"], change),
                ("", ["pods/log"], ["get"]),
                ("coordination.k8s.io", ["leases"], change),
                ("discovery.k8s.io", ["endpointslices"], read),
                ("k8s.cni.cncf.io", ["network-attachment-definitions"], ["get"]),
            )
        ]
        items.append(make("ServiceAccount", kube_name(c, "agent"), vmns))
        for source in sources:
            items += [
                make(
                    "Role",
                    kube_name(c, "agent"),
                    source,
                    {"rules": rules},
                    "rbac.authorization.k8s.io/v1",
                ),
                make(
                    "RoleBinding",
                    (
                        kube_name(c, "agent-" + vmns)
                        if "agent_namespace" in c
                        else kube_name(c, "agent")
                    ),
                    source,
                    {
                        "roleRef": {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "Role",
                            "name": kube_name(c, "agent"),
                        },
                        "subjects": [
                            {
                                "kind": "ServiceAccount",
                                "name": kube_name(c, "agent"),
                                "namespace": vmns,
                            }
                        ],
                    },
                    "rbac.authorization.k8s.io/v1",
                ),
            ]
        policy = {
            "source_namespaces": sources,
            "default_selected_namespaces": selected,
            "restore_namespaces": c["restore_namespaces"],
            "scratch_pvcs": {source: kube_name(c, "scratch") for source in sources},
        }
        items.append(
            make(
                "ConfigMap",
                kube_name(c, "agent-scope"),
                vmns,
                {"data": {"policy.json": json.dumps(policy, sort_keys=True)}},
            )
        )
        for purpose, pvcns in [
            ("journal", vmns),
            *(("scratch", source) for source in sources),
        ]:
            items.append(
                make(
                    "PersistentVolumeClaim",
                    kube_name(c, purpose),
                    pvcns,
                    {
                        "spec": {
                            "storageClassName": c[purpose + "_storage_class"],
                            "volumeMode": "Filesystem",
                            "accessModes": [
                                (
                                    c["scratch_access_mode"]
                                    if purpose == "scratch"
                                    else "ReadWriteOnce"
                                )
                            ],
                            "resources": {
                                "requests": {"storage": c[purpose + "_size"]}
                            },
                        }
                    },
                )
            )
        item = container(c, "agent", 8090)
        item["env"] = [
            env(k, v)
            for k, v in {
                "ENVIRONMENT": "production",
                "PROVIDER": "kubevirt",
                "HOSTNAME": c.get(
                    "agent_id", kube_name(c, "kubevirt-" + c["vm_namespace"])
                ),
                "AGENT_DISPLAY_NAME": c.get("agent_display_name", "KubeVirt agent 1"),
                "MAX_CONCURRENT_BACKUPS": str(c.get("max_concurrent_backups", 1)),
                "KUBE_API_QPS": str(c.get("kube_api_qps", 50)),
                "KUBE_API_BURST": str(c.get("kube_api_burst", 100)),
                "KUBE_NAMESPACE": sources[0],
                "KUBEVIRT_SCOPE_POLICY_FILE": "/scope/policy.json",
                "KUBEVIRT_RESTORE_NAMESPACES": ",".join(c["restore_namespaces"]),
                "KUBEVIRT_BACKUP_SCRATCH_PVC": kube_name(c, "scratch"),
                "KUBEVIRT_NATIVE_BACKUP_TTL_SECONDS": str(
                    c.get("kubevirt_native_backup_ttl_seconds", 36000)
                ),
                "KUBEVIRT_TRANSACTION_TIMEOUT_SECONDS": str(
                    c.get("kubevirt_transaction_timeout_seconds", 0)
                ),
                "KUBEVIRT_RESTORE_IMAGE": c["images"]["agent"],
                "AGENT_IP_ADDRESS": kube_name(c, "agent") + "." + vmns + ".svc",
                "ORCHESTRATOR_URL": "https://" + c["api_host"],
                "KEY_FILE_PATH": "/var/lib/vnbui/agent.key",
                "BACKUP_STORAGE_PATH": "/var/lib/vnbui/backups",
                "ENABLE_API_KEY_VALIDATION": "true",
                "REQUIRE_TLS": "true",
                "TLS_ENABLED": "true",
                "ORCHESTRATOR_VERIFY_SSL": "true",
                "TLS_VERIFY_CLIENT": "true" if c["mtls"] else "false",
                "TLS_CERT_FILE": "/tls/tls.crt",
                "TLS_KEY_FILE": "/tls/tls.key",
                "TLS_CA_FILE": "/trust/ca.crt",
            }.items()
        ]
        item["env"] += [
            env("OPERATION_" + key.upper(), str(value))
            for key, value in operation_budget(c).items()
        ]
        item["env"].append(
            env(
                "KUBEVIRT_SOURCE_HEALTH_PROBES",
                json.dumps(source_health_probes(c), separators=(",", ":")),
            )
        )
        if resource_prefix(c) != "vnbui":
            item["env"].append(env("KUBEVIRT_RESOURCE_PREFIX", resource_prefix(c)))
        item["env"] += [
            secret_env(c, key, "agent_registration")
            for key in ("REGISTRATION_KEY", "KEYSTORE_IDENTITY", "ORCHESTRATOR_API_KEY")
        ]
        item["env"] += [
            env("SSL_CERT_FILE", "/trust/ca.crt"),
            env("KUBEVIRT_RESTORE_CA_FILE", "/trust/ca.crt"),
        ]
        item["volumeMounts"] += [
            mount("scope", "/scope"),
            mount("journal", "/var/lib/vnbui", readOnly=False),
            mount("tls", "/tls"),
            mount("trust", "/trust"),
        ]
        if c["mtls"]:
            item["env"] += [
                env("TLS_CLIENT_CA_FILE", "/client-ca/ca.crt"),
                env("CALLBACK_CLIENT_CERT_FILE", "/var/lib/vnbui/certs/agent.crt"),
                env("CALLBACK_CLIENT_KEY_FILE", "/var/lib/vnbui/certs/agent.key"),
            ]
            item["volumeMounts"] += [
                mount("client-ca", "/client-ca"),
            ]
            for probe in ("livenessProbe", "readinessProbe"):
                item[probe] = {
                    "exec": {"command": ["/vnbui-agent", "-probe-ready"]},
                    "periodSeconds": 15,
                    "initialDelaySeconds": 30,
                    "timeoutSeconds": 6,
                }
        template = pod(
            c,
            "agent",
            item,
            [
                {"name": "scope", "configMap": {"name": kube_name(c, "agent-scope")}},
                {
                    "name": "journal",
                    "persistentVolumeClaim": {"claimName": kube_name(c, "journal")},
                },
                secret_volume(c, "tls", "agent_tls"),
                secret_volume(c, "trust", "trust"),
                *(
                    [
                        mtls_volume(c, "client-ca", "agent_client_ca"),
                    ]
                    if c["mtls"]
                    else []
                ),
            ],
            kube_name(c, "agent"),
        )
        items += [
            deployment(c, "agent", template, vmns),
            service(c, "agent", vmns, 8090),
        ]
        # Destination authority is explicit and namespaced, without backup
        # controller privileges or source VM mutation in recovery scopes.
        for destination in c["restore_namespaces"]:
            restore_rules = [
                {"apiGroups": [group], "resources": names, "verbs": verbs}
                for group, names, verbs in (
                    ("kubevirt.io", ["virtualmachines"], ["get", "create"]),
                    ("", ["persistentvolumeclaims"], ["get", "create"]),
                    ("", ["secrets"], ["get", "create", "delete"]),
                    ("", ["configmaps"], ["get"]),
                    ("", ["pods"], ["get", "list"]),
                    ("batch", ["jobs"], ["get", "create"]),
                    ("k8s.cni.cncf.io", ["network-attachment-definitions"], ["get"]),
                )
            ]
            items += [
                make("ServiceAccount", kube_name(c, "restore-worker"), destination),
                make(
                    "Role",
                    kube_name(c, "restore"),
                    destination,
                    {"rules": restore_rules},
                    "rbac.authorization.k8s.io/v1",
                ),
                make(
                    "RoleBinding",
                    kube_name(c, "restore-" + vmns),
                    destination,
                    {
                        "roleRef": {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "Role",
                            "name": kube_name(c, "restore"),
                        },
                        "subjects": [
                            {
                                "kind": "ServiceAccount",
                                "name": kube_name(c, "agent"),
                                "namespace": vmns,
                            }
                        ],
                    },
                    "rbac.authorization.k8s.io/v1",
                ),
                make(
                    "RoleBinding",
                    kube_name(c, "restore-worker-scc"),
                    destination,
                    {
                        "roleRef": {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "ClusterRole",
                            "name": "system:openshift:scc:nonroot-v2",
                        },
                        "subjects": [
                            {
                                "kind": "ServiceAccount",
                                "name": kube_name(c, "restore-worker"),
                                "namespace": destination,
                            }
                        ],
                    },
                    "rbac.authorization.k8s.io/v1",
                ),
            ]
    else:
        raise ValueError(
            "Choose an installation, schema, API, or agent stage separately"
        )
    if stage == "api" and c.get("licensing"):
        for item in items:
            if item["kind"] != "Deployment" or item["metadata"]["name"] != kube_name(
                c, "backend"
            ):
                continue
            spec = item["spec"]["template"]["spec"]
            spec["volumes"].append(
                {
                    "name": "license-keys",
                    "configMap": {
                        "name": c["licensing"]["config_map"],
                        "items": [
                            {"key": "license-keys.json", "path": "license-keys.json"}
                        ],
                        "defaultMode": 0o444,
                    },
                }
            )
            backend = spec["containers"][0]
            backend["volumeMounts"].append(
                mount(
                    "license-keys",
                    "/etc/vnbui/license-keys.json",
                    subPath="license-keys.json",
                )
            )
            backend["env"].append(
                env("LICENSE_KEYS_FILE", "/etc/vnbui/license-keys.json")
            )
    if stage == "api" and c.get("appearance"):
        for item in items:
            if item["kind"] != "Deployment":
                continue
            spec = item["spec"]["template"]["spec"]
            spec["volumes"].append(
                {
                    "name": "appearance",
                    "configMap": {
                        "name": c["appearance"]["config_map"],
                        "items": c["appearance"]["items"],
                    },
                }
            )
            app = spec["containers"][0]
            appearance_root = "/etc/vesta/appearance"
            app["volumeMounts"].append(mount("appearance", appearance_root))
            if app["name"] == "backend":
                # Already shipped images resolve appearance through this setting.
                app["env"].append(env("APPEARANCE_ROOT", appearance_root))
    return {"apiVersion": "v1", "kind": "List", "items": items}


def base_config():
    """Intentionally unusable site values for the checked-in structural base."""
    c = json.loads((Path(__file__).parent / "config.example.json").read_text())
    c["images"] = {
        name: f"registry.invalid/vesta/{name}@sha256:" + "0" * 64
        for name in ("backend", "frontend", "agent")
    }
    c["journal_storage_class"] = "example-journal"
    c["scratch_storage_class"] = "example-scratch"
    return c


def resource_name(index, item):
    return f"{index:02d}-{item['kind'].lower()}-{item['metadata']['name']}.json"


def write_base_stage(stage, destination):
    """Regenerate one checked-in base stage from the canonical renderer."""
    items = render(base_config(), stage, structural=True)["items"]
    if destination.exists():
        raise ValueError(f"Destination already exists: {destination}")
    destination.mkdir(parents=True)
    names = []
    for index, item in enumerate(items):
        name = resource_name(index, item)
        (destination / name).write_text(json.dumps(item, indent=2) + "\n")
        names.append(name)
    (destination / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n" + "".join(f"  - {name}\n" for name in names)
    )


def replacement_ops(before, after, path=""):
    """Generate exact JSON6902 replacements for site-varying values."""
    if isinstance(before, dict) and isinstance(after, dict):
        if before.keys() != after.keys():
            # A selected supported mode may replace a whole probe or resource
            # object; the checked-in base is still validated independently.
            return [{"op": "replace", "path": path, "value": after}]
        return [
            op
            for key in before
            for op in replacement_ops(
                before[key],
                after[key],
                path + "/" + key.replace("~", "~0").replace("/", "~1"),
            )
        ]
    if before == after:
        return []
    return [{"op": "replace", "path": path, "value": after}]


def write_kustomize(c, stage, destination):
    """Write a self-contained site overlay over the checked-in product base."""
    site_items = render(c, stage)["items"]
    base = base_config()
    base_items = render(base, stage, structural=True)["items"]
    if destination.exists():
        raise ValueError(f"Destination already exists: {destination}")
    if len(site_items) < len(base_items):
        raise ValueError("Base structure diverged from the renderer")
    base_path = BASE_ROOT / stage
    if not base_path.is_dir():
        raise ValueError(f"Missing checked-in product base: {base_path}")
    for index, expected in enumerate(base_items):
        actual = json.loads((base_path / resource_name(index, expected)).read_text())
        if actual != expected:
            raise ValueError("Checked-in Kustomize base is stale; regenerate it")
    # Match the canonical first scope by role rather than array position:
    # additional source scopes insert RBAC/PVC resources before Deployments.
    remaining = list(site_items)
    paired = []
    for before in base_items:

        def equivalent(after):
            if before["kind"] != after["kind"]:
                return False
            left = before["metadata"]["name"].removeprefix(resource_prefix(base) + "-")
            right = after["metadata"]["name"].removeprefix(resource_prefix(c) + "-")
            if left == right:
                return True
            if (
                before["kind"] == "RoleBinding"
                and left.startswith("agent-")
                and right == "agent"
            ):
                return True
            return (
                before["kind"] == "RoleBinding"
                and any(
                    left.startswith(prefix) and right.startswith(prefix)
                    for prefix in ("agent-", "restore-")
                )
                and (left == "restore-worker-scc") == (right == "restore-worker-scc")
            )

        after = next((item for item in remaining if equivalent(item)), None)
        if after is None:
            raise ValueError("Base structure diverged from the renderer")
        paired.append(after)
        remaining.remove(after)
    # Patch the canonical first scope in isolation before combining additional
    # scopes, whose same-name accounts must never match a first-scope patch.
    extra_items = remaining
    overlay = destination / "site" if extra_items else destination
    shutil.copytree(base_path, overlay / "base")
    patches = []
    for index, (before, after) in enumerate(zip(base_items, paired)):
        ops = replacement_ops(before, after)
        if not ops:
            continue
        name = resource_name(index, before).removesuffix(".json") + ".patch.json"
        (overlay / name).write_text(json.dumps(ops, indent=2) + "\n")
        patches.append((before, name))
    (overlay / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n  - base\n"
        + ("patches:\n" if patches else "")
        + "".join(
            "  - target:\n"
            f"      kind: {item['kind']}\n"
            f"      name: {item['metadata']['name']}\n"
            f"    path: {name}\n"
            for item, name in patches
        )
    )
    if extra_items:
        names = []
        for index, item in enumerate(extra_items):
            name = resource_name(index, item)
            (destination / name).write_text(json.dumps(item, indent=2) + "\n")
            names.append(name)
        (destination / "kustomization.yaml").write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\nresources:\n  - site\n"
            + "".join(f"  - {name}\n" for name in names)
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--stage", required=True, choices=STAGES)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Write one stage as a new Kustomize directory instead of JSON on stdout",
    )
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text())
        if args.output_dir:
            write_kustomize(config, args.stage, args.output_dir)
        else:
            print(json.dumps(render(config, args.stage), indent=2))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
