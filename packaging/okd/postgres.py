#!/usr/bin/env python3
"""Offline dedicated PostgreSQL renderer. Never connects, applies or deletes."""

import argparse
from functools import partial
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from render import IMAGE, NAME, obj, kube_name, resource_prefix, validate as validate_site  # noqa: E402


def validate(config):
    if not isinstance(config, dict) or set(config) != {
        "image",
        "storage_class",
        "size",
        "bootstrap_secret",
        "tls_secret",
        "owner_role",
        "resources",
    }:
        raise ValueError("Use exactly the postgres.example.json fields")
    if not isinstance(config["image"], str) or not re.fullmatch(IMAGE, config["image"]):
        raise ValueError("PostgreSQL image must be approved and digest-pinned")
    for key in ("storage_class", "bootstrap_secret", "tls_secret"):
        if not isinstance(config[key], str) or not re.fullmatch(NAME, config[key]):
            raise ValueError("Explicit PostgreSQL storage and Secret names required")
    if config["bootstrap_secret"] == config["tls_secret"]:
        raise ValueError("Separate bootstrap and TLS Secrets required")
    if (
        not isinstance(config["owner_role"], str)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", config["owner_role"])
        or config["owner_role"] in {"postgres", "vnbui_bootstrap"}
    ):
        raise ValueError("Explicit non-bootstrap owner role required")
    if not isinstance(config["size"], str) or not re.fullmatch(
        r"[1-9][0-9]*(Mi|Gi|Ti)", config["size"]
    ):
        raise ValueError("Positive PostgreSQL storage quantity required")
    budgets = config["resources"]
    if not isinstance(budgets, dict) or set(budgets) != {"requests", "limits"}:
        raise ValueError("PostgreSQL resource requests and limits required")
    for budget in budgets.values():
        if (
            not isinstance(budget, dict)
            or set(budget) != {"cpu", "memory"}
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[1-9][0-9]*(m|Mi|Gi)?", value)
                for value in budget.values()
            )
        ):
            raise ValueError("Positive PostgreSQL CPU/memory budgets required")


def render(site, config):
    validate_site(site)
    if site.get("delivery_profile") == "customer-postgresql":
        raise ValueError("customer-postgresql requires a prepared customer database; bundled database rendering is disabled")
    validate(config)
    if site["runtime_role"] in {config["owner_role"], "postgres", "vnbui_bootstrap"}:
        raise ValueError("Runtime, owner and bootstrap roles must be distinct")
    if {config["bootstrap_secret"], config["tls_secret"]} & set(
        site["secrets"].values()
    ):
        raise ValueError("PostgreSQL Secrets must not reuse application Secret names")
    ns = site["namespace"]
    make = partial(obj, part_of=resource_prefix(site))
    secure = {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
        "runAsNonRoot": True,
    }
    labels = {"app": kube_name(site, "postgres"), "app.kubernetes.io/part-of": resource_prefix(site)}
    init_script = (Path(__file__).parent / "postgres-init.sh").read_text()
    items = [
        make(
            "ConfigMap",
            kube_name(site, "postgres-init"),
            ns,
            {
                "data": {
                    "10-vesta.sh": init_script,
                    "pg_hba.conf": "local all all trust\nhostnossl all all all reject\nhostssl all all all scram-sha-256\n",
                }
            },
        ),
        make(
            "PersistentVolumeClaim",
            kube_name(site, "postgres-data"),
            ns,
            {
                "spec": {
                    "storageClassName": config["storage_class"],
                    "volumeMode": "Filesystem",
                    "accessModes": ["ReadWriteOnce"],
                    "resources": {"requests": {"storage": config["size"]}},
                }
            },
        ),
        make(
            "Service",
            kube_name(site, "postgres"),
            ns,
            {
                "spec": {
                    "selector": {"app": kube_name(site, "postgres")},
                    "ports": [{"name": "postgres", "port": 5432, "targetPort": 5432}],
                }
            },
        ),
    ]
    mounts = [
        {"name": name, "mountPath": path, "readOnly": read_only}
        for name, path, read_only in (
            ("data", "/var/lib/postgresql/data", False),
            ("socket", "/var/run/postgresql", False),
            ("tmp", "/tmp", False),
            ("init", "/docker-entrypoint-initdb.d", True),
            ("bootstrap", "/bootstrap", True),
            ("tls", "/tls", True),
        )
    ]
    env = {
        "POSTGRES_USER": "vnbui_bootstrap",
        "POSTGRES_DB": "postgres",
        "POSTGRES_PASSWORD_FILE": "/bootstrap/POSTGRES_PASSWORD",
        "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=trust",
        "PGDATA": "/var/lib/postgresql/data/pgdata",
        "VESTA_OWNER_ROLE": config["owner_role"],
        "VESTA_RUNTIME_ROLE": site["runtime_role"],
        "VESTA_DATABASE": site["database"],
    }
    container = {
        "name": "postgres",
        "image": config["image"],
        "securityContext": secure,
        "resources": config["resources"],
        "env": [{"name": name, "value": value} for name, value in env.items()],
        "args": [
            "postgres",
            "-c",
            "ssl=on",
            "-c",
            "ssl_min_protocol_version=TLSv1.2",
            "-c",
            "ssl_cert_file=/tls/tls.crt",
            "-c",
            "ssl_key_file=/tls/tls.key",
            "-c",
            "hba_file=/docker-entrypoint-initdb.d/pg_hba.conf",
            "-c",
            "password_encryption=scram-sha-256",
            "-c",
            "max_connections=100",
            "-c",
            "log_statement=none",
            "-c",
            "log_min_error_statement=panic",
        ],
        "volumeMounts": mounts,
        "ports": [{"containerPort": 5432}],
        "readinessProbe": {
            "exec": {
                "command": [
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "vnbui_bootstrap",
                    "-d",
                    "postgres",
                ]
            },
            "periodSeconds": 10,
            "timeoutSeconds": 5,
        },
    }
    items.append(
        make(
            "StatefulSet",
            kube_name(site, "postgres"),
            ns,
            {
                "spec": {
                    "replicas": 1,
                    "serviceName": kube_name(site, "postgres"),
                    "updateStrategy": {"type": "OnDelete"},
                    "selector": {"matchLabels": {"app": kube_name(site, "postgres")}},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "terminationGracePeriodSeconds": 60,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "initContainers": [
                                {
                                    "name": "private-tls",
                                    "image": config["image"],
                                    "securityContext": secure,
                                    "resources": config["resources"],
                                    "command": [
                                        "/bin/sh",
                                        "-ec",
                                        "umask 077; cp /source/tls.crt /tls/tls.crt; cp /source/tls.key /tls/tls.key; chmod 600 /tls/tls.key",
                                    ],
                                    "volumeMounts": [
                                        {
                                            "name": "tls-source",
                                            "mountPath": "/source",
                                            "readOnly": True,
                                        },
                                        {"name": "tls", "mountPath": "/tls"},
                                    ],
                                }
                            ],
                            "containers": [container],
                            "volumes": [
                                {
                                    "name": "data",
                                    "persistentVolumeClaim": {
                                        "claimName": kube_name(site, "postgres-data")
                                    },
                                },
                                {
                                    "name": "init",
                                    "configMap": {
                                        "name": kube_name(site, "postgres-init"),
                                        "defaultMode": 365,
                                    },
                                },
                                {
                                    "name": "bootstrap",
                                    "secret": {
                                        "secretName": config["bootstrap_secret"]
                                    },
                                },
                                {
                                    "name": "tls-source",
                                    "secret": {"secretName": config["tls_secret"]},
                                },
                                {
                                    "name": "tls",
                                    "emptyDir": {
                                        "medium": "Memory",
                                        "sizeLimit": "16Mi",
                                    },
                                },
                                {"name": "socket", "emptyDir": {"sizeLimit": "16Mi"}},
                                {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                            ],
                        },
                    },
                }
            },
            "apps/v1",
        )
    )
    items.append(
        make(
            "NetworkPolicy",
            kube_name(site, "postgres"),
            ns,
            {
                "spec": {
                    "podSelector": {"matchLabels": {"app": kube_name(site, "postgres")}},
                    "policyTypes": ["Ingress"],
                    "ingress": [
                        {
                            "from": [
                                {
                                    "podSelector": {
                                        "matchLabels": {"app": kube_name(site, "backend")}
                                    }
                                },
                                {
                                    "podSelector": {
                                        "matchLabels": {"app": kube_name(site, "migration")}
                                    }
                                },
                            ],
                            "ports": [{"protocol": "TCP", "port": 5432}],
                        }
                    ],
                }
            },
            "networking.k8s.io/v1",
        )
    )
    return {"apiVersion": "v1", "kind": "List", "items": items}


def write_kustomize(site, config, destination):
    data = render(site, config)
    destination.mkdir(mode=0o700)
    (destination / "resources.json").write_text(json.dumps(data, indent=2) + "\n")
    (destination / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - resources.json\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--postgres-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        write_kustomize(
            json.loads(args.config.read_text()),
            json.loads(args.postgres_config.read_text()),
            args.output_dir,
        )
    except (ValueError, KeyError, TypeError, OSError):
        print(
            "POSTGRES_RENDER_FAILED: validate private inputs and use a new output directory",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
