"""Installation namespace ceiling and requested/applied selection checks."""

from fastapi import HTTPException


def provider_name(agent):
    return (
        (agent.metrics or {}).get("provider")
        or (agent.capabilities or {}).get("provider")
        or (
            "kubevirt"
            if (agent.capabilities or {}).get("backup_method")
            in {"vmexport", "kubevirt_pull_transaction"}
            else "libvirt"
        )
    )


def namespace_list(value, *, nonempty=False):
    if not isinstance(value, list) or len(value) > 32 or (nonempty and not value):
        raise HTTPException(422, "Invalid source namespace selection")
    if any(not isinstance(ns, str) or not ns or len(ns) > 63 for ns in value) or len(
        set(value)
    ) != len(value):
        raise HTTPException(422, "Invalid source namespace selection")
    return value


def validate_settings(agent, settings):
    provider = provider_name(agent)
    startup_only = {
        "libvirt_uri",
        "virtnbdbackup_path",
        "virtnbdrestore_path",
        "virtnbd_scratch_dir",
        "backup_storage_path",
        "max_concurrent_backups",
        "compression_type",
        "compression_level",
    }
    invalid = set(settings) & startup_only
    if provider == "kubevirt":
        invalid |= set(settings) & {"compression_type", "compression_level"}
    elif "selected_source_namespaces" in settings:
        invalid.add("selected_source_namespaces")
    if invalid:
        raise HTTPException(
            422,
            "Settings unavailable for this provider or require installation reconfiguration: "
            + ", ".join(sorted(invalid)),
        )
    if (
        "heartbeat_interval" in settings
        and not 5 <= settings["heartbeat_interval"] <= 3600
    ):
        raise HTTPException(
            422, "Heartbeat interval must be between 5 and 3600 seconds"
        )
    if "log_level" in settings and settings["log_level"].upper() not in {
        "DEBUG",
        "INFO",
        "WARN",
        "WARNING",
        "ERROR",
    }:
        raise HTTPException(422, "Invalid log level")
    if "selected_source_namespaces" in settings:
        selected = namespace_list(settings["selected_source_namespaces"])
        scope = (agent.metrics or {}).get("scope") or {}
        ceiling = namespace_list(scope.get("source_namespaces"), nonempty=True)
        if not set(selected) <= set(ceiling):
            raise HTTPException(
                422, "Source selection exceeds installed namespace ceiling"
            )


def source_allowed(agent, namespace):
    """Requested narrowing takes effect immediately; widening awaits acknowledgment."""
    if provider_name(agent) != "kubevirt":
        return False
    scope = (agent.metrics or {}).get("scope")
    if not isinstance(scope, dict):
        # Older agents retain their explicit singleton inventory scope. New policy
        # agents must report the installed ceiling before any source is admitted.
        config = agent.config or {}
        singleton = config.get("kube_namespace")
        return isinstance(singleton, str) and bool(singleton) and namespace == singleton
    installed = scope.get("source_namespaces") or []
    applied = scope.get("selected_source_namespaces") or []
    config = agent.config or {}
    requested = config.get("selected_source_namespaces", applied)
    return namespace in installed and namespace in applied and namespace in requested


def require_source_allowed(agent, namespace):
    if not source_allowed(agent, namespace):
        raise HTTPException(
            409, "Source namespace is outside the agent's applied selection"
        )
