"""Bounded agent health classification shared by heartbeat and telemetry."""

HEALTH_REASON_STORAGE_LOW = "storage_low"
HEALTH_REASON_STORAGE_UNKNOWN = "storage_unknown"
HEALTH_REASON_LOAD_HIGH = "load_high"
HEALTH_REASON_LIBVIRT_UNAVAILABLE = "libvirt_unavailable"

HEALTH_REASONS = (
    HEALTH_REASON_STORAGE_LOW,
    HEALTH_REASON_STORAGE_UNKNOWN,
    HEALTH_REASON_LOAD_HIGH,
    HEALTH_REASON_LIBVIRT_UNAVAILABLE,
)


def assess_agent_health(
    heartbeat_data: dict,
    *,
    storage_free_gb_threshold: float,
    storage_free_percent_threshold: float,
    load_percent_threshold: float,
) -> tuple[list[str], list[str]]:
    """Return human-readable issues and stable reason codes for one heartbeat."""
    issues = []
    reasons = []

    storage_free = heartbeat_data.get("backup_storage_free_bytes")
    storage_total = heartbeat_data.get("backup_storage_total_bytes")
    role = heartbeat_data.get("storage_role", "native_capture")
    if storage_free is not None and storage_total is not None and storage_total > 0:
        free_gb = storage_free / (1024**3)
        free_percent = (storage_free / storage_total) * 100 if storage_total > 0 else 0
        if (
            role != "journal" and free_gb < storage_free_gb_threshold
        ) or free_percent < storage_free_percent_threshold:
            issues.append(
                f"Low {'journal' if role == 'journal' else 'backup'} storage: "
                f"{free_gb:.1f}GB free ({free_percent:.1f}%)"
            )
            reasons.append(HEALTH_REASON_STORAGE_LOW)

    elif heartbeat_data.get("storage_measurement_error") or (
        storage_total is not None and storage_total <= 0
    ):
        issues.append("Storage capacity unavailable")
        reasons.append(HEALTH_REASON_STORAGE_UNKNOWN)

    cpu_cores = heartbeat_data.get("cpu_cores") or 1
    load_avg_15m = heartbeat_data.get("load_average_15m")
    load_percent = (
        (load_avg_15m / cpu_cores) * 100 if load_avg_15m is not None else None
    )
    if load_percent is not None and load_percent > load_percent_threshold:
        issues.append(
            f"High load: {load_percent:.0f}% ({load_avg_15m:.2f} on {cpu_cores} cores)"
        )
        reasons.append(HEALTH_REASON_LOAD_HIGH)

    if not heartbeat_data.get(
        "provider_accessible", heartbeat_data.get("libvirt_accessible", True)
    ):
        issues.append(
            "KubeVirt not accessible"
            if heartbeat_data.get("provider") == "kubevirt"
            else "Libvirt not accessible"
        )
        reasons.append(HEALTH_REASON_LIBVIRT_UNAVAILABLE)

    return issues, reasons
