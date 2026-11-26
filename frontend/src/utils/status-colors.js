/**
 * Centralized status-to-Bootstrap-color mapping.
 * Replaces duplicated getStatusColor() across pages.
 */

const COLORS = {
    // Common statuses (backup, restore, verification)
    completed: 'success',
    running: 'info',
    uploading: 'info',
    upload_failed: 'warning',
    upload_completed: 'success',
    failed: 'danger',
    pending: 'warning',
    cancelled: 'secondary',
    queued: 'info',
    passed: 'success',

    // Agent statuses
    online: 'success',
    offline: 'danger',
    degraded: 'warning',

    // Health statuses
    healthy: 'success',
    unhealthy: 'danger',
    not_configured: 'secondary',

    // VM states (domain-specific overrides below)
    stopped: 'secondary',
    paused: 'warning',
    error: 'danger',
    shutoff: 'secondary',

    // Compatibility
    aligned: 'success',
    incompatible: 'danger',
};

// Domain-specific overrides where the same status word means different colors
const DOMAIN_OVERRIDES = {
    vm: { running: 'success' },  // VM running = green (not blue)
};

export function getStatusColor(status, domain = 'default') {
    if (!status) return 'secondary';
    const s = status.toLowerCase();
    const overrides = DOMAIN_OVERRIDES[domain];
    if (overrides && s in overrides) return overrides[s];
    return COLORS[s] || 'secondary';
}
