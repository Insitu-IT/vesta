import { escapeHtml } from './security.js';

export function dataDisks(disks) {
    return (Array.isArray(disks) ? disks : []).filter(d => ![d.device_type, d.type, d.device].some(v => String(v || '').toLowerCase() === 'cdrom'))
        .slice().sort((a, b) => String(a.target || a.device || a.name || '').localeCompare(String(b.target || b.device || b.name || ''), 'en', {numeric: true}));
}

export function renderDiskSummary(disks, t = window.t) {
    const entries = dataDisks(disks);
    const capacity = value => {
        if (value === null || value === undefined || !Number.isFinite(Number(value)) || Number(value) <= 0) return t('inventory.capacity_unknown');
        let size = Number(value), unit = 0;
        while (size >= 1024 && unit < 4) {size /= 1024; unit++;}
        return `${Number(size.toFixed(1))} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit]}`;
    };
    return `<div>${escapeHtml(t('inventory.disk_count', {count: entries.length}))}</div>` + entries.slice(0, 2).map(d => `<div class="small disk-summary">${escapeHtml(d.target || d.device || d.name || t('inventory.disk'))}: <bdi>${escapeHtml(capacity(d.capacity_bytes))}</bdi></div>`).join('') + (entries.length > 2 ? `<div class="small text-secondary">${escapeHtml(t('inventory.more_disks', {count: entries.length - 2}))}</div>` : '');
}

export function renderCbtObservation(vm, t = window.t) {
    const observed = (vm.metadata || vm.vm_metadata)?.changed_block_tracking;
    const raw = observed?.state;
    const key = {enabled: 'enabled', disabled: 'disabled', initializing: 'pending', pending: 'pending', pendingrestart: 'pending'}[String(raw || '').toLowerCase()] || 'unknown';
    const source = ['vm', 'vmi'].includes(observed?.source) ? ` (${observed.source.toUpperCase()})` : '';
    return `${escapeHtml(t('inventory.cbt'))}: ${escapeHtml(t(`inventory.cbt_${key}`))}${source}`;
}
