import { escapeHtml } from './security.js';

const manuals = new Set([
    'https://vestabackup.com/docs/storage-compatibility/',
    'https://vestabackup.com/docs/storage-compatibility/#check-changed-block-tracking',
    'https://vestabackup.com/docs/installation-requirements/',
    'https://vestabackup.com/docs/manuals/backup-safety/',
]);
const groupManual = 'https://vestabackup.com/docs/storage-compatibility/#multiple-disks-and-group-snapshots';

export async function loadBackupGuidance(apiClient, vmId, excluded = []) {
    const params = new URLSearchParams();
    excluded.forEach(target => params.append('exclude_disk', target));
    try {
        return await apiClient.get(`/api/v1/vms/${encodeURIComponent(vmId)}/backup-guidance`, params);
    } catch {
        return null;
    }
}

export function renderBackupGuidance(guidance, t = window.t) {
    if (!guidance || !['full', 'incremental', 'unknown', 'blocked'].includes(guidance.mode) ||
        !/^[a-z_]{1,64}$/.test(guidance.reason)) {
        return `<div class="text-secondary">${escapeHtml(t('guidance.unavailable'))}</div>`;
    }
    const label = key => escapeHtml(t(`guidance.${key}`));
    const link = url => `<a href="${url}" target="_blank" rel="noopener noreferrer">${label('guide')}</a>`;
    const actions = [`<strong>${label(guidance.mode)}</strong><div>${label(guidance.reason)}</div>`];
    if (guidance.affected_disks?.length) {
        actions.push(`<bdi>${escapeHtml(guidance.affected_disks.join(', '))}</bdi>`);
    }
    if (guidance.missing_apis?.length) {
        actions.push(`<code dir="ltr">${escapeHtml(guidance.missing_apis.join(', '))}</code>`);
    }
    const storage = guidance.storage;
    if (['low', 'at_limit'].includes(storage?.state) && ['journal', 'native_capture'].includes(storage.role)) {
        const role = t(`guidance.${storage.role}`);
        const amount = Number.isFinite(storage.used_percent) ? Number(storage.used_percent.toFixed(2)) : '—';
        const key = storage.state === 'at_limit' ? 'capacity_limit' : 'capacity_low';
        actions.push(escapeHtml(t(`guidance.${key}`, {role, amount, limit: storage.admission_used_percent})));
    }
    if (manuals.has(guidance.documentation_url)) actions.push(link(guidance.documentation_url));
    if (guidance.persistent_disks?.length > 1) {
        const reported = guidance.volume_snapshot_statuses || {};
        const states = guidance.persistent_disks.map(target => {
            const state = reported[target] === true ? 'snapshot_yes' : reported[target] === false ? 'snapshot_no' : 'snapshot_unknown';
            return `<li><bdi>${escapeHtml(target)}</bdi> — ${label(state)}</li>`;
        }).join('');
        const api = ['served', 'not_served'].includes(guidance.group_snapshot_api) ? guidance.group_snapshot_api : 'unknown';
        actions.push(`<details><summary>${label('multiple_disks')}</summary><div>${label('native_disks')}</div><ul>${states}</ul><div>${label('group_' + api)} ${label('group_execution')}</div>${link(groupManual)}</details>`);
    }
    return `<div class="small d-grid gap-1">${actions.map(action => `<div>${action}</div>`).join('')}</div>`;
}

// Keep the operator's choice while the selection changes. An old response
// must never enable submission or display evidence for a newer disk set.
export function bindBackupGuidance(modal, vmId, client, t = window.t) {
    const area = modal.querySelector('#backup-mode-guidance');
    const select = modal.querySelector('#backup-type');
    const submit = modal.querySelector('#submit-vm-backup');
    const disks = modal.querySelector('#backup-exclude-disks');
    let current, pending;
    const apply = () => {
        submit.disabled = !!pending || current?.mode === 'blocked' ||
            (current?.mode === 'full' && select.value === 'incremental');
    };
    const refresh = async () => {
        const request = Symbol();
        pending = request;
        area.dataset.vmId = vmId;
        area.textContent = t('guidance.checking');
        apply();
        const excluded = Array.from(disks.querySelectorAll('input:checked'), input => input.value);
        const result = await loadBackupGuidance(client, vmId, excluded);
        if (pending !== request || area.dataset.vmId !== vmId || disks.onchange !== refresh) return;
        pending = null;
        current = result;
        area.innerHTML = renderBackupGuidance(result, t);
        apply();
    };
    select.onchange = apply;
    disks.onchange = refresh;
    return refresh();
}
