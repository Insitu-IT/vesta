import { escapeHtml } from './security.js';

const word = value => typeof value === 'string' && /^[a-z][a-z_]{0,79}$/.test(value);

export function renderBackupSafety(diagnostic, details = false) {
    if (!diagnostic || !word(diagnostic.stage) || !word(diagnostic.reason) ||
        !['refused', 'transient', 'uncertain'].includes(diagnostic.disposition)) return '';
    const t = window.t;
    const summary = `<div class="text-warning small mt-1 backup-safety" role="status">
        ${escapeHtml(t('backups.safety_retained'))}
        <div dir="ltr" class="text-break"><code>${escapeHtml(diagnostic.stage)}: ${escapeHtml(diagnostic.reason)}</code></div>
    </div>`;
    if (!details) return summary;
    const rows = [];
    for (const name of ['expected_native_volumes', 'observed_native_volumes', 'observed_export_links']) {
        const value = diagnostic[name];
        if (Number.isSafeInteger(value) && value >= 0) {
            rows.push(`<div>${escapeHtml(t(`backups.safety_${name}`))}: <code>${value}</code></div>`);
        }
    }
    for (const name of ['native_stop_phase', 'observation_reason', 'read_observation_reason']) {
        if (word(diagnostic[name])) {
            rows.push(`<div>${escapeHtml(t(`backups.safety_${name}`))}: <code dir="ltr">${escapeHtml(diagnostic[name])}</code></div>`);
        }
    }
    for (const name of ['last_trustworthy_observation_at', 'observation_deadline', 'read_observation_deadline']) {
        const value = diagnostic[name];
        if (typeof value === 'string' && /^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(value) && value.length <= 35) {
            rows.push(`<div>${escapeHtml(t(`backups.safety_${name}`))}: <time dir="ltr">${escapeHtml(value)}</time></div>`);
        }
    }
    return `${summary}<div class="small mt-2">${rows.join('')}</div>
        <p class="form-hint mt-2">${escapeHtml(t('backups.safety_guidance'))}</p>`;
}
