import assert from 'node:assert/strict';
import fs from 'node:fs';
import { renderBackupSafety } from '../src/utils/backup-safety.js';

for (const language of ['en', 'he']) {
    const locale = JSON.parse(fs.readFileSync(new URL(`../public/locales/${language}.json`, import.meta.url)));
    globalThis.window = {t: key => key.split('.').reduce((item, part) => item?.[part], locale)};
    const diagnostic = {stage: 'export_admission', reason: 'native_volume_count_mismatch', disposition: 'refused',
        expected_native_volumes: 2, observed_native_volumes: 0, observed_export_links: 0,
        observation_deadline: '2026-11-10T16:03:00Z', native_stop_phase: 'native_absent_unproven'};
    const summary = renderBackupSafety(diagnostic);
    const detail = renderBackupSafety(diagnostic, true);
    assert.ok(summary.includes('native_volume_count_mismatch'));
    assert.ok(detail.includes(window.t('backups.safety_guidance')));
    assert.ok(detail.includes('<code>0</code>'));
    assert.ok(detail.includes('native_absent_unproven'));
    assert.ok(!detail.includes('undefined'));
    assert.equal(renderBackupSafety({...diagnostic, reason: '<img src=x onerror=alert(1)>'}), '');
    assert.equal(renderBackupSafety({...diagnostic, disposition: 'successful'}), '');
    assert.equal(renderBackupSafety(null), '');
    const unexpected = renderBackupSafety({...diagnostic, provider_body: 'SECRET', observed_export_links: '<script>',
        observation_deadline: '<svg onload=alert(1)>'}, true);
    assert.ok(!unexpected.includes('SECRET') && !unexpected.includes('<script>') && !unexpected.includes('<svg'));
}
console.log('PASS: bounded backup safety diagnostics in English and Hebrew');
