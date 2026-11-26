import {enumLabel, storageCapacity} from '../src/utils/status-labels.js';
import {agentProvider, selectedNamespaces} from '../src/utils/agent-scope.js';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const locales = Object.fromEntries(['en', 'he'].map(lang => [lang,
    JSON.parse(fs.readFileSync(new URL(`../public/locales/${lang}.json`, import.meta.url)))]));
let language = 'en';
const t = key => key.split('.').reduce((v, k) => v?.[k], locales[language]);
const sent = [], toasts = [], settingsWrites = [];
let loseReply = false;
const backup = '11111111-1111-4111-8111-111111111111';
const id = '22222222-2222-4222-8222-222222222222';
const row = {id, backup_id: backup, verification_type: 'artifact_scrub', status: 'held', created_by: 'owner'};
const apiClient = {
    get: async path => path.includes('/verifications/') ? row : {items: []},
    post: async (path, body) => {
        sent.push({path, body: JSON.parse(JSON.stringify(body))});
        if (loseReply) {loseReply = false; throw new Error('lost reply');}
        return {...row, status: 'pending'};
    },
    put: async (path, body) => settingsWrites.push({path, body: JSON.parse(JSON.stringify(body))}),
};
const element = () => ({value: '', addEventListener() {}});
const window = {t, addEventListener() {}};
const context = vm.createContext({window, console, URL, URLSearchParams,
    document: {getElementById: element, querySelectorAll: () => []},
    setTimeout() {}, crypto: {randomUUID: () => id}, alert() {}});
async function load(path) {
    const module = new vm.SourceTextModule(fs.readFileSync(new URL(path, import.meta.url), 'utf8'), {context});
    await module.link(specifier => {
        const values = specifier.includes('authenticated-startup') ? {startAuthenticatedServices: async () => {}}
        : specifier.includes('installation.service') ? {installationService: {}}
            : specifier.includes('theme.service') ? {themeService: {button: () => ''}}
            : specifier.includes('vm-inventory') ? {renderDiskSummary: () => '', renderCbtObservation: () => ''}
            : specifier.includes('backup-guidance') ? {bindBackupGuidance() {}, loadBackupGuidance() {}, renderBackupGuidance() {}}
            : specifier.includes('licensing.service') ? {licensingService: {}}
            : specifier.includes('components/licensing') ? {refreshLicenseBanner() {}, renderLicenseSummary() {}, LicensingPanel: class {async load() {} render() {return '';} mount() {}}}
            : specifier.includes('context-help') ? {contextHelp: () => ''}
            : specifier.includes('status-labels') ? {enumLabel: (value, domain) => enumLabel(value, domain, context.window.t), storageCapacity}
            : specifier.includes('agent-scope') ? {agentProvider, selectedNamespaces}
            : specifier.includes('client') ? {apiClient}
            : specifier.includes('security') ? {escapeHtml: value => String(value).replaceAll('<', '&lt;').replaceAll('"', '&quot;')}
            : specifier.includes('status-colors') ? {getStatusColor: () => 'secondary'}
            : specifier.includes('format') ? {formatDate: () => 'completed', formatRelativeTime: () => 'recent'}
            : specifier.includes('auth.service') ? {authService: {}}
            : {assetResolver: {inlineSvg: () => ''}};
        return new vm.SyntheticModule(Object.keys(values), function () {
            for (const [key, value] of Object.entries(values)) this.setExport(key, value);
        }, {context});
    });
    await module.evaluate();
    return module.namespace;
}
const {App} = await load('../src/app.js');
const {VerificationPage} = await load('../src/pages/verification.js');
const app = new App();
app.user = {id: 'owner', role: 'operator'};
app.setupEventListeners();
window.vnbui.showToast = (message, kind) => toasts.push({message, kind});
window.vnbui.refreshPage = () => {};
await window.vnbui.startVerification();
assert.equal(sent.length, 0); // No implicit newest-backup selection.
loseReply = true;
await window.vnbui.startVerification(backup);
assert.equal(app.verificationRequests.get(backup), id);
await window.vnbui.startVerification(backup);
assert.deepEqual(sent[0], sent[1]);
assert.equal(app.verificationRequests.size, 0);
assert.equal(toasts.at(-1).kind, 'info'); // Accepted is not passed.
await window.vnbui.verificationControl(id, 'resume');
assert.deepEqual(sent.at(-1).body, {verification_id: id, action: 'resume'});
await window.vnbui.verificationControl(id, 'cancel');
assert.deepEqual(sent.at(-1).body, {verification_id: id, action: 'cancel'});
const page = new VerificationPage();
for (language of ['en', 'he']) {
    assert.match(page.controls(row), /resume/);
    assert.match(page.controls(row), /cancel/);
    assert.equal(page.controls({...row, status: 'cancelled'}), '');
    assert.ok(!page.controls({...row, created_by: 'other'}).includes("'resume'"));
    assert.equal(page.controls({...row, id: "' onclick='bad()"}), '');
    assert.equal(page.controls({...row, verification_type: 'checksum'}), '');
    assert.equal(page.controls({...row, cancel_requested: true}), '');
    window.vnbui.currentUserRole = 'viewer';
    assert.equal(page.controls(row), '');
    window.vnbui.currentUserRole = 'operator';
    page.verifications = [{...row, completed_at: '2026-10-18T00:00:00Z', result_message: '<script>bad()</script>'}];
    assert.match(page.renderVerificationRows(), /completed/);
}
const {SettingsPage} = await load('../src/pages/settings.js');
const settingsPage = new SettingsPage();
for (language of ['en', 'he']) {
    const manual = t('settings.backup_verification_manual');
    assert.equal(typeof manual, 'string');
    for (const prior of [true, false, undefined]) {
        settingsPage.settings = {verify_backups: prior};
        const html = settingsPage.renderBackupSettings();
        assert.ok(html.includes(manual));
        assert.ok(!html.includes('setting-verify-backups'));
    }
}
for (const cleanup of [true, false]) {
    // Even a stale injected checkbox cannot silently re-enable an unused flag.
    context.document.getElementById = name => ({
        'setting-verify-backups': {checked: true},
        'setting-auto-cleanup': {checked: cleanup},
        'setting-concurrent-backups': {value: '1'},
    })[name] || null;
    await settingsPage.saveAllSettings();
    assert.deepEqual(settingsWrites.at(-1), {path: '/api/v1/settings',
        body: {max_concurrent_backups: 1, auto_cleanup: cleanup}});
}
assert.equal(settingsWrites.length, 2);
console.log('PASS: receipt-bound verification controls');
