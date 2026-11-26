import {enumLabel, storageCapacity} from '../src/utils/status-labels.js';
import {agentProvider, selectedNamespaces} from '../src/utils/agent-scope.js';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const locales = Object.fromEntries(['en', 'he'].map(language => [language,
    JSON.parse(fs.readFileSync(new URL(`../public/locales/${language}.json`, import.meta.url)))]));
let role = 'admin', language = 'en', calls = 0;
const error = {textContent: ''};
const t = key => key.split('.').reduce((value, part) => value?.[part], locales[language]);
const apiClient = {get: async () => ({status: 'healthy'}), download: async (path, name) => {
    calls++;
    assert.equal(path, '/api/v1/health/diagnostics');
    assert.equal(name, 'vnbui-diagnostics.json');
}};
const context = vm.createContext({console, t, window: {t}, document: {
    getElementById: id => {assert.equal(id, 'health-diagnostics-error'); return error;},
}});
const module = new vm.SourceTextModule(fs.readFileSync(
    new URL('../src/pages/health.js', import.meta.url), 'utf8'), {context});
await module.link(specifier => {
    const values = specifier.includes('status-labels') ? {enumLabel: (value, domain) => enumLabel(value, domain, context.window.t), storageCapacity}
            : specifier.includes('agent-scope') ? {agentProvider, selectedNamespaces}
            : specifier.includes('client') ? {apiClient}
        : specifier.includes('auth.service') ? {authService: {hasRole: wanted => role === wanted}}
        : specifier.includes('security') ? {escapeHtml: value => String(value).replaceAll('<', '&lt;')}
        : {getStatusColor: () => 'secondary'};
    return new vm.SyntheticModule(Object.keys(values), function () {
        for (const [key, value] of Object.entries(values)) this.setExport(key, value);
    }, {context});
});
await module.evaluate();
const page = new module.namespace.HealthPage();
for (language of ['en', 'he']) {
    for (role of ['admin', 'operator', 'viewer']) {
        const html = await page.render();
        assert.equal(html.includes('downloadDiagnostics(this)'), role === 'admin');
        if (role === 'admin') {
            assert.ok(html.includes(t('health.diagnostics_scope')));
            assert.equal(typeof t('health.download_diagnostics'), 'string');
        }
    }
    const button = {disabled: false};
    await page.downloadDiagnostics(button);
    assert.equal(button.disabled, false);
    apiClient.download = async () => {throw new Error('private-token-endpoint');};
    await page.downloadDiagnostics(button);
    assert.equal(button.disabled, false);
    assert.equal(error.textContent, t('health.diagnostics_failed'));
    assert.ok(!error.textContent.includes('private-token-endpoint'));
}
let release;
apiClient.download = () => new Promise(resolve => {calls++; release = resolve;});
const button = {disabled: false};
const pending = page.downloadDiagnostics(button);
const before = calls;
await page.downloadDiagnostics(button);
assert.equal(calls, before); // No duplicate in-flight download.
assert.equal(button.disabled, true);
release();
await pending;
assert.equal(button.disabled, false);
console.log('PASS: read-only health diagnostic download');
