import editionExtension from '../src/editions/community.js';
import {enumLabel} from '../src/utils/status-labels.js';
import {agentProvider, selectedNamespaces} from '../src/utils/agent-scope.js';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const pageContent = {innerHTML: ''};
let requests = 0;
let available = true;
const context = vm.createContext({console, window: {t: key => key},
    document: {getElementById: () => pageContent}});
const module = new vm.SourceTextModule(fs.readFileSync(
    new URL('../src/app.js', import.meta.url), 'utf8'), {context});
await module.link(specifier => {
    const values = specifier.includes('authenticated-startup') ? {startAuthenticatedServices: async () => {}}
        : specifier.includes('installation.service') ? {installationService: {}}
            : specifier.includes('theme.service') ? {themeService: {button: () => ''}}
            : specifier.includes('vm-inventory') ? {renderDiskSummary: () => '', renderCbtObservation: () => ''}
            : specifier.includes('backup-guidance') ? {bindBackupGuidance() {}, loadBackupGuidance() {}, renderBackupGuidance() {}}
            : specifier.includes('licensing.service') ? {licensingService: {}}
            : specifier.includes('components/licensing') ? {refreshLicenseBanner() {}, renderLicenseSummary() {}, LicensingPanel: class {async load() {} render() {return '';} mount() {}}}
            : specifier.includes('context-help') ? {contextHelp: () => ''}
            : specifier.includes('agent-scope') ? {agentProvider, selectedNamespaces}
        : specifier.includes('status-labels') ? {enumLabel: (value, domain) => enumLabel(value, domain, context.window.t)}
        : specifier.includes('auth.service') ? {authService: {canManageInstallation: () => false}}
        : specifier.includes('client') ? {apiClient: {get: async () => {
            requests++;
            if (!available) throw new Error('offline');
            return {flags: {multi_tenancy: true, billing_api: true, white_labeling: true, client_encryption: false}};
        }}}
        : specifier.includes('security') ? {escapeHtml: value => String(value)}
        : {assetResolver: {inlineSvg: () => '', icon: () => ''}};
    return new vm.SyntheticModule(Object.keys(values), function () {
        for (const [name, value] of Object.entries(values)) this.setExport(name, value);
    }, {context});
});
await module.evaluate();
const app = new module.namespace.App(editionExtension);
app.user = {role: 'admin'};
await app.loadFeatures();
assert.equal(requests, 1);
assert.equal(app.features.client_encryption, true);
for (const name of ['multi_tenancy', 'billing_api', 'white_labeling']) assert.equal(app.features[name], false);
available = false;
await app.loadFeatures();
assert.equal(requests, 2);
assert.equal(app.features.client_encryption, true);
// Even injected flags cannot add unavailable pages to a community artifact.
app.features = {multi_tenancy: true, billing_api: true, white_labeling: true};
const navigation = app.renderNavigation();
for (const page of ['organizations', 'billing', 'branding']) {
    assert.ok(!navigation.includes(`href="#${page}"`));
    await app.loadPage(page); // No dynamic-import hook exists: importing would fail.
    assert.ok(pageContent.innerHTML.includes('common.page_not_found'));
}
console.log('PASS: community artifact excludes commercial pages');
