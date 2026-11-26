import {enumLabel, storageCapacity} from '../src/utils/status-labels.js';
import {agentProvider, selectedNamespaces} from '../src/utils/agent-scope.js';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

// Exercise the real handlers without a browser, network or installed npm tree.
const nodes = new Map();
const element = id => {
    if (!nodes.has(id)) nodes.set(id, {value: '', checked: false, hidden: false,
        textContent: '', style: {}, addEventListener() {}});
    return nodes.get(id);
};
const sent = [], toasts = [];
let current;
let confirmation;
const apiClient = {
    get: async () => current,
    post: async (path, body) => sent.push({path, body: JSON.parse(JSON.stringify(body))}),
    put: async (path, body) => sent.push({path, body: JSON.parse(JSON.stringify(body))}),
};
const window = {t: key => key, addEventListener() {},
    confirm: text => {confirmation = text; return true;}};
const context = vm.createContext({window, console, URL, URLSearchParams,
    document: {getElementById: element, querySelectorAll: () => []},
    setTimeout() {}, crypto: {randomUUID: () => 'enrollment-request'},
    bootstrap: {Modal: class {
        show() {}
        static getInstance() {return {hide() {}};}
    }},
});
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
            : specifier.includes('security') ? {escapeHtml: value => String(value)}
            : specifier.includes('format') ? {formatDate() {}, formatRelativeTime() {}}
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
const {SchedulesPage} = await load('../src/pages/schedules.js');
const html = new SchedulesPage().renderScheduleModal();
for (const id of ['schedule-policy-options', 'schedule-full-every-days', 'schedule-max-incrementals']) {
    assert.equal((html.match(new RegExp(`id="${id}"`, 'g')) || []).length, 1);
}
assert.match(html, /value="automatic"/);
assert.match(html, /onchange="window.vnbui.updateSchedulePolicy\(\)"/);
const app = new App();
app.user = {role: 'operator'};
app.setupEventListeners();
window.vnbui.showToast = message => toasts.push(message);
window.vnbui.refreshPage = () => {};
window.vnbui.createSchedule();
assert.equal(element('schedule-policy-options').hidden, true);
assert.equal(element('schedule-full-every-days').value, '7');
assert.equal(element('schedule-max-incrementals').value, '6');
element('schedule-backup-type').value = 'automatic';
window.vnbui.updateSchedulePolicy();
assert.equal(element('schedule-policy-options').hidden, false);
element('schedule-name').value = 'daily';
element('schedule-vm-id').value = 'vm-one';
element('schedule-enabled').checked = true;
await window.vnbui.submitSchedule();
assert.deepEqual(sent.at(-1).body.backup_policy, {schema: 1, full_every_days: 7, max_incrementals: 6});
assert.equal(sent.at(-1).body.enabled, false); // creation cannot enroll or activate
assert.equal(sent.at(-1).path, '/api/v1/schedules');

for (const [days, count] of [['', '6'], ['1.5', '6'], ['1e1', '6'], ['0', '6'],
    ['36501', '6'], ['7', ''], ['7', '0'], ['7', '256'], ['7', '-1'], ['7', 'true']]) {
    element('schedule-full-every-days').value = days;
    element('schedule-max-incrementals').value = count;
    const before = sent.length;
    await window.vnbui.submitSchedule();
    assert.equal(sent.length, before, `${days}/${count} must not send`);
    assert.match(toasts.at(-1), /schedules.invalid_policy/);
}
current = {id: 'schedule-one', name: 'saved automatic', vm_id: 'vm-one',
    backup_type: 'automatic', backup_policy: {schema: 1, full_every_days: 12, max_incrementals: 4},
    cron_expression: '0 2 * * *', enabled: false};
await window.vnbui.editSchedule('schedule-one');
assert.equal(element('schedule-policy-options').hidden, false);
assert.equal(element('schedule-full-every-days').value, 12);
assert.equal(element('schedule-max-incrementals').value, 4);
// Real DOM number inputs stringify assigned values.
element('schedule-full-every-days').value = '12';
element('schedule-max-incrementals').value = '4';
await window.vnbui.submitSchedule();
assert.deepEqual(sent.at(-1).body.backup_policy, current.backup_policy);
assert.equal(sent.at(-1).path, '/api/v1/schedules/schedule-one');
assert(!sent.at(-1).body.vm_id); // edits cannot replace the source
for (const kind of ['full', 'incremental']) {
    element('schedule-backup-type').value = kind;
    window.vnbui.updateSchedulePolicy();
    assert.equal(element('schedule-policy-options').hidden, true);
    await window.vnbui.submitSchedule();
    assert.equal(sent.at(-1).body.backup_type, kind);
    assert.equal(sent.at(-1).body.backup_policy, null); // explicit clear, not omission
}
const before = sent.length;
await window.vnbui.enrollScheduleGrant('schedule-one');
assert.equal(sent.length, before); // operator cannot issue a grant
assert.equal(toasts.at(-1), 'schedules.admin_grant_required');
app.user.role = 'admin';
current = {scope: {options: {backup_type: 'automatic', backup_policy: current.backup_policy}},
    revision: 3, scope_sha256: 'sealed-policy-digest', current_grant_id: null};
await window.vnbui.enrollScheduleGrant('schedule-one');
assert.match(confirmation, /full_every_days/); // policy is visible in exact-scope confirmation
assert.match(confirmation, /max_incrementals/);
assert.equal(sent.at(-1).body.scope_sha256, 'sealed-policy-digest');
assert.equal(sent.at(-1).body.expected_revision, 3);
window.vnbui.createSchedule();
assert.equal(element('schedule-id').value, '');
assert.equal(element('schedule-full-every-days').value, '7');
assert.equal(element('schedule-policy-options').hidden, true);
console.log('PASS: automatic schedule form, strict inputs, explicit policy clearing and admin enrollment');
