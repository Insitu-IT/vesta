import {enumLabel, storageCapacity} from '../src/utils/status-labels.js';
import {agentProvider, selectedNamespaces} from '../src/utils/agent-scope.js';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const locales = Object.fromEntries(['en', 'he'].map(lang => [lang,
    JSON.parse(fs.readFileSync(new URL(`../public/locales/${lang}.json`, import.meta.url), 'utf8'))]));
let language = 'en';
const t = (key, values = {}) => {
    let text = key.split('.').reduce((value, part) => value?.[part], locales[language]);
    assert.equal(typeof text, 'string', `Missing ${language} translation ${key}`);
    for (const [name, value] of Object.entries(values)) text = text.replaceAll(`{{${name}}}`, String(value));
    return text;
};
const calls = [];
let answer;
const apiClient = {get: async path => {
    calls.push(path);
    if (answer instanceof Error) throw answer;
    return answer;
}};
let tableListener;
const table = {addEventListener(type, listener) {assert.equal(type, 'click'); tableListener = listener;}};
const context = vm.createContext({window: {t}, console,
    document: {getElementById: id => id === 'backups-table-body' ? table : null},
    setTimeout() {}, clearTimeout() {}, encodeURIComponent});
const security = new vm.SourceTextModule(fs.readFileSync(
    new URL('../src/utils/security.js', import.meta.url), 'utf8'), {context});
await security.link(() => {throw new Error('Unexpected security import');});
await security.evaluate();
const dispatchModule = new vm.SourceTextModule(fs.readFileSync(new URL('../src/utils/operator-dispatch.js', import.meta.url), 'utf8'), {context});
await dispatchModule.link(() => security);
await dispatchModule.evaluate();
const safetyModule = new vm.SourceTextModule(fs.readFileSync(new URL('../src/utils/backup-safety.js', import.meta.url), 'utf8'), {context});
await safetyModule.link(() => security);
await safetyModule.evaluate();
const snapshotModule = new vm.SourceTextModule(fs.readFileSync(new URL('../src/services/snapshot.service.js', import.meta.url), 'utf8'), {context});
await snapshotModule.link(() => new vm.SyntheticModule(['apiClient'], function() {this.setExport('apiClient', apiClient);}, {context}));
await snapshotModule.evaluate();
const module = new vm.SourceTextModule(fs.readFileSync(
    new URL('../src/pages/backups.js', import.meta.url), 'utf8'), {context});
await module.link(specifier => {
    if (specifier.includes('security')) return security;
    if (specifier.includes('operator-dispatch')) return dispatchModule;
    if (specifier.includes('backup-safety')) return safetyModule;
    if (specifier.includes('snapshot.service')) return snapshotModule;
    const values = specifier.includes('/components/file-backups') ? {FileBackupsPanel: class {mount() {} destroy() {}}}
            : specifier.includes('authenticated-startup') ? {startAuthenticatedServices: async () => {}}
        : specifier.includes('installation.service') ? {installationService: {}}
            : specifier.includes('theme.service') ? {themeService: {button: () => ''}}
            : specifier.includes('vm-inventory') ? {renderDiskSummary: () => '', renderCbtObservation: () => ''}
            : specifier.includes('components/licensing') ? {refreshLicenseBanner: () => {}, LicensingPanel: class {async load() {} render() {return '';} mount() {}}}
            : specifier.includes('context-help') ? {contextHelp: () => ''}
            : specifier.includes('status-labels') ? {enumLabel: (value, domain) => enumLabel(value, domain, context.window.t), storageCapacity}
            : specifier.includes('agent-scope') ? {agentProvider, selectedNamespaces}
            : specifier.includes('client') ? {apiClient}
        : specifier.includes('updates') ? {updateService: {}}
        : specifier.includes('status-colors') ? {getStatusColor: () => 'success'}
        : specifier.includes('format') ? {formatRelativeTime: () => '', formatDate: () => '',
            formatSize: () => '1 B', stripAnsi: value => value}
        : {assetResolver: {}};
    return new vm.SyntheticModule(Object.keys(values), function () {
        for (const [key, value] of Object.entries(values)) this.setExport(key, value);
    }, {context});
});
await module.evaluate();
const {BackupsPage} = module.namespace;
const decision = {schema: 1, backup_type: 'full', reason: 'max_incrementals',
    policy: {full_every_days: 7, max_incrementals: 6}, observed_date: '2026-10-18',
    root_date: '2026-10-11', incremental_count: 6};
const page = new BackupsPage();
for (language of ['en', 'he']) {
    for (const reason of ['parent_unavailable', 'new_grant', 'source_changed',
        'root_time_unavailable', 'previous_failure', 'max_incrementals', 'full_interval', 'within_policy']) {
        const html = page.renderSchedulerDecision({...decision, reason,
            backup_type: reason === 'within_policy' ? 'incremental' : 'full',
            ...(['max_incrementals', 'full_interval', 'within_policy'].includes(reason)
                ? {} : {root_date: null, incremental_count: null})});
        assert.ok(html.includes(t(`backups.scheduler_reason_${reason}`)));
        assert.ok(html.includes(t(`backups.scheduler_type_${reason === 'within_policy' ? 'incremental' : 'full'}`)));
        assert.ok(html.includes('2026-10-18'));
        assert.ok(!html.includes('backups.scheduler_'));
    }
}
language = 'en';
assert.match(page.renderSchedulerDecision({...decision, incremental_count: 0}), /incrementals: 0/);
assert.match(page.renderSchedulerDecision({...decision, root_date: null, incremental_count: null}),
    /No usable accepted parent/);
const hostile = page.renderSchedulerDecision({...decision, reason: '<img src=x onerror=bad()>',
    observed_date: '<script>bad()</script>', root_date: '<svg onload=bad()>'});
assert.ok(!hostile.includes('<img') && !hostile.includes('<script') && !hostile.includes('<svg'));
assert.match(hostile, /unrecognized saved reason/);
assert.match(hostile, /&lt;img/);
for (const invalid of [null, {}, {...decision, schema: 2}, {...decision, backup_type: 'automatic'},
    {...decision, reason: null}, {...decision, policy: null}]) {
    assert.throws(() => page.renderSchedulerDecision(invalid), /Unsupported/);
}

function details() {
    let html = '', text = '';
    const target = {hidden: true, get innerHTML() {return html;},
        set innerHTML(value) {html = value; text = '';}, get textContent() {return text;},
        set textContent(value) {text = value; html = '';}};
    return {target, classList: {contains: () => false},
        querySelector: selector => {
            assert.ok(['[data-scheduler-decision]', '[data-recovery-publication]'].includes(selector));
            return selector === '[data-scheduler-decision]' ? target : null;
        }};
}
answer = {id: 'scheduled', scheduler_decision: decision};
const box = details();
await page.loadSchedulerDecision('scheduled', box);
await page.loadSchedulerDecision('scheduled', box);
assert.equal(calls.filter(path => path.endsWith('/scheduled')).length, 1);
assert.match(box.target.innerHTML, /accepted incremental limit/);
assert.equal(box.target.hidden, false);
answer = {id: 'manual', scheduler_decision: null};
const manual = details();
await page.loadSchedulerDecision('manual', manual);
assert.equal(manual.target.hidden, true);

let resolve;
answer = new Promise(done => {resolve = done;});
const first = page.loadSchedulerDecision('in-flight', details());
const second = page.loadSchedulerDecision('in-flight', details());
assert.equal(calls.filter(path => path.endsWith('/in-flight')).length, 1);
resolve({id: 'in-flight', scheduler_decision: decision});
await Promise.all([first, second]);

answer = new Error('read failed');
const retry = details();
await page.loadSchedulerDecision('retry', retry);
assert.match(retry.target.textContent, /Close and reopen/);
assert.equal(page.schedulerDecisionRequests.has('retry'), false);
answer = {id: 'retry', scheduler_decision: decision};
await page.loadSchedulerDecision('retry', retry);
assert.match(retry.target.innerHTML, /Saved automatic backup decision/);
assert.equal(calls.filter(path => path.endsWith('/retry')).length, 2);
for (const bad of [{id: 'wrong', scheduler_decision: decision}, {id: 'invalid'},
    {id: 'invalid', scheduler_decision: {schema: 2}}]) {
    answer = bad;
    await page.loadSchedulerDecision('invalid', retry);
    assert.match(retry.target.textContent, /unavailable/);
    assert.equal(page.schedulerDecisionRequests.has('invalid'), false);
}

page.setupEventListeners();
const before = calls.length;
tableListener({target: {closest: () => ({})}}); // An action button must not fetch.
assert.equal(calls.length, before);
answer = {id: 'from-row', scheduler_decision: decision};
const expanded = details();
const row = {dataset: {backupId: 'from-row'}, nextElementSibling: expanded};
await tableListener({target: {closest: selector => selector === 'tr[data-backup-id]' ? row : null}});
assert.equal(calls.at(-1), '/api/v1/backups/from-row');
assert.match(expanded.target.innerHTML, /Saved automatic backup decision/);
const closed = {dataset: {backupId: 'closed'}, nextElementSibling: {
    classList: {contains: () => true}}};
tableListener({target: {closest: selector => selector === 'tr[data-backup-id]' ? closed : null}});
assert.ok(!calls.some(path => path.endsWith('/closed')));
page.backups = [{id: 'rendered', vm_name: 'VM', status: 'completed', size_bytes: 1,
    backup_type: 'full', capacity_state: 'released', created_at: '2026-10-18T00:00:00Z', tags: {}}];
assert.match(page.renderBackupRows(), /data-scheduler-decision hidden aria-live="polite"/);
console.log('PASS: saved automatic backup decision rendering and read-only expansion');
