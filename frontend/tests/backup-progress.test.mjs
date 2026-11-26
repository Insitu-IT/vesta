import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';

async function harness() {
    const calls = [], timers = [], nodes = new Map();
    for (const name of ['.progress-bar', '.backup-progress-text', '.backup-status', '.backup-transfer-text', '.backup-dispatch']) {
        nodes.set(name, {style: {}, textContent: '', setAttribute(name, value) {this[name] = value;}});
    }
    const context = vm.createContext({console, window: {t: key => key, vnbui: {currentUserRole: 'viewer', refreshPage() {}}},
        document: {querySelector: selector => selector.startsWith('tr[') ? {querySelector: name => nodes.get(name)} : null},
        setInterval: callback => {timers.push(callback); return timers.length;}, clearInterval() {},
    });
    const source = await readFile(new URL('../src/pages/backups.js', import.meta.url), 'utf8');
    const module = new vm.SourceTextModule(source, {context});
    const apiClient = {get: async path => {
        calls.push(path);
        return {items: path.includes('status=uploading') ? [{id: 'upload',
            status: 'uploading', progress: 12,
            storage_progress: {bytes_transferred: 8, total_bytes: 64, phase: 'uploading'}}] : []};
    }};
    const snapshotSource = await readFile(new URL('../src/services/snapshot.service.js', import.meta.url), 'utf8');
    const snapshotModule = new vm.SourceTextModule(snapshotSource, {context});
    await snapshotModule.link(() => new vm.SyntheticModule(['apiClient'], function() {this.setExport('apiClient', apiClient);}, {context}));
    await snapshotModule.evaluate();
    const dispatchModule = new vm.SourceTextModule(await readFile(new URL('../src/utils/operator-dispatch.js', import.meta.url), 'utf8'), {context});
    await dispatchModule.link(() => new vm.SyntheticModule(['escapeHtml'], function() {this.setExport('escapeHtml', value => String(value ?? ''));}, {context}));
    await dispatchModule.evaluate();
    const safetyModule = new vm.SourceTextModule(await readFile(new URL('../src/utils/backup-safety.js', import.meta.url), 'utf8'), {context});
    await safetyModule.link(() => new vm.SyntheticModule(['escapeHtml'], function() {this.setExport('escapeHtml', value => String(value ?? ''));}, {context}));
    await safetyModule.evaluate();
    const subscriptions = new Map();
    await module.link(specifier => {
        const imports = [...source.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]/g)].find(m => m[2] === specifier);
        const values = {apiClient, renderBackupSafety: safetyModule.namespace.renderBackupSafety, renderOperatorDispatch: dispatchModule.namespace.renderOperatorDispatch, loadSnapshot: snapshotModule.namespace.loadSnapshot, updateService: {connectionMode: 'websocket', subscribeResync: callback => {subscriptions.set('resync', callback); return () => {};}, subscribe: (type, callback) => {subscriptions.set(type, callback); return () => {};}},
            enumLabel: value => value, escapeHtml: value => String(value ?? ''), formatSize: value => `${value} B`,
            formatDate: () => '', formatRelativeTime: () => '', stripAnsi: value => value,
            getStatusColor: () => 'info', contextHelp: () => '', assetResolver: {}};
        const names = imports[1].split(',').map(x => x.trim());
        return new vm.SyntheticModule(names, function() {for (const name of names) this.setExport(name, values[name]);}, {context});
    });
    await module.evaluate();
    return {page: new module.namespace.BackupsPage(), calls, timers, nodes, apiClient, subscriptions};
}

test('pending and uploading rows display progress and acknowledged payload bytes', async () => {
    const {page} = await harness();
    for (const status of ['pending', 'running', 'uploading']) {
        page.backups = [{id: 'upload', status, progress: 12, storage_progress: {bytes_transferred: 8, total_bytes: 64}}];
        const html = page.renderBackupRows();
        assert.match(html, /backup-progress-text/);
        assert.match(html, /8 B \/ 64 B/);
        page.filter = 'running';
        assert.equal(page.getFilteredCount('running'), 1);
        assert.equal(page.getFilteredBackups().length, 1);
    }
    assert.equal(page.transferText({bytes_transferred: -1, total_bytes: 64}), '');
});

test('cleanup required rows retain the specific safety predicate and explicit zero observations', async () => {
    const {page} = await harness();
    page.backups = [{id: 'held', status: 'cleanup_required', capacity_state: 'reserved',
        safety_diagnostic: {stage: 'export_admission', reason: 'native_volume_count_mismatch',
            disposition: 'refused', expected_native_volumes: 2, observed_native_volumes: 0}}];
    const html = page.renderBackupRows();
    assert.match(html, /native_volume_count_mismatch/);
    assert.match(html, /backups.safety_guidance/);
    assert.match(html, /<code>0<\/code>/);
});

test('connected sockets still reconcile all active states and update the visible status', async () => {
    const {page, calls, timers, nodes} = await harness();
    page.backups = [{id: 'upload', status: 'pending', progress: 0}];
    page.subscribeToUpdates();
    await timers[0]();
    assert.equal(calls.length, 3);
    for (const status of ['pending', 'running', 'uploading']) assert.ok(calls.includes(`/api/v1/backups?status=${status}&limit=100&skip=0`));
    assert.equal(nodes.get('.backup-status').textContent, 'uploading');
    assert.equal(nodes.get('.progress-bar').style.width, '12%');
    assert.equal(nodes.get('.progress-bar')['aria-valuenow'], '12');
    assert.equal(nodes.get('.backup-transfer-text').textContent, '8 B / 64 B');
    assert.equal(page.backups[0].status, 'uploading');
    assert.equal(page.backups[0].storage_progress.bytes_transferred, 8);
    assert.equal(page.backups[0].storage_progress.phase, 'uploading');
    page.handleBackupProgress({backup_id: 'upload', progress: '<invalid>'});
    assert.equal(nodes.get('.progress-bar').style.width, '12%');
    page.backups[0].status = 'completed';
    page.handleBackupProgress({backup_id: 'upload', status: 'uploading', progress: 11});
    assert.equal(page.backups[0].status, 'completed', 'delayed progress cannot revive a completed row');
    assert.equal(nodes.get('.progress-bar').style.width, '12%');
});

test('completion before the first poll reloads a stale active row when its socket event is lost', async () => {
    const {page, apiClient} = await harness();
    page.backups = [{id: 'finished', status: 'running', progress: 0}];
    apiClient.get = async () => ({items: []});
    let reloads = 0;
    page.loadData = async () => {reloads++;};
    await page.refreshProgress();
    assert.equal(reloads, 1);
});

test('a missed start event discovers an active backup through polling', async () => {
    const {page, apiClient} = await harness();
    page.backups = [];
    apiClient.get = async path => ({items: path.includes('status=running') ? [{id: 'new', status: 'running', progress: 12}] : []});
    let reloads = 0;
    page.loadData = async () => {reloads++;};
    await page.refreshProgress();
    assert.equal(reloads, 1);
    await page.refreshProgress();
    assert.equal(reloads, 1, 'unchanged active IDs do not repeatedly reload the list');
});

test('a failed list reload leaves a missed start eligible for the next reconciliation', async () => {
    const {page, apiClient} = await harness();
    page.backups = [];
    const backup = {id: 'new', status: 'running', progress: 12};
    let reloads = 0;
    apiClient.get = async path => {
        if (path.startsWith('/api/v1/backups?limit=')) {
            reloads++;
            if (reloads === 1) throw new Error('temporary list read failure');
            return {items: [backup]};
        }
        return {items: path.includes('status=running') ? [backup] : []};
    };
    await page.refreshProgress();
    await page.refreshProgress();
    assert.equal(reloads, 2);
    assert.equal(page.backups[0].id, backup.id);
});

test('backup wildcard receives actual event envelopes and reset callbacks await list reads', async () => {
    const {page, subscriptions} = await harness();
    page.subscribeToUpdates();
    let updates = 0, resynced = 0;
    page.handleBackupProgress = data => {assert.equal(data.backup_id, 'one'); updates++;};
    subscriptions.get('*')({type: 'backup_progress', payload: {backup_id: 'one'}});
    page.loadData = async () => {resynced++; return true;};
    await subscriptions.get('resync')('history_lost');
    assert.equal(updates, 1); assert.equal(resynced, 1);
});

test('backup progress snapshot reads all active pages beyond the first hundred', async () => {
    const {page, apiClient} = await harness();
    const seen = [];
    apiClient.get = async url => {
        if (!url.includes('status=running')) return {items: [], has_more: false};
        const skip = Number(new URL(url, 'https://fixture').searchParams.get('skip'));
        seen.push(skip);
        return {items: Array.from({length: skip ? 1 : 100}, (_, n) => ({id: `row-${skip+n}`, status: 'running'})), has_more: skip === 0};
    };
    page.loadData = async () => true;
    await page.refreshProgress();
    assert.deepEqual(seen, [0, 100]); assert.equal(page._knownRunningIds.size, 101);
});

test('dispatch holds appear after initial admission acknowledgment and survive progress-only messages', async () => {
    const {page,nodes,apiClient}=await harness();
    page.backups=[{id:'one',status:'pending',progress:0}];
    const held={state:'held',reason:'original_handoff_unknown',request_id:'original-request'};
    apiClient.get=async path=>({items:path.includes('status=pending')?[{id:'one',status:'pending',operator_dispatch:held}]:[],has_more:false});
    await page.refreshProgress();
    assert.equal(page.backups[0].operator_dispatch.state,'held');
    assert(nodes.get('.backup-dispatch').innerHTML.includes('Reconcile the original attempt'));
    assert(nodes.get('.backup-dispatch').innerHTML.includes('original_handoff_unknown'));
    page.handleBackupProgress({backup_id:'one',progress:1});
    assert.equal(page.backups[0].operator_dispatch.state,'held');
    assert(page.renderBackupRows().includes('original-request'));
    page.handleBackupProgress({backup_id:'one',operator_dispatch:{state:'delivered',request_id:'original-request'}});
    assert.equal(page.backups[0].status,'pending','delivery is never job completion');
});
