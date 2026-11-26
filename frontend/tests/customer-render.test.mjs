import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';

test('rendered dashboard distinguishes empty setup, populated aggregates and failed API in both languages', async () => {
    const server = await createServer({configFile: false, root: new URL('..', import.meta.url).pathname, server: {middlewareMode: true, hmr: false}, appType: 'custom'});
    try {
        globalThis.window = {t: key => key, vnbui: {currentUserRole: 'admin'}};
        const {DashboardPage} = await server.ssrLoadModule('/src/pages/dashboard.js');
        const {AgentsPage} = await server.ssrLoadModule('/src/pages/agents.js');
        const {SettingsPage} = await server.ssrLoadModule('/src/pages/settings.js');
        const {VerificationPage} = await server.ssrLoadModule('/src/pages/verification.js');
        const {HealthPage} = await server.ssrLoadModule('/src/pages/health.js');
        const {authService} = await server.ssrLoadModule('/src/services/auth.service.js');
        authService.getUser = () => ({role: 'admin'});
        const {apiClient} = await server.ssrLoadModule('/src/api/client.js');
        const {assetResolver} = await server.ssrLoadModule('/src/assets/resolver.js');
        assetResolver.manifest = JSON.parse(await readFile(new URL('../public/assets/manifest.json', import.meta.url)));
        for (const lang of ['en', 'he']) {
            const locale = JSON.parse(await readFile(new URL(`../public/locales/${lang}.json`, import.meta.url)));
            window.t = (key, vars = {}) => {
                const value = key.split('.').reduce((o, k) => o?.[k], locale) || key;
                return value.replace(/{{(\w+)}}/g, (_, key) => vars[key] ?? '');
            };
            const empty = {vms: {total: 0, by_status: {}, by_agent: []}, agents: {total: 0, online: 0}, backups: {total: 0, last_24h: 0, by_status: {}}, schedules: {upcoming: 0}, attention: {offline_agents: 0}, recent_backups: [], running_backups: []};
            apiClient.get = async () => empty;
            const page = new DashboardPage(); page.subscribeToUpdates = () => {};
            const setup = await page.render();
            assert.ok(setup.includes(locale.dashboard.setup_title));
            assert.ok(!setup.includes('<canvas'));
            apiClient.get = async () => ({...empty, vms: {total: 110, by_status: {running: 100, paused: 10}, by_agent: [{name: 'first', count: 100}, {name: 'second', count: 10}]}, agents: {total: 2, online: 1}, backups: {total: 5, last_24h: 5, by_status: {completed: 3, held: 2}}, attention: {held_jobs: 2}});
            const populated = await page.render();
            assert.equal((populated.match(/<canvas /g) || []).length, 3);
            assert.ok(populated.includes('100 (91%)'));
            assert.ok(populated.includes(locale.enums.status.held));
            assert.ok(populated.includes(locale.dashboard.needs_attention));
            assert.equal(new Set(['Stopped', 'Shutoff', 'Paused', 'Unavailable', 'Unknown'].map(state => page.chartColor(state))).size, 5);
            assert.equal(page.chartColor('Stopped'), page.chartColor('stopped'));
            assert.equal(page.chartColor('Running'), page.chartColor('running'));
            const groups = Array.from({length: 16}, (_, i) => ({agent_id: `agent-${i}`, name: `Agent ${i}`, count: 1}));
            const categories = page.agentEntries(groups);
            assert.equal(new Set(categories.map(entry => `${entry.color}/${entry.pattern}`)).size, groups.length);
            const reordered = page.agentEntries([...groups].reverse());
            for (const entry of categories) assert.equal(reordered.find(other => other.label === entry.label).color, entry.color);
            assert.ok(categories.some(entry => entry.pattern > 0), 'overflow agent categories get hatch patterns');

            apiClient.get = async () => {throw new Error('unavailable');};
            const expectedError = console.error;
            console.error = () => {};
            let failed;
            try {failed = await page.render();} finally {console.error = expectedError;}
            assert.ok(failed.includes(locale.dashboard.load_failed));
            assert.ok(!failed.includes(locale.dashboard.setup_title));
            assert.ok(!failed.includes('<canvas'));
            const verification = new VerificationPage();
            assert.equal(verification.getSuccessRate(), null);
            verification.loadData = async () => {};
            const rendered = await verification.render();
            assert.ok(rendered.includes('verification-actions'));
            assert.ok(!rendered.includes('>0%</span>'));
            assert.notEqual(locale.enums.status.stopped, locale.enums.status.shutoff, 'VM state legend labels remain distinct');
            globalThis.t = window.t;
            const health = new HealthPage();
            health.loadData = async () => {};
            health.health = {status: 'degraded', timestamp: '2026-10-31T01:00:00Z', metrics: {total_vms: 3}};
            const healthHtml = await health.render();
            assert.ok(healthHtml.includes('row-cols-1 row-cols-md-2 row-cols-xl-5'));
            assert.ok(healthHtml.includes('class="col-12 col-sm-auto" id="health-last-check"'));
            assert.ok(healthHtml.includes(locale.enums.status.degraded));
            const agentModal = new AgentsPage().renderAgentDetailsModal();
            assert.ok(!agentModal.includes('agent-setting-backup_timeout'));
            assert.ok(!agentModal.includes('agent-setting-max_concurrent_backups'));
            assert.ok(agentModal.includes('<option value="WARNING">WARNING</option>'));
            const settings = new SettingsPage();
            settings.v3Settings = {'storage.type': 'local'};
            const storage = settings.renderStorageSettings();
            assert.ok(storage.includes(locale.experience.legacy_destination));
            assert.ok(!storage.includes('value="local"'));
            assert.ok(!storage.includes('setting-v3-s3-delete-local-mode'));
            assert.ok(!storage.includes('setting-default-retention-storage'));
            assert.ok(storage.includes(locale.experience.remote_retention_hint));
        }
    } finally {await server.close(); delete globalThis.window; delete globalThis.t;}
});
