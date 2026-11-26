import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';

test('KubeVirt detail renders the heartbeat namespace-to-PVC map safely in both languages', async () => {
    const server = await createServer({configFile: false, root: new URL('..', import.meta.url).pathname, server: {middlewareMode: true, hmr: false}, appType: 'custom'});
    const originals = Object.fromEntries(['window', 'document', 'bootstrap'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
    const nodes = new Map();
    const node = id => {
        if (!nodes.has(id)) nodes.set(id, {value: '', textContent: '', innerHTML: '', disabled: false,
            classList: {add() {}, remove() {}}, addEventListener() {}, querySelectorAll: () => [], insertAdjacentHTML() {}});
        return nodes.get(id);
    };
    globalThis.window = {t: key => key, addEventListener() {}, vnbui: {}};
    globalThis.document = {getElementById: node, querySelectorAll: () => []};
    globalThis.bootstrap = {Tab: class {show() {}}, Modal: class {show() {}}};
    try {
        const {App} = await server.ssrLoadModule('/src/app.js');
        const {apiClient} = await server.ssrLoadModule('/src/api/client.js');
        // The object shape is ScopeReport(): ScratchPVCs is map[string]string.
        const heartbeatScope = {source_namespaces: ['one', 'two'], selected_source_namespaces: ['one'], restore_namespaces: ['recovery'], scratch_pvcs: {one: 'scratch-one', two: 'scratch-two'}, applied_revision: 'revision-one'};
        let scope = structuredClone(heartbeatScope);
        apiClient.get = async () => ({id: 'agent-one', hostname: 'technical-agent', status: 'online', capabilities: {provider: 'kubevirt'}, config: {}, metrics: {scope}});
        const app = new App();
        app.user = {role: 'admin'};
        app.setupEventListeners();
        window.vnbui.showToast = () => {throw new Error('Unexpected agent detail failure');};
        for (const language of ['en', 'he']) {
            const locale = JSON.parse(await readFile(new URL(`../public/locales/${language}.json`, import.meta.url)));
            window.t = key => key.split('.').reduce((value, part) => value?.[part], locale) || key;
            scope = structuredClone(heartbeatScope);
            await window.vnbui.viewAgentDetails('agent-one');
            assert.ok(node('agent-provider-settings').innerHTML.includes('one: scratch-one, two: scratch-two'));
            assert.ok(node('agent-provider-settings').innerHTML.includes(locale.agents.scope_scratch));
            scope.scratch_pvcs = {};
            await window.vnbui.viewAgentDetails('agent-one');
            assert.ok(node('agent-provider-settings').innerHTML.includes(locale.agents.scope_none));
            for (const malformed of [null, ['scratch-one'], {one: ['scratch-one']}, {one: 12}, {'': 'scratch-one'}]) {
                scope.scratch_pvcs = malformed;
                await window.vnbui.viewAgentDetails('agent-one');
                assert.ok(node('agent-provider-settings').innerHTML.includes(locale.enums.status.unknown));
            }
            scope.scratch_pvcs = {'<namespace>': 'scratch-<img src=x onerror=alert(1)>'};
            await window.vnbui.viewAgentDetails('agent-one');
            const html = node('agent-provider-settings').innerHTML;
            assert.ok(html.includes('&lt;namespace&gt;: scratch-&lt;img'));
            assert.ok(!html.includes('<img src=x'));
        }
    } finally {
        await server.close();
        for (const [key, descriptor] of Object.entries(originals)) {
            if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
        }
    }
});
