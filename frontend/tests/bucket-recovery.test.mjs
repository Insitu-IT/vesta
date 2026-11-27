import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

import {escapeHtml} from '../src/utils/security.js';

const source = await readFile(new URL('../src/pages/bucket-recovery.js', import.meta.url), 'utf8');
const context = vm.createContext({});
const dependencies = {
    '/client.js': {apiClient: {}},
    '/auth.service.js': {authService: {}},
    '/security.js': {escapeHtml},
    '/format.js': {formatDate: String},
};
const module = new vm.SourceTextModule(source, {context});
await module.link(specifier => {
    const exports = Object.entries(dependencies).find(([suffix]) => specifier.endsWith(suffix))[1];
    return new vm.SyntheticModule(Object.keys(exports), function () {
        for (const [name, value] of Object.entries(exports)) this.setExport(name, value);
    }, {context});
});
await module.evaluate();
const {BucketRecovery} = module.namespace;

const destination = [{id: 'agent-fixture', name: 'Synthetic agent', namespaces: ['recovery']}];

test('verified native metadata prepopulates each captured MAC without requiring the source VM', () => {
    const page = new BucketRecovery();
    const html = page.renderTarget({
        point: {name: 'Captured VM', provider: 'libvirt'}, destination_agents: destination,
        requires_kek: true,
        source: {
            disks: ['vda'], exclusions: [],
            interfaces: [{source_mac: '52:54:00:00:00:0a', source_network: 'old-network'}],
        },
    });
    assert.match(html, /name="source_mac" value="52:54:00:00:00:0a"/);
    assert.match(html, /old-network/);
    assert.match(html, /name="network" required/);
    assert.doesNotMatch(html, /Add network|Remove/);
});

test('verified KubeVirt metadata presents every captured network and external dependency', () => {
    const page = new BucketRecovery();
    const html = page.renderTarget({
        point: {name: 'Captured VM', provider: 'kubevirt'}, destination_agents: destination,
        source: {
            volumes: [{name: 'vda', capacity_bytes: 1000}],
            networks: [{name: 'frontend', type: 'pod', source_mac: null}],
            dependencies: [{kind: 'secret', name: 'cloud-config'}, {kind: 'configMap', name: 'app-config'}],
        },
    });
    assert.match(html, /name="name" value="frontend"/);
    assert.match(html, /name="source_name" value="cloud-config"/);
    assert.match(html, /name="source_name" value="app-config"/);
    assert.equal((html.match(/name="destination_name" required/g) || []).length, 2);
});

test('unsigned restore command includes the inspected version as one quoted argument', async () => {
    const page = new BucketRecovery();
    page.target = {innerHTML: ''};
    await page.selectPoint({
        status: 'unsigned',
        backup_id: '22222222-2222-4222-8222-222222222222',
        generation_key: 'test/generation.json',
        version_id: "opaque'version",
    });
    assert.ok(page.target.innerHTML.includes(escapeHtml("--generation-key 'test/generation.json'")));
    assert.ok(page.target.innerHTML.includes(escapeHtml("--version-id 'opaque'\"'\"'version'")));
});
