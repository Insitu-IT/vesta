import {SvgFixtureParser, svgFixtures} from './helpers/svg-dom-fixtures.mjs';
globalThis.DOMParser = SvgFixtureParser;
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { enumLabel, storageCapacity } from '../src/utils/status-labels.js';
import { agentProvider, selectedNamespaces } from '../src/utils/agent-scope.js';
import { validateManifest, safeAssetPath, packPath, safeSvg } from '../src/assets/appearance.js';
import { AssetResolver } from '../src/assets/resolver.js';
const manifest = {schema_version: 1, id: 'site-pack', version: '1.0.0', name: 'Site', type: 'theme', assets: { 'brand-logo': {file: 'logo.svg', content_type: 'image/svg+xml'}}, meta: {vnbui: {schema_version: 1, product_name: 'Site backup', colors: {primary: '#123456'}, density: 'compact'}}};
const bundled = {schema_version: 1, id: 'vnbui-assets', version: '1.0.0', name: 'Default', type: 'icon-set', assets: {'brand-logo': {file: 'brand-logo.svg', content_type: 'image/svg+xml'}, 'nav-vms': {file: 'tabler://server', content_type: 'text/x-tabler-icon'}}};
test('English and Hebrew enums are localized and unknown values do not leak API enums', async () => {
    for (const lang of ['en', 'he']) {
        const data = JSON.parse(await readFile(new URL(`../public/locales/${lang}.json`, import.meta.url)));
        const t = key => key.split('.').reduce((o, k) => o?.[k], data) || key;
        for (const status of ['online', 'degraded', 'completed', 'held']) assert.equal(enumLabel(status, 'status', t), data.enums.status[status]);
        assert.equal(enumLabel('admin', 'role', t), data.enums.role.admin);
        assert.equal(enumLabel('future_unrecognized_value', 'status', t), data.enums.status.unknown);
    }
});
test('unknown and inconsistent storage measurements remain unknown', () => {
    for (const [free, total] of [[0, 0], [null, 10], [10, null], [-1, 10], [20, 10], [NaN, 20]]) assert.equal(storageCapacity(free, total), null);
    assert.equal(storageCapacity(0, 100), 0);
    assert.equal(storageCapacity(30, 100), 30);
});
test('provider uses capability, never hostname; selected scope stays within ceiling', () => {
    assert.equal(agentProvider({hostname: 'kubevirt-agent', capabilities: {}}), 'unknown');
    assert.equal(agentProvider({capabilities: {backup_method: 'native_push'}}), 'libvirt');
    assert.deepEqual(selectedNamespaces('', ['one']), []);
    assert.deepEqual(selectedNamespaces('one, two', ['one', 'two']), ['one', 'two']);
    for (const value of ['one,one', 'Upper', 'outside']) assert.throws(() => selectedNamespaces(value, ['one']));
    assert.throws(() => selectedNamespaces('one', null));
});
test('appearance metadata rejects executable styles, remote files and path traversal', () => {
    assert.equal(validateManifest(structuredClone(manifest)).id, 'site-pack');
    for (const path of ['../logo.svg', 'https://example.com/a.svg', '/logo.svg', 'foo/../a.svg', 'a.svg?x=1']) assert.equal(safeAssetPath(path), false);
    assert.equal(packPath('/appearance/packs/site-pack/1.0.0'), true);
    assert.equal(packPath('/appearance/packs/../1.0.0'), false);
    for (const meta of [{css: 'body{}'}, {colors: {primary: 'url(https://example.com)'}}, {product_name: '<script>'}, {font_family: 'remote'}, {density: 'arbitrary'}]) {
        const bad = structuredClone(manifest); Object.assign(bad.meta.vnbui, meta); assert.throws(() => validateManifest(bad));
    }
});
test('invalid active pack falls back to previous; missing assets preserve bundled icons', async () => {
    const resolver = new AssetResolver();
    await resolver.init(async (url, opts) => {
        if (opts?.method === 'HEAD' || opts?.method === 'GET') return {ok: true, text: async () => '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'};
        return {ok: true, json: async () => url === '/assets/manifest.json' ? bundled : url === '/appearance/config.json' ? {schema_version: 1, active_pack: '/appearance/packs/bad-pack/1.0.0', previous_pack: '/appearance/packs/site-pack/1.0.0'} : url.includes('bad-pack') ? {schema_version: 2} : manifest};
    });
    assert.equal(resolver.productName, 'Site backup');
    assert.equal(resolver.assetUrl('brand-logo'), '/appearance/packs/site-pack/1.0.0/logo.svg');
    assert.equal(resolver.icon('nav-vms'), '<i class="ti ti-server"></i>');
    assert.match(resolver.inlineSvg('brand-logo'), /^<img /);
});
test('missing pack files or offline config fall back to bundled defaults', async () => {
    for (const offline of [true, false]) {
        const resolver = new AssetResolver();
        await resolver.init(async (url, opts) => {
            if (url === '/assets/manifest.json') return {ok: true, json: async () => bundled};
            if (offline) throw new Error('offline');
            if (opts?.method === 'HEAD' || opts?.method === 'GET') return {ok: false};
            return {ok: true, json: async () => url === '/appearance/config.json' ? {schema_version: 1, active_pack: '/appearance/packs/site-pack/1.0.0'} : manifest};
        });
        assert.equal(resolver.productName, 'Vesta');
        assert.equal(resolver.assetUrl('brand-logo'), '/assets/brand-logo.svg');
    }
});

test('variant axes follow declaration order and prefix fallback; invalid schema rejects', () => {
    const value = structuredClone(manifest);
    value.variant_schema = {state: {values: ['ok', 'failed'], default: 'ok'}, mode: {values: ['full', 'incremental'], default: 'full'}};
    value.assets['brand-logo'] = {content_type: 'image/svg+xml', variants: {'ok/full': 'full.svg', failed: 'failed.svg'}, default: 'default.svg'};
    validateManifest(value);
    const resolver = new AssetResolver(); resolver.manifest = value;
    assert.equal(resolver.resolve('brand-logo'), 'full.svg');
    assert.equal(resolver.resolve('brand-logo', {state: 'failed', mode: 'incremental'}), 'failed.svg');
    assert.match(resolver.svg('brand-logo'), /full.svg/);
    for (const mutate of [v => {v.extra = true;}, v => {v.assets['brand-logo'].file = 'both.svg';}, v => {v.variant_schema.state.default = 'invalid';}, v => {v.assets['brand-logo'].variants = {'full/ok': 'wrong.svg'};}]) {
        const invalid = structuredClone(value); mutate(invalid); assert.throws(() => validateManifest(invalid));
    }
});
test('SVG rejects active content, external references and data URLs', () => {
    assert.equal(safeSvg('<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" fill="url(#gradient)"/></svg>'), true);
    for (const svg of ['<svg><script>alert(1)</script></svg>', '<svg onload="alert(1)"/>', '<svg><use href="https://example.com"/></svg>', '<svg><image href="data:image/png;base64,1"/></svg>', '<svg><path style="fill:red"/></svg>', '<svg><path fill="url(https://example.com)"/></svg>']) assert.equal(safeSvg(svg), false);
});

test('stalled optional appearance fetch aborts and preserves prelogin bundled defaults', async () => {
    const resolver = new AssetResolver();
    let aborted = false;
    await resolver.init((url, opts) => {
        if (url === '/assets/manifest.json') return Promise.resolve({ok: true, json: async () => bundled});
        return new Promise((_, reject) => opts.signal.addEventListener('abort', () => {aborted = true; reject(new Error('aborted'));}, {once: true}));
    }, {requestTimeoutMs: 10, totalTimeoutMs: 50});
    assert.equal(aborted, true);
    assert.equal(resolver.productName, 'Vesta');
});
for (const elapsed of [10, 100]) {
    test(`a timed out active pack uses the previous pack only with remaining budget (${elapsed} ms elapsed)`, async context => {
        const resolver = new AssetResolver();
        // Keep the real abort timer, but control the deadline clock so a busy
        // runner cannot turn the within-budget case into the expired case.
        let now = 1700000000000;
        context.mock.method(Date, 'now', () => now);
        let aborted = false, previousRequested = false;
        await resolver.init((url, opts) => {
            if (url.includes('bad-pack')) return new Promise((_, reject) => opts.signal.addEventListener('abort', () => {
                aborted = true;
                now += elapsed;
                reject(new Error('aborted'));
            }, {once: true}));
            if (url.includes('/site-pack/')) previousRequested = true;
            if (opts?.method === 'GET') return Promise.resolve({ok: true, text: async () => '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>'});
            return Promise.resolve({ok: true, json: async () => url === '/assets/manifest.json' ? bundled : url === '/appearance/config.json' ? {schema_version: 1, active_pack: '/appearance/packs/bad-pack/1.0.0', previous_pack: '/appearance/packs/site-pack/1.0.0'} : manifest});
        }, {requestTimeoutMs: 10, totalTimeoutMs: 100});
        assert.equal(aborted, true);
        assert.equal(previousRequested, elapsed < 100);
        assert.equal(resolver.productName, elapsed < 100 ? 'Site backup' : 'Vesta');
    });
}

test('shared parsed SVG fixtures obey the passive namespace policy in Node', () => {
    for (const fixture of svgFixtures) assert.equal(safeSvg(fixture.xml), fixture.accepted, fixture.name);
});

test('shipped Summer defaults and all brand variants match the approved immutable pack offline', async () => {
    const actual = JSON.parse(await readFile(new URL('../public/assets/manifest.json', import.meta.url)));
    const approved = JSON.parse(await readFile(new URL('../../branding/vesta/packs/vesta-1.2.0/manifest.json', import.meta.url)));
    const resolver = new AssetResolver();
    await resolver.init(async url => url === '/assets/manifest.json' ? {ok: true, json: async () => actual} : {ok: false});
    assert.equal(resolver.productName, 'Vesta');
    assert.deepEqual(resolver.appearance, approved.meta.vnbui);
    assert.equal(resolver.assetUrl('brand-logo'), '/assets/vesta-1-2-0/summer-light.svg');
    for (const [key, asset] of Object.entries(approved.assets)) {
        for (const file of new Set([asset.file, asset.default, ...Object.values(asset.variants || {})].filter(Boolean))) {
            assert.deepEqual(await readFile(new URL(`../public/assets/vesta-1-2-0/${file}`, import.meta.url)),
                await readFile(new URL(`../../branding/vesta/packs/vesta-1.2.0/${file}`, import.meta.url)), key);
        }
    }
    for (const edition of ['oss', 'commercial']) for (const theme of ['light', 'dark']) {
        for (const key of ['brand-logo', 'brand-favicon']) assert.equal(resolver.assetUrl(key, {edition, theme}),
            `/assets/vesta-1-2-0/${edition === 'oss' ? 'summer' : edition}-${theme}.svg`);
    }
});

test('partial customer overrides inherit Summer colors and resolve inherited artwork with its own axes', async () => {
    const actual = JSON.parse(await readFile(new URL('../public/assets/manifest.json', import.meta.url)));
    const partial = {schema_version: 1, id: 'custom-pack', version: '1.0.0', name: 'Custom', type: 'theme',
        variant_schema: {state: {values: ['ok'], default: 'ok'}},
        assets: {'action-check': {variants: {ok: 'tabler://check'}, default: 'tabler://check', content_type: 'text/x-tabler-icon'}},
        meta: {vnbui: {schema_version: 1, colors: {primary: '#123456'}}}};
    const resolver = new AssetResolver();
    await resolver.init(async url => ({ok: true, json: async () => url === '/assets/manifest.json' ? actual :
        url === '/appearance/config.json' ? {schema_version: 1, active_pack: '/appearance/packs/custom-pack/1.0.0'} : partial}));
    assert.equal(resolver.productName, 'Vesta');
    assert.equal(resolver.appearance.colors.primary, '#123456');
    assert.equal(resolver.appearance.colors['body-bg'], '#FAFAF2');
    assert.equal(resolver.assetUrl('brand-logo', {edition: 'commercial', theme: 'dark'}), '/assets/vesta-1-2-0/commercial-dark.svg');
    assert.equal(resolver.resolve('action-check'), 'tabler://check');
});
