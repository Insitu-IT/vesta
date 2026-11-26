import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import {AssetResolver, assetResolver} from '../src/assets/resolver.js';
import {applyAppearance, SAFE_DARK_COLORS, themeColors, validateManifest} from '../src/assets/appearance.js';
import {readTheme, themeService} from '../src/services/theme.service.js';

const manifest = JSON.parse(await readFile(new URL('../public/assets/manifest.json', import.meta.url)));
const rootFixture = () => {
    const values = new Map();
    return {values, root: {dataset: {}, style: {setProperty: (key,value) => values.set(key,value), removeProperty: key => values.delete(key)}}};
};

test('legacy light colors never bleed into dark; repeated transitions clear stale overrides', () => {
    const {values, root} = rootFixture();
    applyAppearance(manifest.meta.vesta, root, 'light');
    assert.equal(values.get('--tblr-body-bg'), '#FAFAF2');
    applyAppearance(manifest.meta.vesta, root, 'dark');
    assert.equal(values.get('--tblr-body-bg'), SAFE_DARK_COLORS['body-bg']);
    assert.equal(values.get('--tblr-primary-fg'), '#000000');
    applyAppearance(manifest.meta.vesta, root, 'light');
    assert.equal(values.get('--tblr-body-bg'), '#FAFAF2');
    assert.equal(values.get('--tblr-primary-fg'), '#FFFFFF');
    applyAppearance({schema_version: 2, theme_colors: {light: {primary: '#123456'}}}, root, 'light');
    assert.equal(values.has('--tblr-body-bg'), false);
    assert.equal(values.has('--tblr-body-color-rgb'), false);
});

test('theme maps accept only constrained v2 data; malformed versions fail closed', () => {
    const make = meta => ({...structuredClone(manifest), meta: {vnbui: meta}});
    validateManifest(make({schema_version: 2, colors: {primary: '#123456'}, theme_colors: {light: {}, dark: {'body-bg': '#123456'}}}));
    for (const meta of [{schema_version: 1, theme_colors: {}}, {schema_version: 2, theme_colors: {system: {}}}, {schema_version: 2, theme_colors: {dark: null}}, {schema_version: 2, theme_colors: {dark: {primary: 'red'}}}, {schema_version: 2, theme_colors: {dark: {css: '#123456'}}}, {schema_version: 3}]) assert.throws(() => validateManifest(make(meta)));
});

test('resolved file cache follows theme/edition and explicit dark sidebar dimensions', () => {
    const resolver = new AssetResolver(); resolver.manifest = manifest;
    resolver.svgCache.set(resolver.assetUrl('brand-logo'), '<svg width="24" height="24"><title>light</title></svg>');
    assert.ok(resolver.inlineSvg('brand-logo').includes('<title>light</title>'));
    resolver.theme = 'dark';
    assert.ok(!resolver.inlineSvg('brand-logo').includes('<title>light</title>'));
    assert.ok(resolver.inlineSvg('brand-logo').includes('summer-dark.svg'));
    resolver.theme = 'light'; resolver.edition = 'commercial';
    assert.ok(resolver.assetUrl('brand-logo').includes('commercial-light.svg'));
    assert.ok(resolver.assetUrl('brand-logo', {theme: 'dark'}).includes('commercial-dark.svg'));
    resolver.edition = 'oss';
    assert.ok(resolver.inlineSvg('brand-logo').includes('<title>light</title>'));
});

test('before-paint initialization respects saved preference and blocked storage', async () => {
    const source = await readFile(new URL('../index.html', import.meta.url), 'utf8');
    const script = source.match(/<script>([\s\S]*?)<\/script>/)[1];
    for (const value of ['dark', 'light', null, 'system']) {
        const {root} = rootFixture();
        runInNewContext(script, {document: {documentElement: root}, localStorage: {getItem: () => value}});
        assert.equal(root.dataset.bsTheme, value === 'dark' ? 'dark' : 'light');
    }
    const {root} = rootFixture();
    runInNewContext(script, {document: {documentElement: root}, get localStorage() {throw Error('blocked');}});
    assert.equal(root.dataset.bsTheme, 'light');
    assert.equal(readTheme({getItem() {throw Error('blocked');}}), 'light');
});

test('repeated saved switches update document, artwork, chart notification and translated toggle names', async () => {
    const previous = {document: globalThis.document, window: globalThis.window, CustomEvent: globalThis.CustomEvent};
    const {root, values} = rootFixture(); const stored = new Map(); const events = [];
    globalThis.document = {documentElement: root, querySelector: () => null, querySelectorAll: () => []};
    globalThis.window = {localStorage: {getItem: key => stored.get(key), setItem: (key,value) => stored.set(key,value)}, dispatchEvent: event => events.push(event), t: key => key};
    globalThis.CustomEvent = class {constructor(type,options) {this.type = type; this.detail = options.detail;}};
    assetResolver.manifest = manifest; assetResolver.appearance = manifest.meta.vesta;
    try {
        themeService.initialize();
        assert.equal(themeService.theme, 'light');
        await themeService.toggle();
        assert.equal(root.dataset.bsTheme, 'dark');
        assert.equal(values.get('--tblr-body-bg'), SAFE_DARK_COLORS['body-bg']);
        assert.ok(themeService.button().includes('theme.switch_light'));
        assert.equal(stored.get('vnbui-theme'), 'dark');
        await themeService.toggle();
        assert.equal(values.get('--tblr-body-bg'), '#FAFAF2');
        assert.ok(themeService.button().includes('theme.switch_dark'));
        assert.equal(events.length, 2);
        assert.equal(events[0].type, 'vnbui:theme-change');
        window.localStorage.setItem = () => {throw Error('blocked');};
        await themeService.toggle();
        assert.equal(root.dataset.bsTheme, 'dark');
    } finally {
        Object.assign(globalThis, previous);
    }
});

test('frontend shares installer/backend v2 metadata fixture decisions', async () => {
    const fixtures = JSON.parse(await readFile(new URL('../../tests/fixtures/visual-assets-theme-v2.json', import.meta.url)));
    for (const fixture of fixtures) {
        const candidate = {...structuredClone(manifest), meta: {vnbui: fixture.metadata}};
        if (fixture.valid) assert.doesNotThrow(() => validateManifest(candidate), fixture.name);
        else assert.throws(() => validateManifest(candidate), fixture.name);
    }
});


test('legacy custom light palette overrides a v2 bundled light map without contaminating dark', async () => {
    const defaults = structuredClone(manifest);
    defaults.meta.vesta.schema_version = 2;
    defaults.meta.vesta.theme_colors = {light: {primary: '#111111'}, dark: {primary: '#EEEEEE'}};
    const custom = {schema_version: 1, id: 'custom-pack', version: '1.0.0', name: 'Custom', type: 'theme', assets: {'action-check': {file: 'tabler://check', content_type: 'text/x-tabler-icon'}}, meta: {vnbui: {schema_version: 1, colors: {primary: '#123456'}}}};
    const resolver = new AssetResolver();
    await resolver.init(async url => ({ok: true, json: async () => url === '/assets/manifest.json' ? defaults : url === '/appearance/config.json' ? {schema_version: 1, active_pack: '/appearance/packs/custom-pack/1.0.0'} : custom}));
    assert.equal(themeColors(resolver.appearance, 'light').primary, '#123456');
    assert.equal(themeColors(resolver.appearance, 'dark').primary, '#EEEEEE');
});
