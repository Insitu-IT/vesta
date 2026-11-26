import test from 'node:test';
import assert from 'node:assert/strict';
import {AssetResolver} from '../src/assets/resolver.js';

function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => {resolve = yes; reject = no;});
    return {promise, resolve, reject};
}
async function bounded(promise) {
    let timer;
    try {return await Promise.race([promise, new Promise((_, reject) => {timer = setTimeout(() => reject(new Error('Optional font blocked identity rendering')), 100);})]);}
    finally {clearTimeout(timer);}
}
async function fontPage(load, run) {
    const originalDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
    const originalFontFace = Object.getOwnPropertyDescriptor(globalThis, 'FontFace');
    const variables = new Map();
    const added = [];
    const description = {};
    const favicon = {};
    const loadingName = {};
    globalThis.document = {
        documentElement: {style: {setProperty: (key, value) => variables.set(key, value)}, dataset: {}},
        fonts: {add: font => added.push(font)},
        querySelector: selector => selector.startsWith('meta') ? description : favicon,
        querySelectorAll: () => [loadingName],
    };
    globalThis.FontFace = class {load() {return load(this);}};
    const resolver = new AssetResolver();
    resolver.productName = 'Site backup';
    resolver.appearance = {schema_version: 1, font_asset: 'site-font', font_family: 'serif'};
    resolver.manifest = {assets: {'site-font': {file: 'site.woff2', content_type: 'font/woff2'}, 'brand-favicon': {file: 'favicon.svg', content_type: 'image/svg+xml'}}};
    resolver.packBasePath = '/appearance/packs/site-pack/1.0.0';
    resolver.overrides = new Set(['site-font']);
    try {await run({resolver, variables, added, description, loadingName});}
    finally {
        if (originalDocument) Object.defineProperty(globalThis, 'document', originalDocument); else delete globalThis.document;
        if (originalFontFace) Object.defineProperty(globalThis, 'FontFace', originalFontFace); else delete globalThis.FontFace;
    }
}

test('a never-settling optional font cannot block prelogin identity rendering', async () => {
    await fontPage(() => new Promise(() => {}), async ({resolver, variables, added, description, loadingName}) => {
        await bounded(resolver.apply({fontTimeoutMs: 10}));
        assert.equal(document.title, 'Site backup');
        assert.equal(description.content, 'Site backup');
        assert.equal(loadingName.textContent, 'Site backup');
        assert.equal(variables.get('--tblr-font-sans-serif'), 'Georgia, serif');
        await bounded(resolver.fontReady);
        assert.deepEqual(added, []);
    });
});

test('rejected and late-rejected fonts retain fallback without unhandled rejection', async () => {
    for (const late of [false, true]) {
        const pending = deferred();
        await fontPage(() => late ? pending.promise : Promise.reject(new Error('Font unavailable')), async ({resolver, variables, added}) => {
            await bounded(resolver.apply({fontTimeoutMs: 10}));
            await bounded(resolver.fontReady);
            if (late) {pending.reject(new Error('Late font failure')); await new Promise(resolve => setImmediate(resolve));}
            assert.equal(variables.get('--tblr-font-sans-serif'), 'Georgia, serif');
            assert.deepEqual(added, []);
        });
    }
});

test('a font completing after its deadline does not alter the fallback theme', async () => {
    const pending = deferred();
    await fontPage(() => pending.promise, async ({resolver, variables, added}) => {
        await resolver.apply({fontTimeoutMs: 10});
        await bounded(resolver.fontReady);
        pending.resolve();
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(variables.get('--tblr-font-sans-serif'), 'Georgia, serif');
        assert.deepEqual(added, []);
    });
});

test('a superseded font load cannot override a later appearance', async () => {
    const pending = deferred();
    await fontPage(() => pending.promise, async ({resolver, variables, added}) => {
        await resolver.apply({fontTimeoutMs: 100});
        const earlierFont = resolver.fontReady;
        resolver.appearance = {schema_version: 1, font_family: 'mono'};
        await resolver.apply();
        pending.resolve();
        await bounded(earlierFont);
        assert.equal(variables.get('--tblr-font-sans-serif'), 'monospace');
        assert.deepEqual(added, []);
    });
});

test('a font loaded within its deadline activates while identity renders independently', async () => {
    await fontPage(font => Promise.resolve(font), async ({resolver, variables, added}) => {
        await bounded(resolver.apply({fontTimeoutMs: 50}));
        await bounded(resolver.fontReady);
        assert.equal(document.title, 'Site backup');
        assert.equal(added.length, 1);
        assert.equal(variables.get('--tblr-font-sans-serif'), 'SitePackFont, system-ui, sans-serif');
    });
});
