import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';
import {validateBootstrap, installationService, InstallationService} from '../src/services/installation.service.js';

const config = (edition = 'community', mode = 'single_organization', oidc = false) => ({schema_version: 1, edition, auth_mode: mode, login_methods: {password: true, oidc}});

test('bootstrap validates required contract and retries after unavailable or malformed responses', async () => {
    for (const bad of [null, {}, {...config(), schema_version: 2}, {...config(), edition: 'paid'}, {...config(), auth_mode: 'guessed'}, {...config(), login_methods: {password: 'true', oidc: false}}]) assert.throws(() => validateBootstrap(bad));
    for (const fetcher of [async () => {throw Error('offline');}, async () => ({ok: false}), async () => ({ok: true, json: async () => ({})})]) {
        installationService.configuration = null;
        await assert.rejects(installationService.load(fetcher));
        assert.equal(installationService.configuration, null);
        assert.equal((await installationService.load(async () => ({ok: true, json: async () => config()}))).edition, 'community');
    }
});

test('EN/HE login follows installation auth methods and distribution independently of license status', async () => {
    const server = await createServer({configFile: false, root: new URL('..', import.meta.url).pathname, server: {middlewareMode: true, hmr: false}, appType: 'custom'});
    try {
        const {App} = await server.ssrLoadModule('/src/app.js');
        const {installationService: service, InstallationService: IsolatedInstallationService} = await server.ssrLoadModule('/src/services/installation.service.js');
        const {assetResolver} = await server.ssrLoadModule('/src/assets/resolver.js');
        const {authService} = await server.ssrLoadModule('/src/services/auth.service.js');
        assetResolver.manifest = JSON.parse(await readFile(new URL('../public/assets/manifest.json', import.meta.url)));
        assetResolver.apply = async () => {};
        for (const lang of ['en', 'he']) {
            const locale = JSON.parse(await readFile(new URL(`../public/locales/${lang}.json`, import.meta.url)));
            globalThis.window = {t: key => key.split('.').reduce((o,k) => o?.[k], locale) || key, vnbuiTranslator: {getAvailableLocales: () => [{code: lang, name: lang, active: true}]}};
            for (const edition of ['community', 'commercial']) for (const mode of ['single_organization', 'multi_organization']) for (const oidc of [true, false]) {
                const page = new App(); const app = {innerHTML: ''}; const listeners = new Map(); const nodes = new Map();
                globalThis.document = {getElementById(id) {
                    if (id === 'app') return app;
                    if (!app.innerHTML.includes(`id="${id}"`)) return null;
                    if (!nodes.has(id)) nodes.set(id, {style: {}, addEventListener: (type, handler) => listeners.set(`${id}/${type}`, handler)});
                    return nodes.get(id);
                }};
                const isolated = new IsolatedInstallationService(edition);
                service.load = () => isolated.load(async () => ({ok: true, json: async () => ({...config(edition, mode, oidc), license: {paid: true, valid: false}})}));
                await page.showLogin();
                assert.equal(app.innerHTML.includes('name="org_id"'), mode === 'multi_organization');
                assert.equal(app.innerHTML.includes('href="/api/v1/auth/oidc/login"'), oidc);
                assert.equal(assetResolver.edition, edition === 'commercial' ? 'commercial' : 'oss');
                assert.ok(app.innerHTML.includes('id="login-language"'));
                assert.ok(app.innerHTML.includes(locale.profile.language));
                let requested;
                authService.login = async (...args) => {requested = args;}; page.init = async () => {};
                await listeners.get('login-form/submit')({preventDefault() {}, target: {username: {value: 'user'}, password: {value: 'secret'}, org_id: {value: 'organization-one'}, querySelector: () => ({})}});
                assert.deepEqual(requested, ['user', 'secret', mode === 'multi_organization' ? 'organization-one' : '']);
            }
            const app = {innerHTML: ''};
            globalThis.document = {getElementById: id => id === 'app' ? app : {addEventListener() {}}};
            for (const artifactEdition of ['community', 'commercial']) {
                const isolated = new IsolatedInstallationService(artifactEdition);
                const opposite = artifactEdition === 'community' ? 'commercial' : 'community';
                service.load = () => isolated.load(async () => ({ok: true, json: async () => config(opposite)}));
                await new App().showLogin();
                assert.ok(app.innerHTML.includes(locale.login.bootstrap_error), 'mismatched artifacts fail before rendering auth controls');
                assert.ok(!app.innerHTML.includes('id="login-form"'));
                assert.ok(!app.innerHTML.includes('name="org_id"'));
                assert.equal(isolated.configuration, null, 'a mismatched bootstrap never enters the configuration cache');
            }
            const originalLoad = service.load; service.load = async () => {throw Error('offline');};
            try {await new App().showLogin();} finally {service.load = originalLoad;}
            assert.ok(app.innerHTML.includes(locale.login.bootstrap_error));
            assert.ok(app.innerHTML.includes('id="bootstrap-retry"'));
            assert.ok(!app.innerHTML.includes('login-form'));
            assert.ok(!app.innerHTML.includes('name="org_id"'));
            assert.ok(!app.innerHTML.includes('/api/v1/auth/oidc/login'));
        }
    } finally {await server.close();}
});


test('artifact edition is immutable and both matching distribution pairs pass after fetch', async () => {
    for (const edition of ['community', 'commercial']) {
        const service = new InstallationService(edition);
        assert.throws(() => {service.artifactEdition = edition === 'community' ? 'commercial' : 'community';}, TypeError);
        const response = await service.load(async () => ({ok: true, json: async () => config(edition)}));
        assert.equal(response.edition, edition);
    }
    assert.throws(() => validateBootstrap(config('commercial')), /artifact/);
    assert.throws(() => new InstallationService('paid'));
});
