import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'vite';

const summary = patch => ({schema_version: 1, status: 'required', reason_code: 'missing', notice_required: true, acknowledged: false, can_manage: true, registration_url: 'https://vestabackup.com/portal/licensing', notice_scope: 'a'.repeat(64), policy: {version: 'registration-v1', usage_rules_configured: false}, ...patch});
const details = status => ({status, certificate: {product: 'vesta', license_id: 'fixture-license', customer_id: 'PRIVATE_ACCOUNT', class: 'free', issued_at: '2026-01-01T00:00:00Z', coverage: {modules: []}}, trust_store: {state: 'configured', key_ids: ['local']}, acknowledgement: null, installation_id: 'installation-fixture'});

test('advisory notice, installation-admin workflow and service permissions in EN/HE', async () => {
    const server = await createServer({configFile: false, root: new URL('..', import.meta.url).pathname, server: {middlewareMode: true, hmr: false, ws: false}, appType: 'custom'});
    try {
        const {LicensingService, MAX_LICENSE_BYTES, validateLicenseStatus} = await server.ssrLoadModule('/src/services/licensing.service.js');
        const {licenseBanner, LicensingPanel, licenseErrorKey, renderCertificate} = await server.ssrLoadModule('/src/components/licensing.js');
        globalThis.document = {getElementById: () => null};
        for (const lang of ['en', 'he']) {
            const locale = JSON.parse(await readFile(new URL(`../public/locales/${lang}.json`, import.meta.url)));
            globalThis.window = {t: key => key.split('.').reduce((obj, k) => obj?.[k], locale) || key};
            const t = window.t;
            for (const [code, key] of [['unknown_key', 'error_unknown_key'], ['invalid_signature', 'error_signature'], ['expired', 'error_expired'], ['not_yet_valid', 'error_not_yet_valid'], ['wrong_installation', 'error_wrong_installation'], ['unsupported_schema', 'error_schema'], ['unsupported_policy', 'error_schema'], ['invalid_json', 'error_malformed'], ['document_too_large', 'file_large'], ['challenge_expired', 'error_challenge_expired'], ['challenge_scope_changed', 'error_challenge_scope']]) {
                assert.equal(licenseErrorKey({data: {detail: {code, message: '<img src=x onerror=unsafe>'}}}), key);
                assert.ok(locale.licensing[key]);
            }
            assert.equal(licenseErrorKey({data: {detail: {code: 'future_unknown', message: 'PRIVATE'}}}), 'operation_failed');
            const certificate = renderCertificate(details(summary()).certificate, t);
            assert.ok(certificate.includes('<dl class="row">'));
            assert.ok(certificate.includes(locale.licensing.no_expiry));
            assert.ok(certificate.includes(locale.licensing.class_free));
            assert.ok(certificate.includes('<details><summary>'));
            assert.ok(!certificate.includes('<details open'), 'raw certificate data is collapsed by default');

            assert.ok(licenseBanner(summary({notice_scope: 'b'.repeat(64), acknowledged: false}), t), 'a fresh scope requiring acknowledgement shows a new notice');

            for (const status of ['not_required', 'valid_free', 'valid_paid']) {
                assert.equal(licenseBanner(summary({status, notice_required: false}), t), '');
            }
            for (const status of ['required', 'invalid', 'expired', 'not_yet_valid', 'wrong_installation', 'insufficient_coverage']) {
                const banner = licenseBanner(summary({status, customer: 'PRIVATE_CUSTOMER'}), t);
                assert.ok(banner.includes(locale.licensing.states[status]));
                assert.ok(banner.includes(locale.licensing.advisory));
                assert.ok(!banner.includes('PRIVATE_CUSTOMER'));
                assert.ok(!banner.includes('href="https:'));
                assert.ok(!banner.includes('<iframe') && !banner.includes('<img'));
                assert.equal(licenseBanner(summary({status, acknowledged: true}), t), '');
            }
            const localReminder = summary({reason_code: 'community_usage_threshold_reached'});
            assert.ok(licenseBanner(localReminder, t).includes(locale.licensing.local_threshold_reached));
            const expired = summary({status: 'expired', reason_code: 'community_usage_below_threshold'});
            assert.ok(licenseBanner(expired, t).includes(locale.licensing.states.expired));
            const usagePanel = new LicensingPanel();
            usagePanel.detail = {...details(localReminder), community_usage: {
                schedule_version: 'community-usage-6.0.81-v1', successful_backups: 101,
                inventoried_vms: 20, registered_agents: 3, threshold_reached: true,
            }};
            assert.ok(usagePanel.render(t).includes(locale.licensing.usage_scope));
            assert.ok(usagePanel.render(t).includes('<bdi>101</bdi>'));
            assert.ok(licenseBanner(summary({can_manage: false}), t).includes('href="#licensing"'));
            assert.ok(licenseBanner(summary({can_manage: false}), t).includes(locale.licensing.contact_admin));
            assert.ok(!licenseBanner(summary({registration_url: ''}), t).includes('data-license-copy-banner'), 'clearing the address omits banner copy controls');
            const cleared = new LicensingPanel(); cleared.detail = details(summary({registration_url: ''}));
            assert.ok(!cleared.render(t).includes('id="license-registration-display"'));
            assert.ok(cleared.render(t).includes('id="license-registration-url"'), 'administrators can configure a cleared address');

            let state = details(summary()); const calls = [];
            const service = {
                details: async () => state,
                prepare: async confirmed => {calls.push(['prepare', confirmed]); return {challenge: 'one-use-token', expected_phrase: 'HIDE LICENSING NOTICE', notice_scope: state.status.notice_scope};},
                confirm: async (challenge, phrase) => {calls.push(['confirm', challenge, phrase]); state = {...state, status: {...state.status, acknowledged: true}, acknowledgement: {actor: {label: 'Admin <actor>', user_id: 'user'}, acknowledged_at: '2026-11-01T12:00:00Z'}};},
                restore: async () => {calls.push(['restore']); state = {...state, status: {...state.status, acknowledged: false}, acknowledgement: null};},
                importLicense: async () => {calls.push(['import']); throw Object.assign(Error('PRIVATE_BACKEND_DETAIL'), {status: 400});},
            };
            const panel = new LicensingPanel(service); panel.repaint = () => {};
            await panel.load();
            assert.ok(panel.render(t).includes('PRIVATE_ACCOUNT'), 'certificate information remains in the admin panel');
            assert.ok(panel.render(t).includes('id="license-ack-checkbox"'));
            assert.ok(!panel.render(t).includes('id="license-phrase"'));
            let checked = false, phrase = '';
            const root = {querySelectorAll: () => [], querySelector: id => id === '#license-ack-checkbox' ? {checked} : id === '#license-phrase' ? {value: phrase} : {files: [{size: MAX_LICENSE_BYTES + 1, text() {assert.fail('oversized files must not be read');}}]}};
            await panel.act('prepare', root);
            assert.deepEqual(calls, [], 'unchecked first confirmation sends no request');
            checked = true; await panel.act('prepare', root);
            assert.deepEqual(calls, [['prepare', true]]);
            assert.ok(panel.render(t).includes('id="license-phrase"'));
            assert.ok(!panel.render(t).includes('id="license-ack-checkbox"'), 'second confirmation is a separate step');
            await panel.act('confirm', root);
            assert.equal(calls.length, 1, 'a wrong phrase sends no confirm request');
            phrase = 'HIDE LICENSING NOTICE'; await panel.act('confirm', root);
            assert.deepEqual(calls[1], ['confirm', 'one-use-token', phrase]);
            assert.ok(panel.render(t).includes('Admin &lt;actor&gt;'));
            assert.ok(panel.render(t).includes('2026-11-01T12:00:00Z'));
            assert.equal(licenseBanner(state.status, t), '');
            await panel.act('restore', root);
            assert.ok(licenseBanner(state.status, t));
            await panel.act('import', root);
            assert.equal(calls.some(call => call[0] === 'import'), false, 'oversized local file never reaches API');
            await panel.act('import', {...root, querySelector: () => ({files: [{size: 2, text: async () => '{}'}]})});
            assert.ok(panel.render(t).includes('PRIVATE_ACCOUNT'), 'failed import retains accepted certificate');
            assert.ok(!panel.render(t).includes('PRIVATE_BACKEND_DETAIL'));
            service.importLicense = async () => {throw {data: {detail: {code: 'unknown_key', message: 'PRIVATE_RAW_ERROR'}}};};
            await panel.act('import', {...root, querySelector: () => ({files: [{size: 2, text: async () => '{}'}]})});
            assert.ok(panel.render(t).includes(locale.licensing.error_unknown_key));
            assert.ok(!panel.render(t).includes('PRIVATE_RAW_ERROR'));

            const pasted = value => ({...root, querySelector: () => ({value})});
            await panel.act('import-pasted', pasted('   '));
            assert.equal(panel.error, 'paste_required');
            await panel.act('import-pasted', pasted('{}'));
            assert.equal(panel.error, 'error_unknown_key');
            assert.equal(panel.detail.certificate.license_id, 'fixture-license');

            const imported = [];
            service.importLicense = async envelope => {
                imported.push(envelope);
                return {...state, certificate: {...state.certificate, license_id: 'replacement-' + imported.length}};
            };
            await panel.act('import-pasted', pasted('  {"signed":"paste"}'));
            assert.equal(panel.detail.certificate.license_id, 'replacement-1');
            assert.equal(panel.message, 'imported');
            await panel.act('import', {...root, querySelector: () => ({files: [{size: 10, text: async () => '{"signed":"file"}'}]})});
            assert.deepEqual(imported, ['  {"signed":"paste"}', '{"signed":"file"}']);
            assert.equal(panel.detail.certificate.license_id, 'replacement-2');
            const copied = [];
            Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {writeText: async value => copied.push(value)}});
            await panel.act('copy-installation-id', root);
            await panel.act('copy-license-id', root);
            assert.deepEqual(copied, [state.installation_id, 'replacement-2']);
            navigator.clipboard.writeText = async () => {throw Error('unavailable');};
            await panel.act('copy-license-id', root);
            assert.equal(panel.error, 'id_copy_failed');
            delete navigator.clipboard;

            service.details = async () => {throw Error('unavailable');}; await panel.load();
            assert.ok(panel.render(t).includes(locale.licensing.unavailable));
            assert.ok(!panel.render(t).includes('PRIVATE_ACCOUNT'));
        }
        const requests = []; let permission = true, authorityChecks = 0;
        const auth = {requireInstallationAccess: async () => {authorityChecks++; if (!permission) throw Object.assign(Error('Denied'), {status: 403});}};
        const api = Object.fromEntries(['get', 'post', 'put', 'delete'].map(method => [method, async (...args) => {requests.push([method, ...args]); return method === 'get' && args[0].endsWith('/status') ? summary() : details(summary());}]));
        const client = new LicensingService(api, auth);
        await client.summary(); assert.equal(authorityChecks, 0);
        await client.details(); await client.importLicense('{}'); await client.registrationUrl('https://offline.example/register'); await client.registrationUrl(''); await client.prepare(true); await client.confirm('challenge', 'HIDE LICENSING NOTICE'); await client.restore();
        assert.equal(authorityChecks, 7, 'every admin call refreshes persisted installation authority');
        assert.deepEqual(requests.find(call => call[1].endsWith('/import')), ['post', '/api/v1/licensing/import', {envelope: '{}'}]);
        assert.deepEqual(requests.find(call => call[1].endsWith('/confirm')), ['post', '/api/v1/licensing/acknowledgement/confirm', {confirm: true, challenge: 'challenge', phrase: 'HIDE LICENSING NOTICE'}]);
        const count = requests.length; permission = false;
        await assert.rejects(client.details(), error => error.status === 403);
        assert.equal(requests.length, count, 'denied installation actor never calls admin API');
        await assert.rejects(client.importLicense('א'.repeat(MAX_LICENSE_BYTES)), /file_large/, 'UTF8 byte limit applies independently of file.size');
        await assert.rejects(client.registrationUrl('http://remote.invalid'), /operation_failed/);
        assert.throws(() => client.prepare(false), /ack_required/);
        assert.throws(() => validateLicenseStatus({}), /Invalid/);
    } finally {await server.close();}
});


test('Settings remains available through a hung licensing lookup and cancels on navigation', async t => {
    const server = await createServer({
        configFile: false,
        root: new URL('..', import.meta.url).pathname,
        server: {middlewareMode: true, hmr: false, ws: false},
        appType: 'custom',
    });
    try {
        const {SettingsPage} = await server.ssrLoadModule('/src/pages/settings.js');
        const {authService} = await server.ssrLoadModule('/src/services/auth.service.js');
        const locale = JSON.parse(await readFile(new URL('../public/locales/en.json', import.meta.url)));
        const store = new Map();
        globalThis.sessionStorage = {
            getItem: key => store.get(key) ?? null,
            setItem: (key, value) => store.set(key, value),
            removeItem: key => store.delete(key),
        };
        globalThis.window = {t: key => key.split('.').reduce((value, segment) => value?.[segment], locale) || key};
        let root;
        const makeRoot = html => {
            const retry = html.includes('data-license-action="retry"')
                ? {dataset: {licenseAction: 'retry'}, addEventListener(_, click) { this.click = click; }}
                : null;
            return {
                html,
                retry,
                querySelectorAll: () => retry ? [retry] : [],
                set outerHTML(next) { root = makeRoot(next); },
            };
        };
        globalThis.document = {
            getElementById: id => id === 'licensing-panel' ? root : null,
            querySelector: () => null,
            querySelectorAll: () => [],
        };
        t.mock.timers.enable({apis: ['setTimeout']});
        authService.requireInstallationAccess = async () => {};
        const page = new SettingsPage();
        for (const method of ['loadData', 'loadAPIKeys', 'loadVersionInfo', 'loadCompatibility',
            'loadV3Settings', 'loadEncryptionKeys', 'loadPKIStatus']) page[method] = async () => {};

        const requests = [];
        page.licensingPanel.service = {
            details: signal => new Promise(resolve => requests.push({signal, resolve})),
        };
        const html = await page.render();
        assert.match(html, /id="settings-encryption"/);
        assert.match(html, /id="settings-licensing"/);
        assert.ok(html.includes(locale.common.loading));
        assert.equal(requests.length, 0, 'render leaves advisory I/O to the mounted panel');

        root = makeRoot(html);
        const mounting = page.afterRender();
        assert.equal(requests.length, 1);
        assert.equal(requests[0].signal.aborted, false);
        page.markDirty();
        assert.equal(page.isDirty, true, 'settings interaction remains available');
        t.mock.timers.tick(5000);
        await mounting;
        assert.equal(requests[0].signal.aborted, true);
        assert.ok(root.html.includes(locale.licensing.unavailable));
        assert.ok(root.retry);

        const retrying = root.retry.click();
        assert.equal(requests.length, 2);
        requests[1].resolve(details(summary({status: 'valid_free', notice_required: false})));
        await retrying;
        assert.ok(root.html.includes(locale.licensing.states.valid_free));
        requests[0].resolve(details(summary({status: 'expired'})));
        await Promise.resolve();
        assert.ok(!root.html.includes(locale.licensing.states.expired));

        const leaving = root.retry.click();
        assert.equal(requests.length, 3);
        page.destroy();
        root = makeRoot('replacement page');
        requests[2].resolve(details(summary({status: 'expired'})));
        await leaving;
        assert.equal(requests[2].signal.aborted, true);
        assert.equal(root.html, 'replacement page');
    } finally {
        t.mock.timers.reset();
        delete globalThis.document;
        delete globalThis.sessionStorage;
        delete globalThis.window;
        await server.close();
    }
});

test('cancelling a registration read preserves session across late authority and API responses', async () => {
    const server = await createServer({
        configFile: false,
        root: new URL('..', import.meta.url).pathname,
        server: {middlewareMode: true, hmr: false, ws: false},
        appType: 'custom',
    });
    const originalFetch = globalThis.fetch;
    try {
        const {authService} = await server.ssrLoadModule('/src/services/auth.service.js');
        const {licensingService} = await server.ssrLoadModule('/src/services/licensing.service.js');
        const store = new Map();
        globalThis.sessionStorage = {
            getItem: key => store.get(key) ?? null,
            setItem: (key, value) => store.set(key, value),
            removeItem: key => store.delete(key),
        };
        globalThis.window = {location: {replace() { assert.fail('aborted read redirected to login'); }}};
        authService.setToken('current-token');
        authService.setUser({username: 'current'});

        const current = {username: 'current', can_manage_installation: true};
        for (const phase of ['authority', 'details']) {
            const controller = new AbortController();
            let requestStarted;
            const started = new Promise(resolve => { requestStarted = resolve; });
            globalThis.fetch = (url, {signal}) => {
                assert.equal(signal, controller.signal);
                if (phase === 'details' && url === '/api/v1/auth/me') {
                    return Promise.resolve({ok: true, json: async () => current});
                }
                assert.equal(url, phase === 'authority' ? '/api/v1/auth/me' : '/api/v1/licensing');
                return new Promise(resolve => requestStarted(resolve));
            };

            const requested = licensingService.details(controller.signal);
            const resolveResponse = await started;
            controller.abort();
            resolveResponse(phase === 'authority'
                ? {ok: true, json: async () => ({username: 'stale'})}
                : {ok: false, status: 401});
            await assert.rejects(requested, {name: 'AbortError'});
            assert.equal(authService.getToken(), 'current-token');
            assert.equal(authService.getUser().username, 'current');
        }
    } finally {
        globalThis.fetch = originalFetch;
        delete globalThis.sessionStorage;
        delete globalThis.window;
        await server.close();
    }
});
