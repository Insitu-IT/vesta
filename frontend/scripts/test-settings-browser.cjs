const licenseFixture = require('./licensing-fixture.cjs');
/* Production dist in Chromium; provider/API fixtures, not browser-to-PG or TLS-handshake evidence. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

module.exports = async function settingsCases(browser, origin, results) {
    const reports = [];
    const cases = ['admin', 'viewer', 'operator'].map(role => ({name: `settings-deny-${role}`, role, denied: true}));
    cases.push({name: 'settings-roundtrip'}, {name: 'settings-legacy-default', legacy: true});
    for (const operation of ['save', 'test']) {
        cases.push({name: `settings-revoked-${operation}`, operation, revoked: true});
        for (const status of [400, 401, 403, 409, 500]) cases.push({name: `settings-${operation}-${status}`, operation, status});
    }
    const token = ['fixture', Buffer.from(JSON.stringify({exp: 4102444800})).toString('base64url'), 'fixture'].join('.');
    for (const spec of cases) {
        const context = await browser.newContext({viewport: {width: 1440, height: 1100}});
        const page = await context.newPage();
        page.setDefaultTimeout(10000);
        const writes = [], leaks = new Set();
        let revoked = false, profileReads = 0;
        const actor = {id: '20000000-0000-0000-0000-000000000001', org_id: '10000000-0000-0000-0000-000000000001',
            username: 'settings-actor', role: spec.role || 'viewer', is_active: true,
            auth_source: 'local', role_source: 'local', is_platform_admin: !spec.denied, can_manage_installation: !spec.denied};
        const settings = {'oidc.enabled': true, 'oidc.issuer': 'https://issuer.test', 'oidc.client_id': 'client',
            'oidc.scopes': 'openid profile', 'oidc.role_claim': 'groups', 'oidc.admin_values': 'admin',
            'oidc.operator_values': '', 'oidc.default_role': spec.legacy ? 'admin' : 'viewer'};
        page.on('console', msg => {
            if (msg.text().includes('PRIVATE_SETTINGS_DETAIL')) leaks.add('private-detail');
            if (msg.text().includes(token)) leaks.add('bearer');
        });
        await context.addInitScript(token => {
            if (sessionStorage.getItem('settings_initialized')) return;
            sessionStorage.setItem('settings_initialized', '1');
            sessionStorage.setItem('auth_token', token);
            sessionStorage.setItem('current_user', JSON.stringify({role: 'admin', is_platform_admin: true, can_manage_installation: true}));
            localStorage.setItem('current_user', JSON.stringify({is_platform_admin: true}));
        }, token);
        await page.route('**/api/**', route => {
            const req = route.request(), url = new URL(req.url());
            const reply = (body, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(body)});
            if (url.pathname.startsWith('/api/v1/demo/')) return reply({}, 404);
            if (url.pathname === '/api/v1/licensing/status') return reply(licenseFixture.status(actor.can_manage_installation && !revoked));
            if (url.pathname === '/api/v1/licensing') return reply(licenseFixture.details(licenseFixture.status(actor.can_manage_installation && !revoked)));
            if (url.pathname === '/api/v1/bootstrap') return reply({schema_version: 1, edition: 'community', auth_mode: 'single_organization', login_methods: {password: true, oidc: true}});
            if (url.pathname === '/api/v1/auth/me') {
                profileReads++;
                return reply({...actor, is_platform_admin: actor.is_platform_admin && !revoked,
                    can_manage_installation: actor.can_manage_installation && !revoked});
            }
            if (url.pathname === '/api/v1/features') return reply({});
            if (url.pathname === '/api/v1/compatibility') return reply({status: 'aligned', degraded_mode: false});
            if (url.pathname === '/api/v1/auth/oidc/status') return reply({enabled: true});
            if (url.pathname === '/api/v1/settings/v3' && req.method() === 'GET') {
                return reply({settings, secrets: {'oidc.client_secret': {configured: true, source: 'ui'}}, encryption_configured: true});
            }
            if ((url.pathname === '/api/v1/settings/v3' && req.method() === 'PUT') || url.pathname === '/api/v1/auth/oidc/test') {
                writes.push({path: url.pathname, body: req.postDataJSON()});
                if (spec.status) return reply({detail: 'PRIVATE_SETTINGS_DETAIL<img src=x onerror="window.__unsafe=1">'}, spec.status);
                if (req.method() === 'PUT') {Object.assign(settings, req.postDataJSON()); return reply({status: 'ok'});}
                return reply({check: 'discovery_only', credentials_verified: false});
            }
            return reply({items: [], total: 0});
        });
        try {
            await page.goto(origin + '/#settings');
            if (spec.denied) {
                await page.locator('#sidebar-menu').waitFor();
                assert.equal(await page.locator('#sidebar-menu a[href="#settings"]').count(), 0);
                assert.equal(await page.locator('#btn-save-oidc, #btn-test-oidc').count(), 0);
                assert.equal(writes.length, 0);
            } else {
                await page.locator('a[href="#settings-security"]').click();
                await page.locator('#setting-v3-oidc-issuer').waitFor({state: 'visible'});
                assert.equal(await page.locator('#setting-v3-oidc-client-secret').inputValue(), '');
                assert.equal(await page.locator('#setting-v3-oidc-client-secret').getAttribute('placeholder'), '(keep existing)');
                assert.equal(await page.locator('#setting-v3-oidc-role-claim').inputValue(), 'groups');
                assert.equal(await page.locator('#setting-v3-oidc-admin-values').inputValue(), 'admin');
                assert.equal(await page.locator('#setting-v3-oidc-operator-values').inputValue(), '');
                if (spec.legacy) {
                    assert.equal(await page.locator('#setting-v3-oidc-default-role').inputValue(), '');
                    assert(await page.locator('#btn-save-oidc').isDisabled());
                    assert(await page.locator('#btn-test-oidc').isDisabled());
                    await page.locator('#setting-v3-oidc-default-role').selectOption('viewer');
                }
                await page.locator('#setting-v3-oidc-client-id').fill(' revised-client ');
                await page.locator('#setting-v3-oidc-client-secret').fill('********');
                const before = profileReads;
                revoked = !!spec.revoked;
                await page.locator(spec.operation === 'test' ? '#btn-test-oidc' : '#btn-save-oidc').click();
                await page.waitForFunction(() => !document.querySelector('#btn-test-oidc')?.disabled ||
                    document.querySelector('#login-form') || document.querySelector('.toast'));
                if (spec.revoked || spec.status) {
                    if (spec.status === 401) await page.locator('#login-form').waitFor();
                    else await page.getByText(spec.operation === 'test' ? 'OIDC discovery failed' : 'Unable to save OIDC settings', {exact: true}).waitFor();
                    assert.equal(writes.length, spec.revoked ? 0 : 1);
                } else {
                    await page.waitForFunction(() => document.querySelector('#setting-v3-oidc-client-id')?.value === 'revised-client');
                    assert.deepEqual(writes[0], {path: '/api/v1/settings/v3', body: {...settings, 'oidc.client_id': 'revised-client'}});
                    await page.locator('#btn-test-oidc').click();
                    await page.getByText('Issuer discovery verified. Client credentials were not tested.', {exact: true}).waitFor();
                    assert.deepEqual(writes[1], {path: '/api/v1/auth/oidc/test', body: {issuer: 'https://issuer.test'}});
                }
                assert(profileReads > before, 'Authority must be re-read before save/test');
            }
            assert.equal(await page.getByText('PRIVATE_SETTINGS_DETAIL', {exact: false}).count(), 0);
            assert.equal(await page.evaluate(() => window.__unsafe), undefined);
            assert.equal(leaks.size, 0, 'Sensitive console categories: ' + [...leaks].join(','));
            reports.push({name: spec.name, status: 'passed'});
            await page.screenshot({path: path.join(results, spec.name + '.png')});
        } catch (error) {
            reports.push({name: spec.name, status: 'failed'});
            await page.screenshot({path: path.join(results, spec.name + '-failure.png')});
            throw error;
        } finally {
            fs.writeFileSync(path.join(results, 'settings-results.json'), JSON.stringify({
                commit: process.env.CI_COMMIT_SHA || null, browser: browser.version(),
                expected: 17, reports, skips: 0,
            }, null, 2));
            await context.close();
        }
    }
    assert.equal(reports.length, 17);
    console.log('PASS: 17 real Chromium Settings cases; HTTP fixtures; zero skips');
};
