/* Production Chromium presentation with local HTTP fixtures; no certificate issuance/trust evidence. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const fixture = require('./licensing-fixture.cjs');
module.exports = async function licensingCases(browser, origin, results) {
    const reports = [];
    for (const language of ['en', 'he']) for (const admin of [true, false]) {
        const name = `licensing-${language}-${admin ? 'admin' : 'ordinary'}`;
        const context = await browser.newContext({viewport: {width: admin ? 1440 : 390, height: 1000}});
        const page = await context.newPage(); page.setDefaultTimeout(12000);
        const locale = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../public/locales/${language}.json`)));
        let status = fixture.status(admin, {status: 'expired', reason_code: 'expired', notice_required: true});
        let licenseId = 'fixture-license';
        let detailReads = 0;
        let ack = null; const writes = [], external = [], errors = [];
        const detail = () => ({...fixture.details(status), certificate: {product: 'vesta', license_id: licenseId, customer_id: 'ADMIN_ONLY_CUSTOMER', class: 'free', issued_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-01T00:00:00Z', coverage: {modules: []}}, acknowledgement: ack});
        const token = ['fixture', Buffer.from(JSON.stringify({exp: 4102444800})).toString('base64url'), 'fixture'].join('.');
        await context.addInitScript(({token, language}) => {sessionStorage.setItem('auth_token', token); localStorage.setItem('preferredLanguage', language);}, {token, language});
        page.on('pageerror', error => errors.push(error.message));
        await page.route('**/*', route => {
            if (new URL(route.request().url()).origin !== origin) {external.push(route.request().url()); return route.abort('blockedbyclient');}
            return route.continue();
        });
        await page.route(url => url.origin === origin && url.pathname.startsWith('/api/'), route => {
            const request = route.request(), url = new URL(request.url());
            const reply = (body, code = 200) => route.fulfill({status: code, contentType: 'application/json', body: JSON.stringify(body)});
            if (url.pathname.startsWith('/api/v1/demo/')) return reply({}, 404);
            if (url.pathname === '/api/v1/bootstrap') return reply({schema_version: 1, edition: 'community', auth_mode: 'single_organization', login_methods: {password: true, oidc: false}});
            if (url.pathname === '/api/v1/auth/me') return reply({id: 'fixture-admin', username: 'License administrator', role: admin ? 'admin' : 'viewer', org_id: 'fixture-org', is_active: true, can_manage_installation: admin, is_platform_admin: admin, auth_source: 'local'});
            if (url.pathname === '/api/v1/features') return reply({flags: {}});
            if (url.pathname === '/api/v1/compatibility') return reply({status: 'aligned', degraded_mode: false});
            if (url.pathname === '/api/v1/dashboard/summary') return reply({vms: {total: 0, by_status: {}, by_agent: []}, agents: {total: 0, online: 0}, backups: {total: 0, last_24h: 0, by_status: {}}, schedules: {upcoming: 0}, attention: {}});
            if (url.pathname === '/api/v1/licensing/status') return reply(status);
            if (url.pathname === '/api/v1/licensing') {
                detailReads++;
                return reply(admin ? detail() : {}, admin ? 200 : 403);
            }
            if (url.pathname.startsWith('/api/v1/licensing/')) {
                if (!admin) return reply({}, 403);
                const body = request.method() === 'DELETE' ? null : request.postDataJSON(); writes.push({path: url.pathname, body});
                if (url.pathname.endsWith('/prepare')) return reply({challenge: 'single-use-browser-challenge', expected_phrase: 'HIDE LICENSING NOTICE', notice_scope: status.notice_scope, expires_at: '2099-01-01T00:00:00Z', status});
                if (url.pathname.endsWith('/confirm')) {status = {...status, acknowledged: true}; ack = {actor: {kind: 'user', label: 'Fixture administrator', user_id: 'fixture-admin'}, acknowledged_at: '2026-11-01T12:00:00Z'}; return reply(status);}
                if (url.pathname.endsWith('/acknowledgement')) {status = {...status, acknowledged: false}; ack = null; return reply(status);}
                if (url.pathname.endsWith('/registration-url')) {status = {...status, registration_url: body.url}; return reply(detail());}
                if (url.pathname.endsWith('/import')) {
                    const replacement = { '{"fixture":"paste"}': 'pasted-id', '{"fixture":"upload"}': 'uploaded-id' }[body.envelope];
                    if (!replacement) return reply({detail: {code: 'invalid_envelope', message: 'PRIVATE_LICENSE_ERROR'}}, 400);
                    licenseId = replacement;
                    status = {...status, status: 'valid_free', reason_code: 'certificate_valid', notice_required: false};
                    return reply(detail());
                }
            }
            if (request.method() !== 'GET') return route.abort('blockedbyclient');
            if (url.pathname.startsWith('/api/v1/settings')) return reply({settings: {'backup.capacity_admission': {enabled: false}}});
            return reply({items: [], total: 0});
        });
        try {
            await page.goto(origin + '/#dashboard');
            await page.locator('#licensing-banner .alert').waitFor();
            assert((await page.locator('#licensing-banner').innerText()).includes(locale.licensing.states[status.status]));
            assert.equal(await page.locator('a').evaluateAll(
                (links, address) => links.some(link => link.href === address), status.registration_url
            ), false, 'the configured registration address is display-only');
            assert(!(await page.locator('body').innerText()).includes('ADMIN_ONLY_CUSTOMER'));
            if (!admin) {
                assert.equal(await page.locator('#sidebar-menu a[href="#settings"]').count(), 0);
                await page.locator('#licensing-banner .alert').click({position: {x: 8, y: 8}});
                await page.locator('#licensing-summary').waitFor();
                assert((await page.locator('#licensing-summary').innerText()).includes(locale.licensing.states.expired));
                assert((await page.locator('#licensing-summary').innerText()).includes(locale.licensing.contact_admin));
                assert.equal(await page.locator('#licensing-panel, #license-file, #license-paste').count(), 0);
                assert(!(await page.locator('body').innerText()).includes('ADMIN_ONLY_CUSTOMER'));
                assert.equal(detailReads, 0);
                assert.deepEqual(writes, []);
            } else {
                await page.locator('#licensing-banner .alert').click({position: {x: 8, y: 8}});
                const details = page.locator('#licensing-panel dl');
                for (const value of ['ADMIN_ONLY_CUSTOMER', 'fixture-license', 'browser-installation-fixture']) {
                    await details.getByText(value, {exact: true}).waitFor();
                }
                assert.equal(new URL(page.url()).hash, '#licensing');
                await page.locator('#license-paste').fill('{"fixture":"paste"}');
                await page.locator('[data-license-action="import-pasted"]').click();
                await page.locator('#licensing-panel dl').getByText('pasted-id', {exact: true}).waitFor();
                await page.locator('#license-paste').fill('{}');
                await page.locator('[data-license-action="import-pasted"]').click();
                await page.locator('[data-license-feedback] .alert-danger').waitFor();
                assert((await page.locator('#licensing-panel').innerText()).includes('pasted-id'));
                await page.locator('#license-file').setInputFiles({name: 'replacement.json', mimeType: 'application/json', buffer: Buffer.from('{"fixture":"upload"}')});
                await page.locator('[data-license-action="import"]').click();
                await page.locator('#licensing-panel dl').getByText('uploaded-id', {exact: true}).waitFor();
                await page.waitForFunction(() => !document.querySelector('#licensing-banner .alert'));
                await page.goto(origin + '/#settings');
                await page.locator('a[href="#settings-licensing"]').click();
                await page.locator('#licensing-panel dl').getByText('uploaded-id', {exact: true}).waitFor();
                writes.length = 0;
                status = {...status, status: 'expired', reason_code: 'expired', notice_required: true};
                await page.locator('[data-license-action="retry"]').click();
                await page.locator('[data-license-action="prepare"]').click();
                assert.equal(writes.length, 0, 'unchecked first confirmation sends no request');
                await page.locator('#license-ack-checkbox').check();
                await page.locator('[data-license-action="prepare"]').click();
                await page.locator('#license-phrase').waitFor({state: 'visible'});
                assert.equal(writes.length, 1);
                assert.equal(await page.locator('#license-ack-checkbox').count(), 0);
                await page.locator('#license-phrase').fill('wrong');
                await page.locator('[data-license-action="confirm"]').click();
                assert.equal(writes.length, 1, 'wrong phrase does not consume challenge');
                await page.locator('#license-phrase').fill('HIDE LICENSING NOTICE');
                await page.locator('[data-license-action="confirm"]').click();
                await page.locator('[data-license-action="restore"]').waitFor();
                await page.waitForFunction(() => document.querySelector('#licensing-banner').textContent.trim() === '');
                assert((await page.locator('#licensing-panel').innerText()).includes('Fixture administrator'));
                assert((await page.locator('#licensing-panel').innerText()).includes(locale.licensing.states.expired), 'hiding notice does not grant a valid license');
                await page.locator('[data-license-action="restore"]').click();
                await page.locator('#licensing-banner .alert').waitFor();
                await page.locator('#license-file').setInputFiles({name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from('{}')});
                await page.locator('[data-license-action="import"]').click();
                await page.locator('[data-license-feedback] .alert-danger').waitFor();
                assert(!(await page.locator('body').innerText()).includes('PRIVATE_LICENSE_ERROR'));
                assert((await page.locator('#licensing-panel').innerText()).includes('ADMIN_ONLY_CUSTOMER'));
                await page.locator('#license-registration-url').fill('https://registration.invalid/offline');
                await page.locator('[data-license-action="save-url"]').click();
                await page.waitForFunction(() => document.querySelector('#license-registration-display').value === 'https://registration.invalid/offline');
                assert.equal(await page.locator('a[href*="registration.invalid"]').count(), 0);
                status = {...status, notice_scope: 'b'.repeat(64), acknowledged: false};
                await page.locator('[data-license-action="retry"]').click();
                await page.locator('#licensing-banner .alert').waitFor();
                assert(writes.every(write => write.path.startsWith('/api/v1/licensing/')));
            }
            assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'license UI must fit narrow LTR/RTL');
            assert.deepEqual(external, [], 'registration never contacts the displayed address');
            assert.deepEqual(errors, []);
            reports.push({name, status: 'passed'});
            await page.screenshot({path: path.join(results, name + '.png')});
        } catch (error) {reports.push({name, status: 'failed', error: error.message}); await page.screenshot({path: path.join(results, name + '-failure.png')}); throw error;}
        finally {fs.writeFileSync(path.join(results, 'licensing-results.json'), JSON.stringify({browser: browser.version(), expected: 4, reports, skips: 0}, null, 2)); await context.close();}
    }
};
