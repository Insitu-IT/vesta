const licenseFixture = require('./licensing-fixture.cjs');
/* Actual built UI in the existing Chromium process; HTTP/provider fixtures, not IdP/PG evidence. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

module.exports = async function authenticationCases(browser, origin, results) {
    const artifactEdition = process.env.BROWSER_ARTIFACT_EDITION || 'community';
    assert(['community', 'commercial'].includes(artifactEdition), 'Invalid BROWSER_ARTIFACT_EDITION');
    const multi = artifactEdition === 'commercial';
    const reports = [];
    const orgs = ['10000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000002'];
    const privateText = 'PRIVATE_AUTH_DETAIL<img src=x onerror="window.__unsafe=1">';
    const jwt = exp => ['fixture', Buffer.from(JSON.stringify({exp, role: 'admin', is_platform_admin: true,
        org_id: orgs[1]})).toString('base64url'), 'fixture'].join('.');
    const token = jwt(4102444800);
    let cases = [];
    for (const language of ['en', 'he']) {
        for (const bootstrapFailure of ['unavailable', 'malformed']) cases.push({name: `bootstrap-${language}-${bootstrapFailure}`, language, kind: 'bootstrap', bootstrapFailure});
        for (const selection of ['', ...orgs]) cases.push({name: `local-${language}-${selection || 'oss'}`, language, selection, kind: 'login'});
        for (const failure of ['missing-org', 'malformed-org', 'unknown-org', 'bad-password', 'disabled-user', 'disabled-org', 'missing-identity', 'ambiguous-identity']) {
            cases.push({name: `${language}-${failure}`, language, kind: 'login', failure,
                selection: failure === 'missing-org' ? '' : failure === 'malformed-org' ? 'display-name' :
                    failure === 'unknown-org' ? '10000000-0000-0000-0000-000000000099' : orgs[0]});
        }
    }
    for (const failure of ['missing', 'malformed', 'expired', 'profile-refused', 'malformed-fragment', 'duplicate-fragment', 'expired-fragment']) {
        cases.push({name: `restore-${failure}`, kind: 'restore', failure});
    }
    for (const roleSource of ['local', 'oidc']) cases.push({name: `oidc-profile-${roleSource}`, kind: 'oidc', roleSource});
    cases.push({name: 'persisted-profile-restore', kind: 'restore'});
    cases.push({name: 'logout-before-ack', kind: 'logout'});
    cases.push({name: 'refresh-persisted-profile', kind: 'refresh'});
    if (multi) cases = cases.filter(spec => !(spec.kind === 'login' && !spec.failure && !spec.selection));
    else cases = cases.filter(spec => spec.kind !== 'login' || (!spec.selection && !spec.failure) || ['bad-password', 'disabled-user', 'missing-identity', 'ambiguous-identity'].includes(spec.failure)).map(spec => spec.kind === 'login' ? {...spec, selection: ''} : spec);
    for (const language of ['en', 'he']) cases.push({name: `${artifactEdition}-${language}-artifact-mismatch`, language, kind: 'artifact-mismatch'});
    const expected = multi ? 38 : 28;
    assert.equal(cases.length, expected);
    for (const spec of cases) {
        const context = await browser.newContext({viewport: {width: 1440, height: 1000}});
        const page = await context.newPage();
        page.setDefaultTimeout(10000);
        const requests = [], leakKinds = new Set();
        page.on('console', msg => {
            for (const [kind, value] of [['private-detail', 'PRIVATE_AUTH_DETAIL'], ['bearer', token], ['password', 'fixture-password']]) {
                if (msg.text().includes(value)) leakKinds.add(kind);
            }
        });
        page.on('websocket', socket => {
            if (socket.url().includes(token) || new URL(socket.url()).search) leakKinds.add('websocket-url');
        });
        const selected = spec.selection || orgs[0];
        const profile = {id: '20000000-0000-0000-0000-000000000001', username: 'same-user',
            full_name: '<img src=x onerror="window.__unsafe=1">', org_id: selected,
            role: 'viewer', is_active: true, is_platform_admin: false, can_manage_installation: false,
            auth_source: spec.kind === 'oidc' ? 'oidc' : 'local', role_source: spec.roleSource || 'local',
            oidc_subject: spec.kind === 'oidc' ? 'same-subject' : null, oidc_issuer: 'https://issuer.invalid'};
        const locale = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../public/locales/${spec.language || 'en'}.json`)));
        let firstProfileUrl, oidcRequest;
        let bootstrapReads = 0;
        await page.route('**/locales/**', route => {
            // The production entry point removes credentials before its first async locale fetch.
            assert(!page.url().includes('access_token'));
            return route.continue();
        });
        await context.addInitScript(({spec, token, expired}) => {
            localStorage.setItem('preferredLanguage', spec.language || 'en');
            if (sessionStorage.getItem('initialized')) return;
            sessionStorage.setItem('initialized', '1');
            // Deliberately forged custody must never become verified identity.
            sessionStorage.setItem('current_user', JSON.stringify({role: 'admin', is_platform_admin: true, org_id: 'forged'}));
            localStorage.setItem('current_user', JSON.stringify({role: 'admin', is_platform_admin: true}));
            if (!['login', 'oidc', 'bootstrap', 'artifact-mismatch'].includes(spec.kind) && spec.failure !== 'missing') {
                sessionStorage.setItem('auth_token', spec.failure === 'malformed' ? 'malformed' : spec.failure === 'expired' ? expired : token);
            }
        }, {spec, token, expired: jwt(1)});
        await page.route('**/api/**', route => {
            const request = route.request(), url = new URL(request.url());
            requests.push({path: url.pathname, method: request.method(), body: request.postData(), headers: request.headers()});
            const reply = (body, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(body)});
            if (url.pathname.startsWith('/api/v1/demo/')) return reply({}, 404);
            if (url.pathname === '/api/v1/licensing/status') return reply(licenseFixture.status(false));
            if (url.pathname === '/api/v1/licensing') return reply(licenseFixture.details(licenseFixture.status(false)));
            if (url.pathname === '/api/v1/bootstrap') {
                if (spec.kind === 'bootstrap' && bootstrapReads++ === 0) return spec.bootstrapFailure === 'unavailable' ? reply({detail: privateText}, 503) : reply({schema_version: 99, edition: 'commercial'});
                const installedEdition = spec.kind === 'artifact-mismatch' ? (multi ? 'community' : 'commercial') : artifactEdition;
                return reply({schema_version: 1, edition: installedEdition, auth_mode: installedEdition === 'commercial' ? 'multi_organization' : 'single_organization', login_methods: {password: true, oidc: true}});
            }
            if (url.pathname === '/api/v1/auth/oidc/status') return reply({enabled: true});
            if (url.pathname === '/api/v1/auth/oidc/login') {
                oidcRequest = url;
                // Simulates the server-bound provider round trip; query input never chooses its owner.
                return route.fulfill({status: 302, headers: {location: origin + '/#access_token=' + token}});
            }
            if (url.pathname === '/api/v1/auth/login') return spec.failure ? reply({detail: privateText}, 401) : reply({access_token: token});
            if (url.pathname === '/api/v1/auth/me') {
                firstProfileUrl ??= page.url();
                return spec.failure === 'profile-refused' ? reply({detail: privateText}, 401) : reply(profile);
            }
            if (url.pathname === '/api/v1/auth/logout') return route.abort('failed');
            if (url.pathname === '/api/v1/auth/refresh') {
                profile.role = 'operator';
                return reply({access_token: token});
            }
            if (url.pathname === '/api/v1/features') return reply({});
            if (url.pathname === '/api/v1/compatibility') return reply({status: 'aligned', degraded_mode: false});
            return reply({items: [], total: 0});
        });
        try {
            let fragment = '';
            if (spec.failure === 'duplicate-fragment') fragment = '#access_token=' + token + '&access_token=' + token;
            if (spec.failure === 'expired-fragment') fragment = '#access_token=' + jwt(1);
            if (spec.failure === 'malformed-fragment') fragment = '#access_token=malformed';
            await page.goto(origin + '/' + fragment);
            if (spec.kind === 'artifact-mismatch') {
                await page.locator('#bootstrap-retry').waitFor();
                assert((await page.locator('body').innerText()).includes(locale.login.bootstrap_error));
                assert.equal(await page.locator('#login-form, #login-organization, #sidebar-menu').count(), 0);
                assert.equal(requests.filter(request => request.path === '/api/v1/auth/me' || request.path === '/api/v1/auth/login').length, 0, 'mismatched distribution never starts authentication');
                assert.equal(leakKinds.size, 0);
                reports.push({name: 'auth-' + spec.name, status: 'passed'});
                await page.screenshot({path: path.join(results, 'auth-' + spec.name + '.png')});
                continue;
            } else if (spec.kind === 'bootstrap') {
                await page.locator('#bootstrap-retry').waitFor();
                assert.equal(await page.locator('#login-form').count(), 0);
                assert.equal(await page.locator('#login-organization').count(), 0);
                assert.equal(await page.locator('a[href="/api/v1/auth/oidc/login"]').count(), 0);
                assert((await page.locator('body').innerText()).includes(locale.login.bootstrap_error));
                assert.equal(requests.filter(request => request.path === '/api/v1/auth/me').length, 0);
                await page.locator('#bootstrap-retry').click();
                await page.locator('#login-form').waitFor();
                assert.equal(await page.locator('#login-organization').count(), multi ? 1 : 0);
            } else if (spec.kind === 'login') {
                await page.locator('#login-form').waitFor();
                if (multi) {
                    assert.equal(await page.locator('#login-organization-help').innerText(), locale.login.organization_help);
                    await page.locator('#login-organization').fill(spec.selection);
                } else assert.equal(await page.locator('#login-organization').count(), 0, 'Community sign-in omits organization');
                await page.locator('[name="username"]').fill('same-user');
                await page.locator('[name="password"]').fill('fixture-password');
                await page.locator('#login-form button[type="submit"]').click();
                if (spec.failure) {
                    await page.locator('#login-error').waitFor();
                    assert.equal(await page.locator('#login-error').innerText(), locale.login.error);
                } else await page.locator('#sidebar-menu').waitFor();
                const logins = requests.filter(r => r.path === '/api/v1/auth/login');
                assert.equal(logins.length, 1);
                const form = new URLSearchParams(logins[0].body);
                assert.deepEqual([...form.keys()].sort(), spec.selection ? ['org_id', 'password', 'username'] : ['password', 'username']);
                assert.equal(form.get('org_id'), spec.selection || null);
                assert.equal(form.get('username'), 'same-user');
                assert(!Object.keys(logins[0].headers).some(h => /organization|tenant/.test(h)));
            } else if (spec.kind === 'oidc') {
                await page.locator('#login-form').waitFor();
                if (multi) await page.locator('#login-organization').fill(orgs[1]);
                else assert.equal(await page.locator('#login-organization').count(), 0);
                await page.locator('a[href="/api/v1/auth/oidc/login"]').click();
                await page.locator('#sidebar-menu').waitFor();
                assert.equal(oidcRequest.search, ''); // installation-bound OIDC, not arbitrary form tenant
                assert(!firstProfileUrl.includes('access_token'));
                assert(!page.url().includes('access_token'));
            } else if (spec.failure) {
                await page.locator('#login-form').waitFor();
                if (spec.failure.includes('fragment')) assert(!page.url().includes('access_token'));
                if (spec.failure !== 'profile-refused') assert.equal(requests.filter(r => r.path === '/api/v1/auth/me').length, 0);
            } else {
                await page.locator('#sidebar-menu').waitFor();
                if (spec.kind === 'refresh') {
                    assert(await page.evaluate(() => window.vnbui.auth.refreshAccessToken()));
                    assert.equal(await page.evaluate(() => window.vnbui.auth.verifiedUser.role), 'operator');
                    assert.equal(requests.filter(r => r.path === '/api/v1/auth/refresh').length, 1);
                }
                if (spec.kind === 'logout') {
                    await page.evaluate(() => {
                        const original = window.fetch;
                        window.fetch = (url, options) => {
                            if (url === '/api/v1/auth/logout') sessionStorage.setItem('logout-observation', JSON.stringify({
                                cleared: !window.vnbui.auth.verifiedUser && !sessionStorage.getItem('auth_token') &&
                                    !sessionStorage.getItem('current_user') && !localStorage.getItem('current_user'),
                                method: options.method, bearer: options.headers.Authorization.startsWith('Bearer '),
                            }));
                            return original(url, options);
                        };
                    });
                    await page.locator('.dropdown').filter({has: page.locator('#logout-btn')}).locator('[data-bs-toggle="dropdown"]').click();
                    await page.locator('#logout-btn').click();
                    await page.locator('#login-form').waitFor();
                    await page.waitForFunction(() => sessionStorage.getItem('logout-observation'));
                    assert.deepEqual(await page.evaluate(() => JSON.parse(sessionStorage.getItem('logout-observation'))),
                        {cleared: true, method: 'POST', bearer: true});
                    const logout = requests.filter(r => r.path === '/api/v1/auth/logout');
                    assert.equal(logout.length, 1);
                    assert.equal(logout[0].headers.authorization, 'Bearer ' + token);
                    assert.equal(new URL(page.url()).pathname, '/login');
                }
            }
            if (spec.failure || ['logout', 'bootstrap'].includes(spec.kind)) {
                assert.deepEqual(await page.evaluate(() => [sessionStorage.getItem('auth_token'), sessionStorage.getItem('current_user'), localStorage.getItem('current_user')]), [null, null, null]);
            } else {
                const actual = await page.evaluate(() => window.vnbui.auth.verifiedUser);
                assert.equal(actual.org_id, selected);
                assert.equal(actual.role, spec.kind === 'refresh' ? 'operator' : 'viewer');
                assert.equal(actual.is_platform_admin, false);
                assert.equal(actual.role_source, spec.roleSource || 'local');
                assert.equal(await page.locator('#sidebar-menu a[href="#settings"]').count(), 0);
                assert.equal(await page.locator('#sidebar-menu a[href="#users"]').count(), 0);
                await page.locator('.dropdown').filter({has: page.locator('#profile-btn')}).locator('[data-bs-toggle="dropdown"]').click();
                await page.locator('#profile-btn').click();
                await page.locator('#modal-profile.show').waitFor();
                assert.equal(await page.locator('#profile-organization').innerText(), selected);
                assert.equal(await page.locator('#profile-username').inputValue(), 'same-user');
                const expectedRole = spec.kind === 'refresh' ? 'operator' : 'viewer';
                assert.equal(typeof locale.enums.role[expectedRole], 'string');
                assert.equal(await page.locator('#profile-role').inputValue(), locale.enums.role[expectedRole]);
                assert.equal(await page.locator('#profile-fullname').inputValue(), profile.full_name);
                if (spec.kind === 'oidc') {
                    assert.equal(await page.locator('#profile-role-source').innerText(), spec.roleSource);
                    assert(await page.locator('#profile-fullname').evaluate(element => element.readOnly));
                }
            }
            if (spec.kind !== 'refresh') assert.equal(requests.filter(r => r.path === '/api/v1/auth/refresh').length, 0);
            assert.equal(await page.evaluate(() => window.__unsafe), undefined);
            assert(!(await page.locator('body').innerText()).includes('PRIVATE_AUTH_DETAIL'));
            assert.equal(leakKinds.size, 0, 'Console custody violation (categories only in result record)');
            reports.push({name: 'auth-' + spec.name, status: 'passed'});
            await page.screenshot({path: path.join(results, 'auth-' + spec.name + '.png')});
        } catch (error) {
            reports.push({name: 'auth-' + spec.name, status: 'failed', consoleLeakCategories: [...leakKinds].sort()});
            await page.screenshot({path: path.join(results, 'auth-' + spec.name + '-failure.png')});
            throw error;
        } finally {
            fs.writeFileSync(path.join(results, 'auth-results.json'), JSON.stringify({commit: process.env.CI_COMMIT_SHA,
                browser: browser.version(), artifact_edition: artifactEdition, expected, reports, skips: 0}, null, 2));
            await context.close();
        }
    }
    console.log(`PASS: ${expected} ${artifactEdition} real Chromium auth/session cases; HTTP fixtures; zero skips`);
};
