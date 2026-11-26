const licenseFixture = require('./licensing-fixture.cjs');
/* Real Chromium + production Vite output. HTTP fixtures are not PostgreSQL or IdP evidence. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {createHash} = require('node:crypto');
const {chromium} = require('playwright');

const root = process.env.FRONTEND_DIST ? path.resolve(process.env.FRONTEND_DIST) : path.resolve(__dirname, '../dist');
const artifactEdition = process.env.BROWSER_ARTIFACT_EDITION || 'community';
assert(['community', 'commercial'].includes(artifactEdition), 'Invalid BROWSER_ARTIFACT_EDITION');
const authOnly = process.env.AUTH_ONLY === '1';
assert(authOnly || artifactEdition === 'community', 'The complete users/settings runner requires the Community fixture artifact');
const results = path.join(process.env.VNBUI_BROWSER_RESULTS || path.resolve(__dirname, '../browser-results'), artifactEdition);
assert(fs.existsSync(path.join(root, 'index.html')), 'Built frontend/dist is required');
fs.mkdirSync(results, {recursive: true});
const server = http.createServer((req, res) => {
    const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    const file = path.resolve(root, '.' + pathname);
    if (!file.startsWith(root + path.sep) && file !== root) {
        res.writeHead(403).end(); return;
    }
    const target = fs.existsSync(file) && fs.statSync(file).isFile() ? file : path.join(root, 'index.html');
    const mime = {'.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json',
        '.svg': 'image/svg+xml', '.html': 'text/html', '.woff2': 'font/woff2'};
    res.setHeader('Content-Type', mime[path.extname(target)] || 'application/octet-stream');
    fs.createReadStream(target).pipe(res);
});
const org = '10000000-0000-0000-0000-000000000001';
const ids = ['20000000-0000-0000-0000-000000000001', '20000000-0000-0000-0000-000000000002'];
const display = "same');window.__unsafe=1;//<img src=x onerror=window.__unsafe=2>";
const privateDetail = '<img src=x onerror="window.__unsafe=3">PRIVATE_BACKEND_DETAIL';
const reports = [];
let browser;

async function specimen(options, run) {
    const context = await browser.newContext({viewport: {width: 1440, height: 1000}});
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const requests = [];
    const telemetryRequests = [];
    let siteConfigRequests = 0;
    page.on('request', request => {
        const pathname = new URL(request.url()).pathname;
        if (pathname === '/site-config.json') siteConfigRequests++;
        if (pathname === '/apm' || pathname.startsWith('/apm/')) telemetryRequests.push(pathname);
    });
    const users = ids.map(id => ({id, org_id: org, username: display, full_name: display,
        email: 'same@example.invalid', role: 'admin', is_active: true,
        auth_source: options.oidc ? 'oidc' : 'local', role_source: options.oidc && !options.pinned ? 'oidc' : 'local',
        oidc_subject: options.oidc ? id : null, oidc_issuer: options.oidc ? 'https://issuer.invalid' : null,
        created_at: '2026-09-13T00:00:00Z'}));
    const actor = {id: '30000000-0000-0000-0000-000000000001', org_id: org,
        username: 'actor', role: options.role || 'admin', auth_source: 'local', role_source: 'local',
        is_active: true, is_platform_admin: !!options.platform, can_manage_installation: !!options.platform};
    // Synthetic bearer has no server authority: /me and every API response below are explicit fixtures.
    const token = ['fixture', Buffer.from(JSON.stringify({exp: 4102444800})).toString('base64url'), 'fixture'].join('.');
    await context.addInitScript(token => {
        if (!sessionStorage.getItem('browser_initialized')) {
            sessionStorage.setItem('auth_token', token);
            sessionStorage.setItem('browser_initialized', '1');
        }
    }, token);
    await page.route('**/api/**', route => {
        const req = route.request(), url = new URL(req.url()), method = req.method();
        const reply = (body, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(body)});
        if (url.pathname.startsWith('/api/v1/demo/')) return reply({}, 404);
            if (url.pathname === '/api/v1/licensing/status') return reply(licenseFixture.status(!!options.platform));
            if (url.pathname === '/api/v1/licensing') return reply(licenseFixture.details(licenseFixture.status(!!options.platform)));
            if (url.pathname === '/api/v1/bootstrap') return reply({schema_version: 1, edition: 'community', auth_mode: 'single_organization', login_methods: {password: true, oidc: false}});
        if (url.pathname === '/api/v1/auth/me') return reply(actor);
        if (url.pathname === '/api/v1/auth/oidc/status') return reply({enabled: false});
        if (url.pathname === '/api/v1/features') return reply({});
        if (url.pathname === '/api/v1/compatibility') return reply({status: 'aligned', degraded_mode: false});
        if (url.pathname === '/api/v1/users') return reply({items: users, total: 2});
        if (url.pathname.startsWith('/api/v1/users/')) {
            const id = url.pathname.split('/').at(-1);
            if (method === 'GET') return reply(users.find(u => u.id === id) || {}, users.some(u => u.id === id) ? 200 : 404);
            requests.push({method, id, body: req.postDataJSON()});
            return options.status ? reply({detail: privateDetail}, options.status) : reply({id, message: 'ok'});
        }
        return reply({items: [], total: 0});
    });
    try {
        await page.goto(`http://127.0.0.1:${server.address().port}/#users`);
        await run(page, requests);
        assert(siteConfigRequests > 0, 'runtime site config must be loaded');
        assert.deepEqual(telemetryRequests, [], 'default frontend must not send browser telemetry');
        assert.equal(await page.evaluate(() => window.__unsafe), undefined);
        assert.equal(await page.getByText('PRIVATE_BACKEND_DETAIL', {exact: false}).count(), 0);
        await page.screenshot({path: path.join(results, options.name + '.png')});
        reports.push({name: options.name, status: 'passed'});
    } catch (error) {
        reports.push({name: options.name, status: 'failed'});
        await page.screenshot({path: path.join(results, options.name + '-failure.png')});
        throw error;
    } finally { await context.close(); }
}

async function mutation(page, method) {
    const row = page.locator('#users-table-body tr').nth(1);
    await row.waitFor();
    assert((await row.innerText()).includes(display));
    if (method === 'DELETE') {
        assert.equal(await page.locator('#modal-delete-user input#delete-user-id[type="hidden"]').count(), 1);
        await row.locator('button[onclick*="deleteUser"]').click();
        await page.locator('#modal-delete-user.show').waitFor();
        assert.equal(await page.locator('#delete-user-id').inputValue(), ids[1]);
        assert.equal(await page.locator('#delete-user-name').innerText(), display);
        await page.locator('#modal-delete-user button[onclick*="submitDeleteUser"]').click();
    } else {
        await row.locator('button[onclick*="editUser"]').click();
        await page.locator('#modal-user.show').waitFor();
        assert.equal(await page.locator('#user-id').inputValue(), ids[1]);
        await page.locator('#user-fullname').fill('Updated display');
        await page.locator('#modal-user button[onclick*="submitUser"]').click();
    }
}

(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launch({headless: true});
    if (authOnly) {
        await require('./test-auth-browser.cjs')(browser, `http://127.0.0.1:${server.address().port}`, results);
        return;
    }
    for (const method of ['PUT', 'DELETE']) {
        for (const status of [0, 400, 401, 403, 404, 409]) {
            await specimen({name: `${method}-${status || 'allowed'}`, status}, async (page, requests) => {
                await mutation(page, method);
                if (status === 401) {
                    await page.locator('#login-form').waitFor();
                    assert.equal(await page.evaluate(() => sessionStorage.getItem('auth_token')), null);
                } else {
                    const message = status ? (method === 'PUT' ? 'Failed to save user' : 'Failed to delete user')
                        : (method === 'PUT' ? 'User saved successfully' : 'User deleted');
                    await page.getByText(message, {exact: true}).waitFor();
                }
                assert.equal(requests.length, 1);
                assert.equal(requests[0].method, method);
                assert.equal(requests[0].id, ids[1]);
                if (method === 'PUT') assert.deepEqual(requests[0].body, {
                    username: display, full_name: 'Updated display', email: 'same@example.invalid', role: 'admin', is_active: true});
            });
        }
    }
    for (const role of ['viewer', 'operator']) {
        await specimen({name: `denied-${role}`, role, platform: true}, async page => {
            await page.getByText('Access denied', {exact: true}).waitFor();
            await page.evaluate(() => {
                sessionStorage.setItem('current_user', JSON.stringify({role: 'admin', is_platform_admin: true}));
                window.vnbui.navigateTo('users');
            });
            await page.getByText('Access denied', {exact: true}).waitFor();
            assert.equal(await page.locator('#users-table-body, #modal-user, #modal-delete-user').count(), 0);
            assert.equal(await page.locator('#sidebar-menu a[href="#users"]').count(), 0);
        });
    }
    await specimen({name: 'oidc-local-pin', oidc: true}, async (page, requests) => {
        await page.locator('#users-table-body tr').nth(1).locator('button[onclick*="editUser"]').click();
        await page.locator('#modal-user.show').waitFor();
        for (const name of ['username', 'fullname', 'email']) assert(await page.locator('#user-' + name).getAttribute('readonly') !== null);
        assert(await page.locator('#user-role').isDisabled());
        assert(!await page.locator('#user-password-group').isVisible());
        await page.locator('#user-role-source').selectOption('local');
        assert(await page.locator('#user-role').isEnabled());
        await page.locator('#user-role').selectOption('admin');
        await page.locator('#modal-user button[onclick*="submitUser"]').click();
        await page.getByText('User saved successfully', {exact: true}).waitFor();
        assert.deepEqual(requests, [{method: 'PUT', id: ids[1], body: {role_source: 'local', role: 'admin'}}]);
    });
    await specimen({name: 'oidc-return-to-groups', oidc: true, pinned: true}, async (page, requests) => {
        await page.locator('#users-table-body tr').nth(1).locator('button[onclick*="editUser"]').click();
        await page.locator('#modal-user.show').waitFor();
        assert(await page.locator('#user-role').isEnabled());
        await page.locator('#user-role-source').selectOption('oidc');
        assert(await page.locator('#user-role').isDisabled());
        await page.getByText('SSO roles apply on next login. Select local to pin an explicit role.', {exact: true}).waitFor();
        await page.locator('#modal-user button[onclick*="submitUser"]').click();
        await page.getByText('User saved successfully', {exact: true}).waitFor();
        assert.deepEqual(requests, [{method: 'PUT', id: ids[1], body: {role_source: 'oidc'}}]);
    });
    assert.equal(reports.length, 16);
    console.log('PASS: 16 real Chromium Users cases; HTTP fixtures, no live IdP/database evidence; zero skips');
    await require('./test-auth-browser.cjs')(browser, `http://127.0.0.1:${server.address().port}`, results);
    await require('./test-settings-browser.cjs')(browser, `http://127.0.0.1:${server.address().port}`, results);
    await require('./test-licensing-browser.cjs')(browser, `http://127.0.0.1:${server.address().port}`, results);
    reports.push(await require('./test-locale-cache-browser.cjs')(browser, results));
})().catch(error => {console.error(error); process.exitCode = 1;}).finally(async () => {
    fs.writeFileSync(path.join(results, 'results.json'), JSON.stringify({
        commit: process.env.CI_COMMIT_SHA || null,
        artifact_edition: artifactEdition, mode: authOnly ? 'auth-only' : 'full',
        index_sha256: createHash('sha256').update(fs.readFileSync(path.join(root, 'index.html'))).digest('hex'),
        browser: browser?.version(), reports, skips: 0,
    }, null, 2));
    if (browser) await browser.close();
    server.close();
});
