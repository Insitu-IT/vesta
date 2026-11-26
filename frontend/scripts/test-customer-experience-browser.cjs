const licenseFixture = require('./licensing-fixture.cjs');
/* Real Chromium + production output; synthetic APIs only, no customer access. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

module.exports = async function customerExperience(browser, baseURL, results) {
    const reports = [];
    fs.mkdirSync(results, {recursive: true});
    const agentId = '20000000-0000-0000-0000-000000000001';
    const vmiUid = '50000000-0000-0000-0000-000000000001';
    const agent = {id: agentId, hostname: 'technical-agent', display_name: 'Production cluster', status: 'online', vm_count: 110,
        capabilities: {provider: 'kubevirt', backup_method: 'kubevirt_pull_transaction'},
        config: {selected_source_namespaces: ['protected'], scope_revision: 4},
        metrics: {provider: 'kubevirt', health_status: 'degraded', backup_storage_free_bytes: 0, backup_storage_total_bytes: 0,
            scope: {source_namespaces: ['protected', 'extra'], selected_source_namespaces: ['protected'], restore_namespaces: ['restored'], scratch_pvcs: {protected: 'scratch'}, applied_revision: 3}}};
    const summary = {vms: {total: 110, by_status: {Running: 60, Stopped: 10, Shutoff: 10, Paused: 10, Unavailable: 10, Unknown: 10}, by_agent: Array.from({length: 16}, (_, i) => ({agent_id: 'chart-agent-' + i, name: 'Agent group ' + i, count: i === 0 ? 95 : 1}))},
        agents: {total: 16, online: 1}, backups: {total: 5, last_24h: 5, by_status: {completed: 3, held: 2}, period_start: '2026-10-29T12:00:00Z', period_end: '2026-10-30T12:00:00Z'},
        schedules: {upcoming: 2}, attention: {held_jobs: 2, held_backups: 0}, recent_backups: [], running_backups: []};
    for (const lang of ['en', 'he']) for (const width of [1920, 1440, 390, 375]) {
        const name = `customer-${lang}-${width}`;
        const context = await browser.newContext({viewport: {width, height: 947}, locale: lang === 'he' ? 'he-IL' : 'en-US'});
        const page = await context.newPage();
        const writes = [];
        const pageErrors = [];
        const externalRequests = [];
        await page.route('**/*', route => {
            if (new URL(route.request().url()).origin !== new URL(baseURL).origin) {externalRequests.push(route.request().url()); return route.abort('blockedbyclient');}
            return route.continue();
        });
        page.on('pageerror', error => pageErrors.push(error.message));
        page.setDefaultTimeout(12000);
        const token = ['fixture', Buffer.from(JSON.stringify({exp: 4102444800})).toString('base64url'), 'fixture'].join('.');
        await context.addInitScript(({lang, token}) => {if (!sessionStorage.getItem('customer-initialized')) {sessionStorage.setItem('auth_token', token); sessionStorage.setItem('customer-initialized', '1');} localStorage.setItem('preferredLanguage', lang);}, {lang, token});
        await page.route('**/appearance/**', route => {
            const url = new URL(route.request().url());
            const reply = body => route.fulfill({contentType: 'application/json', body: JSON.stringify(body)});
            if (url.pathname === '/appearance/config.json') return reply({schema_version: 1, active_pack: '/appearance/packs/invalid-pack/1.0.0', previous_pack: '/appearance/packs/customer-pack/1.0.0'});
            if (url.pathname.includes('invalid-pack')) return reply({schema_version: 2});
            if (url.pathname.endsWith('manifest.json')) return reply({schema_version: 1, id: 'customer-pack', version: '1.0.0', name: 'Customer pack', type: 'theme', variant_schema: {edition: {values: ['oss', 'commercial'], default: 'oss'}, theme: {values: ['light', 'dark'], default: 'light'}}, assets: Object.fromEntries(['brand-logo', 'brand-favicon'].map(key => [key, {content_type: 'image/svg+xml', variants: {'oss/light': 'logo-light.svg', 'oss/dark': 'logo-dark.svg', 'commercial/light': 'commercial-light.svg', 'commercial/dark': 'commercial-dark.svg'}, default: 'logo-light.svg'}])), meta: {vnbui: {schema_version: 2, product_name: 'Customer Backup', colors: {primary: '#19655b'}, theme_colors: {dark: {primary: '#88CDB8'}}, density: 'compact'}}});
            return route.fulfill({contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#19655b"/></svg>'});
        });
        await page.route('**/api/**', route => {
            const req = route.request(), url = new URL(req.url());
            const reply = (body, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(body)});
            if (!['GET', 'HEAD'].includes(req.method())) {writes.push({path: url.pathname, method: req.method(), body: req.postDataJSON()}); return reply({});}
            if (url.pathname.startsWith('/api/v1/demo/')) return reply({}, 404);
            if (url.pathname === '/api/v1/licensing/status') return reply(licenseFixture.status(true));
            if (url.pathname === '/api/v1/licensing') return reply(licenseFixture.details(licenseFixture.status(true)));
            if (url.pathname === '/api/v1/bootstrap') return reply({schema_version: 1, edition: 'community', auth_mode: 'single_organization', login_methods: {password: true, oidc: false}});
            if (url.pathname === '/api/v1/auth/me') return reply({id: 'actor', org_id: 'tenant', username: 'admin-user', role: 'admin', is_active: true, auth_source: 'local', is_platform_admin: true, can_manage_installation: true});
            if (url.pathname === '/api/v1/auth/oidc/status') return reply({enabled: false});
            if (url.pathname === '/api/v1/compatibility') return reply({contract_version: 6, scope: 'organization-online-agents', organization_id: 'tenant', agents: [], warnings: [], status: 'aligned', degraded_mode: false});
            if (url.pathname === '/api/v1/features') return reply({});
            if (url.pathname === '/api/v1/dashboard/summary') return reply(summary);
            if (url.pathname === '/api/v1/health') return reply({status: 'degraded', timestamp: '2026-10-31T01:41:24Z',
                agents: {status: 'degraded', online: 2, total: 3, healthy: 2}, storage: {status: 'healthy', used_space: 307680000000, backup_count: 17},
                database: {status: 'healthy', response_time: 2, connections: 7, max_connections: 100}, api: {status: 'healthy', version: '6.0.56'},
                s3: {configured: true, status: 'healthy', endpoint: 'https://hel1.your-objectstorage.com', bucket: 'my-objectstorage'},
                metrics: {total_vms: 110}, services: []});

            if (url.pathname === '/api/v1/vms') return reply({items: [{id: '40000000-0000-0000-0000-000000000001', name: 'A realistic long VM name for narrow layouts', agent_id: agentId, agent_hostname: 'Production cluster', state: 'Running', memory_kb: 1048576, vcpu_count: 2, inventory_present: true, vmi_uid: vmiUid, metadata: {changed_block_tracking: {state: 'Enabled', source: 'vmi'}}, disks: [{target: 'vdb', capacity_bytes: null}, {target: 'vda', capacity_bytes: 10737418240}, {target: 'vdc', capacity_bytes: 21474836480}, {target: 'sda', device: 'cdrom', capacity_bytes: 9000}]}], total: 1});
            if (url.pathname === '/api/v1/agents') return reply([agent]);
            if (url.pathname === `/api/v1/agents/${agentId}`) return reply(agent);
            if (url.pathname === '/api/v1/backups' && url.searchParams.get('status') === 'completed') return reply({items: [{id: '30000000-0000-0000-0000-000000000001', vm_name: 'Example VM'}]});
            return reply({items: [], total: 0});
        });
        try {
            await page.goto(`${baseURL}/arbitrary.path?fixture=retained#vms`);
            await page.locator('#vm-search').waitFor();
            assert.equal(new URL(page.url()).pathname, '/');
            assert.equal(new URL(page.url()).search, '?fixture=retained');
            assert.equal(new URL(page.url()).hash, '#vms');
            assert.equal(await page.locator('#backup-workers').count(), 0, 'unsupported per-backup workers are not editable');
            assert.equal(await page.locator('#vms-table-body .disk-summary').count(), 2, 'inventory shows the first two actual disks');
            assert((await page.locator('#vms-table-body .disk-summary').first().innerText()).includes('vda: 10 GiB'));
            assert((await page.locator('#vms-table-body').innerText()).includes(await page.evaluate(() => window.t('inventory.capacity_unknown'))));
            assert((await page.locator('#vms-table-body').innerText()).includes(await page.evaluate(() => window.t('inventory.more_disks', {count: 1}))));
            await page.locator('#vms-table-body').getByText(`VMI: ${vmiUid}`, {exact: true}).waitFor();

            assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'VM list must not widen the page');
            const search = page.locator('#vm-search');
            const perimeter = await search.evaluate(input => {
                const group = input.closest('.search-control'), icon = group.querySelector('.input-group-text');
                const box = group.getBoundingClientRect(), textBox = input.getBoundingClientRect(), iconBox = icon.getBoundingClientRect();
                const css = getComputedStyle(group), iconCss = getComputedStyle(icon);
                return {left: box.left, right: box.right, viewport: innerWidth, borders: [css.borderLeftWidth, css.borderRightWidth, css.borderTopWidth, css.borderBottomWidth], radii: [css.borderTopLeftRadius, css.borderTopRightRadius, css.borderBottomLeftRadius, css.borderBottomRightRadius], overlap: Math.min(textBox.right, iconBox.right) - Math.max(textBox.left, iconBox.left), padding: [iconCss.paddingLeft, iconCss.paddingRight]};
            });
            assert(perimeter.left >= 0 && perimeter.right <= perimeter.viewport + 1, 'search stays inside narrow viewport');
            assert(perimeter.borders.every(value => parseFloat(value) >= 1), 'search perimeter has all four borders');
            assert(perimeter.radii.every(value => parseFloat(value) > 0), 'search perimeter has complete corners in either direction');
            assert(perimeter.padding.every(value => parseFloat(value) > 0), 'icon has balanced space in either direction');
            assert(perimeter.overlap <= 1, 'search input and icon do not overlap');
            await search.focus();
            assert.notEqual(await search.evaluate(input => getComputedStyle(input.closest('.search-control')).boxShadow), 'none', 'keyboard focus has visible outline');
            const clearedSearch = page.waitForResponse(response => {const url = new URL(response.url()); return url.pathname === '/api/v1/vms' && !url.searchParams.get('search');});
            await search.fill('Long search phrase that must fit without overlapping the icon');
            await search.fill('');
            await clearedSearch;
            await page.locator('#vm-search').waitFor();
            await page.evaluate(() => window.vnbui.navigateTo('dashboard'));

            await page.locator('#vm-states').waitFor();
            assert.equal(await page.title(), 'Customer Backup', 'invalid active pack must use previous pack');
            assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--tblr-primary').trim()), '#19655b');
            assert.equal(await page.locator('html').getAttribute('dir'), lang === 'he' ? 'rtl' : 'ltr');
            assert.equal(await page.locator('#page-content canvas').count(), 3);
            const categories = await page.evaluate(() => {
                const current = window.vnbui.currentPage;
                const states = current.chartData.find(data => data.id === 'vm-states');
                const agents = current.chartData.find(data => data.id === 'vm-agents');
                return {stateColors: states.colors, canvasColors: current.charts.find(chart => chart.canvas.id === 'vm-states').data.datasets[0].backgroundColor, stateLabels: states.entries.map(entry => entry.label), groupStyles: agents.entries.map(entry => `${entry.color}/${entry.pattern}`)};
            });
            assert.equal(new Set(categories.stateColors).size, 6, 'actual Running/Stopped/Shutoff/Paused/Unavailable/Unknown have distinct colors');
            assert.deepEqual(categories.canvasColors, categories.stateColors, 'canvas and legend category colors agree');
            assert.equal(new Set(categories.stateLabels).size, 6, 'state labels remain distinct');
            assert.equal(new Set(categories.groupStyles).size, 16, 'more than seven agent groups remain distinguishable');
            const beforeFavicon = await page.locator('link[rel="icon"]').getAttribute('href');
            const sidebarBefore = await page.locator('aside [data-vnbui-asset="brand-logo"]').getAttribute('src');
            assert(sidebarBefore.endsWith('/logo-dark.svg'), 'dark sidebar always requests dark artwork');
            const modeButton = page.locator((width >= 1440 ? 'header' : 'aside') + ' [data-theme-toggle]');
            await modeButton.click();
            await page.waitForFunction(() => document.documentElement.dataset.bsTheme === 'dark');
            await page.waitForFunction(previous => document.querySelector('link[rel="icon"]').getAttribute('href') !== previous, beforeFavicon);
            assert.equal(await page.locator('aside [data-vnbui-asset="brand-logo"]').getAttribute('src'), sidebarBefore);
            assert.equal(await page.locator('aside [data-vnbui-asset="brand-logo"]').evaluate(node => getComputedStyle(node).filter), 'none');
            await page.reload();
            await page.locator('#vm-states').waitFor();
            assert.equal(await page.locator('html').getAttribute('data-bs-theme'), 'dark', 'saved theme survives reload');
            await modeButton.click();
            await page.waitForFunction(() => document.documentElement.dataset.bsTheme === 'light');
            await page.waitForFunction(previous => document.querySelector('link[rel="icon"]').getAttribute('href') === previous, beforeFavicon);

            assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'dashboard must not overflow the page');
            const chart = await page.locator('#vm-states').boundingBox();
            const legend = await page.locator('.dashboard-chart-legend').first().boundingBox();
            assert(legend.width <= 241, 'legend counts must remain close to labels');
            if (width >= 1440) {const charts = await page.locator('.dashboard-chart-canvas').evaluateAll(nodes => nodes.map(node => node.closest('.card').getBoundingClientRect().y)); assert(Math.max(...charts) - Math.min(...charts) < 2, 'wide dashboard uses one chart row');}
            if (width < 600) assert(legend.y > chart.y + chart.height - 1, 'narrow legends stack below canvas');
            else assert(legend.y >= chart.y - legend.height, 'desktop legend stays alongside or below canvas without clipping');
            if (width >= 1440) {
                const profile = await page.locator('header .nav-item.dropdown > a').evaluate(el => {const a = el.querySelector('.avatar').getBoundingClientRect(), text = el.querySelector('.d-xl-block').getBoundingClientRect(); return {gap: document.dir === 'rtl' ? a.left - text.right : text.left - a.right};});
                assert(profile.gap >= 7, 'avatar and profile text must have a visible gap');
                const role = await page.locator('header .small').innerText(); assert.notEqual(role, 'admin');
            }
            const profileToggle = page.locator((width >= 1440 ? 'header' : 'aside') + ' .nav-item.dropdown > a');
            await profileToggle.click();
            const profileItem = page.locator(width >= 1440 ? '#profile-btn' : '#profile-btn-mobile');
            await profileItem.waitFor({state: 'visible'});
            assert.equal(await profileItem.evaluate(el => getComputedStyle(el).gap), '8px', 'profile dropdown preserves item icon gap');
            await profileToggle.click();
            await page.screenshot({path: path.join(results, name + '-dashboard.png')});
            await page.evaluate(() => window.vnbui.navigateTo('verification'));
            await page.locator('#verification-backup').waitFor();
            const hint = page.locator('.context-help summary').first();
            await hint.focus();
            assert.equal(await hint.locator('..').locator('.context-help-copy').isVisible(), true, 'help is readable on keyboard focus');
            await page.keyboard.press('Escape');
            assert.equal(await hint.locator('..').locator('.context-help-copy').isVisible(), false, 'Escape dismisses focused help');
            await hint.click();
            assert.equal(await hint.locator('..').getAttribute('open'), '', 'native disclosure opens on touch-style click');
            await page.locator('.page-header .page-title').click({position: {x: 2, y: 2}});
            assert.equal(await hint.locator('..').getAttribute('open'), null, 'a reachable outside interaction closes help');

            assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'verification table must scroll inside its card');
            const select = await page.locator('#verification-backup').boundingBox();
            const button = await page.locator('button[onclick*="startVerification"]').boundingBox();
            assert(width < 600 ? button.y >= select.y + select.height : Math.abs(button.y - select.y) <= 2, 'verification selector and Start layout');
            assert.equal(await page.locator('.badge').filter({hasText: /^0%$/}).count(), 0, 'empty history is no percentage');
            if (lang === 'he') assert.equal(await page.locator('#verification-backup').evaluate(el => parseFloat(getComputedStyle(el).backgroundPosition) <= 20 || getComputedStyle(el).backgroundPosition.includes('left')), true);
            await page.screenshot({path: path.join(results, name + '-verification.png')});
            await page.evaluate(() => window.vnbui.navigateTo('agents'));
            await page.locator('button[onclick*="viewAgentDetails"], a[onclick*="viewAgentDetails"]').first().waitFor({state: 'attached'});
            const agentText = await page.locator('#page-content').innerText();
            if (lang === 'he') assert(!agentText.includes('degraded') && !agentText.includes('online'));
            assert(!agentText.includes('0% of 0'), 'unknown capacity must not imply zero space');
            assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'agents table must scroll inside its card');
            await page.locator('.table [data-bs-toggle="dropdown"]').first().click();
            const menu = page.locator('.table .dropdown-menu.show');
            await menu.waitFor({state: 'visible'});
            assert.equal(await menu.evaluate(el => getComputedStyle(el).position), width < 600 ? 'fixed' : 'absolute');
            await menu.locator('[onclick*="viewAgentDetails"]').click();
            await page.locator('#modal-agent-details.show').waitFor();
            await page.locator('#agent-settings-tab').click();
            await page.locator('#agent-setting-selected_source_namespaces').waitFor({state: 'visible'});
            assert((await page.locator('#agent-provider-settings').innerText()).includes('protected: scratch'));
            assert.equal(await page.locator('#agent-setting-backup_timeout').count(), 0);
            assert.equal(await page.locator('#agent-setting-libvirt_uri').count(), 0);
            assert.equal(await page.locator('#agent-setting-compression_type').count(), 0);
            await page.locator('#agent-setting-log_level').selectOption('WARNING');
            assert.equal(await page.locator('#agent-setting-log_level').inputValue(), 'WARNING');
            await page.locator('#agent-setting-selected_source_namespaces').fill('outside');
            await page.locator('#agent-settings-save-btn').click();
            assert.equal(writes.length, 0, 'out-of-ceiling selection must not reach API');
            assert((await page.locator('.toast-container').innerText()).length > 0);
            if (width >= 1440) await page.screenshot({path: path.join(results, name + '-scope.png')});
            if (lang === 'en' && width >= 1440) {
                await page.locator('#agent-setting-selected_source_namespaces').fill('protected');
                await page.locator('#agent-setting-heartbeat_interval').fill('30');
                page.once('dialog', dialog => dialog.accept());
                await page.locator('#agent-settings-save-btn').click();
                await page.locator('#modal-agent-details').waitFor({state: 'hidden'});
                assert.deepEqual(writes, [{path: `/api/v1/agents/${agentId}/settings`, method: 'PATCH', body: {heartbeat_interval: 30, log_level: 'WARNING', selected_source_namespaces: ['protected']}}]);
            }
            if (await page.locator('#modal-agent-details.show').count()) {
                await page.locator('#modal-agent-details .modal-header [data-bs-dismiss="modal"]').click();
                await page.locator('#modal-agent-details').waitFor({state: 'hidden'});
            }
            await page.evaluate(() => window.vnbui.navigateTo('health'));
            await page.locator('#health-components').waitFor({state: 'visible'});
            const cards = await page.locator('#health-components > .col').evaluateAll(elements => elements.map(el => {
                const box = el.getBoundingClientRect();
                return {x: box.x, y: box.y, width: box.width};
            }));
            assert.equal(cards.length, 5);
            assert(cards.every(card => card.width >= (width === 1440 ? 190 : 250)), 'health component cards must have readable width');
            if (width < 600) assert(cards.every((card, i) => i === 0 || card.y > cards[i - 1].y), 'narrow health cards must stack');
            else assert(cards.every(card => Math.abs(card.y - cards[0].y) <= 2), 'desktop health cards retain one row');
            const status = await page.locator('#health-overall h1').boundingBox();
            const checked = await page.locator('#health-last-check').boundingBox();
            assert(status.width >= 140 && status.height < 72, 'overall status must remain readable');
            if (width < 600) assert(checked.y >= status.y + status.height, 'narrow last-check timestamp belongs below status');
            assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'health must not overflow');
            await page.screenshot({path: path.join(results, name + '-health.png')});
            const writesBeforeLogin = writes.length;
            await page.evaluate(() => sessionStorage.removeItem('auth_token'));
            await page.goto(`${baseURL}/login`);
            await page.locator('#login-form').waitFor();
            assert.equal(await page.locator('#login-organization').count(), 0);
            const loginBrand = page.locator('.navbar-brand [data-vnbui-asset="brand-logo"]');
            assert((await loginBrand.getAttribute('src')).endsWith('/logo-light.svg'));
            await page.locator('[data-theme-toggle]').click();
            await page.waitForFunction(() => document.querySelector('.navbar-brand [data-vnbui-asset="brand-logo"]')?.getAttribute('src')?.endsWith('/logo-dark.svg'));
            await page.locator('[data-theme-toggle]').click();
            await page.waitForFunction(() => document.querySelector('.navbar-brand [data-vnbui-asset="brand-logo"]')?.getAttribute('src')?.endsWith('/logo-light.svg'));
            assert.equal(writes.length, writesBeforeLogin, 'appearance acceptance sends no writes');
            assert.deepEqual(pageErrors, []);
            assert.deepEqual(externalRequests, [], 'airgapped UI attempts no external asset requests');
            reports.push({name, status: 'passed', api_writes: writes.length});
        } catch (error) {
            reports.push({name, status: 'failed', error: error.message});
            await page.screenshot({path: path.join(results, name + '-failure.png')});
            throw error;
        } finally {
            fs.writeFileSync(path.join(results, 'customer-experience-results.json'), JSON.stringify({browser: browser.version(), reports, expected: 8, skips: 0}, null, 2));
            await context.close();
        }
    }
    await require('./test-appearance-chain-browser.cjs')(browser, baseURL, results);
    console.log('PASS: 8 Chromium customer UI fixtures at 1920/1440/390/375px in English/Hebrew; no customer access; supported synthetic settings payload verified');
};

if (require.main === module) {
    const http = require('node:http');
    const {chromium} = require('playwright');
    const root = path.resolve(__dirname, '../dist');
    const results = process.env.VNBUI_BROWSER_RESULTS || path.resolve(__dirname, '../browser-results');
    const server = http.createServer((req, res) => {
        const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
        const file = path.resolve(root, '.' + pathname);
        if (!file.startsWith(root + path.sep) && file !== root) {res.writeHead(403).end(); return;}
        const target = fs.existsSync(file) && fs.statSync(file).isFile() ? file : path.join(root, 'index.html');
        const mime = {'.js':'application/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.html':'text/html','.woff2':'font/woff2'};
        res.setHeader('Content-Type', mime[path.extname(target)] || 'application/octet-stream');
        fs.createReadStream(target).pipe(res);
    });
    let browser;
    (async () => {await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); browser = await chromium.launch({headless: true, args: ['--no-sandbox']}); await module.exports(browser, `http://127.0.0.1:${server.address().port}`, results);})()
        .catch(error => {console.error(error); process.exitCode = 1;})
        .finally(async () => {await browser?.close(); server.close();});
}
