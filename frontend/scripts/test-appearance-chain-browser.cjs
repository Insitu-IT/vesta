const licenseFixture = require('./licensing-fixture.cjs');
/* Native Chromium XML parsing over shared raw fixtures and exact helper output. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const fixtureRoot = path.resolve(__dirname, '../../tests/fixtures');
const svgFixtures = JSON.parse(fs.readFileSync(path.join(fixtureRoot, 'visual-assets-svg-v1.json'))).cases;
const prepared = JSON.parse(fs.readFileSync(path.join(fixtureRoot, 'visual-assets-prefixed-pack-v1.json')));

module.exports = async function appearanceChain(browser, origin, results) {
    const files = new Map(prepared.projection.items.map(item => ['/appearance/' + item.path, Buffer.from(prepared.resource.binaryData[item.key], 'base64')]));
    const activePath = `/appearance/packs/${prepared.active_manifest.id}/${prepared.active_manifest.version}`;
    const activeName = prepared.active_manifest.meta.vnbui.product_name;
    const previousName = prepared.previous_manifest.meta.vnbui.product_name;
    const context = await browser.newContext({viewport: {width: 1024, height: 768}});
    const page = await context.newPage();
    const reports = [];
    const writes = [];
    fs.mkdirSync(results, {recursive: true});
    try {
        await page.route('**/appearance/**', route => {
            const file = files.get(new URL(route.request().url()).pathname);
            return file ? route.fulfill({contentType: route.request().url().endsWith('.svg') ? 'image/svg+xml' : 'application/json', body: file}) : route.fulfill({status: 404, body: ''});
        });
        await page.route('**/api/**', route => {
            const request = route.request(), pathname = new URL(request.url()).pathname;
            if (!['GET', 'HEAD'].includes(request.method())) {writes.push({method: request.method(), path: pathname}); return route.abort();}
            const body = pathname === '/api/v1/licensing/status' ? licenseFixture.status() : pathname === '/api/v1/bootstrap' ? {schema_version: 1, edition: 'community', auth_mode: 'single_organization', login_methods: {password: true, oidc: false}} : pathname === '/api/v1/auth/oidc/status' ? {enabled: false} : {};
            return route.fulfill({status: pathname.startsWith('/api/v1/demo/') ? 404 : 200, contentType: 'application/json', body: JSON.stringify(body)});
        });
        await page.route('**/__svg-fixtures/*.svg', route => {
            const name = path.basename(new URL(route.request().url()).pathname, '.svg');
            const fixture = svgFixtures.find(item => item.name === name);
            return fixture ? route.fulfill({contentType: 'image/svg+xml', body: fixture.xml}) : route.fulfill({status: 404, body: ''});
        });
        await page.route('**/site-config.json', route => route.fulfill({contentType: 'application/json', body: '{"apm":{"enabled":false}}'}));
        await page.goto(origin + '/login');
        await page.locator('#login-form').waitFor();
        assert.equal(await page.title(), activeName);
        assert.equal(await page.evaluate(() => window.vnbui.assets.productName), activeName);
        const img = page.locator('.navbar-brand img');
        await img.waitFor();
        await page.waitForFunction(() => {const image = document.querySelector('.navbar-brand img'); return image?.complete && image.naturalWidth > 0;});
        reports.push({name: 'exact-helper-produced-prefixed-pack-activation', status: 'passed'});
        const outcomes = await page.evaluate(async ({fixtures, activePath}) => {
            const Resolver = window.vnbui.assets.constructor;
            const outcomes = [];
            for (const fixture of fixtures) {
                const resolver = new Resolver();
                await resolver.init((url, options) => new URL(url, location.origin).pathname === activePath + '/logo.svg'
                    ? Promise.resolve(new Response(fixture.xml, {status: 200, headers: {'Content-Type': 'image/svg+xml'}}))
                    : fetch(url, options));
                let decoded = null;
                if (fixture.accepted) {
                    const image = new Image();
                    image.src = location.origin + '/__svg-fixtures/' + fixture.name + '.svg';
                    try {await image.decode(); decoded = image.naturalWidth > 0;} catch {decoded = false;}
                }
                outcomes.push({name: fixture.name, accepted: fixture.accepted, productName: resolver.productName, decoded});
            }
            return outcomes;
        }, {fixtures: svgFixtures, activePath});
        for (const outcome of outcomes) {
            assert.equal(outcome.productName, outcome.accepted ? activeName : previousName, outcome.name);
            if (outcome.accepted) assert.equal(outcome.decoded, true, outcome.name + ' must decode as an SVG image');
            reports.push({name: 'raw-xml-' + outcome.name, status: 'passed', image_decoded: outcome.decoded});
        }
        assert.deepEqual(writes, []);
        await page.screenshot({path: path.join(results, 'appearance-prefixed-helper-pack.png')});
        console.log(`PASS: exact helper pack activation + ${svgFixtures.length} native XML appearance cases; HTTP fixtures; zero writes`);
    } catch (error) {
        reports.push({name: 'appearance-chain', status: 'failed', error: error.message});
        await page.screenshot({path: path.join(results, 'appearance-chain-failure.png')});
        throw error;
    } finally {
        fs.writeFileSync(path.join(results, 'appearance-chain-results.json'), JSON.stringify({browser: browser.version(), helper_config_map: prepared.projection.config_map, reports, skips: 0}, null, 2));
        await context.close();
    }
};

if (require.main === module) {
    const http = require('node:http');
    const {chromium} = require('playwright');
    const root = path.resolve(__dirname, '../dist');
    const results = process.env.VNBUI_BROWSER_RESULTS || path.resolve(__dirname, '../browser-results');
    const server = http.createServer((request, response) => {
        const file = path.resolve(root, '.' + decodeURIComponent(new URL(request.url, 'http://localhost').pathname));
        if (file !== root && !file.startsWith(root + path.sep)) {response.writeHead(403).end(); return;}
        const target = fs.existsSync(file) && fs.statSync(file).isFile() ? file : path.join(root, 'index.html');
        const mime = {'.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.html': 'text/html', '.woff2': 'font/woff2'};
        response.setHeader('Content-Type', mime[path.extname(target)] || 'application/octet-stream');
        fs.createReadStream(target).pipe(response);
    });
    let browser;
    (async () => {await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); browser = await chromium.launch({headless: true, args: ['--no-sandbox']}); await module.exports(browser, `http://127.0.0.1:${server.address().port}`, results);})()
        .catch(error => {console.error(error); process.exitCode = 1;})
        .finally(async () => {await browser?.close(); server.close();});
}
