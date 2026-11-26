/* Run against an actual backend: DOCS_BASE_URL=http://127.0.0.1:8000 node this-file. */
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

(async () => {
    const base = (process.env.DOCS_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
    const origin = new URL(base).origin;
    const browser = await chromium.launch({
        headless: true,
        ...(process.env.BROWSER_EXECUTABLE ? {executablePath: process.env.BROWSER_EXECUTABLE} : {}),
        args: ['--no-sandbox'],
    });
    try {
        for (const route of ['/docs', '/redoc']) {
            const page = await browser.newPage();
            const external = [], errors = [], loaded = [];
            await page.route('**/*', async request => {
                if (new URL(request.request().url()).origin !== origin) {
                    external.push(request.request().url());
                    await request.abort();
                } else await request.continue();
            });
            page.on('pageerror', error => errors.push(error.message));
            page.on('console', message => {if (message.type() === 'error') errors.push(message.text());});
            page.on('response', response => {
                if (response.ok()) loaded.push(new URL(response.url()).pathname);
            });
            await page.goto(base + route);
            const operation = route === '/docs'
                ? page.locator('.swagger-ui .opblock').first()
                : page.locator('[data-section-id*="operation/"]').first();
            await operation.waitFor({state: 'visible'});
            if (route === '/redoc') {
                // A query must run through the blob worker and return a result.
                const search = page.getByRole('textbox', {name: 'Search'});
                const heading = await operation.locator('h2').innerText();
                await search.fill(heading.trim());
                await page.locator('[role="search"] li').first().waitFor({state: 'visible'});
            }
            // Include asynchronous branding/worker activity in the observation.
            await page.waitForTimeout(750);
            assert(loaded.some(path => path.endsWith('/openapi.json')), 'OpenAPI loaded');
            assert(loaded.some(path => path.includes('/docs-assets/')), 'local assets loaded');
            assert.deepEqual(external, [], 'zero attempted off-origin requests');
            assert.deepEqual(errors, [], 'zero browser/CSP errors');
            console.log(JSON.stringify({route, loaded, external, errors}));
            await page.close();
        }
    } finally {
        await browser.close();
    }
})().catch(error => {console.error(error); process.exitCode = 1;});
