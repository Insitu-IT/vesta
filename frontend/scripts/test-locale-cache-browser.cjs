/* Real Chromium HTTP-cache regression for the source Translator module. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

module.exports = async function testLocaleCache(browser, results) {
    const source = fs.readFileSync(path.resolve(__dirname, '../src/i18n/translator.js'));
    const labels = {
        stale: {en: 'Old dashboard', he: 'לוח ישן'},
        current: {en: 'Current dashboard', he: 'לוח עדכני'},
    };
    const served = {en: 0, he: 0};
    let generation = 'stale';
    const server = http.createServer((req, res) => {
        const pathname = new URL(req.url, 'http://localhost').pathname;
        if (pathname === '/warm.html' || pathname === '/fresh.html') {
            res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store'});
            res.end(pathname === '/warm.html' ? '<!doctype html><html><body>cache warmup</body></html>' : `
<!doctype html><html><script type="module">
import {Translator} from '/translator.js';
try {
    const translator = new Translator('en');
    await translator.load('en');
    const english = translator.t('nav.dashboard');
    await translator.setLanguage('he');
    window.localeResult = {english, hebrew: translator.t('nav.dashboard'),
        direction: document.documentElement.dir, language: document.documentElement.lang};
} catch (error) { window.localeResult = {error: String(error)}; }
</script></html>`);
            return;
        }
        if (pathname === '/translator.js') {
            res.writeHead(200, {'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store'});
            res.end(source);
            return;
        }
        const match = /^\/locales\/(en|he)\.json$/.exec(pathname);
        if (match) {
            const lang = match[1];
            served[lang]++;
            res.writeHead(200, {'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600'});
            res.end(JSON.stringify({_metadata: {direction: lang === 'he' ? 'rtl' : 'ltr'},
                nav: {dashboard: labels[generation][lang]}}));
            return;
        }
        res.writeHead(404).end();
    });
    const context = await browser.newContext();
    const page = await context.newPage();
    const report = {name: 'locale-cache-browser', status: 'failed', source: 'frontend/src/i18n/translator.js',
        scope: 'source Translator over real same-origin Chromium HTTP cache; no production bundle assertion'};
    try {
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const base = `http://127.0.0.1:${server.address().port}`;
        await page.goto(`${base}/warm.html`);
        const first = await page.evaluate(async () => Promise.all(['en', 'he'].map(async lang =>
            (await (await fetch(`/locales/${lang}.json`)).json()).nav.dashboard)));
        assert.deepEqual(first, [labels.stale.en, labels.stale.he]);
        assert.deepEqual(served, {en: 1, he: 1});

        generation = 'current';
        const cached = await page.evaluate(async () => Promise.all(['en', 'he'].map(async lang =>
            (await (await fetch(`/locales/${lang}.json`)).json()).nav.dashboard)));
        assert.deepEqual(cached, first, 'default fetch must demonstrate the stale browser cache');
        assert.deepEqual(served, {en: 1, he: 1}, 'default fetch must not reach the server');

        await page.goto(`${base}/fresh.html`);
        await page.waitForFunction(() => window.localeResult !== undefined);
        const actual = await page.evaluate(() => window.localeResult);
        assert.deepEqual(actual, {english: labels.current.en, hebrew: labels.current.he,
            direction: 'rtl', language: 'he'});
        assert.deepEqual(served, {en: 2, he: 2}, 'Translator must refetch both cached locale URLs');
        report.status = 'passed';
        report.default_fetch_cached_stale = true;
        report.translator_refetched = true;
        report.server_requests = {...served};
        return report;
    } catch (error) {
        report.error = String(error);
        report.server_requests = {...served};
        throw error;
    } finally {
        fs.writeFileSync(path.join(results, 'locale-cache-browser.json'), JSON.stringify(report, null, 2) + '\n');
        await context.close();
        await new Promise(resolve => server.close(resolve));
    }
};
