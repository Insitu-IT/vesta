import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const locales = Object.fromEntries(['en', 'he'].map(language => [language,
    JSON.parse(fs.readFileSync(new URL(`../public/locales/${language}.json`, import.meta.url)))]));
const maintenanceKeys = ['admission_maintenance', 'admission_maintenance_hint'];
const staleLocales = structuredClone(locales);
for (const locale of Object.values(staleLocales)) {
    for (const key of maintenanceKeys) delete locale.settings[key];
}
let translator, confirm = false, failure = false;
const t = key => translator.t(key);
const localeRequests = [];
const fetchLocale = async (url, options) => {
    const language = /^\/locales\/(en|he)\.json$/.exec(url)?.[1];
    assert.ok(language, `Unexpected locale URL: ${url}`);
    const cache = options?.cache;
    localeRequests.push({url, cache});
    return {ok: true, json: async () => (cache === 'no-store' ? locales : staleLocales)[language]};
};
const nodes = new Map([
    ['setting-admission-limit', {value: '1'}], ['setting-admission-paused', {checked: false}],
    ['setting-admission-maintenance', {checked: false}],
    ['save-admission-policy', {disabled: false}], ['admission-policy-result', {textContent: ''}],
]);
const writes = [];
let settings = {};
const apiClient = {get: async () => ({settings}), put: async (path, body) => {
    writes.push({path, body: JSON.parse(JSON.stringify(body))});
    if (failure) throw new Error('private-error-token');
}};
const context = vm.createContext({console, fetch: fetchLocale, window: {t, confirm: () => confirm},
    document: {documentElement: {}, getElementById: id => nodes.get(id) || null}});
const translatorModule = new vm.SourceTextModule(fs.readFileSync(
    new URL('../src/i18n/translator.js', import.meta.url), 'utf8'), {context});
await translatorModule.link(() => assert.fail('Unexpected translator import'));
await translatorModule.evaluate();
const module = new vm.SourceTextModule(fs.readFileSync(
    new URL('../src/pages/settings.js', import.meta.url), 'utf8'), {context});
await module.link(specifier => {
    const values = specifier.includes('authenticated-startup') ? {startAuthenticatedServices: async () => {}}
        : specifier.includes('installation.service') ? {installationService: {}}
            : specifier.includes('theme.service') ? {themeService: {button: () => ''}}
            : specifier.includes('vm-inventory') ? {renderDiskSummary: () => '', renderCbtObservation: () => ''}
            : specifier.includes('components/licensing') ? {refreshLicenseBanner: () => {}, LicensingPanel: class {async load() {} render() {return '';} mount() {}}}
            : specifier.includes('context-help') ? {contextHelp: () => ''}
            : specifier.includes('client') ? {apiClient}
        : specifier.includes('security') ? {escapeHtml: value => String(value)} : {authService: {}};
    return new vm.SyntheticModule(Object.keys(values), function () {
        for (const [key, value] of Object.entries(values)) this.setExport(key, value);
    }, {context});
});
await module.evaluate();
for (const language of ['en', 'he']) {
    translator = new translatorModule.namespace.Translator();
    await translator.load(language);
    assert.deepEqual(localeRequests.at(-1), {url: `/locales/${language}.json`, cache: 'no-store'});
    const page = new module.namespace.SettingsPage();
    assert.ok(page.renderAdmissionSettings().includes('disabled'));
    await page.saveAdmissionPolicy();
    const before = writes.length;
    await page.loadV3Settings(); // Missing projection is NOT a known absent policy.
    assert.equal(page.v3Loaded, false);
    settings = {'backup.capacity_admission': null};
    await page.loadV3Settings(); // An older server cannot supply the new pause contract.
    assert.equal(page.v3Loaded, false);
    settings = {'backup.capacity_admission': null, 'backup.admission_pause': null};
    await page.loadV3Settings();
    assert.equal(page.v3Loaded, true);
    const markup = page.renderAdmissionSettings();
    assert.ok(markup.includes('checked'));
    for (const key of maintenanceKeys) {
        assert.ok(markup.includes(locales[language].settings[key]));
        assert.ok(!markup.includes(`settings.${key}`));
    }
    confirm = false;
    await page.saveAdmissionPolicy();
    assert.equal(writes.length, before);
    confirm = true;
    nodes.get('setting-admission-paused').checked = false;
    await page.saveAdmissionPolicy();
    assert.deepEqual(writes.at(-1), {path: '/api/v1/settings/v3', body: {
        'backup.capacity_admission': {schema: 1, revision: 1, limit: 1, maintenance: false},
        'backup.admission_pause': {schema: 1, revision: 1, paused: false},
    }});
    nodes.get('setting-admission-paused').checked = true;
    await page.saveAdmissionPolicy();
    assert.equal(writes.at(-1).body['backup.capacity_admission'].revision, 1);
    assert.equal(writes.at(-1).body['backup.capacity_admission'].maintenance, false);
    assert.deepEqual(writes.at(-1).body['backup.admission_pause'], {schema: 1, revision: 2, paused: true});
    nodes.get('setting-admission-maintenance').checked = true;
    confirm = false;
    const beforeMaintenance = writes.length;
    await page.saveAdmissionPolicy();
    assert.equal(writes.length, beforeMaintenance);
    confirm = true;
    await page.saveAdmissionPolicy();
    assert.equal(writes.at(-1).body['backup.capacity_admission'].maintenance, true);
    assert.equal(writes.at(-1).body['backup.admission_pause'].paused, true);
    const validWrites = writes.length;
    for (const value of ['0', '100001', '1.5', 'NaN', '1e2', '']) {
        nodes.get('setting-admission-limit').value = value;
        await page.saveAdmissionPolicy();
    }
    assert.equal(writes.length, validWrites);
    nodes.get('setting-admission-limit').value = '1';
    failure = true;
    await page.saveAdmissionPolicy();
    assert.equal(page.v3Loaded, false);
    assert.equal(nodes.get('save-admission-policy').disabled, true);
    assert.equal(nodes.get('admission-policy-result').textContent, t('settings.admission_save_failed'));
    await page.saveAdmissionPolicy();
    assert.equal(writes.length, validWrites + 1); // No retry/rebase on unknown outcome.
    failure = false;
    settings = {};
    nodes.get('setting-admission-paused').checked = false;
    nodes.get('setting-admission-maintenance').checked = false;
    page.v3Settings = {'backup.capacity_admission': {schema: 1, revision: 3, limit: '<script>', maintenance: false}};
    assert.ok(!page.renderAdmissionSettings().includes('<script>'));
}
console.log('PASS: explicit safe admission settings');
