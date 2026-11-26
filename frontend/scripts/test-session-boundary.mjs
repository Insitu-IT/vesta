import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { authService as auth } from '../src/services/auth.service.js';

const store = new Map();
globalThis.sessionStorage = {
    getItem: key => store.get(key) ?? null,
    setItem: (key, value) => store.set(key, value),
    removeItem: key => store.delete(key),
};
let navigation = 0;
globalThis.window = {
    location: {hash: '', pathname: '/login', search: '', replace: path => {
        assert.equal(path, '/login'); navigation++;
    }},
    history: {replaceState: (_, title, path) => {
        assert.equal(path, '/login'); window.location.hash = '';
    }},
};
const token = exp => `fixture.${Buffer.from(JSON.stringify({exp, org_id: 'bound-org'})).toString('base64url')}.fixture`;
const valid = token(Date.now() / 1000 + 60);
const seed = value => {auth.setToken(value); auth.setUser({username: 'prior'});};
const cleared = () => {assert.equal(auth.getToken(), null); assert.equal(auth.getUser(), null);};
for (const value of [null, 'malformed', token(0), token('future')]) {
    seed(value);
    globalThis.fetch = () => {throw new Error('No refresh/request allowed');};
    assert.equal(await auth.restoreSession(), false);
    cleared();
}
for (const failure of ['401', 'network']) {
    seed(valid);
    let calls = 0;
    globalThis.fetch = async () => {
        calls++;
        if (failure === 'network') throw new Error('private transport detail');
        return {ok: false, status: 401};
    };
    assert.equal(await auth.restoreSession(), false);
    assert.equal(calls, 1);
    cleared();
}
window.location.hash = '#access_token=' + valid;
globalThis.fetch = async (url, options) => {
    assert.equal(window.location.hash, ''); // scrubbed before any async identity lookup
    assert.equal(url, '/api/v1/auth/me');
    assert.equal(options.headers.Authorization, 'Bearer ' + valid);
    return {ok: true, json: async () => ({username: 'current', role: 'viewer'})};
};
assert.equal(await auth.restoreSession(), true);
assert.equal(auth.getUser().username, 'current');
window.location.hash = '#access_token=' + valid + '&access_token=extra';
assert.equal(await auth.restoreSession(), false);
cleared();
assert.equal(window.location.hash, '');

for (const value of [null, 'malformed', token(0)]) {
    seed(value);
    globalThis.fetch = () => {throw new Error('Expired bearer must not be refreshed');};
    assert.equal(await auth.refreshAccessToken(), false);
    cleared();
}
seed(valid);
globalThis.fetch = async url => ({ok: true, json: async () => url.endsWith('/refresh')
    ? {access_token: valid} : {username: 'persisted-now', role: 'viewer'}});
assert.equal(await auth.refreshAccessToken(), true);
assert.equal(auth.getUser().username, 'persisted-now');
seed(valid);
globalThis.fetch = async () => ({ok: false, status: 401});
assert.equal(await auth.refreshAccessToken(), false);
cleared();

for (const failure of ['401', 'network']) {
    seed(valid);
    globalThis.fetch = async () => {
        cleared(); // removal and navigation precede even a hung network request
        assert.ok(navigation > 0);
        if (failure === 'network') throw new Error('private transport detail');
        return {ok: false, status: 401};
    };
    await auth.logout();
    cleared();
}
let calls = 0;
const context = vm.createContext({window, URL, URLSearchParams, console: {log() {}}});
const module = new vm.SourceTextModule(fs.readFileSync(new URL('../src/api/client.js', import.meta.url), 'utf8'), {
    context, initializeImportMeta: meta => {meta.env = {DEV: false};},
});
await module.link(specifier => {
    const exports = specifier.includes('operator-requests.service') ? {operatorRequests: {configure() {}, post: (path, data, send) => send(), acknowledge() {}, render() {}}} : specifier.includes('auth.service') ? {authService: auth} : {getVersion: () => 'fixture'};
    return new vm.SyntheticModule(Object.keys(exports), function () {
        for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    }, {context});
});
await module.evaluate();
const client = module.namespace.apiClient;
const form = {fixture: 'multipart body'};
const transports = {
    request: () => client.request('/protected'),
    upload: () => client.upload('/protected', form),
    download: () => client.download('/protected', 'fixture.bin'),
    postForBlob: () => client.postForBlob('/protected', {fixture: true}),
    get: () => client.get('/protected'),
    post: () => client.post('/protected'),
    put: () => client.put('/protected'),
    patch: () => client.patch('/protected'),
    delete: () => client.delete('/protected'),
};
auth.refreshAccessToken = () => {throw new Error('No automatic refresh allowed');};
for (const [name, invoke] of Object.entries(transports)) {
    seed(valid); calls = 0; navigation = 0;
    context.fetch = async (url, options) => {
        calls++;
        assert.equal(url, '/protected');
        assert.equal(options.headers.Authorization, 'Bearer ' + valid);
        return {status: 401, ok: false,
            json: () => {throw new Error('401 body must not be consumed');},
            blob: () => {throw new Error('401 body must not be consumed');}};
    };
    await assert.rejects(invoke(), error => error.status === 401, name);
    assert.equal(calls, 1, name); assert.equal(navigation, 1, name); cleared();

    // Ordinary errors keep custody and their structured error, with no retry.
    seed(valid); calls = 0; navigation = 0;
    context.fetch = async () => {calls++; return {
        ok: false, status: 403, json: async () => ({detail: 'Denied'})};};
    await assert.rejects(invoke(), error => error.status === 403 && error.message === 'Denied', name);
    assert.equal(calls, 1, name); assert.equal(navigation, 0, name);
    assert.equal(auth.getToken(), valid); assert.equal(auth.getUser().username, 'prior');
}
// Successful form, JSON, text and binary responses keep their transport contracts.
const blob = {fixture: 'binary'};
const lifecycle = [];
window.URL = {
    createObjectURL: value => {assert.equal(value, blob); lifecycle.push('create'); return 'blob:fixture';},
    revokeObjectURL: value => {assert.equal(value, 'blob:fixture'); lifecycle.push('revoke');},
};
context.document = {
    createElement: tag => {assert.equal(tag, 'a'); return {click() {
        assert.equal(this.href, 'blob:fixture'); assert.equal(this.download, 'fixture.bin'); lifecycle.push('click');
    }};},
    body: {appendChild() {lifecycle.push('append');}, removeChild() {lifecycle.push('remove');}},
};
for (const name of ['request', 'upload', 'download', 'postForBlob']) {
    calls = 0;
    context.fetch = async (_, options) => {
        calls++;
        if (name === 'upload') {
            assert.equal(options.body, form); assert.equal(options.headers['Content-Type'], undefined);
        }
        if (name === 'postForBlob') {
            assert.equal(options.body, '{"fixture":true}');
            assert.equal(options.headers['Content-Type'], 'application/json');
        }
        return {ok: true, status: 200, headers: {get: () => 'application/json'},
            json: async () => 'json-result', blob: async () => blob};
    };
    const result = await transports[name]();
    assert.equal(result, name === 'download' ? undefined : name === 'postForBlob' ? blob : 'json-result');
    assert.equal(calls, 1);
}
assert.deepEqual(lifecycle, ['create', 'append', 'click', 'remove', 'revoke']);
context.fetch = async () => ({ok: true, status: 200, headers: {get: () => 'text/plain'}, text: async () => 'plain'});
assert.equal(await client.request('/text'), 'plain');
const main = fs.readFileSync(new URL('../src/main.js', import.meta.url), 'utf8');
assert.match(main, /if \(!await authService.restoreSession\(\)\)/);
assert.doesNotMatch(main, /refreshAccessToken/);
assert.ok(main.indexOf('authService.consumeCallbackFragment();') < main.indexOf('await translator.load'));
// Actual API client, synthetic responses: backend-5 skew is not a live server.
const aligned = {contract_version: 6, scope: 'organization-online-agents',
    organization_id: 'fixture-org', status: 'aligned', degraded_mode: false, agents: []};
for (const report of [aligned, {...aligned, status: 'incompatible', degraded_mode: true},
    {status: 'aligned', degraded_mode: false, agents: []},
    {...aligned, contract_version: 5}, {...aligned, scope: 'installation'}, null]) {
    calls = 0;
    context.fetch = async url => {
        calls++; assert.equal(url, '/api/v1/compatibility');
        return {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => report};
    };
    const result = await client.checkCompatibility();
    assert.equal(calls, 1);
    const supported = report?.contract_version === 6 && report.scope === 'organization-online-agents';
    assert.equal(result.status, supported ? report.status : 'unverified');
    assert.equal(client.isDegradedMode(), result.status !== 'aligned');
}
for (const failure of ['503', '401', 'network']) {
    client.compatibilityStatus = aligned;
    seed(valid); calls = 0;
    context.fetch = async () => {
        calls++;
        if (failure === 'network') throw new Error('private network detail');
        return {ok: false, status: Number(failure), json: async () => ({detail: 'private detail'})};
    };
    const report = await client.checkCompatibility();
    assert.equal(report.status, 'unverified');
    assert.equal(client.isDegradedMode(), true);
    assert.equal(calls, 1);
    assert.ok(!JSON.stringify(report).includes('private'));
}
for (const [payload, expected] of [
    [{detail: {code: 'organization_retained', message: 'Organization retains original request custody'}}, 'Organization retains original request custody'],
    [{detail: {code: 'operator_outcome_unresolved'}}, 'operator outcome unresolved'],
    [{detail: 'Legacy refusal'}, 'Legacy refusal'],
    [{detail: [{msg: 'Field required', input: 'PRIVATE-INPUT'}, {msg: 'Invalid UUID'}, {input: 'PRIVATE-INPUT'}]}, 'Field required; Invalid UUID'],
    [{detail: {input: 'PRIVATE-INPUT'}}, 'HTTP 409'],
    [{message: 'Legacy message'}, 'Legacy message'],
]) {
    const error = await client.parseError({status: 409, json: async () => payload});
    assert.equal(error.message, expected);
    assert.equal(typeof error.message, 'string');
    assert.equal(error.data, payload);
    assert(!error.message.includes('PRIVATE-INPUT'));
    assert(!error.message.includes('[object Object]'));
}
console.log('PASS: session cleanup, fragment replacement, startup refusal and single-request 401');
