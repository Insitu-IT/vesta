import {enumLabel, storageCapacity} from '../src/utils/status-labels.js';
import {agentProvider, selectedNamespaces} from '../src/utils/agent-scope.js';
// No browser/dependency download: run the real service and rendered login method.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { authService } from '../src/services/auth.service.js';

const values = new Map();
globalThis.sessionStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
};
const org = 'd321cd87-74d5-4a1d-9a34-e2d8e0e6af80';
for (const selection of ['', '  ', ` ${org} `]) {
    const calls = [];
    globalThis.fetch = async (url, options) => {
        calls.push({url, options});
        return {ok: true, json: async () => url.endsWith('/login')
            ? {access_token: 'test-token'} : {username: 'viewer', org_id: org, role: 'viewer'}};
    };
    await authService.login('viewer', 'test-password', selection);
    assert.equal(calls[0].options.headers['Content-Type'], 'application/x-www-form-urlencoded');
    assert.equal(calls[0].options.body.get('org_id'), selection.trim() || null);
    assert.equal(calls[0].options.body.get('password'), 'test-password');
    assert.equal(calls[1].url, '/api/v1/auth/me');
    assert.equal(calls[1].options.headers.Authorization, 'Bearer test-token');
}
for (const failure of ['login-denied', 'identity-denied']) {
    globalThis.fetch = async url => ({
        ok: url.endsWith('/login') && failure === 'identity-denied',
        json: async () => ({access_token: 'unverified', detail: 'Denied'}),
    });
    await assert.rejects(authService.login('viewer', 'test-password', org));
    assert.equal(authService.getToken(), null);
    assert.equal(authService.getUser(), null);
}
globalThis.fetch = async () => ({ok: false, json: async () => {
    assert.fail('A denied login must not decode private backend error detail');
}});
await assert.rejects(authService.login('viewer', 'test-password', org), {message: 'Login failed'});
assert.equal(authService.getToken(), null);
assert.equal(authService.getUser(), null);

const wire = [];
const SocketDouble = class {
    static OPEN = 1;
    constructor(url, protocols) {
        wire.push({url, protocols}); this.readyState = 0;
        queueMicrotask(() => {this.readyState = SocketDouble.OPEN; this.onopen?.();});
    }
    close() {this.readyState = 3;}
};
const socketContext = vm.createContext({console, WebSocket: SocketDouble,
    setTimeout, clearTimeout, setInterval, clearInterval});
const socketModule = new vm.SourceTextModule(fs.readFileSync(new URL('../src/services/updates.service.js', import.meta.url), 'utf8'), {context: socketContext});
await socketModule.link(specifier => {
    const exports = specifier === './auth.service.js' ? {authService} : {apiClient: {get: async () => ({enableWebSocket: true, enablePolling: false})}};
    return new vm.SyntheticModule(Object.keys(exports), function () {
        for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    }, {context: socketContext});
});
await socketModule.evaluate();
const {updateService} = socketModule.namespace;
authService.setToken('fixture-socket-credential');
updateService.getWebSocketUrl = () => 'wss://example.invalid/ws';
updateService.handleConnectionFailure = () => {};
await updateService.connectWebSocket();
assert.equal(wire.length, 0, 'Inactive transport never connects before authenticated startup');
await updateService.initialize();
assert.equal(updateService.connectionMode, 'websocket');
assert.deepEqual(JSON.parse(JSON.stringify(wire)), [{url: 'wss://example.invalid/ws', protocols: ['vnbui', 'bearer.fixture-socket-credential']}]);
const logged = [];
const oldError = console.error, oldLog = console.log;
console.error = (...args) => logged.push(args);
console.log = (...args) => logged.push(args);
const socket = updateService.ws;
const onError = socket.onerror, onClose = socket.onclose;
onError({target: {url: 'fixture-socket-credential'}});
onClose({code: 1000, reason: 'fixture-socket-credential'});
console.error = oldError; console.log = oldLog;
assert(!JSON.stringify(logged).includes('fixture-socket-credential'));
updateService.destroy();
assert.equal(updateService.healthInterval, null);
assert.equal(updateService.reconnectTimer, null);
authService.clearToken();

// Execute App.showLogin unchanged. Replace unrelated imported services explicitly;
// this is a DOM-contract test, not a browser/layout or backend-RLS assertion.
const elements = {
    app: {innerHTML: ''},
    'login-error': {style: {}, textContent: ''},
    'login-form': {addEventListener: (_, fn) => { elements.submit = fn; }},
};
const context = vm.createContext({
    window: {location: {hash: ''}, t: key => key},
    document: {getElementById: id => elements[id]},
    URLSearchParams,
});
const loginCalls = [];
const modules = {
    './services/authenticated-startup.js': {startAuthenticatedServices: async () => {}},
    './utils/status-labels.js': {enumLabel: (value, domain) => enumLabel(value, domain, context.window.t), storageCapacity},
    './utils/agent-scope.js': {agentProvider, selectedNamespaces},
    './components/licensing.js': {refreshLicenseBanner() {}, renderLicenseSummary() {}, LicensingPanel: class {}},
    './services/licensing.service.js': {licensingService: {}},
    './utils/backup-guidance.js': {bindBackupGuidance() {}, loadBackupGuidance() {}, renderBackupGuidance() {}},

    './services/installation.service.js': {installationService: {load: async () => ({edition: 'commercial', auth_mode: 'multi_organization', login_methods: {password: true, oidc: true}})}},
    './services/theme.service.js': {themeService: {button: () => ''}},
    './utils/vm-inventory.js': {renderDiskSummary: () => '', renderCbtObservation: () => ''},
    './services/auth.service.js': {authService: {login: async (...args) => {loginCalls.push(args);}}},
    './utils/security.js': {escapeHtml: value => value},
    './api/client.js': {apiClient: {get: async () => ({enabled: true})}},
    './assets/resolver.js': {assetResolver: {productName: 'vnbui', inlineSvg: () => '', apply: async () => {}}},
};
const appModule = new vm.SourceTextModule(fs.readFileSync(new URL('../src/app.js', import.meta.url), 'utf8'), {context});
await appModule.link(specifier => {
    const exports = modules[specifier];
    assert.ok(exports, `Unexpected dependency: ${specifier}`);
    return new vm.SyntheticModule(Object.keys(exports), function () {
        for (const [key, value] of Object.entries(exports)) this.setExport(key, value);
    }, {context});
});
await appModule.evaluate();
const app = new appModule.namespace.App();
let initialized = 0;
app.init = async () => { initialized++; };
await app.showLogin();
assert.match(elements.app.innerHTML, /name="org_id"/);
assert.match(elements.app.innerHTML, /aria-describedby="login-organization-help"/);
assert.match(elements.app.innerHTML, /login.organization_help/);
assert.match(elements.app.innerHTML, /href="\/api\/v1\/auth\/oidc\/login"/);
const button = {};
await elements.submit({preventDefault() {}, target: {
    username: {value: 'viewer'}, password: {value: 'test-password'},
    org_id: {value: org}, querySelector: () => button,
}});
assert.deepEqual(loginCalls[0], ['viewer', 'test-password', org]);
assert.equal(initialized, 1);
modules['./services/auth.service.js'].authService.login = async () => {throw new Error('<script>denied</script>');};
await elements.submit({preventDefault() {}, target: {
    username: {value: 'viewer'}, password: {value: 'test-password'},
    org_id: {value: org}, querySelector: () => button,
}});
assert.equal(elements['login-error'].textContent, 'login.error');
assert.equal(elements['login-error'].innerHTML, undefined);
assert.equal(button.disabled, false);
assert.equal(initialized, 1);
console.log('PASS: OSS/commercial encoding, failure cleanup, rendered form, SSO binding, text-only errors');
