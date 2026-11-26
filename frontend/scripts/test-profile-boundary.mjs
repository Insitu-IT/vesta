import {enumLabel, storageCapacity} from '../src/utils/status-labels.js';
import {agentProvider, selectedNamespaces} from '../src/utils/agent-scope.js';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {authService as auth} from '../src/services/auth.service.js';
import {escapeHtml} from '../src/utils/security.js';

const storage = new Map();
globalThis.sessionStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key),
};
globalThis.window = {t: key => key, location: {replace() {}}, vnbui: {currentUserId: 'actor'}};
const context = vm.createContext({window, URL, URLSearchParams, sessionStorage, console,
    setTimeout() {}, fetch: (...args) => globalThis.fetch(...args)});
async function load(path, exports) {
    const module = new vm.SourceTextModule(fs.readFileSync(new URL(path, import.meta.url), 'utf8'), {
        context, initializeImportMeta: meta => {meta.env = {DEV: false};},
    });
    await module.link(specifier => {
        const values = exports(specifier);
        return new vm.SyntheticModule(Object.keys(values), function () {
            for (const [key, value] of Object.entries(values)) this.setExport(key, value);
        }, {context});
    });
    await module.evaluate();
    return module.namespace;
}
const {apiClient} = await load('../src/api/client.js', spec => spec.includes('operator-requests.service') ? {operatorRequests: {configure() {}, post: (path, data, send) => send(), acknowledge() {}, render() {}}} : spec.includes('auth.service')
    ? {authService: auth} : {getVersion: () => 'fixture'});
const deps = spec => spec.includes('authenticated-startup') ? {startAuthenticatedServices: async () => {}}
    : spec.includes('components/licensing') ? {refreshLicenseBanner() {}, renderLicenseSummary() {}, LicensingPanel: class {async load() {} render() {return '';} mount() {}}}
    : spec.includes('licensing.service') ? {licensingService: {}}
    : spec.includes('backup-guidance') ? {bindBackupGuidance() {}, loadBackupGuidance() {}, renderBackupGuidance() {}}
    : spec.includes('installation.service') ? {installationService: {}}
    : spec.includes('theme.service') ? {themeService: {button: () => ''}}
    : spec.includes('vm-inventory') ? {renderDiskSummary: () => '', renderCbtObservation: () => ''}
    : spec.includes('context-help') ? {contextHelp: () => ''}
    : spec.includes('status-labels') ? {enumLabel: (value, domain) => enumLabel(value, domain, context.window.t), storageCapacity}
    : spec.includes('agent-scope') ? {agentProvider, selectedNamespaces}
    : spec.includes('auth.service') ? {authService: auth}
    : spec.includes('client') ? {apiClient} : spec.includes('security') ? {escapeHtml}
    : spec.includes('format') ? {formatDate: () => '', formatRelativeTime: () => ''}
    : {assetResolver: {icon: () => '', inlineSvg: () => ''}};
const {SettingsPage} = await load('../src/pages/settings.js', deps);
const {UsersPage} = await load('../src/pages/users.js', deps);
const {App} = await load('../src/app.js', deps);
const profile = {id: 'actor', username: '<img src=x>', org_id: 'organization-one',
    role: 'admin', auth_source: 'local', role_source: 'local', is_active: true,
    is_platform_admin: false, can_manage_installation: false};
let current = profile;
let writes = [];
globalThis.fetch = async (url, options) => {
    if (url === '/api/v1/auth/me') return {ok: true, json: async () => ({...current})};
    writes.push({url, options});
    return {ok: true, headers: {get: () => 'application/json'}, json: async () => ({ok: true})};
};
auth.setToken('fixture-bearer');
auth.setUser({...profile, can_manage_installation: true});
assert.equal(auth.canManageInstallation(), false); // storage is never authority
const app = new App();
app.user = profile;
assert(!app.renderNavigation().includes('href="#settings"'));
assert(app.renderNavigation().includes('href="#users"')); // tenant-admin function remains
await assert.rejects(new SettingsPage().render(), error => error.status === 403);
assert.equal(writes.length, 0); // direct navigation fetched no configuration
for (const method of [
    () => apiClient.put('/api/v1/settings/v3', {values: {}}),
    () => apiClient.post('/api/v1/auth/oidc/test', {}),
    () => apiClient.upload('/api/v1/settings/import', {}),
    () => apiClient.download('/api/v1/settings/export', 'unused'),
    () => apiClient.postForBlob('/api/v1/settings/export', {}),
]) {
    await assert.rejects(method(), error => error.status === 403);
    assert.equal(writes.length, 0);
}
for (const source of ['local', 'oidc']) {
    current = {...profile, auth_source: source, role: 'viewer',
        is_platform_admin: true, can_manage_installation: true};
    await auth.fetchUserData();
    app.user = auth.getUser();
    assert(app.renderNavigation().includes('href="#settings"'));
    assert(!app.renderNavigation().includes('href="#users"')); // platform != tenant role
    assert.match(await new UsersPage().render(), /Access denied/);
    const body = {values: {'oidc.enabled': false, 'oidc.client_id': 'public-client'}};
    await apiClient.put('/api/v1/settings/v3', body);
    assert.deepEqual(JSON.parse(writes.at(-1).options.body), body);
    assert(!writes.at(-1).options.body.includes('client_secret'));
    assert.equal(auth.getUser().org_id, profile.org_id);
}
// Server-revoked authority overrides stale verified and stored profile.
current = profile;
const before = writes.length;
await assert.rejects(apiClient.post('/api/v1/auth/oidc/test', {}), error => error.status === 403);
assert.equal(writes.length, before);
// Exercise the actual profile handler with text/value-only DOM doubles.
const nodes = new Map();
context.document = {
    querySelectorAll: () => [],
    getElementById: id => {
        if (!nodes.has(id)) nodes.set(id, {value: '', textContent: '', style: {},
            classList: {toggle() {}, add() {}, remove() {}}, addEventListener() {}, reset() {},
            set innerHTML(value) {throw new Error('Profile must not use HTML sinks');},
        });
        return nodes.get(id);
    },
};
window.addEventListener = () => {};
let shown = 0;
context.bootstrap = {Modal: class {show() {shown++;}}};
app.setupEventListeners();
window.vnbui.showToast = () => {throw new Error('Unexpected profile failure');};
for (const source of ['local', 'oidc']) {
    current = {...profile, auth_source: source, role: 'viewer',
        full_name: '<script>fixture</script>', email: 'same@example.invalid'};
    await window.vnbui.openProfile();
    assert.equal(nodes.get('profile-fullname').value, current.full_name);
    assert.equal(nodes.get('profile-organization').textContent, profile.org_id);
    assert.equal(nodes.get('profile-fullname').readOnly, true);
    assert.equal(nodes.get('profile-save').disabled, true);
    if (source === 'oidc') assert.equal(nodes.get('profile-role-source').textContent, 'local');
}
assert.equal(shown, 2);
assert.equal(writes.length, before); // Profile never requests admin-only /users/{id}.
for (const failure of ['disabled', 'network']) {
    globalThis.fetch = async () => {
        if (failure === 'network') throw new Error('private transport');
        return {ok: false, status: 401};
    };
    await assert.rejects(auth.requireInstallationAccess(), error => error.status === 403);
    assert.equal(auth.getUser(), null);
    assert.equal(auth.canManageInstallation(), false);
}
const users = new UsersPage();
users.users = [
    {...profile, id: 'first', is_active: true},
    {...profile, id: 'second', org_id: 'organization-two', auth_source: 'oidc', is_active: false},
    {...profile, id: 'third', org_id: 'organization-three', auth_source: null, is_active: null},
];
const html = users.renderUserRows();
assert(!html.includes('<img src=x>'));
assert(html.includes('&lt;img src=x&gt;'));
assert(html.includes('organization-one') && html.includes('organization-two'));
assert.equal((html.match(/users.status_active/g) || []).length, 1);
assert.equal((html.match(/users.status_disabled/g) || []).length, 1);
assert(html.includes('users.role_pinned') && html.includes('common.unknown'));
current = {...profile, role: 'admin'};
globalThis.fetch = async () => ({ok: true, json: async () => current});
await auth.fetchUserData();
globalThis.fetch = async () => {throw new Error('private transport detail');};
const failureHtml = await users.render();
assert(failureHtml.includes('common.failed_to_load'));
assert(!failureHtml.includes('users.total_users') && !failureHtml.includes('private transport'));
// Actual Users submit handlers omit hidden/provider-owned fields.
const sent = [];
apiClient.put = async (path, body) => {sent.push({path, body: JSON.parse(JSON.stringify(body))});};
apiClient.post = apiClient.put;
context.bootstrap.Modal.getInstance = () => ({hide() {}});
const toasts = [];
window.vnbui.showToast = message => toasts.push(message);
const input = (id, value) => {context.document.getElementById(id).value = value;};
apiClient.get = async () => ({...profile, id: 'oidc-user', auth_source: 'oidc', role_source: 'oidc', is_active: false});
await window.vnbui.editUser('oidc-user');
assert.equal(nodes.get('user-role').disabled, true);
assert.equal(nodes.get('user-email').readOnly, true);
assert.equal(nodes.get('user-active').checked, false);
input('user-role-source', 'local');
nodes.get('user-role-source').onchange();
assert.equal(nodes.get('user-role').disabled, false);
window.vnbui.createUser();
assert.equal(nodes.get('user-email').readOnly, false);
assert.equal(nodes.get('user-role').disabled, false);
assert.equal(nodes.get('user-role-source').onchange, null);
assert.equal(nodes.get('user-id').value, '');
input('user-id', 'oidc-user');
input('user-auth-source', 'oidc');
input('user-username', 'immutable');
input('user-fullname', '<script>immutable</script>');
input('user-email', 'immutable@example.invalid');
input('user-role', 'viewer');
input('user-role-source', 'oidc');
await window.vnbui.submitUser();
assert.deepEqual(sent.at(-1).body, {role_source: 'oidc'});
input('user-role-source', 'local');
await window.vnbui.submitUser();
assert.deepEqual(sent.at(-1).body, {role_source: 'local', role: 'viewer'});
input('user-id', '');
input('user-auth-source', 'local');
input('user-username', '  new  ');
input('user-fullname', '  Name  ');
input('user-email', '  mail@example.invalid  ');
input('user-password', 'Private1!Password');
context.document.getElementById('user-active').checked = false;
await window.vnbui.submitUser();
assert.deepEqual(sent.at(-1).body, {username: 'new', full_name: 'Name', email: 'mail@example.invalid',
    role: 'viewer', is_active: false, password: 'Private1!Password'});
const count = sent.length;
input('user-username', '  ');
await window.vnbui.submitUser();
assert.equal(sent.length, count);
apiClient.put = async () => {throw new Error('<script>private server detail</script>');};
input('user-id', 'oidc-user');
input('user-auth-source', 'oidc');
await window.vnbui.submitUser();
assert.equal(toasts.at(-1), 'Failed to save user');
input('reset-new-password', 'old secret');
input('reset-confirm-password', 'old secret');
window.vnbui.resetPassword('target', 'same');
assert.equal(nodes.get('reset-new-password').value, '');
assert.equal(nodes.get('reset-confirm-password').value, '');
// Check the real template before the DOM double can synthesize a missing node.
assert.match(users.renderDeleteModal(), /<input type="hidden" id="delete-user-id">/);
assert.equal((users.renderDeleteModal().match(/id="delete-user-id"/g) || []).length, 1);
window.vnbui.deleteUser('exact-target', '<script>same-name</script>');
assert.equal(nodes.get('delete-user-id').value, 'exact-target');
assert.equal(nodes.get('delete-user-name').textContent, '<script>same-name</script>');
apiClient.delete = async path => {sent.push({path, method: 'DELETE'});};
await window.vnbui.submitDeleteUser();
assert.deepEqual(sent.at(-1), {path: '/api/v1/users/exact-target', method: 'DELETE'});
assert.equal(toasts.at(-1), 'User deleted');
apiClient.delete = async () => {throw new Error('<script>private conflict detail</script>');};
await window.vnbui.submitDeleteUser();
assert.equal(toasts.at(-1), 'Failed to delete user');
const settings = new SettingsPage();
settings.v3Secrets = {'oidc.client_secret': {configured: true}};
for (const [field, value] of Object.entries({issuer: ' https://issuer.test ', 'client-id': ' client ',
    scopes: ' openid  profile openid ', 'default-role': 'viewer', 'role-claim': ' ',
    'admin-values': ' admins ', 'operator-values': '', 'client-secret': '********'})) {
    input('setting-v3-oidc-' + field, value);
}
nodes.get('setting-v3-oidc-enabled') || input('setting-v3-oidc-enabled', '');
nodes.get('setting-v3-oidc-enabled').checked = true;
let bound = 0;
// Tracking is installed synchronously on the mounted form. A timer double that
// immediately ran callbacks hid the lost-input interval in the real browser.
context.setTimeout = () => {throw new Error('Unexpected deferred form binding');};
context.document.querySelector = () => null;
context.document.querySelectorAll = () => [{addEventListener(kind, callback) {bound++; this[kind] = callback;}}];
nodes.set('settings-security', {set innerHTML(value) {assert.equal(value, 'rendered');}});
settings.renderSecuritySettings = () => 'rendered';
settings.loadV3Settings = async () => {};
apiClient.put = async (path, body) => {sent.push({path, body: JSON.parse(JSON.stringify(body))});};
await settings.saveOIDCSettings();
assert.deepEqual(sent.at(-1).body, {'oidc.enabled': true, 'oidc.issuer': 'https://issuer.test',
    'oidc.client_id': 'client', 'oidc.scopes': 'openid profile', 'oidc.default_role': 'viewer',
    'oidc.role_claim': '', 'oidc.admin_values': 'admins', 'oidc.operator_values': ''});
assert.equal(bound, 2);
input('setting-v3-oidc-scopes', 'profile');
settings.markDirty();
assert.equal(nodes.get('btn-save-oidc').disabled, true);
const requests = sent.length;
await settings.saveOIDCSettings();
assert.equal(sent.length, requests);
input('setting-v3-oidc-client-id', '');
input('setting-v3-oidc-client-secret', '');
apiClient.post = async (path, body) => {
    sent.push({path, body: JSON.parse(JSON.stringify(body))});
    return {check: 'discovery_only', credentials_verified: false};
};
await settings.testOIDCConfiguration();
assert.deepEqual(sent.at(-1).body, {issuer: 'https://issuer.test'});
assert.match(nodes.get('oidc-test-result').textContent, /credentials were not tested/);
apiClient.post = async () => {throw new Error('<script>secret error</script>');};
await settings.testOIDCConfiguration();
assert.equal(nodes.get('oidc-test-result').textContent, 'OIDC discovery failed');
input('setting-v3-oidc-issuer', 'http://issuer.test');
const noRequest = sent.length;
await settings.testOIDCConfiguration();
assert.equal(sent.length, noRequest);
assert.equal(nodes.get('btn-test-oidc').disabled, true);
input('setting-v3-oidc-issuer', 'https://issuer.test');
settings.v3Settings['oidc.default_role'] = 'admin';
input('setting-v3-oidc-default-role', '');
settings.updateOIDCButtonStates();
assert.equal(nodes.get('btn-test-oidc').disabled, true);
assert.equal(nodes.get('btn-save-oidc').disabled, true);
const legacyRequests = sent.length;
await settings.testOIDCConfiguration();
await settings.saveOIDCSettings();
assert.equal(sent.length, legacyRequests);
input('setting-v3-oidc-default-role', 'viewer');
settings.markDirty();
assert.equal(nodes.get('btn-test-oidc').disabled, true);
input('setting-v3-oidc-client-id', 'client');
input('setting-v3-oidc-scopes', 'openid profile');
settings.markDirty();
assert.equal(nodes.get('btn-save-oidc').disabled, false);
assert.equal(nodes.get('btn-test-oidc').disabled, false);
console.log('PASS: persisted profile, installation admission and Settings discovery/save; browser doubles only');
