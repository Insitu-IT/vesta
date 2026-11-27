import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';

const capabilities = {contract_version: 1, request_header: 'Idempotency-Key', request_identity: 'uuid',
    secret_replay: false, agent_key_rotation: 'staged-candidate-activation', actions: [
        'backup.create', 'backup.close_unreserved', 'queue.create', 'backup.bulk_create', 'restore.create', 'credential.orchestrator.create',
        'credential.registration.create', 'credential.agent.rotate', 'encryption.create', 'encryption.rotate']};

async function harness(storage = new Map()) {
    const calls = [], nodes = new Map(), toasts = [], events = new Map(), intervals = [];
    let token = 'bearer';
    let user = {id: 'alice', org_id: 'organization-one', role: 'admin'};
    const auth = {
        getUser: () => user,
        getToken: () => token,
        clearToken() {},
        canManageInstallation: () => user?.can_manage_installation === true,
        requireInstallationAccess: async () => {},
    };
    const document = {addEventListener: (name, callback) => events.set(name, callback), getElementById: id => nodes.get(id) || null, querySelector: () => null, querySelectorAll: () => []};
    const context = vm.createContext({console, t: key => key, URL, URLSearchParams, TextEncoder, Uint8Array, crypto: webcrypto,
        localStorage: {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value)},
        window: {confirm: () => false, location: {origin: 'https://vesta.test', hash: '#vms'}, addEventListener() {}, t: key => key, vnbui: {}},
        document, setTimeout() {}, setInterval(callback) {intervals.push(callback); return intervals.length;}, clearInterval() {}, confirm: () => true, prompt: () => 'named-key',
        bootstrap: {Modal: {getInstance: () => ({hide() {}})}},
    });
    let handler = async (url, options) => {
        if (url.endsWith('/operator/capabilities')) return capabilities;
        if (url.includes('/operator/requests/')) {
            const id = url.split('/').at(-1);
            return {request_id: id, action: 'backup.create', contract_version: 1, state: 'admitted', receipt: {id: 'backup-one'}, dispatches: []};
        }
        return {request_id: options.headers['Idempotency-Key'], id: 'result-one', status: 'queued', summary: {created: 1, skipped: 0, failed: 0}};
    };
    context.fetch = async (url, options) => {
        calls.push({url, options});
        const data = await handler(url, options);
        if (data?.wireResponse) return data.wireResponse;
        return {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => data};
    };
    const modules = new Map();
    const synthetic = values => new vm.SyntheticModule(Object.keys(values), function() {
        for (const [name, value] of Object.entries(values)) this.setExport(name, value);
    }, {context});
    async function load(name) {
        if (modules.has(name)) return modules.get(name);
        const source = await readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
        const module = new vm.SourceTextModule(source, {context, initializeImportMeta: meta => {meta.env = {DEV: false};}});
        modules.set(name, module);
        await module.link(async specifier => {
            if (specifier === './bucket-recovery.js') return load('pages/bucket-recovery.js');
            if (specifier.includes('operator-requests.service')) return load('services/operator-requests.service.js');
            if (specifier.includes('operator-dispatch')) return load('utils/operator-dispatch.js');
            if (specifier.includes('snapshot.service')) return load('services/snapshot.service.js');
            if (specifier.includes('updates.service')) return synthetic({updateService:{subscribeResync:()=>()=>{},subscribe:()=>()=>{}}});
            if (specifier.includes('api/client') || specifier === './api/client.js') return load('api/client.js');
            if (specifier.includes('auth.service')) return synthetic({authService: auth});
            if (specifier.endsWith('version.js')) return synthetic({getVersion: () => 'fixture'});
            if (specifier.endsWith('/services/licensing.service.js')) return synthetic({licensingService: {}});
            if (specifier.endsWith('/components/file-backups.js')) {
                return synthetic({FileBackupsPanel: class { mount() {} destroy() {} }});
            }
            if (specifier.endsWith('/components/licensing.js')) {
                return synthetic({LicensingPanel: class {}, refreshLicenseBanner() {}, renderLicenseSummary() {}});
            }
            const match = [...source.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]/g)].find(item => item[2] === specifier);
            assert(match, `known import ${specifier}`);
            return synthetic(Object.fromEntries(match[1].split(',').map(name => [name.trim(), name.trim() === 'escapeHtml' ? value => String(value ?? '') : () => {}])));
        });
        return module;
    }
    const clientModule = await load('api/client.js'); await clientModule.evaluate();
    const api = clientModule.namespace.apiClient;
    const recovery = modules.get('services/operator-requests.service.js').namespace.operatorRequests;
    return {api, recovery, calls, storage, context, nodes, toasts, events, intervals, load,
        setToken(value) {token = value;},
        setUser(value) {user = value;}, setHandler(value) {handler = value;},
        mutations: () => calls.filter(call => call.options.method === 'POST')};
}

test('concurrent create calls send one UUID and acknowledgment permits an explicit later new request', async () => {
    const h = await harness();
    const [one, two] = await Promise.all([h.api.post('/api/v1/backups', {vm_id: 'one'}), h.api.post('/api/v1/backups', {vm_id: 'one'})]);
    assert.equal(h.mutations().length, 1); assert.equal(one.request_id, two.request_id);
    assert.match(one.request_id, /^[0-9a-f-]{36}$/);
    assert.equal(h.recovery.records().length, 1);
    h.api.acknowledge(one); assert.equal(h.recovery.records().length, 0);
    const next = await h.api.post('/api/v1/backups', {vm_id: 'one'});
    assert.notEqual(next.request_id, one.request_id);
});

test('transport and JSON-body loss survive reload and only GET the original request', async () => {
    for (const failure of ['transport', 'body']) {
        const h = await harness();
        h.setHandler(async (url, options) => {
            if (options.method === 'GET') return capabilities;
            if (failure === 'transport') throw new Error('connection lost');
            return {wireResponse: {ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => {throw new Error('body lost');}}};
        });
        await assert.rejects(h.api.post('/api/v1/backups', {vm_id: 'one'}), error => error.outcomeUnknown);
        const id = h.mutations()[0].options.headers['Idempotency-Key'];
        const reloaded = await harness(h.storage);
        await assert.rejects(reloaded.api.post('/api/v1/backups', {vm_id: 'one'}), error => error.operatorRecovery);
        assert.equal(reloaded.mutations().length, 0);
        assert(reloaded.calls.some(call => call.url.endsWith(`/operator/requests/${id}`)));
        assert.equal(reloaded.recovery.records()[0].request_id, id);
        reloaded.recovery.acknowledgeReviewed(id); assert.equal(reloaded.recovery.records().length, 0);
    }
});

test('stored intent excludes raw bodies and secrets; recovered credentials never enter blank key modals', async () => {
    const h = await harness();
    h.setHandler(async (url, options) => options.method === 'GET' ? capabilities : {
        request_id: options.headers['Idempotency-Key'], api_key: 'PRIVATE-ONE-TIME', usage_snippet: 'PRIVATE-SNIPPET', secret_delivery: 'one_time'});
    const result = await h.api.post('/api/v1/orchestrator-keys', {name: 'PRIVATE-NAME', password: 'PRIVATE-PASSWORD'});
    const saved = [...h.storage.values()].join('');
    for (const text of ['PRIVATE-ONE-TIME','PRIVATE-SNIPPET','PRIVATE-NAME','PRIVATE-PASSWORD']) assert(!saved.includes(text));
    assert.equal(h.recovery.records().length, 1, 'secret stays pending until explicit saved acknowledgment');
    const id = result.request_id;
    h.setHandler(async url => url.endsWith('/capabilities') ? capabilities : {request_id: id, action: 'credential.orchestrator.create',
        contract_version: 1, state: 'admitted', secret_delivery: 'unavailable', current_resource:{id:'credential-one',enabled:false,api_key:'SHOULD-NOT-APPEAR'}, receipt: {id: 'credential-one', api_key: 'SHOULD-NOT-APPEAR', usage_snippet: 'SHOULD-NOT-APPEAR'}});
    const metadata = await h.recovery.inspect(id);
    assert(!JSON.stringify(metadata).includes('SHOULD-NOT-APPEAR'));
    assert.equal(metadata.current_resource.enabled,false);
    const module = await h.load('services/key-management.service.js'); await module.evaluate();
    const keys = module.namespace.keyManagementService;
    let messages = 0; keys.showToast = () => messages++;
    keys.showKeyModal('recovered', {secret_delivery: 'unavailable'});
    assert.equal(messages, 1); // No DOM access or secret input is attempted.
});

test('scope changes cannot inspect or acknowledge another principal pending identity', async () => {
    const h = await harness();
    const result = await h.api.post('/api/v1/backups', {vm_id: 'one'});
    h.setUser({id: 'bob', org_id: 'organization-two', role: 'admin'});
    assert.equal(h.recovery.records().length, 0);
    await assert.rejects(h.recovery.inspect(result.request_id));
    h.api.acknowledge(result);
    h.setUser({id: 'alice', org_id: 'organization-one', role: 'admin'});
    assert.equal(h.recovery.records().length, 1);
});

test('undeclared routes bypass negotiation; capability404 keeps legacy declared calls without recovery claims', async () => {
    const h = await harness();
    await h.api.post('/api/v1/search', {query: 'one'});
    assert.equal(h.calls.length, 1); assert.equal(h.calls[0].options.headers['Idempotency-Key'], undefined);
    h.setHandler(async (url, options) => options.method === 'GET' ? {wireResponse: {ok: false, status: 404, json: async () => ({detail: 'not deployed'})}} : {id: 'legacy'});
    const result = await h.api.post('/api/v1/backups', {vm_id: 'legacy'});
    assert.equal(result.id, 'legacy'); assert.equal(h.recovery.records().length, 0);
    assert.equal(h.mutations().at(-1).options.headers['Idempotency-Key'], undefined);
});

test('real App backup/restore/group and VM bulk callers acknowledge only after processing', async () => {
    const h = await harness();
    const module = await h.load('app.js'); await module.evaluate();
    const app = new module.namespace.App(); app.user = {id: 'alice', role: 'admin'};
    app.setupEventListeners();
    h.context.window.vnbui.showToast = () => {};
    h.context.window.vnbui.navigateTo = () => {};
    for (const [id,value] of Object.entries({'backup-vm-id':'one','backup-type':'full','backup-retention':'30','backup-description':'',
        'restore-backup-id':'backup-one','restore-target':'new','restore-new-name':'restored'})) h.nodes.set(id,{value});
    h.nodes.set('modal-restore', {dataset: {provider: 'kubevirt'}});
    h.nodes.set('restore-kubevirt-target', {value: '{"name":"destination"}'});
    await h.context.window.vnbui.submitBackupFromModal();
    await h.context.window.vnbui.submitRestore();
    await h.context.window.vnbui.backupGroup('group-one','Group');
    const vmsModule = await h.load('pages/vms.js'); await vmsModule.evaluate();
    const vms = new vmsModule.namespace.VMsPage(); vms.selectedIds.add('one'); vms.clearSelection = () => {};
    await vms.bulkBackupSelected();
    assert.equal(h.mutations().length, 4); assert(h.mutations().every(call => call.options.headers['Idempotency-Key']));
    assert.equal(h.recovery.records().length, 0);
});

test('real key creation callbacks and encryption handlers use identity-aware client', async () => {
    const h = await harness();
    const module = await h.load('services/key-management.service.js'); await module.evaluate();
    const keys = module.namespace.keyManagementService;
    const callbacks = [];
    keys.showFormModal = (title, fields, submit) => callbacks.push(submit);
    keys.showKeyModal = (title, result) => h.api.acknowledge(result);
    keys.showToast = () => {};
    await keys.createOrchestratorKey(); await callbacks.pop()({name: 'one'});
    await keys.createRegistrationKey(); await callbacks.pop()({name: 'one', agent_hostname: 'host-one'});
    await keys.rotateAgentKey('agent-one','Agent');
    const settingsModule = await h.load('pages/settings.js'); await settingsModule.evaluate();
    const settings = new settingsModule.namespace.SettingsPage();
    settings.loadEncryptionKeys = async () => {}; settings.renderEncryptionSettings = () => '';
    h.context.window.vnbui.showToast = () => {};
    await settings.createEncryptionKey(); await settings.rotateEncryptionKey('key-one');
    assert.equal(h.mutations().length, 5);
    assert(h.mutations().every(call => call.options.headers['Idempotency-Key']));
    assert.equal(h.recovery.records().length, 0);
});

test('pre-admission validation clears identity while 409/5xx and lookup404 retain it', async () => {
    for (const status of [422, 409, 503]) {
        const h = await harness();
        h.setHandler(async (url, options) => options.method === 'GET' ? capabilities : {wireResponse: {
            ok: false, status, json: async () => ({detail: {code: 'test_refusal'}})}});
        await assert.rejects(h.api.post('/api/v1/backups', {vm_id:'one'}));
        assert.equal(h.recovery.records().length, status === 422 ? 0 : 1);
        if (status !== 422) {
            h.setHandler(async () => ({wireResponse: {ok:false,status:404,json:async()=>({detail:{code:'request_not_found'}})}}));
            await assert.rejects(h.api.post('/api/v1/backups', {vm_id:'one'}));
            assert.equal(h.mutations().length, 1); assert.equal(h.recovery.records().length, 1);
        }
    }
});

test('storage failure refuses submission before the mutation boundary', async () => {
    const h = await harness();
    h.context.localStorage.setItem = () => {throw new Error('quota exhausted');};
    await assert.rejects(h.api.post('/api/v1/backups', {vm_id:'one'}));
    assert.equal(h.mutations().length, 0);
});

test('actual caller processing failure retains the original identity for inspection', async () => {
    const h = await harness();
    const module = await h.load('services/key-management.service.js'); await module.evaluate();
    const keys = module.namespace.keyManagementService;
    let submit;
    keys.showFormModal = (title, fields, callback) => {submit = callback;};
    keys.showKeyModal = () => {throw new Error('modal rendering failed');};
    await keys.createRegistrationKey();
    await assert.rejects(submit({name:'one',agent_hostname:'one'}));
    assert.equal(h.recovery.records().length, 1);
    assert.equal(h.mutations().length, 1);
});

test('saving or copying a staged candidate never activates it or posts again', async () => {
    const h = await harness();
    h.setHandler(async (url, options) => options.method === 'GET' ? capabilities : {
        request_id:options.headers['Idempotency-Key'], rotation_id:'rotation-one', agent_id:'agent-one',
        api_key:'PRIVATE-CANDIDATE',state:'pending',secret_delivery:'one_time'});
    const result = await h.api.post('/api/v1/agents/agent-one/rotate-key', {});
    const module = await h.load('services/key-management.service.js'); await module.evaluate();
    const keys = module.namespace.keyManagementService;
    const events = new Map();
    let html = '';
    h.context.document.body = {insertAdjacentHTML(position, value) {html = value;}};
    h.nodes.set('api-key-modal', {remove(){}, addEventListener(name, callback){events.set(name,callback);}});
    h.nodes.set('acknowledge-generated-key', {addEventListener(name,callback){events.set(`saved:${name}`,callback);}});
    h.nodes.set('generated-api-key', {select(){}});
    h.context.document.execCommand = () => {};
    h.context.bootstrap.Modal = class {show(){}};
    keys.showToast = () => {}; keys.reloadPreservingTab = () => {};
    keys.showKeyModal('candidate', result);
    assert(html.includes('--activate')); assert(html.includes('0600'));
    keys.copyToClipboard('generated-api-key');
    assert.equal(h.recovery.records().length, 1);
    events.get('saved:click')();
    assert.equal(h.recovery.records().length, 0);
    events.get('hidden.bs.modal').call({remove(){}});
    assert.equal(h.mutations().length, 1);
    assert(!h.calls.some(call => call.url.endsWith('/activate')));
});

test('external encryption actions excluded from capabilities preserve legacy behavior', async () => {
    const h = await harness();
    h.setHandler(async (url, options) => options.method === 'GET' ? {...capabilities,
        actions: capabilities.actions.filter(action => !action.startsWith('encryption.'))} : {id:'external-key'});
    const result = await h.api.post('/api/v1/encryption/keys', {name:'external'});
    assert.equal(result.id,'external-key'); assert.equal(h.recovery.records().length,0);
    assert.equal(h.mutations()[0].options.headers['Idempotency-Key'],undefined);
});

test('agent rotation inspection and cancellation use explicit metadata GET/DELETE only', async () => {
    const h = await harness();
    const metadata = {rotation_id:'rotation-one',agent_id:'agent-one',state:'pending',key_prefix:'prefix',api_key:'NEVER-DISPLAY'};
    h.setHandler(async (url, options) => url.endsWith('/key-rotations') ? {items:[metadata],total:1} :
        {...metadata,state:options.method === 'DELETE' ? 'cancelled' : 'pending'});
    const module = await h.load('services/key-management.service.js'); await module.evaluate();
    const keys = module.namespace.keyManagementService;
    let html = '', status = '';
    const callbacks = {};
    const refresh = {dataset:{refresh:'rotation-one'},addEventListener(event,callback){callbacks.refresh=callback;}};
    const cancel = {dataset:{cancel:'rotation-one'},remove(){},addEventListener(event,callback){callbacks.cancel=callback;}};
    const element = {remove(){},addEventListener(){},querySelectorAll(selector){return selector==='[data-refresh]'?[refresh]:[cancel];},
        querySelector(){return {set textContent(value){status=value;}};}};
    h.nodes.set('agent-rotation-modal',element);
    h.context.document.body = {insertAdjacentHTML(position,value){html=value;}};
    h.context.bootstrap.Modal=class {show(){}};
    h.context.CSS={escape:value=>value}; keys.showToast=()=>{};
    await keys.inspectAgentRotations('agent-one');
    assert(!html.includes('NEVER-DISPLAY'));
    await callbacks.refresh(); assert(status.includes('pending'));
    await callbacks.cancel(); assert(status.includes('cancelled'));
    assert.deepEqual(h.calls.map(call=>call.options.method),['GET','GET','DELETE']);
    assert(!h.calls.some(call=>call.url.endsWith('/activate')));
});

test('404 inspection never resends; confirmed retry uses the exact original UUID after intent re-entry', async () => {
    const h = await harness();
    let admitted = false;
    h.setHandler(async (url, options) => {
        if (url.endsWith('/capabilities')) return capabilities;
        if (url.includes('/operator/requests/')) {
            if (!admitted) return {wireResponse:{ok:false,status:404,json:async()=>({detail:{code:'request_not_found'}})}};
            return {request_id:url.split('/').at(-1),action:'backup.create',contract_version:1,state:'admitted',receipt:{id:'original-backup'},dispatches:[]};
        }
        if (h.mutations().length === 1) throw new Error('original never reached server');
        admitted = true;
        return {request_id:options.headers['Idempotency-Key'],id:'original-backup'};
    });
    await assert.rejects(h.api.post('/api/v1/backups',{vm_id:'one'}));
    const id = h.recovery.records()[0].request_id;
    await assert.rejects(h.recovery.inspect(id));
    await assert.rejects(h.recovery.retryOriginal(id),'inspection alone never restores a request body');
    await assert.rejects(h.api.post('/api/v1/backups',{vm_id:'one'}));
    assert.equal(h.mutations().length,1,'re-entering the form only inspects');
    h.context.window.confirm=()=>false;
    await h.recovery.retryOriginal(id); assert.equal(h.mutations().length,1);
    h.context.window.confirm=()=>true;
    await h.recovery.retryOriginal(id);
    assert.equal(h.mutations().length,2);
    assert(h.mutations().every(call=>call.options.headers['Idempotency-Key']===id));
    assert.equal(h.recovery.records()[0].request_id,id);
    assert.equal(h.recovery.inspected.get(`${h.recovery.scope()}:${id}`).state,'admitted');
});

test('unresolved original retry is explicit, one-shot, and cancelled when its modal closes', async () => {
    const h = await harness();
    h.setHandler(async (url, options) => {
        if (url.endsWith('/capabilities')) return capabilities;
        if (options.method==='GET') return {request_id:url.split('/').at(-1),action:'backup.create',contract_version:1,state:'unresolved',receipt:{},dispatches:[]};
        throw new Error('response lost');
    });
    await assert.rejects(h.api.post('/api/v1/backups',{vm_id:'one'}));
    const id=h.recovery.records()[0].request_id;
    await assert.rejects(h.api.post('/api/v1/backups',{vm_id:'one'}));
    assert.equal(h.mutations().length,1);
    h.events.get('input')();
    await assert.rejects(h.recovery.retryOriginal(id), 'editing any field discards the bound retry intent');
    await assert.rejects(h.api.post('/api/v1/backups',{vm_id:'one'}));
    h.events.get('hidden.bs.modal')();
    await assert.rejects(h.recovery.retryOriginal(id));
    assert.equal(h.mutations().length,1);
    await assert.rejects(h.api.post('/api/v1/backups',{vm_id:'one'}));
    h.context.window.confirm=()=>true;
    await assert.rejects(h.recovery.retryOriginal(id));
    assert.equal(h.mutations().length,2);
    await assert.rejects(h.recovery.retryOriginal(id),'next attempt requires re-entry and inspection');
    assert.equal(h.mutations().length,2);
});

test('session replacement clears lookup/retry/capability caches and rejects old capability promises', async () => {
    const h=await harness();
    let release;
    h.setHandler(async()=>new Promise(resolve=>{release=resolve;}));
    const old=h.recovery.capability();
    for(let n=0;n<12;n++) await Promise.resolve();
    h.recovery.inspected.set('old',{state:'admitted'});
    h.recovery.retryIntents.set('old',{send(){throw new Error('stale');}});
    h.setToken('replacement-session'); h.recovery.scope();
    assert.equal(h.recovery.capabilities.size,0);assert.equal(h.recovery.inspected.size,0);assert.equal(h.recovery.retryIntents.size,0);
    h.setHandler(async()=>capabilities);
    const current=await h.recovery.capability();
    release(capabilities); await assert.rejects(old);
    assert.equal(current.contract_version,1); assert.equal(h.recovery.capabilities.size,1,'old rejection cannot evict current cache');
});

test('inspection retains dispatch hold reasons and resource presence without secret fields', async () => {
    const h=await harness();
    const result=await h.api.post('/api/v1/backups',{vm_id:'one'});
    h.setHandler(async()=>({request_id:result.request_id,action:'backup.create',contract_version:1,state:'admitted',receipt:{},dispatches:[{
        kind:'backup',resource_id:'one',state:'held',reason:'original_source_unproven',resource_present:false,api_key:'PRIVATE'}]}));
    const outcome=await h.recovery.inspect(result.request_id);
    assert.equal(outcome.dispatches[0].reason,'original_source_unproven');
    assert.equal(outcome.dispatches[0].resource_present,false);
    assert(!JSON.stringify(outcome).includes('PRIVATE'));
});

test('cooperative browser lock covers the request claim without including raw intent in lock names', async () => {
    const h=await harness();
    const locks=[];
    h.context.navigator={locks:{request:async(name,callback)=>{locks.push(name);return callback();}}};
    await h.api.post('/api/v1/backups',{vm_id:'PRIVATE-INTENT'});
    assert.equal(locks.length,1);assert(!locks[0].includes('PRIVATE-INTENT'));
});

test('same-intent modal re-entry offers explicit confirmation and returns the original-ID result to its caller', async () => {
    const h=await harness();
    let originalId;
    h.setHandler(async(url,options)=>{
        if(url.endsWith('/capabilities'))return capabilities;
        if(options.method==='GET')return {wireResponse:{ok:false,status:404,json:async()=>({detail:{code:'request_not_found'}})}};
        originalId ||= options.headers['Idempotency-Key'];
        if(h.mutations().length===1)throw new Error('before server receipt');
        return {request_id:options.headers['Idempotency-Key'],id:'one'};
    });
    await assert.rejects(h.api.post('/api/v1/backups',{vm_id:'one'}));
    let confirmations=0;
    h.context.window.confirm=message=>{confirmations++;assert(message.includes(originalId));return true;};
    const result=await h.api.post('/api/v1/backups',{vm_id:'one'});
    assert.equal(confirmations,1);assert.equal(result.request_id,originalId);assert.equal(h.mutations().length,2);
    h.api.acknowledge(result);assert.equal(h.recovery.records().length,0);
});

test('published frontend route inventory includes injected recovery reads and staged rotation controls', async () => {
    const inventory=JSON.parse(await readFile(new URL('../api-calls.json',import.meta.url),'utf8'));
    for(const [method,path] of [['GET','/api/v1/operator/capabilities'],['GET','/api/v1/operator/requests/:param'],
        ['GET','/api/v1/agents/:param/key-rotations'],['GET','/api/v1/agents/:param/key-rotations/:param'],['DELETE','/api/v1/agents/:param/key-rotations/:param']]) {
        assert(inventory.some(call=>call.method===method&&call.path===path),`${method} ${path} must remain in the route-test denominator`);
    }
});

test('backup and restore rows expose durable dispatch holds after request acknowledgment in both languages', async () => {
    const h=await harness();
    const response=await h.api.post('/api/v1/restores',{backup_id:'one'});
    h.api.acknowledge(response);assert.equal(h.recovery.records().length,0);
    const backupsModule=await h.load('pages/backups.js');await backupsModule.evaluate();
    const restoresModule=await h.load('pages/restores.js');await restoresModule.evaluate();
    const dispatch={state:'held',reason:'handoff_response_unknown',request_id:response.request_id};
    for(const language of ['en','he']) {
        const locale=JSON.parse(await readFile(new URL(`../public/locales/${language}.json`,import.meta.url),'utf8'));
        h.context.window.t=key=>key.split('.').reduce((value,part)=>value?.[part],locale)||key;
        const backups=new backupsModule.namespace.BackupsPage();
        backups.backups=[{id:'backup-one',status:'pending',operator_dispatch:dispatch}];
        const restores=new restoresModule.namespace.RestoresPage();
        restores.restores=[{id:'restore-one',status:'pending',kubevirt_target:{namespace:'target'},operator_dispatch:dispatch}];
        for(const html of [backups.renderBackupRows(),restores.renderRestoreRows()]) {
            assert(html.includes(locale.operator_recovery.dispatch_held));
            assert(html.includes('handoff_response_unknown'));
            assert(html.includes(response.request_id));
        }
        dispatch.state='delivered';
        assert(restores.renderRestoreRows().includes(locale.operator_recovery.dispatch_delivered));
        assert.equal(restores.restores[0].status,'pending');
        dispatch.state='held';
    }
    assert.equal(h.mutations().length,1,'rendering a hold does not resume or recreate work');
});

test('restore snapshots naturally expose a later dispatch hold after the initial response was acknowledged', async () => {
    const h=await harness();
    const admitted=await h.api.post('/api/v1/restores',{backup_id:'one'});
    h.api.acknowledge(admitted);assert.equal(h.recovery.records().length,0);
    let state='pending', visible='';
    h.setHandler(async()=>({items:[{id:'restore-one',status:'pending',operator_dispatch:{state,reason:state==='held'?'dispatch_reply_unknown':null,request_id:admitted.request_id}}],total:1}));
    const module=await h.load('pages/restores.js');await module.evaluate();
    const page=new module.namespace.RestoresPage();
    h.context.window.vnbui.refreshPage=()=>{visible=page.renderRestoreRows();};
    await page.render();
    assert.equal(h.intervals.length,1);
    state='held';await h.intervals[0]();
    assert(visible.includes('Reconcile the original attempt'));
    assert(visible.includes('dispatch_reply_unknown'));assert.equal(page.restores[0].status,'pending');
    assert.equal(h.mutations().length,1,'snapshot observation never resubmits or resumes');
    page.destroy();
});

test('pending unreserved close visibility is restricted to operators in EN and HE', async () => {
    const h = await harness();
    const module = await h.load('pages/backups.js'); await module.evaluate();
    const page = new module.namespace.BackupsPage();
    for (const language of ['en', 'he']) {
        const locale = JSON.parse(await readFile(new URL(`../public/locales/${language}.json`, import.meta.url), 'utf8'));
        h.context.window.t = key => key.split('.').reduce((value, part) => value?.[part], locale) || key;
        for (const role of ['admin', 'operator', 'viewer', undefined]) {
            h.context.window.vnbui.currentUserRole = role;
            for (const status of ['pending', 'running', 'failed', 'completed']) {
                for (const capacity_state of ['unreserved', 'reserved', undefined]) {
                    page.backups = [{id: 'backup-one', status, capacity_state}];
                    const html = page.renderBackupRows();
                    const visible = ['admin', 'operator'].includes(role) && status === 'pending' && capacity_state === 'unreserved';
                    assert.equal(html.includes('window.vnbui.closeUnreservedBackup('), visible, `${language}/${role}/${status}/${capacity_state}`);
                    if (visible) assert(html.includes(locale.backups.close_unreserved));
                }
            }
        }
        assert(locale.backups.close_unreserved_confirm);
        assert(locale.operator_recovery.backup_close_unreserved);
    }
});

async function closeRequestApp(h) {
    const module = await h.load('app.js'); await module.evaluate();
    const app = new module.namespace.App(); app.user = {id: 'alice', role: 'admin'};
    app.setupEventListeners();
    h.context.window.vnbui.showToast = (message, kind) => h.toasts.push({message, kind});
    h.context.window.vnbui.refreshPage = () => {};
    return h.context.window.vnbui.closeUnreservedBackup;
}

test('explicit pending close posts empty intent with close action identity and acknowledges reviewed success', async () => {
    const h = await harness();
    const close = await closeRequestApp(h);
    let confirmations = 0;
    h.context.confirm = message => {confirmations++; assert.equal(message, 'backups.close_unreserved_confirm'); return false;};
    await close('backup-one');
    assert.equal(h.calls.length, 0);
    h.context.confirm = () => {confirmations++; return true;};
    h.setHandler(async (url, options) => {
        if (options.method === 'GET') return capabilities;
        assert.equal(h.recovery.records()[0].action, 'backup.close_unreserved');
        return {backup_id: 'backup-one', status: 'failed', reason: 'pre_dispatch_no_effect', capacity_state: 'unreserved', request_id: options.headers['Idempotency-Key']};
    });
    await close('backup-one');
    assert.equal(confirmations, 2);
    assert.equal(h.mutations().length, 1);
    assert.equal(h.mutations()[0].url, '/api/v1/backups/backup-one/close-unreserved');
    assert.equal(h.mutations()[0].options.body, '{}');
    assert.match(h.mutations()[0].options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/);
    assert.equal(h.recovery.records().length, 0);
    assert.equal(h.toasts[0].message, 'backups.close_unreserved_closed');
});

test('pending close response loss recovers only original identity and server refusal code remains visible', async () => {
    const h = await harness();
    const close = await closeRequestApp(h);
    h.setHandler(async (url, options) => {
        if (options.method === 'GET') return capabilities;
        throw new Error('response lost');
    });
    await close('backup-one');
    const original = h.recovery.records()[0];
    assert.equal(original.action, 'backup.close_unreserved');
    const reloaded = await harness(h.storage);
    const reopenedClose = await closeRequestApp(reloaded);
    reloaded.setHandler(async url => url.endsWith('/capabilities') ? capabilities : {
        request_id: original.request_id, action: 'backup.close_unreserved', contract_version: 1,
        state: 'admitted', receipt: {backup_id: 'backup-one', status: 'failed', reason: 'pre_dispatch_no_effect', capacity_state: 'unreserved'}, dispatches: []});
    await reopenedClose('backup-one');
    assert.equal(reloaded.mutations().length, 0);
    assert(reloaded.calls.some(call => call.url.endsWith(`/operator/requests/${original.request_id}`)));
    assert.equal(reloaded.recovery.records()[0].request_id, original.request_id);

    const refused = await harness();
    refused.context.t = (key, vars) => `${key}: ${vars?.reason || ''}`;
    const refusedClose = await closeRequestApp(refused);
    refused.setHandler(async (url, options) => options.method === 'GET' ? capabilities : {wireResponse: {
        ok: false, status: 409, json: async () => ({detail: {code: 'backup_custody_ambiguous'}})}});
    await refusedClose('backup-one');
    assert(refused.toasts[0].message.includes('backup_custody_ambiguous'));
    assert.equal(refused.recovery.records()[0].action, 'backup.close_unreserved');
});
