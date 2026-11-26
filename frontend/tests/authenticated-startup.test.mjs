import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';

// Run real auth, startup and transport modules with controlled network/clock.
// No browser bundle, socket server or dependency install.
async function harness(config = {enableWebSocket: true, enablePolling: true}) {
    let now = 0, nextId = 0;
    const timers = new Map(), calls = [], sockets = [], storage = new Map();
    const schedule = (callback, delay, repeat = false) => {
        const id = ++nextId; timers.set(id, {callback, delay, repeat, at: now + delay}); return id;
    };
    class Socket {
        static OPEN = 1;
        constructor(url, protocols) {this.url = url; this.protocols = protocols; this.readyState = 0; sockets.push(this);}
        open() {this.readyState = 1; this.onopen?.();}
        fail() {this.onerror?.(); this.onclose?.({code: 1006});}
        close() {this.readyState = 3; this.onclose?.({code: 1000});}
        send() {}
    }
    const apiClient = {
        async get(url) {calls.push(url); return url.endsWith('/config/realtime') ? config : {items: [], next_cursor: 'cursor', has_more: false, reset_required: false, reset_reason: null, retention_seconds: 300, delivery: 'best_effort'};},
        async checkCompatibility() {calls.push('compatibility'); return {degraded_mode: false};},
    };
    const context = vm.createContext({
        console: {log() {}, warn() {}, error() {}},
        window: {vnbui: {}, location: {protocol: 'https:', host: 'vesta.test', hash: '#dashboard', replace() {}}},
        sessionStorage: {getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)},
        localStorage: {removeItem() {}},
        Date: class extends Date {static now() {return now;}},
        setTimeout: (f, d) => schedule(f, d), clearTimeout: id => timers.delete(id),
        setInterval: (f, d) => schedule(f, d, true), clearInterval: id => timers.delete(id),
        WebSocket: Socket, AbortSignal, URLSearchParams,
        fetch: async () => {calls.push('logout'); return {ok: true};},
    });
    const modules = new Map();
    const synthetic = values => new vm.SyntheticModule(Object.keys(values), function() {
        for (const [key, value] of Object.entries(values)) this.setExport(key, value);
    }, {context});
    async function load(name) {
        if (modules.has(name)) return modules.get(name);
        const source = await readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
        const module = new vm.SourceTextModule(source, {context}); modules.set(name, module);
        await module.link(async specifier => {
            if (specifier.includes('client.js')) return synthetic({apiClient});
            if (specifier.endsWith('auth.service.js')) return load('services/auth.service.js');
            if (specifier.endsWith('updates.service.js')) return load('services/updates.service.js');
            if (specifier.endsWith('authenticated-startup.js')) return load('services/authenticated-startup.js');
            const match = [...source.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]/g)].find(m => m[2] === specifier);
            assert(match, `Known static test import ${specifier}`);
            return synthetic(Object.fromEntries(match[1].split(',').map(key => [key.trim(), () => {}])));
        });
        return module;
    }
    const startupModule = await load('services/authenticated-startup.js'); await startupModule.evaluate();
    const auth = modules.get('services/auth.service.js').namespace.authService;
    const updates = modules.get('services/updates.service.js').namespace.updateService;
    const start = startupModule.namespace.startAuthenticatedServices;
    const flush = async () => {for (let n = 0; n < 12; n++) await Promise.resolve();};
    async function advance(ms) {
        const until = now + ms;
        while (true) {
            const due = [...timers].filter(([, t]) => t.at <= until).sort((a,b) => a[1].at-b[1].at)[0];
            if (!due) break;
            const [id, timer] = due; now = timer.at;
            if (timer.repeat) timer.at += timer.delay; else timers.delete(id);
            timer.callback(); await flush();
        }
        now = until; await flush();
    }
    return {context, auth, updates, start, calls, sockets, timers, flush, advance, load, apiClient};
}

test('interactive App.init and restored/OIDC App.init share one live authenticated startup', async () => {
    const h = await harness();
    const module = await h.load('app.js'); await module.evaluate();
    const App = module.namespace.App;
    const app = new App();
    h.auth.fetchUserData = async () => ({username: 'viewer'});
    for (const method of ['loadFeatures', 'render', 'setupEventListeners', 'navigate']) app[method] = () => {};
    await h.start(app); assert.equal(h.sockets.length, 0, 'anonymous entry creates no authenticated transport');
    // Completion of ordinary password sign-in calls this exact App.init path.
    h.auth.setToken('ordinary-session');
    const interactive = app.init(); await h.flush();
    assert.equal(h.sockets.length, 1);
    assert.equal(h.context.window.vnbui.updates, h.updates);
    assert.equal(h.sockets[0].url, 'wss://vesta.test/ws');
    assert.deepEqual(Array.from(h.sockets[0].protocols), ['vnbui', 'bearer.ordinary-session']);
    h.sockets[0].open(); await interactive;
    const restore = new App();
    for (const method of ['loadFeatures', 'render', 'setupEventListeners', 'navigate']) restore[method] = () => {};
    await restore.init();
    assert.equal(h.sockets.length, 1, 'rerender/restored session creates no duplicate socket');
    assert.equal(h.calls.filter(x => x === 'compatibility').length, 1);
    assert.equal(h.calls.filter(x => x.endsWith('/config/realtime')).length, 1);
    assert.equal(h.updates.connectionMode, 'websocket');
    h.context.window.location.hash = '#settings'; await restore.refreshPage();
    assert.equal(h.sockets.length, 1, 'Settings page refresh preserves the authenticated transport');
    h.auth.clearToken();
    assert.equal(h.sockets[0].readyState, 3);
    assert.equal(h.updates.healthInterval, null);
    assert.equal(h.updates.pollingInterval, null);
    assert.equal(h.updates.reconnectTimer, null);
});

test('blocked WebSockets naturally retry once per socket and poll; logout stops all transport timers', async () => {
    const h = await harness(); h.auth.setToken('session');
    const first = h.start({}); const duplicate = h.start({});
    assert.equal(first, duplicate, 'concurrent authenticated startup shares one promise');
    await h.flush();
    for (let n = 0; n < 3; n++) {
        assert.equal(h.sockets.length, n + 1);
        h.sockets[n].fail(); await h.flush();
        if (n === 0) await first;
        if (n < 2) await h.advance(5000);
    }
    assert.equal(h.updates.connectionMode, 'polling');
    assert.equal(h.updates.reconnectAttempts, 3, 'error+close count as one failed handshake');
    assert(h.calls.some(url => url.startsWith('/api/v1/updates?contract=2')), 'natural fallback performs an actual read through API client');
    const polls = h.calls.filter(x => x.startsWith('/api/v1/updates?contract=2')).length;
    await h.advance(5000);
    assert(h.calls.filter(x => x.startsWith('/api/v1/updates?contract=2')).length > polls);
    await h.auth.logout();
    assert.equal(h.timers.size, 0);
    const count = h.calls.length; await h.advance(60000); assert.equal(h.calls.length, count);
});

test('logout during pending handshake cannot revive updates; a new session can start', async () => {
    const h = await harness(); h.auth.setToken('old-session');
    const old = h.start({}); await h.flush();
    h.auth.clearToken(); await old;
    assert.equal(h.timers.size, 0);
    const staleOpen = h.sockets[0].onopen; assert.equal(staleOpen, null);
    h.auth.setToken('new-session'); const current = h.start({}); await h.flush();
    assert.equal(h.sockets.length, 2); h.sockets[1].open(); await current;
    assert.equal(h.updates.connectionMode, 'websocket');
    h.auth.clearToken(); assert.equal(h.timers.size, 0);
});

test('server-disabled WebSockets use polling immediately without a socket', async () => {
    const h = await harness({enableWebSocket: false, enablePolling: true, pollingInterval: 10000});
    h.auth.setToken('viewer'); await h.start({});
    assert.equal(h.sockets.length, 0); assert.equal(h.updates.connectionMode, 'polling');
    assert(h.calls.some(url => url.startsWith('/api/v1/updates?contract=2'))); h.auth.clearToken(); assert.equal(h.timers.size, 0);
});


test('logout before the realtime configuration resolves prevents late socket/timer creation', async () => {
    let release;
    const h = await harness(new Promise(resolve => {release = resolve;}));
    h.auth.setToken('session'); const pending = h.start({}); await h.flush();
    h.auth.clearToken(); release({enableWebSocket: true, enablePolling: true}); await pending;
    assert.equal(h.sockets.length, 0); assert.equal(h.timers.size, 0);
    assert.equal(h.calls.filter(x => x === 'compatibility').length, 0);
});


test('healthy socket loss polls during retry, reconnect retains cursor polling and stale sockets are ignored', async () => {
    const h = await harness(); h.auth.setToken('session');
    const initial = h.start({}); await h.flush(); h.sockets[0].open(); await initial;
    const healthTimer = h.updates.healthInterval;
    let delivered = 0; h.updates.subscribe('backup_progress', () => delivered++);
    const message = {data: JSON.stringify({type: 'backup_progress', payload: {progress: 1}})};
    const staleMessage = h.sockets[0].onmessage, staleOpen = h.sockets[0].onopen;
    staleMessage(message); await h.flush(); assert.equal(delivered, 0, 'socket is only a catch-up hint');
    h.sockets[0].fail(); await h.flush();
    assert.equal(h.updates.connectionMode, 'polling'); assert(h.updates.pollingInterval);
    assert(h.calls.some(url => url.startsWith('/api/v1/updates')), 'polling starts before delayed reconnect');
    staleMessage(message); staleOpen();
    assert.equal(delivered, 0); assert.equal(h.updates.connectionMode, 'polling');
    await h.advance(5000); assert.equal(h.sockets.length, 2);
    h.sockets[1].open(); await h.flush();
    assert.equal(h.updates.connectionMode, 'websocket'); assert(h.updates.pollingInterval, 'bounded cursor reads continue with a connected socket');
    assert.equal(h.updates.healthInterval, healthTimer, 'reconnect retains one health timer');
    h.sockets[1].onmessage(message); await h.flush(); assert.equal(delivered, 0);
    h.auth.clearToken(); assert.equal(h.timers.size, 0);
});

const envelope = (items = [], extra = {}) => ({items, next_cursor: 'next', has_more: false,
    reset_required: false, reset_reason: null, retention_seconds: 300, delivery: 'best_effort', ...extra});

test('cursor pages drain in order and socket hints share one in-flight read', async () => {
    const h = await harness({enableWebSocket: false, enablePolling: true});
    h.auth.setToken('cursor-session'); await h.start({}); await h.flush();
    let release, reads = 0;
    const received = [];
    h.updates.subscribe('backup_progress', data => received.push(data.progress));
    h.apiClient.get = async url => {
        reads++;
        if (reads === 1) return new Promise(resolve => {release = resolve;});
        assert(url.includes('cursor=page-one'));
        return envelope([{type: 'backup_progress', payload: {progress: 2}, sequence: 2}], {next_cursor: 'page-two'});
    };
    const first = h.updates.poll();
    const duplicate = h.updates.poll();
    assert.equal(first, duplicate); assert.equal(reads, 1);
    release(envelope([{type: 'backup_progress', payload: {progress: 1}, sequence: 1}], {next_cursor: 'page-one', has_more: true}));
    // The coalesced hint performs one additional read after this drain.
    h.updates.pollRequested = false;
    await first;
    assert.deepEqual(received, [1, 2]); assert.equal(h.updates.cursor, 'page-two');
    assert.equal(reads, 2); h.auth.clearToken();
});

test('reset awaits authoritative resync then catches events emitted during the snapshot', async () => {
    const h = await harness({enableWebSocket: false, enablePolling: true});
    h.auth.setToken('reset-session'); await h.start({}); await h.flush();
    const previous = h.updates.cursor;
    let release, reads = 0;
    h.updates.subscribeResync(() => new Promise(resolve => {release = resolve;}));
    h.apiClient.get = async url => {
        reads++;
        if (reads === 1) return envelope([], {next_cursor: 'reset-boundary', reset_required: true, reset_reason: 'history_lost'});
        assert(url.includes('cursor=reset-boundary'));
        return envelope([], {next_cursor: 'caught-up'});
    };
    const pending = h.updates.poll(); await h.flush();
    assert.equal(h.updates.cursor, previous); assert.equal(reads, 1);
    release(); await pending;
    assert.equal(reads, 2); assert.equal(h.updates.cursor, 'caught-up');
    h.auth.clearToken();
});

test('failed resync and malformed envelopes retain the original cursor without fabricating time', async () => {
    const h = await harness({enableWebSocket: false, enablePolling: true});
    h.auth.setToken('failed-session'); await h.start({}); await h.flush();
    const previous = h.updates.cursor;
    const unsubscribe = h.updates.subscribeResync(async () => {throw new Error('snapshot unavailable');});
    h.apiClient.get = async () => envelope([], {next_cursor: 'unaccepted', reset_required: true, reset_reason: 'process_changed'});
    await h.updates.poll(); assert.equal(h.updates.cursor, previous);
    unsubscribe();
    h.apiClient.get = async () => [];
    await h.updates.poll(); assert.equal(h.updates.cursor, previous);
    h.auth.clearToken();
});

test('logout during an outstanding cursor read or resync cannot revive cursor state', async () => {
    const h = await harness({enableWebSocket: false, enablePolling: true});
    h.auth.setToken('old-session'); await h.start({}); await h.flush();
    let release;
    h.apiClient.get = async () => new Promise(resolve => {release = resolve;});
    const pending = h.updates.poll(); h.auth.clearToken();
    release(envelope([], {next_cursor: 'stale'})); await pending;
    assert.equal(h.updates.cursor, null); assert.equal(h.updates.pollInFlight, null);
    assert.equal(h.timers.size, 0);
});
