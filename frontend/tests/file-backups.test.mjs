import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../src/components/file-backups.js', import.meta.url), 'utf8');
const target = { kind: 'file_set', agent_id: '49739323-5bdd-47eb-a2a7-67948dfe41d9', file_set: 'exports' };

async function setup() {
    const storage = new Map();
    const calls = [];
    const questions = [];
    const fixture = {scope: 'origin/org-one/operator-one', disposition: 'lost', acceptsRetry: true};
    const context = vm.createContext({
        crypto: webcrypto, TextEncoder,
        window: { t: key => key, confirm: question => { questions.push(question); return fixture.acceptsRetry; } },
        sessionStorage: {
            getItem: key => storage.get(key) ?? null,
            setItem: (key, value) => storage.set(key, value),
            removeItem: key => storage.delete(key),
        },
    });
    const dependencies = {
        apiClient: { async request(path, options) {
            assert.equal(path, '/api/v1/file-backups');
            assert.equal(options.method, 'POST');
            assert.deepEqual(JSON.parse(options.body), {target});
            calls.push(options.headers['Idempotency-Key']);
            if (fixture.disposition === 'lost') throw new Error('response unavailable');
            return { id: calls.at(-1), target };
        }},
        operatorRequests: {scope: () => fixture.scope},
        escapeHtml: String, formatDate: String, formatSize: String,
    };
    const module = new vm.SourceTextModule(source, { context });
    await module.link(specifier => {
        const names = specifier.endsWith('/client.js') ? ['apiClient'] :
            specifier.endsWith('/operator-requests.service.js') ? ['operatorRequests'] :
            specifier.endsWith('/security.js') ? ['escapeHtml'] : ['formatDate', 'formatSize'];
        return new vm.SyntheticModule(names, function () {
            for (const key of names) this.setExport(key, dependencies[key]);
        }, { context });
    });
    await module.evaluate();
    function newPage() {
        const panel = new module.namespace.FileBackupsPanel('backups');
        panel.root = {querySelector: () => ({reportValidity: () => true})};
        panel.selectedSet = () => ({target, storage: {bucket: 'sample'}});
        panel.mutate = action => action();
        return panel;
    }
    return {fixture, storage, calls, questions, newPage};
}

test('a lost manual response retains the original identity across reload and requires an explicit retry', async () => {
    const h = await setup();
    await assert.rejects(h.newPage().saveForm(), /response unavailable/);
    const original = h.calls[0];
    assert.match(original, /^[0-9a-f-]{36}$/);
    assert.equal(h.storage.size, 1);
    assert.doesNotMatch(JSON.stringify([...h.storage]), /exports|operator-one|49739323/);
    h.fixture.disposition = 'accepted';
    h.fixture.acceptsRetry = false;
    await h.newPage().saveForm();
    assert.deepEqual(h.calls, [original]);
    h.fixture.acceptsRetry = true;
    await h.newPage().saveForm();
    assert.deepEqual(h.calls, [original, original]);
    assert.equal(h.questions.length, 2);
    assert.equal(h.storage.size, 0);
});

test('a different organization or actor receives an independent manual request identity', async () => {
    const h = await setup();
    await assert.rejects(h.newPage().saveForm());
    h.fixture.scope = 'origin/org-two/operator-two';
    await assert.rejects(h.newPage().saveForm());
    assert.notEqual(h.calls[0], h.calls[1]);
    assert.equal(h.questions.length, 0);
    assert.equal(h.storage.size, 2);
});
