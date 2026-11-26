import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSiteConfig, rumEnabled } from '../src/utils/site-config.js';

const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const imageDefault = readJson('../public/site-config.json');
const baseConfigMap = readJson('../../packaging/okd/kustomize/base/api/02-configmap-vesta-frontend.json');
const baseDeployment = readJson('../../packaging/okd/kustomize/base/api/03-deployment-vesta-frontend.json');
const indexHtml = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
assert.deepEqual(imageDefault, { apm: { enabled: false } });
assert.doesNotMatch(indexHtml, /fonts\.googleapis\.com/);
assert.deepEqual(JSON.parse(baseConfigMap.data['site-config.json']), imageDefault);
assert.ok(baseDeployment.spec.template.spec.containers[0].volumeMounts.some(
    (mount) => mount.mountPath === '/usr/share/nginx/html/site-config.json'
        && mount.subPath === 'site-config.json'
        && mount.readOnly === true,
));

const calls = [];
const enabled = await loadSiteConfig(async (...args) => {
    calls.push(args);
    return { ok: true, json: async () => ({ apm: { enabled: true } }) };
});
assert.deepEqual(enabled, { apm: { enabled: true } });
assert.equal(rumEnabled(enabled), true);
assert.deepEqual(calls, [['/site-config.json', { cache: 'no-store' }]]);

for (const response of [
    { ok: true, json: async () => ({ apm: { enabled: 'true' } }) },
    { ok: true, json: async () => ({ apm: { enabled: false } }) },
    { ok: true, json: async () => ({}) },
    { ok: false },
    { ok: true, json: async () => { throw new Error('invalid JSON'); } },
]) {
    const config = await loadSiteConfig(async () => response);
    assert.equal(config.apm.enabled, false);
    assert.equal(rumEnabled(config), false);
}
assert.equal((await loadSiteConfig(async () => { throw new Error('offline'); })).apm.enabled, false);
