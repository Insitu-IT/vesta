import assert from 'node:assert/strict';
import {checkArtifactFile} from './check-artifact-dist.mjs';

for (const name of ['organizations-a.js', 'billing-a.js', 'branding-a.js', 'org-selector-a.js']) {
    assert.throws(() => checkArtifactFile(`dist/assets/${name}`, '', 'community'));
    checkArtifactFile(`dist/assets/${name}`, '', 'commercial');
}
for (const edition of ['community', 'commercial']) {
    assert.throws(() => checkArtifactFile('dist/public.MAP', '', edition));
    checkArtifactFile('dist/assets/backups-a.js', '/api/v1/backups', edition);
}
for (const endpoint of ['organizations', 'billing/usage', 'branding']) {
    assert.throws(() => checkArtifactFile('dist/assets/index.js', `/api/v1/${endpoint}`, 'community'));
}
assert.throws(() => checkArtifactFile('dist/index.js', '', 'unknown'));
assert.throws(
    () => checkArtifactFile('dist/locales/en.json', '{"branding":{}}', 'community'),
    /Commercial translations/
);
assert.throws(
    () => checkArtifactFile('dist/assets/manifest.json', '{"assets":{"nav-billing":{}}}', 'community'),
    /Commercial icon/
);
console.log('PASS: build-output edition and source-map guard');
