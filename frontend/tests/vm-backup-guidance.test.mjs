import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {bindBackupGuidance, loadBackupGuidance, renderBackupGuidance} from '../src/utils/backup-guidance.js';
import {escapeHtml} from '../src/utils/security.js';

for (const lang of ['en', 'he']) {
    const catalog = JSON.parse(await readFile(new URL(`../public/locales/${lang}.json`, import.meta.url)));
    const t = (key, vars = {}) => key.split('.').reduce((group, name) => group[name], catalog)
        .replace(/{{(\w+)}}/g, (_, name) => vars[name]);
    test(`${lang}: a healthy single-disk VM sees its own recommendation`, () => {
        const html = renderBackupGuidance({
            mode: 'full', reason: 'checkpoint_missing', affected_disks: [], persistent_disks: ['disk'],
            storage: {state:'measured', role:'journal'}, documentation_url:'javascript:alert(1)',
        }, t);
        assert.ok(html.includes(escapeHtml(catalog.guidance.checkpoint_missing)));
        assert.doesNotMatch(html, /javascript|<details>/);
        assert.ok(!html.includes(escapeHtml(catalog.guidance.capacity_low)));
        assert.ok(renderBackupGuidance(null, t).includes(escapeHtml(catalog.guidance.unavailable)));
    });
    test(`${lang}: multidisk evidence distinguishes served APIs, enabled volumes and the provider path`, () => {
        const html = renderBackupGuidance({
            mode:'blocked', reason:'storage_at_limit', persistent_disks:['disk','<untrusted>'],
            storage: {role:'journal',state:'at_limit',used_percent:95,admission_used_percent:95},
            volume_snapshot_statuses:{disk:true}, group_snapshot_api:'served',
            documentation_url:'https://vestabackup.com/docs/manuals/backup-safety/',
        }, t);
        for (const key of ['snapshot_yes','snapshot_unknown','group_served','group_execution']) {
            assert.ok(html.includes(escapeHtml(catalog.guidance[key])));
        }
        assert.ok(html.includes('95%') && html.includes('backup-safety/') && html.includes('&lt;untrusted&gt;'));
        assert.doesNotMatch(html, /<untrusted>/);
    });
}

test('mode guidance uses repeated disk targets and ignores outdated responses', async () => {
    const calls = [], area = {dataset:{}}, select = {value:'incremental'}, submit = {};
    let excluded = [];
    const disks = {querySelectorAll:()=>excluded.map(value=>({value}))};
    const modal = {querySelector:id=>({
        '#backup-mode-guidance':area, '#backup-type':select, '#submit-vm-backup':submit, '#backup-exclude-disks':disks,
    })[id]};
    const client = {get:(path,params)=>new Promise(resolve=>calls.push({path,params,resolve}))};
    const t = key=>key;
    const first = bindBackupGuidance(modal, 'one', client, t);
    assert.equal(submit.disabled,true);
    excluded = ['data a','data&b'];
    const second = disks.onchange();
    assert.equal(calls[1].path,'/api/v1/vms/one/backup-guidance');
    assert.deepEqual(calls[1].params.getAll('exclude_disk'),excluded);
    calls[1].resolve({mode:'full',reason:'checkpoint_changed'});
    await second;
    calls[0].resolve({mode:'incremental',reason:'checkpoint_recorded'});
    await first;
    assert.match(area.innerHTML,/checkpoint_changed/);
    assert.equal(submit.disabled,true);
    select.value = 'full'; select.onchange();
    assert.equal(submit.disabled,false);
    const third = disks.onchange();
    calls[2].resolve({mode:'blocked',reason:'cbt_disabled'});
    await third;
    assert.equal(submit.disabled,true);
    assert.equal(await loadBackupGuidance({get(){throw Error('old API');}},'one'),null);
});
