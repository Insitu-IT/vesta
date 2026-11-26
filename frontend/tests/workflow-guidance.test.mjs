import {escapeHtml} from '../src/utils/security.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {normalizeUiPath} from '../src/utils/ui-path.js';
import {dataDisks, renderDiskSummary, renderCbtObservation} from '../src/utils/vm-inventory.js';
import {contextHelp, installContextHelp} from '../src/components/context-help.js';

for (const lang of ['en', 'he']) {
    const locale = JSON.parse(await readFile(new URL(`../public/locales/${lang}.json`, import.meta.url)));
    const t = (key, vars = {}) => key.split('.').reduce((o,k) => o?.[k], locale).replace(/{{(\w+)}}/g, (_, k) => vars[k]);
    test(`${lang}: disk summaries show real capacity in stable order, exclude CDROM and preserve unknowns`, () => {
        const disks = [{target: 'vdc', capacity_bytes: null}, {target: 'vda', capacity_bytes: 10737418240}, {target: 'vdb', capacity_bytes: null}, {target: 'sda', device: 'cdrom', capacity_bytes: 9000}];
        const html = renderDiskSummary(disks, t);
        assert.equal(dataDisks(disks).length, 3);
        assert.ok(html.includes('10 GiB'));
        assert.ok(html.includes(locale.inventory.capacity_unknown));
        assert.ok(html.includes(t('inventory.more_disks', {count: 1})));
        assert.ok(!html.includes('sda'));
        assert.ok(!html.includes('vdc'));
        for (const count of [0, 1, 2]) assert.ok(renderDiskSummary(disks.slice(0, count), t).includes(t('inventory.disk_count', {count})));
        assert.equal(disks[0].target, 'vdc');
    });
    test(`${lang}: observed CBT stays distinct from disk eligibility and absent observations`, () => {
        for (const [state, key] of [['Enabled','enabled'],['Disabled','disabled'],['Initializing','pending'],['future','unknown'],[null,'unknown']]) {
            const html = renderCbtObservation({metadata: {changed_block_tracking: {state, source: 'vmi'}}}, t);
            assert.ok(html.includes(escapeHtml(locale.inventory[`cbt_${key}`])));
            assert.ok(html.includes('VMI'));
        }
        assert.ok(renderCbtObservation({}, t).includes(escapeHtml(locale.inventory.cbt_unknown)));
    });
    test(`${lang}: every workflow hint has native touch/keyboard disclosure and accessible text`, () => {
        for (const key of Object.keys(locale.help).filter(k => k !== 'label')) {
            const html = contextHelp(key, t);
            assert.ok(html.includes('<summary aria-label='));
            assert.ok(html.includes('aria-describedby='));
            assert.ok(html.includes(locale.help[key]));
        }
    });
}

test('unsupported UI paths normalize without losing query, hash or history state', () => {
    for (const pathname of ['/bla', '/old/deep/path', '/another-name', '/hello.world', '/reports.v2', '/dotted.path/']) {
        const calls = []; const state = {navigation: 2};
        assert.equal(normalizeUiPath({pathname, search: '?return=one', hash: '#vms'}, {state, replaceState: (...args) => calls.push(args)}), true);
        assert.deepEqual(calls, [[state, '', '/?return=one#vms']]);
    }
    for (const pathname of ['/', '/login', '/api/v1/auth/oidc/callback', '/appearance/config.json', '/metrics', '/assets/missing.js', '/locales/en.json', '/favicon.svg', '/site-config.json', '/missing.js']) assert.equal(normalizeUiPath({pathname}, {}), false);
});


test('Escape dismisses focus/hover help and open disclosures without moving unrelated focus', () => {
    const originalDocument = globalThis.document;
    const listeners = new Map();
    const makeHelp = (open = false) => {
        const classes = new Set(); let focusCalls = 0;
        const help = {open, dataset: {}, classList: {add: value => classes.add(value), remove: value => classes.delete(value)}, contains: node => node?.owner === help};
        const summary = {owner: help, focus: () => {focusCalls++;}};
        help.querySelector = () => summary;
        return {help, summary, classes, focusCalls: () => focusCalls};
    };
    const focused = makeHelp(), hovered = makeHelp(), opened = makeHelp(true);
    globalThis.document = {
        activeElement: focused.summary,
        addEventListener: (type, listener) => listeners.set(type, listener),
        querySelectorAll: selector => {assert.ok(selector.includes(':focus-within') && selector.includes(':hover')); return [focused.help, hovered.help, opened.help];},
    };
    try {
        installContextHelp(); listeners.get('keydown')({key: 'Escape'});
        for (const item of [focused, hovered, opened]) {assert.equal(item.help.open, false); assert.ok(item.classes.has('context-help-dismissed'));}
        assert.equal(focused.focusCalls(), 1);
        assert.equal(hovered.focusCalls(), 0); assert.equal(opened.focusCalls(), 0);
        listeners.get('pointerover')({target: {closest: () => hovered.help}, relatedTarget: hovered.summary});
        assert.ok(hovered.classes.has('context-help-dismissed'), 'moving inside a dismissed hint does not reopen it');
        listeners.get('pointerover')({target: {closest: () => hovered.help}, relatedTarget: null});
        assert.equal(hovered.classes.has('context-help-dismissed'), false, 'reentering the hint allows hover help again');
        assert.equal(hovered.help.open, true, 'hover opens the actual native disclosure content');
        focused.help.open = false;
        listeners.get('focusin')({target: {closest: () => focused.help}});
        assert.equal(focused.help.open, true, 'keyboard focus opens the actual native disclosure content');
    } finally {globalThis.document = originalDocument;}
});
