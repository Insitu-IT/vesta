import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { collectNotices, thirdPartyNotices } from './third-party-notices.mjs';

function fixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vnbui-notices-'));
  const pkg = path.join(root, 'node_modules', '@example', 'runtime');
  fs.mkdirSync(pkg, { recursive: true });
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: '@example/runtime', version: '1.2.3', license: 'MIT' }));
  fs.writeFileSync(path.join(pkg, 'LICENSE'), 'Copyright Example\nPermission is hereby granted.\n');
  fs.writeFileSync(path.join(pkg, 'NOTICE.txt'), 'Retain this attribution.\n');
  const bundle = { app: { type: 'chunk', modules: { [path.join(pkg, 'index.js')]: {}, [path.join(pkg, 'other.js')]: {} } } };
  try { run({ root, pkg, bundle }); } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('copies full upstream license and notice once, without build paths/source', () => fixture(({ root, bundle }) => {
  const result = collectNotices(root, bundle);
  assert.equal(result.match(/@example\/runtime@1.2.3/g).length, 1);
  assert.ok(result.includes('Copyright Example\nPermission is hereby granted.'));
  assert.ok(result.includes('Retain this attribution.'));
  assert.ok(!result.includes(root));
  let emitted;
  thirdPartyNotices(root).generateBundle.call({ emitFile(value) { emitted = value; } }, {}, bundle);
  assert.equal(emitted.fileName, 'THIRD-PARTY-NOTICES.txt');
  assert.equal(emitted.source, result);
}));

test('missing full license refuses instead of manufacturing permission', () => fixture(({ root, pkg, bundle }) => {
  fs.unlinkSync(path.join(pkg, 'LICENSE'));
  assert.throws(() => collectNotices(root, bundle), /Missing full upstream license/);
}));

test('unknown or private distribution terms refuse', () => fixture(({ root, pkg, bundle }) => {
  for (const metadata of [
    { name: '@example/runtime', version: '1.2.3', license: 'AGPL-3.0-only' },
    { name: '@example/runtime', version: '1.2.3', license: 'MIT', private: true }
  ]) {
    fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify(metadata));
    assert.throws(() => collectNotices(root, bundle), /distribution-terms review/);
  }
}));

test('symlink license cannot leak a file outside the dependency', () => fixture(({ root, pkg, bundle }) => {
  const external = path.join(root, 'private.txt');
  fs.writeFileSync(external, 'Not a distributable notice');
  fs.unlinkSync(path.join(pkg, 'LICENSE'));
  fs.symlinkSync(external, path.join(pkg, 'LICENSE'));
  assert.throws(() => collectNotices(root, bundle), /Missing full upstream license/);
}));

test('empty and binary documents refuse', () => fixture(({ root, pkg, bundle }) => {
  for (const text of ['', 'not\0text']) {
    fs.writeFileSync(path.join(pkg, 'LICENSE'), text);
    assert.throws(() => collectNotices(root, bundle), /Invalid legal document/);
  }
}));

test('no dependency inventory refuses; virtual helpers do not become packages', () => fixture(({ root }) => {
  assert.throws(() => collectNotices(root, { app: { type: 'chunk', modules: { '\0vite:helper': {} } } }), /No bundled dependency/);
}));

test('unreviewed license indirection refuses', () => fixture(({ root, pkg, bundle }) => {
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: '@example/runtime', version: '1.2.3', license: 'SEE LICENSE IN LICENSE' }));
  assert.throws(() => collectNotices(root, bundle), /distribution-terms review/);
}));

test('reviewed package identity cannot borrow changed license bytes', () => fixture(({ root, pkg, bundle }) => {
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'stackframe', version: '0.3.1', license: 'SEE LICENSE IN LICENSE' }));
  assert.throws(() => collectNotices(root, bundle), /Reviewed upstream license changed/);
}));

test('retains the supplied published-Tabler attributions and complete MIT terms', () => fixture(({ root, pkg, bundle }) => {
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: '@tabler/core', version: '1.4.0', license: 'MIT' }));
  fs.unlinkSync(path.join(pkg, 'LICENSE'));
  const target = path.join(root, 'public/licenses');
  fs.mkdirSync(target, { recursive: true });
  fs.copyFileSync(new URL('../public/licenses/tabler-core.MIT.txt', import.meta.url), path.join(target, 'tabler-core.MIT.txt'));
  const output = collectNotices(root, bundle);
  assert.ok(output.includes('Copyright 2018-2025 codecalm.net Paweł Kuna'));
  assert.ok(output.includes('Permission is hereby granted, free of charge'));
}));

test('supplied notice cannot silently change its reviewed terms', () => fixture(({ root, pkg, bundle }) => {
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: '@tabler/core', version: '1.4.0', license: 'MIT' }));
  const target = path.join(root, 'public/licenses');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'tabler-core.MIT.txt'), 'Changed terms');
  assert.throws(() => collectNotices(root, bundle), /Supplied upstream notice changed/);
}));
