// Build-time legal documents for the packages actually present in output chunks.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const accepted = new Set(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD', 'Unlicense', 'CC0-1.0', 'Zlib']);
const legalName = /^(?:licen[cs]e|copying|notice|copyright|patents)(?:[._-].*)?$/i;
// The locked package declares notice indirection; its full Unlicense document
// has been reviewed. Bind that classification to the exact upstream bytes.
const reviewed = new Map([['stackframe@0.3.1', {
  declaration: 'SEE LICENSE IN LICENSE', file: 'LICENSE',
  sha256: '88d9b4eb60579c191ec391ca04c16130572d7eedc4a86daa58bf28c6e14c9bcd'
}]]);
// This published npm archive omits its referenced license. Retain both its
// original banner attributions and the publisher's complete MIT document.
const suppliedDocuments = new Map([['@tabler/core@1.4.0', {
  declaration: 'MIT', file: 'public/licenses/tabler-core.MIT.txt',
  sha256: '3605c55f5911dd6af642033b6d759386ebebf6ddd5becdbe49ec06edb1077b87'
}]]);

export function collectNotices(root, bundle) {
  const modules = path.resolve(root, 'node_modules');
  const packages = new Map();
  for (const chunk of Object.values(bundle)) {
    if (chunk.type !== 'chunk') continue;
    for (const id of Object.keys(chunk.modules)) {
      if (id.startsWith('\0')) continue;
      const filename = id.split('?')[0];
      if (!filename.startsWith(modules + path.sep)) continue;
      let directory = path.dirname(filename);
      let found = false;
      while (directory.startsWith(modules + path.sep)) {
        const manifest = path.join(directory, 'package.json');
        if (fs.existsSync(manifest)) {
          const pkg = JSON.parse(fs.readFileSync(manifest, 'utf8'));
          if (pkg.name && pkg.version) {
            if (!fs.realpathSync(directory).startsWith(fs.realpathSync(modules) + path.sep)) {
              throw new Error('Bundled dependency resolves outside node_modules');
            }
            const review = reviewed.get(`${pkg.name}@${pkg.version}`);
            if (pkg.private || (!accepted.has(pkg.license) && (!review || review.declaration !== pkg.license))) {
              throw new Error(`Bundled package needs distribution-terms review: ${pkg.name}`);
            }
            if (!accepted.has(pkg.license)) {
              const file = path.join(directory, review.file);
              const info = fs.lstatSync(file);
              if (!info.isFile() || info.isSymbolicLink() || info.size > 1024 * 1024) {
                throw new Error(`Unsafe reviewed legal document: ${pkg.name}`);
              }
              const body = fs.readFileSync(file);
              if (createHash('sha256').update(body).digest('hex') !== review.sha256) {
                throw new Error(`Reviewed upstream license changed: ${pkg.name}`);
              }
            }
            packages.set(directory, pkg);
            found = true;
            break;
          }
        }
        directory = path.dirname(directory);
      }
      if (!found) throw new Error('Unidentified bundled dependency');
    }
  }
  if (!packages.size) throw new Error('No bundled dependency notice inventory');
  const sections = [];
  for (const [directory, pkg] of packages) {
    const documents = fs.readdirSync(directory, { withFileTypes: true })
      .filter(entry => entry.isFile() && legalName.test(entry.name))
      .map(entry => ({ name: entry.name, file: path.join(directory, entry.name) }));
    const supplied = suppliedDocuments.get(`${pkg.name}@${pkg.version}`);
    if (supplied) {
      if (pkg.license !== supplied.declaration) throw new Error(`Supplied notice terms changed: ${pkg.name}`);
      documents.push({ name: 'LICENSE.distribution.txt', file: path.join(root, supplied.file), sha256: supplied.sha256 });
    }
    documents.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    if (!documents.some(doc => /^(?:licen[cs]e|copying)(?:[._-].*)?$/i.test(doc.name))) {
      throw new Error(`Missing full upstream license for bundled package: ${pkg.name}`);
    }
    const texts = documents.map(({ name, file, sha256 }) => {
      if (fs.lstatSync(file).isSymbolicLink() || fs.statSync(file).size > 1024 * 1024) {
        throw new Error(`Unsafe legal document for bundled package: ${pkg.name}`);
      }
      const text = fs.readFileSync(file, 'utf8');
      if (!text.trim() || text.includes('\0')) throw new Error(`Invalid legal document: ${pkg.name}`);
      if (sha256 && createHash('sha256').update(text).digest('hex') !== sha256) {
        throw new Error(`Supplied upstream notice changed: ${pkg.name}`);
      }
      return `${name}\n${text.trim()}\n`;
    });
    sections.push({ key: `${pkg.name}@${pkg.version}`, text: texts.join('\n') });
  }
  sections.sort((a, b) => a.key.localeCompare(b.key, 'en'));
  return 'Third-party notices for bundled browser dependencies.\nUpstream terms apply to their respective components.\n\n' +
    sections.map(section => `${section.key}\n${section.text}`).join('\n');
}

export function thirdPartyNotices(root) {
  return {
    name: 'third-party-notices',
    enforce: 'post',
    generateBundle(_options, bundle) {
      this.emitFile({ type: 'asset', fileName: 'THIRD-PARTY-NOTICES.txt', source: collectNotices(root, bundle) });
    }
  };
}
