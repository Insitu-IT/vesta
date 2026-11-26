// Validate actual build output: runtime route masking is not artifact exclusion.
import {readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export function checkArtifactFile(name, content, edition) {
    if (!['community', 'commercial'].includes(edition)) throw new Error('Invalid artifact edition');
    if (/\.map$/i.test(name)) throw new Error(`Source map in artifact: ${name}`);
    if (edition !== 'community') return;
    if (/(^|\/)(organizations|billing|branding|org-selector)-[^/]*\.js$/.test(name)) {
        throw new Error(`Commercial chunk in Community artifact: ${name}`);
    }
    if (/\.js$/.test(name) && /\/api\/v1\/(organizations|billing\/usage|branding)/.test(content)) {
        throw new Error(`Commercial endpoint in Community artifact: ${name}`);
    }
    if (/(^|\/)locales\/[^/]+\.json$/.test(name)) {
        const locale = JSON.parse(content);
        if (['organizations', 'billing', 'branding'].some(key => Object.hasOwn(locale, key))) {
            throw new Error(`Commercial translations in Community artifact: ${name}`);
        }
    }
    if (/(^|\/)assets\/manifest\.json$/.test(name)) {
        const {assets} = JSON.parse(content);
        if (['nav-organizations', 'nav-billing', 'nav-branding'].some(key => Object.hasOwn(assets, key))) {
            throw new Error(`Commercial icon in Community artifact: ${name}`);
        }
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const edition = process.env.VNBUI_ARTIFACT_EDITION || 'community';
    const walk = directory => {
        for (const entry of readdirSync(directory, {withFileTypes: true})) {
            const name = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(name);
            else if (entry.isFile()) checkArtifactFile(name, /\.(js|json)$/.test(name) ? readFileSync(name, 'utf8') : '', edition);
            else throw new Error(`Non-regular build output: ${name}`);
        }
    };
    walk('dist');
    const notices = readFileSync('dist/THIRD-PARTY-NOTICES.txt', 'utf8');
    if (!notices.startsWith('Third-party notices for bundled browser dependencies.\n')) {
        throw new Error('Missing bundled dependency notices');
    }
    console.log(`PASS: ${edition} artifact contents`);
}
