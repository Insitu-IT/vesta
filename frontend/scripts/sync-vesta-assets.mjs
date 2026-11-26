/** Copy the approved immutable pack into the standalone frontend build context. */
import {readFile, writeFile, mkdir, copyFile} from 'node:fs/promises';

const pack = new URL('../../branding/vesta/packs/vesta-1.2.0/', import.meta.url);
const publicAssets = new URL('../public/assets/', import.meta.url);
const theme = JSON.parse(await readFile(new URL('manifest.json', pack)));
const catalog = JSON.parse(await readFile(new URL('manifest.json', publicAssets)));
const prefix = `${theme.id}-${theme.version.replaceAll('.', '-')}/`;
await mkdir(new URL(prefix, publicAssets), {recursive: true});
const local = file => file.startsWith('tabler://') ? file : prefix + file;
for (const [key, value] of Object.entries(theme.assets)) {
    const asset = structuredClone(value);
    for (const file of new Set([asset.file, asset.default, ...Object.values(asset.variants || {})].filter(Boolean))) {
        if (!file.startsWith('tabler://')) await copyFile(new URL(file, pack), new URL(local(file), publicAssets));
    }
    if (asset.file) asset.file = local(asset.file);
    if (asset.default) asset.default = local(asset.default);
    if (asset.variants) asset.variants = Object.fromEntries(Object.entries(asset.variants).map(([variant, file]) => [variant, local(file)]));
    catalog.assets[key] = {...catalog.assets[key], ...asset};
    if (asset.variants) delete catalog.assets[key].file;
}
const meta = {...catalog.meta, vesta: theme.meta.vesta ?? theme.meta.vnbui};
delete meta.vnbui;
Object.assign(catalog, {
    id: 'vesta-assets', version: theme.version, name: 'Vesta Visual Assets', type: 'theme',
    description: 'Vesta Summer defaults, commercial/light/dark brand variants and application icons',
    variant_schema: theme.variant_schema,
    meta,
});
await writeFile(new URL('manifest.json', publicAssets), JSON.stringify(catalog, null, 2) + '\n');
// Keep the pre-existing public favicon URL consistent for bookmarks and static clients.
await copyFile(new URL('summer-light.svg', pack), new URL('../public/favicon.svg', import.meta.url));
console.log(`Bundled approved ${theme.id}/${theme.version} with OSS/light defaults.`);
