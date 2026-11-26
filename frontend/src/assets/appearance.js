/** Runtime pack metadata is data only; no executable CSS, HTML, or remote URLs. */
export const DEFAULT_PRODUCT_NAME = 'Vesta';
const COLOR_KEYS = new Set(['primary', 'success', 'warning', 'danger', 'body-bg', 'body-color']);
const FONTS = {system: 'system-ui, sans-serif', sans: 'Arial, sans-serif', serif: 'Georgia, serif', mono: 'monospace'};
export function safeAssetPath(path) {
    return typeof path === 'string' && /^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+$/.test(path) && !path.split('/').some(p => p === '.' || p === '..');
}
export function packPath(path) {
    return typeof path === 'string' && /^\/appearance\/packs\/[a-z0-9]+(?:-[a-z0-9]+)*\/\d+\.\d+\.\d+$/.test(path);
}
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fields = (value, allowed) => object(value) && Object.keys(value).every(key => allowed.includes(key));
const optionalText = (value, key) => value[key] === undefined || typeof value[key] === 'string';
export function appearanceMetadata(manifest) {
    const meta = manifest.meta;
    return meta && Object.hasOwn(meta, 'vesta') ? meta.vesta : meta?.vnbui;
}
export function validateManifest(manifest) {
    if (!fields(manifest, ['schema_version', 'id', 'version', 'name', 'description', 'type', 'author', 'meta', 'variant_schema', 'categories', 'assets']) || manifest.schema_version !== 1 || (typeof manifest.id !== 'string' || manifest.id.length < 2 || manifest.id.length > 50 || !SLUG.test(manifest.id)) || (typeof manifest.version !== 'string' || manifest.version.length > 32 || !/^\d+\.\d+\.\d+$/.test(manifest.version)) || typeof manifest.name !== 'string' || !manifest.name.trim() || manifest.name.trim().length > 100 || /[<>\x00-\x1f\x7f]/.test(manifest.name) || typeof manifest.type !== 'string' || !SLUG.test(manifest.type) || !object(manifest.assets)) throw new Error('Invalid asset manifest');
    if (!optionalText(manifest, 'description') || !optionalText(manifest, 'author') || (manifest.meta !== undefined && !object(manifest.meta))) throw new Error('Invalid manifest metadata');
    if ((manifest.description?.length || 0) > 500 || (manifest.author?.length || 0) > 255 || Object.keys(manifest.assets).length < 1 || Object.keys(manifest.assets).length > 64 || new TextEncoder().encode(JSON.stringify(manifest)).length > 65536) throw new Error('Asset manifest limits exceeded');
    const axes = manifest.variant_schema || {};
    if (!object(axes) || Object.keys(axes).length > 8) throw new Error('Invalid variant schema');
    for (const [name, axis] of Object.entries(axes)) {
        if (!/^[a-z][a-z0-9_]*$/.test(name) || !fields(axis, ['label', 'values', 'default']) || !optionalText(axis, 'label') || !Array.isArray(axis.values) || !axis.values.length || axis.values.length > 32 || axis.values.some(v => typeof v !== 'string' || !SLUG.test(v)) || new Set(axis.values).size !== axis.values.length || !axis.values.includes(axis.default)) throw new Error('Invalid variant axis');
    }
    const categories = manifest.categories || {};
    if (!object(categories) || Object.entries(categories).some(([name, category]) => !SLUG.test(name) || !fields(category, ['label', 'order']) || !optionalText(category, 'label') || (category.order !== undefined && !Number.isInteger(category.order)))) throw new Error('Invalid categories');
    for (const [key, asset] of Object.entries(manifest.assets)) {
        if (!SLUG.test(key) || !fields(asset, ['label', 'category', 'tags', 'content_type', 'file', 'variants', 'default']) || !optionalText(asset, 'label') || !['image/svg+xml', 'image/png', 'image/jpeg', 'image/webp', 'image/x-icon', 'text/x-tabler-icon', 'font/woff2'].includes(asset.content_type)) throw new Error('Invalid asset');
        if (asset.category !== undefined && !Object.hasOwn(categories, asset.category)) throw new Error('Unknown asset category');
        if (asset.tags !== undefined && (!Array.isArray(asset.tags) || asset.tags.some(t => typeof t !== 'string'))) throw new Error('Invalid asset tags');
        const simple = typeof asset.file === 'string';
        if (simple ? asset.variants !== undefined || asset.default !== undefined : !object(asset.variants) || !Object.keys(asset.variants).length || Object.keys(asset.variants).length > 128 || typeof asset.default !== 'string' || asset.file !== undefined) throw new Error('Invalid asset shape');
        if (!simple) {
            const dimensions = Object.values(axes);
            if (!dimensions.length) throw new Error('Missing variant schema');
            for (const variant of Object.keys(asset.variants)) {
                const values = variant.split('/');
                if (values.length > dimensions.length || values.some((value, index) => !dimensions[index].values.includes(value))) throw new Error('Invalid variant key');
            }
        }
        const files = [asset.file, asset.default, ...Object.values(asset.variants || {})].filter(v => v !== undefined);
        if (files.some(file => asset.content_type === 'text/x-tabler-icon' ? typeof file !== 'string' || !/^tabler:\/\/[a-z0-9-]+$/.test(file) : !safeAssetPath(file))) throw new Error('Invalid asset path');
    }
    const meta = appearanceMetadata(manifest);
    if (meta !== undefined) {
        if (!object(meta) || ![1, 2].includes(meta.schema_version) || Object.keys(meta).some(k => !['schema_version', 'product_name', 'colors', 'font_family', 'font_asset', 'density', ...(meta.schema_version === 2 ? ['theme_colors'] : [])].includes(k))) throw new Error('Invalid appearance metadata');
        if (meta.product_name !== undefined && (typeof meta.product_name !== 'string' || !meta.product_name.trim() || meta.product_name.length > 80 || /[<>\x00-\x1f\x7f]/.test(meta.product_name))) throw new Error('Invalid product name');
        if (meta.colors !== undefined && (!object(meta.colors) || Object.entries(meta.colors).some(([k, v]) => !COLOR_KEYS.has(k) || (typeof v !== 'string' || !/^#[0-9a-fA-F]{6}$/.test(v))))) throw new Error('Invalid theme colors');
        if (meta.theme_colors !== undefined && (!fields(meta.theme_colors, ['light', 'dark']) || Object.values(meta.theme_colors).some(colors => !object(colors) || Object.entries(colors).some(([k, v]) => !COLOR_KEYS.has(k) || typeof v !== 'string' || !/^#[0-9a-fA-F]{6}$/.test(v))))) throw new Error('Invalid theme color maps');
        if (meta.font_family !== undefined && !Object.hasOwn(FONTS, meta.font_family)) throw new Error('Invalid font family');
        if (meta.font_asset !== undefined && manifest.assets[meta.font_asset]?.content_type !== 'font/woff2') throw new Error('Invalid font asset');
        if (meta.density !== undefined && !['comfortable', 'compact'].includes(meta.density)) throw new Error('Invalid density');
    }
    return manifest;
}
export function safeSvg(text) {
    if (typeof text !== 'string' || /<!DOCTYPE|<!ENTITY|<\?/i.test(text) || typeof globalThis.DOMParser !== 'function') return false;
    const svgNamespace = 'http://www.w3.org/2000/svg';
    const xmlNamespace = 'http://www.w3.org/XML/1998/namespace';
    const xlinkNamespace = 'http://www.w3.org/1999/xlink';
    const xmlnsNamespace = 'http://www.w3.org/2000/xmlns/';
    const allowed = new Set(['svg', 'g', 'path', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'title', 'desc', 'defs', 'linearGradient', 'radialGradient', 'stop', 'clipPath', 'mask', 'text', 'tspan', 'use', 'symbol']);
    try {
        const document = new DOMParser().parseFromString(text, 'image/svg+xml');
        const root = document.documentElement;
        if (!root || root.localName !== 'svg' || document.getElementsByTagName('parsererror').length) return false;
        for (const node of [root, ...root.querySelectorAll('*')]) {
            if (!allowed.has(node.localName) || node.namespaceURI !== svgNamespace) return false;
            for (const attribute of node.attributes) {
                const namespace = attribute.namespaceURI || '';
                const name = attribute.localName.toLowerCase();
                const value = attribute.value;
                // Namespace declarations do not fetch resources. Every use of a
                // declared namespace is checked on the element or attribute.
                if (namespace === xmlnsNamespace) continue;
                if (namespace === xmlNamespace && !['space', 'lang'].includes(attribute.localName)) return false;
                if (namespace === xlinkNamespace && attribute.localName !== 'href') return false;
                if (namespace && ![svgNamespace, xmlNamespace, xlinkNamespace].includes(namespace)) return false;
                if (name.startsWith('on') || ['style', 'src'].includes(name)) return false;
                if (name === 'href' && !/^#[A-Za-z_][A-Za-z0-9_.:-]*$/.test(value)) return false;
                if (/(?:https?:|data:|javascript:|@import)/i.test(value)) return false;
                if (/url\(/i.test(value) && !/^url\(#[A-Za-z_][A-Za-z0-9_.:-]*\)$/.test(value)) return false;
            }
        }
        return true;
    } catch {return false;}
}
export const SAFE_DARK_COLORS = Object.freeze({primary: '#8FC96B', success: '#7DBD72', warning: '#E6B84A', danger: '#EF8585', 'body-bg': '#182433', 'body-color': '#E8EDF3'});
export function themeColors(meta = {}, theme = 'light') {
    return theme === 'dark' ? {...SAFE_DARK_COLORS, ...meta.theme_colors?.dark} : {...meta.colors, ...meta.theme_colors?.light};
}
export function applyAppearance(meta = {}, root = document.documentElement, theme = root.dataset.bsTheme || 'light') {
    for (const key of COLOR_KEYS) {
        root.style.removeProperty?.(`--tblr-${key}`);
        for (const suffix of ['rgb', 'fg', 'darken', 'lt']) root.style.removeProperty?.(`--tblr-${key}-${suffix}`);
    }
    root.style.removeProperty?.('--tblr-font-sans-serif');
    for (const [key, value] of Object.entries(themeColors(meta, theme))) {
        root.style.setProperty(`--tblr-${key}`, value);
        const rgb = [1, 3, 5].map(offset => parseInt(value.slice(offset, offset + 2), 16));
        root.style.setProperty(`--tblr-${key}-rgb`, rgb.join(', '));
        if (['primary', 'success', 'warning', 'danger'].includes(key)) {
            const linear = rgb.map(channel => {const v = channel / 255; return v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4;});
            const luminance = linear[0] * .2126 + linear[1] * .7152 + linear[2] * .0722;
            root.style.setProperty(`--tblr-${key}-fg`, luminance > .179 ? '#000000' : '#FFFFFF');
            root.style.setProperty(`--tblr-${key}-darken`, `color-mix(in srgb, ${value} 85%, #000000)`);
            root.style.setProperty(`--tblr-${key}-lt`, `color-mix(in srgb, ${value} 12%, var(--tblr-bg-surface))`);
        }
    }
    if (meta.font_family) root.style.setProperty('--tblr-font-sans-serif', FONTS[meta.font_family]);
    root.dataset.density = meta.density || 'comfortable';
}
