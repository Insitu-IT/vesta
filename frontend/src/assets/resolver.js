import { escapeHtml } from '../utils/security.js';
import { validateManifest, packPath, safeSvg, applyAppearance, appearanceMetadata, DEFAULT_PRODUCT_NAME } from './appearance.js';
/**
 * Visual asset resolver for Vesta.
 * Loads manifest.json conforming to the Visual Assets Standard (v1).
 */

export class AssetResolver {
    constructor() {
        this.edition = 'oss';
        this.theme = 'light';
        this.manifest = null;
        this.basePath = '/assets';
        this.svgCache = new Map();
        this.overrides = new Set();
        this.productName = DEFAULT_PRODUCT_NAME;
    }

    async init(fetcher = globalThis.fetch, {requestTimeoutMs = 1500, totalTimeoutMs = 5000, bundledAssets = {}} = {}) {
        const response = await fetcher('/assets/manifest.json');
        if (!response.ok) throw new Error('Bundled asset manifest unavailable');
        const manifest = validateManifest(await response.json());
        this.manifest = Object.keys(bundledAssets).length
            ? validateManifest({...manifest, assets: {...manifest.assets, ...bundledAssets}})
            : manifest;
        this.bundledManifest = this.manifest;
        const defaults = appearanceMetadata(this.bundledManifest) || {};
        this.appearance = defaults;
        this.productName = defaults.product_name || DEFAULT_PRODUCT_NAME;
        const deadline = Date.now() + totalTimeoutMs;
        const optionalRequest = async (url, options = {}, body = 'json') => {
            const remaining = deadline - Date.now();
            if (remaining <= 0) throw new Error('Appearance initialization deadline exceeded');
            const controller = new AbortController();
            let timer;
            const timeout = new Promise((_, reject) => {
                timer = setTimeout(() => {controller.abort(); reject(new Error('Appearance request timed out'));}, Math.min(requestTimeoutMs, remaining));
            });
            try {
                return await Promise.race([(async () => {
                    const response = await fetcher(url, {...options, signal: controller.signal});
                    if (!response.ok) throw new Error('Appearance resource unavailable');
                    return body ? await response[body]() : true;
                })(), timeout]);
            } finally {clearTimeout(timer);}
        };
        try {
            const config = await optionalRequest('/appearance/config.json', {cache: 'no-store'});
            if (config.schema_version !== 1) return;
            for (const path of [config.active_pack, config.previous_pack]) {
                if (!packPath(path)) continue;
                try {
                    const manifest = validateManifest(await optionalRequest(`${path}/manifest.json`, {cache: 'no-store'}));
                    if (path !== `/appearance/packs/${manifest.id}/${manifest.version}`) continue;
                    // Check referenced files before activating an immutable pack.
                    const files = new Set(Object.values(manifest.assets).flatMap(a => [a.file, a.default, ...Object.values(a.variants || {})]).filter(f => f && !f.startsWith('tabler://')));
                    const checks = await Promise.all([...files].map(async file => {
                        const svg = Object.values(manifest.assets).some(asset => asset.content_type === 'image/svg+xml' && [asset.file, asset.default, ...Object.values(asset.variants || {})].includes(file));
                        const content = await optionalRequest(`${path}/${file}`, {method: svg ? 'GET' : 'HEAD'}, svg ? 'text' : null);
                        return svg ? safeSvg(content) : content;
                    }));
                    if (checks.some(valid => !valid)) continue;
                    this.manifest = {...this.bundledManifest, ...manifest, assets: {...this.bundledManifest.assets, ...manifest.assets}};
                    this.overrides = new Set(Object.keys(manifest.assets));
                    this.packBasePath = path;
                    const custom = appearanceMetadata(manifest) || {};
                    this.appearance = {...defaults, ...custom, colors: {...defaults.colors, ...custom.colors}, theme_colors: {light: {...defaults.theme_colors?.light, ...custom.colors, ...custom.theme_colors?.light}, dark: {...defaults.theme_colors?.dark, ...custom.theme_colors?.dark}}};
                    this.productName = this.appearance.product_name || DEFAULT_PRODUCT_NAME;
                    return;
                } catch { /* Try previous pack, then bundled defaults. */ }
            }
        } catch { /* Optional runtime configuration; bundled defaults remain usable offline. */ }
    }

    async apply({fontTimeoutMs = 1500} = {}) {
        const revision = (this.fontApplyRevision || 0) + 1;
        this.fontApplyRevision = revision;
        const appearance = this.appearance || {};
        applyAppearance(appearance.font_asset && !appearance.font_family ? {...appearance, font_family: 'system'} : appearance, document.documentElement, this.theme);
        // Login and identity rendering never wait for an optional font GET.
        this.fontReady = this._loadFont(revision, fontTimeoutMs);
        document.title = this.productName;
        const description = document.querySelector('meta[name="description"]');
        if (description) description.content = this.productName;
        const favicon = document.querySelector('link[rel="icon"]');
        if (favicon) favicon.href = this.assetUrl('brand-favicon');
        document.querySelectorAll('[data-product-name]').forEach(node => {node.textContent = this.productName;});
    }

    async _loadFont(revision, timeoutMs) {
        if (!this.appearance?.font_asset || !globalThis.FontFace) return;
        let timer;
        try {
            const file = this.resolve(this.appearance.font_asset);
            const font = new FontFace('SitePackFont', `url("${this.packBasePath}/${file}")`);
            const loaded = await Promise.race([
                font.load().then(() => true, () => false),
                new Promise(resolve => {timer = setTimeout(() => resolve(false), timeoutMs);}),
            ]);
            // Timed-out or superseded loads cannot change the active theme later.
            if (loaded && revision === this.fontApplyRevision) {
                document.fonts.add(font);
                document.documentElement.style.setProperty('--tblr-font-sans-serif', 'SitePackFont, system-ui, sans-serif');
            }
        } catch { /* Keep the configured fallback font. */ }
        finally {clearTimeout(timer);}
    }

    assetUrl(key, dimensions) {
        const file = this.resolve(key, dimensions);
        return file ? `${this.overrides.has(key) ? this.packBasePath : this.basePath}/${file}` : '';
    }

    // Preload SVG content for assets that need inline rendering
    async preload(assetKeys, dimensions) {
        await Promise.all(assetKeys.map(key => this._fetchSvg(key, dimensions)));
    }

    // Returns HTML string for an icon (handles both tabler:// and SVG file assets)
    icon(assetKey, opts = {}) {
        const asset = this._getAsset(assetKey);
        if (!asset) return '';
        const cls = opts.class || '';

        if (asset.content_type === 'text/x-tabler-icon') {
            const iconName = this.resolve(assetKey).replace('tabler://', '');
            return `<i class="ti ti-${iconName}${cls ? ' ' + escapeHtml(cls) : ''}"></i>`;
        }

        // SVG file asset
        return this.svg(assetKey, opts);
    }

    // Returns <img> tag for SVG file assets
    svg(assetKey, opts = {}) {
        const asset = this._getAsset(assetKey);
        const file = this.resolve(assetKey, opts.dimensions);
        if (!asset || !file || file.startsWith('tabler://')) return '';
        const w = opts.width || 24;
        const h = opts.height || 24;
        const cls = opts.class || '';
        return `<img src="${this.assetUrl(assetKey, opts.dimensions)}" width="${w}" height="${h}" class="${escapeHtml(cls)}" ${this.assetAttributes(assetKey, opts)} alt="${escapeHtml(asset.label || assetKey)}">`;
    }

    // Returns cached inline SVG markup (must preload first)
    inlineSvg(assetKey, opts = {}) {
        if (this.overrides.has(assetKey)) return this.svg(assetKey, opts);
        const cached = this.svgCache.get(this.assetUrl(assetKey, opts.dimensions));
        if (!cached) return this.svg(assetKey, opts); // fallback to <img>
        // Inject class/width/height into the SVG root element
        let svg = cached;
        svg = svg.replace('<svg', `<svg ${this.assetAttributes(assetKey, opts)}`);
        if (opts.class) svg = svg.replace('<svg', `<svg class="${escapeHtml(opts.class)}"`);
        if (opts.width) svg = svg.replace(/width="[^"]*"/, `width="${opts.width}"`);
        if (opts.height) svg = svg.replace(/height="[^"]*"/, `height="${opts.height}"`);
        return svg;
    }

    assetAttributes(key, opts) {
        return `data-vnbui-asset="${escapeHtml(key)}"${opts.dimensions?.theme ? ` data-asset-theme="${escapeHtml(opts.dimensions.theme)}"` : ''}${opts.dimensions?.edition ? ` data-asset-edition="${escapeHtml(opts.dimensions.edition)}"` : ''}`;
    }

    refreshRenderedAssets() {
        document.querySelectorAll('[data-vnbui-asset]').forEach(node => {
            const dimensions = {};
            if (node.dataset.assetTheme) dimensions.theme = node.dataset.assetTheme;
            if (node.dataset.assetEdition) dimensions.edition = node.dataset.assetEdition;
            node.outerHTML = this.inlineSvg(node.dataset.vnbuiAsset, {class: node.getAttribute('class') || '', width: node.getAttribute('width') || 24, height: node.getAttribute('height') || 24, dimensions});
        });
    }

    // Variant resolution per the standard
    resolve(assetKey, dimensions = {}) {
        dimensions = {edition: this.edition, theme: this.theme, ...dimensions};
        const asset = this._getAsset(assetKey);
        if (!asset) return null;

        if (asset.file) return asset.file; // Simple asset
        if (!asset.variants) return asset.default || null;

        // Build variant key from dimensions in schema order
        // Inherited assets keep their own axes when a customer pack declares others.
        const owner = this.bundledManifest && !this.overrides.has(assetKey) ? this.bundledManifest : this.manifest;
        const schema = owner.variant_schema || {};
        const dims = Object.keys(schema);
        const key = dims.map(d => dimensions[d] || schema[d].default).join('/');

        if (asset.variants[key]) return asset.variants[key];

        // Fallback: drop dimensions from right
        for (let i = dims.length - 1; i > 0; i--) {
            const partial = dims.slice(0, i).map(d => dimensions[d] || schema[d].default).join('/');
            if (asset.variants[partial]) return asset.variants[partial];
        }

        return asset.default;
    }

    has(assetKey) {
        return !!(this.manifest?.assets?.[assetKey]);
    }

    getAsset(assetKey) {
        return this._getAsset(assetKey);
    }

    _getAsset(assetKey) {
        if (!this.manifest) {
            console.warn('AssetResolver: manifest not loaded');
            return null;
        }
        const asset = this.manifest.assets[assetKey];
        if (!asset) {
            console.warn(`AssetResolver: unknown asset "${assetKey}"`);
            return null;
        }
        return asset;
    }

    async _fetchSvg(assetKey, dimensions) {
        const asset = this._getAsset(assetKey);
        const file = this.resolve(assetKey, dimensions);
        if (!asset || !file || file.startsWith('tabler://') || this.overrides.has(assetKey)) return;
        const url = this.assetUrl(assetKey, dimensions);
        try {
            const resp = await fetch(url);
            if (!resp.ok) return;
            const text = await resp.text();
            if (safeSvg(text)) this.svgCache.set(url, text);
        } catch (e) {
            console.warn(`AssetResolver: failed to preload SVG for "${assetKey}"`, e);
        }
    }
}

export const assetResolver = new AssetResolver();
