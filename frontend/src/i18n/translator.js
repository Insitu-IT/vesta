/**
 * Lightweight i18n Translator for vnbui
 *
 * Features:
 * - Fetches locale JSON from /locales/{lang}.json
 * - Dot-notation key lookup: t('nav.dashboard')
 * - {{var}} interpolation: t('common.showing', {start: 1, end: 50, total: 100})
 * - Simple plural: t('vms.selected', {count: 5}) → picks _one / _other
 * - RTL: sets dir/lang on <html> element
 * - Dispatches 'i18n:change' CustomEvent on language switch
 * - Persists choice to localStorage
 * - Exposed as window.t for onclick handlers
 */
/**
 * Available locales with display names.
 * Add new locales here when adding a language — the UI auto-discovers from this list.
 */
const AVAILABLE_LOCALES = [
    { code: 'en', name: 'English' },
    { code: 'he', name: 'עברית' },
];

export class Translator {
    constructor(defaultLang = 'en', loadLocaleExtension = null) {
        this.defaultLang = defaultLang;
        this.loadLocaleExtension = loadLocaleExtension;
        this.currentLang = null;
        this.translations = {};
        this.metadata = {};
        this.cache = new Map();
    }

    /**
     * Detect preferred language: localStorage > navigator > default
     */
    detectLanguage() {
        const stored = localStorage.getItem('preferredLanguage');
        if (stored) return stored;

        const codes = AVAILABLE_LOCALES.map(l => l.code);
        const nav = navigator.language?.substring(0, 2);
        if (nav && codes.includes(nav)) return nav;

        return this.defaultLang;
    }

    /**
     * Load a locale JSON file and set it as active
     */
    async load(lang) {
        if (this.cache.has(lang)) {
            this._apply(lang, this.cache.get(lang));
            return;
        }

        const response = await fetch(`/locales/${lang}.json`, { cache: 'no-store' });
        if (!response.ok) {
            console.error(`[i18n] Failed to load locale: ${lang}`);
            if (lang !== this.defaultLang) {
                return this.load(this.defaultLang);
            }
            return;
        }

        const data = await response.json();
        if (this.loadLocaleExtension) {
            const extension = await this.loadLocaleExtension(lang);
            for (const [section, labels] of Object.entries(extension)) {
                data[section] = {...data[section], ...labels};
            }
        }
        this.cache.set(lang, data);
        this._apply(lang, data);
    }

    /**
     * Apply loaded translations
     */
    _apply(lang, data) {
        this.currentLang = lang;
        this.metadata = data._metadata || {};
        this.translations = data;

        // Set document direction and language
        const dir = this.metadata.direction || 'ltr';
        document.documentElement.dir = dir;
        document.documentElement.lang = lang;
    }

    /**
     * Translate a key with optional interpolation
     */
    t(key, vars = {}) {
        if (!key || typeof key !== 'string') return String(key || '');

        // Handle pluralization: if vars.count exists, try _one/_other suffixes
        if (vars.count !== undefined) {
            const pluralSuffix = vars.count === 1 ? '_one' : '_other';
            const pluralVal = this._resolve(key + pluralSuffix);
            if (pluralVal !== null) {
                return this._interpolate(pluralVal, vars);
            }
        }

        const val = this._resolve(key);
        if (val === null) return key; // Missing key → return key path

        return this._interpolate(val, vars);
    }

    /**
     * Walk dot-notation path to find value
     */
    _resolve(key) {
        const parts = key.split('.');
        let current = this.translations;

        for (const part of parts) {
            if (current && typeof current === 'object' && part in current) {
                current = current[part];
            } else {
                return null;
            }
        }

        return typeof current === 'string' ? current : null;
    }

    /**
     * Replace {{var}} placeholders
     */
    _interpolate(text, vars) {
        if (!vars || Object.keys(vars).length === 0) return text;
        return text.replace(/\{\{(\w+)\}\}/g, (_, name) => {
            return vars[name] !== undefined ? String(vars[name]) : `{{${name}}}`;
        });
    }

    /**
     * Switch language, persist, and notify
     */
    async setLanguage(lang) {
        await this.load(lang);
        localStorage.setItem('preferredLanguage', lang);
        window.dispatchEvent(new CustomEvent('i18n:change', { detail: { lang } }));
    }

    /**
     * Get current language code
     */
    getLanguage() {
        return this.currentLang || this.defaultLang;
    }

    /**
     * Check if current language is RTL
     */
    isRTL() {
        return this.metadata.direction === 'rtl';
    }

    /**
     * Get available locales for language picker UI.
     * Returns [{code, name, active}] sorted with active locale first.
     */
    getAvailableLocales() {
        return AVAILABLE_LOCALES.map(l => ({
            ...l,
            active: l.code === this.currentLang
        }));
    }
}
