import { escapeHtml } from '../utils/security.js';
import { assetResolver } from '../assets/resolver.js';
export const THEME_STORAGE_KEY = 'vnbui-theme';

export function readTheme(storage) {
    try { return storage?.getItem(THEME_STORAGE_KEY) === 'dark' ? 'dark' : 'light'; }
    catch { return 'light'; }
}

class ThemeService {
    initialize() {
        let storage;
        try {storage = window.localStorage;} catch { /* The in-memory preference still works. */ }
        this.theme = document.documentElement.dataset.bsTheme || readTheme(storage);
        assetResolver.theme = this.theme;
        document.documentElement.dataset.bsTheme = this.theme;
        document.documentElement.style.colorScheme = this.theme;
    }

    button() {
        const t = window.t;
        const label = t(this.theme === 'dark' ? 'theme.switch_light' : 'theme.switch_dark');
        return `<button type="button" class="btn btn-icon btn-ghost-secondary theme-toggle" data-theme-toggle aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}"><i class="ti ti-${this.theme === 'dark' ? 'sun' : 'moon'} icon" aria-hidden="true"></i></button>`;
    }

    async toggle() {
        this.theme = this.theme === 'dark' ? 'light' : 'dark';
        try {window.localStorage.setItem(THEME_STORAGE_KEY, this.theme);} catch { /* Optional persistence. */ }
        document.documentElement.dataset.bsTheme = this.theme;
        document.documentElement.style.colorScheme = this.theme;
        assetResolver.theme = this.theme;
        await assetResolver.apply();
        assetResolver.refreshRenderedAssets();
        document.querySelectorAll('[data-theme-toggle]').forEach(node => {node.outerHTML = this.button();});
        window.dispatchEvent(new CustomEvent('vnbui:theme-change', {detail: {theme: this.theme}}));
    }

    listen() {
        document.addEventListener('click', event => {
            if (event.target.closest('[data-theme-toggle]')) this.toggle();
        });
    }
}
export const themeService = new ThemeService();
