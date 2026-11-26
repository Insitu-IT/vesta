const DISABLED = Object.freeze({ apm: Object.freeze({ enabled: false }) });

export function rumEnabled(config) {
    return config?.apm?.enabled === true;
}

export async function loadSiteConfig(fetcher = globalThis.fetch) {
    try {
        const response = await fetcher('/site-config.json', { cache: 'no-store' });
        if (!response.ok) {
            return DISABLED;
        }
        const config = await response.json();
        return rumEnabled(config)
            ? { apm: { enabled: true } }
            : DISABLED;
    } catch {
        // Missing, malformed or unreachable site configuration never enables RUM.
        return DISABLED;
    }
}
