// Use the edition selected by the build. Unbundled source defaults to Community.
export const ARTIFACT_EDITION = typeof __VNBUI_COMMERCIAL_UI__ !== 'undefined' && __VNBUI_COMMERCIAL_UI__ ? 'commercial' : 'community';

export function validateBootstrap(value, artifactEdition = ARTIFACT_EDITION) {
    if (value?.schema_version !== 1 || !['community', 'commercial'].includes(value.edition) || !['single_organization', 'multi_organization'].includes(value.auth_mode) || typeof value.login_methods?.password !== 'boolean' || typeof value.login_methods?.oidc !== 'boolean' || (!value.login_methods.password && !value.login_methods.oidc)) throw new Error('Invalid installation bootstrap');
    if (value.edition !== artifactEdition) throw new Error('Frontend artifact does not match the installed distribution');
    return value;
}

export class InstallationService {
    constructor(artifactEdition = ARTIFACT_EDITION) {
        if (!['community', 'commercial'].includes(artifactEdition)) throw new Error('Invalid frontend artifact edition');
        Object.defineProperty(this, 'artifactEdition', {value: artifactEdition});
        this.configuration = null;
    }
    async load(fetcher = globalThis.fetch) {
        if (this.configuration) return validateBootstrap(this.configuration, this.artifactEdition);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        try {
            const response = await fetcher('/api/v1/bootstrap', {cache: 'no-store', credentials: 'same-origin', signal: controller.signal});
            if (!response.ok) throw new Error('Installation bootstrap unavailable');
            this.configuration = validateBootstrap(await response.json(), this.artifactEdition);
            return this.configuration;
        } finally {clearTimeout(timer);}
    }
}
export const installationService = new InstallationService();
