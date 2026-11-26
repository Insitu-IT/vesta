import { apiClient } from '../api/client.js';
import { authService } from './auth.service.js';

export const MAX_LICENSE_BYTES = 65536;
const BASE = '/api/v1/licensing';
export function validateLicenseStatus(value) {
    if (value?.schema_version !== 1 || typeof value.status !== 'string' || typeof value.notice_required !== 'boolean' || typeof value.acknowledged !== 'boolean' || typeof value.can_manage !== 'boolean' || typeof value.registration_url !== 'string' || typeof value.notice_scope !== 'string') throw new Error('Invalid license status');
    return value;
}
export class LicensingService {
    constructor(api = apiClient, auth = authService) {this.api = api; this.auth = auth;}
    async summary() {return validateLicenseStatus(await this.api.get(`${BASE}/status`));}
    async admin(method, suffix = '', body) {
        await this.auth.requireInstallationAccess();
        return this.api[method](BASE + suffix, ...(body === undefined ? [] : [body]));
    }
    async details(signal) {
        await this.auth.requireInstallationAccess(signal);
        signal?.throwIfAborted();
        const detail = await this.api.get(BASE, {}, {signal});
        validateLicenseStatus(detail.status);
        return detail;
    }
    async importLicense(envelope) {
        if (typeof envelope !== 'string' || new TextEncoder().encode(envelope).length > MAX_LICENSE_BYTES) throw new Error('file_large');
        return this.admin('post', '/import', {envelope});
    }
    async registrationUrl(url) {
        if (typeof url !== 'string' || url.length > 2048 || (url && new URL(url).protocol !== 'https:')) throw new Error('operation_failed');
        return this.admin('put', '/registration-url', {url});
    }
    prepare(confirmed) {
        if (confirmed !== true) throw new Error('ack_required');
        return this.admin('post', '/acknowledgement/prepare', {confirm: true});
    }
    confirm(challenge, phrase) {return this.admin('post', '/acknowledgement/confirm', {confirm: true, challenge, phrase});}
    restore() {return this.admin('delete', '/acknowledgement');}
}
export const licensingService = new LicensingService();
