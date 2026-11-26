/**
 * API client with fail-closed session expiry handling
 */
import { operatorRequests } from '../services/operator-requests.service.js';
import { authService } from '../services/auth.service.js';
import { getVersion } from '../version.js';

class ApiClient {
    constructor() {
        this.baseUrl = '';  // Use relative URLs to leverage proxy
        this.requestInterceptors = [];
        this.responseInterceptors = [];
        this.compatibilityStatus = null;  // Cache compatibility status
        operatorRequests.configure(url => this.get(url), this.baseUrl);
    }

    /**
     * Make HTTP request with automatic authentication
     */
    async request(url, options = {}) {
        options.signal?.throwIfAborted();
        await this.checkInstallationAccess(url);
        // Apply request interceptors
        for (const interceptor of this.requestInterceptors) {
            options = await interceptor(url, options);
        }

        // Add default headers including frontend version
        options.headers = {
            'Content-Type': 'application/json',
            'X-Frontend-Version': getVersion(),
            ...options.headers
        };

        // Add auth token
        const token = authService.getToken();
        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }

        // Make request
        let response;
        try {
            response = await fetch(`${this.baseUrl}${url}`, options);
        } catch (error) {
            throw new Error(`Network error: ${error.message}`);
        }

        options.signal?.throwIfAborted();
        this.rejectUnauthorized(response);

        // Apply response interceptors
        for (const interceptor of this.responseInterceptors) {
            response = await interceptor(response);
        }

        // Handle errors
        if (!response.ok) {
            const error = await this.parseError(response);
            throw error;
        }

        // Parse response
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return response.json();
        }
        return response.text();
    }

    // Run before parsers/interceptors on every transport, including binary/form
    // requests. A rejected bearer is never retried or refreshed automatically.
    rejectUnauthorized(response) {
        if (response.status !== 401) return;
        authService.clearToken();
        window.location.replace('/login');
        const error = new Error('Session expired. Please log in again.');
        error.status = 401;
        throw error;
    }

    async checkInstallationAccess(url) {
        const path = new URL(url, 'https://client.invalid').pathname;
        if (path === '/api/v1/settings' || path.startsWith('/api/v1/settings/') ||
            path === '/api/v1/auth/oidc/test') {
            await authService.requireInstallationAccess();
        }
    }

    /**
     * Parse error response
     */
    async parseError(response) {
        let message = `HTTP ${response.status}`;
        let errorData = null;

        try {
            errorData = await response.json();
            const detail = errorData?.detail;
            const text = value => typeof value === 'string' && value.trim() ? value : null;
            const validation = Array.isArray(detail)
                ? detail.map(item => text(item?.msg)).filter(Boolean).join('; ')
                : null;
            message = text(detail?.message) || text(detail?.code)?.replace(/_/g, ' ') ||
                validation || text(detail) || text(errorData?.message) || message;
        } catch {
            // Not JSON, use status text
            message = response.statusText || message;
        }

        const error = new Error(message);
        error.status = response.status;
        error.response = response;
        error.data = errorData;
        return error;
    }

    /**
     * Add request interceptor
     */
    addRequestInterceptor(interceptor) {
        this.requestInterceptors.push(interceptor);
    }

    /**
     * Add response interceptor
     */
    addResponseInterceptor(interceptor) {
        this.responseInterceptors.push(interceptor);
    }

    // HTTP method shortcuts

    /**
     * GET request
     */
    async get(url, params = {}, {signal} = {}) {
        const queryString = new URLSearchParams(params).toString();
        const fullUrl = queryString ? `${url}?${queryString}` : url;
        return this.request(fullUrl, { method: 'GET', signal });
    }

    /**
     * POST request
     */
    async post(url, data = {}) {
        operatorRequests.configure(path => this.get(path), this.baseUrl);
        const body = JSON.stringify(data);
        return operatorRequests.post(url, JSON.parse(body), requestId => this.request(url, {
            method: 'POST',
            headers: requestId ? {'Idempotency-Key': requestId} : {},
            body
        }));
    }

    acknowledge(result) {
        operatorRequests.acknowledge(result);
    }

    operatorCapabilities() {
        operatorRequests.configure(path => this.get(path), this.baseUrl);
        return operatorRequests.capability();
    }

    renderRequestRecovery() {
        operatorRequests.configure(path => this.get(path), this.baseUrl);
        operatorRequests.render();
    }

    /**
     * PUT request
     */
    async put(url, data = {}) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    /**
     * PATCH request
     */
    async patch(url, data = {}) {
        return this.request(url, {
            method: 'PATCH',
            body: JSON.stringify(data)
        });
    }

    /**
     * DELETE request
     */
    async delete(url) {
        return this.request(url, { method: 'DELETE' });
    }

    /**
     * Upload file
     */
    async upload(url, formData) {
        await this.checkInstallationAccess(url);
        const token = authService.getToken();

        const options = {
            method: 'POST',
            headers: {},
            body: formData
        };

        // Add auth token
        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }

        // Don't set Content-Type, let browser set it with boundary
        const response = await fetch(`${this.baseUrl}${url}`, options);
        this.rejectUnauthorized(response);

        if (!response.ok) {
            const error = await this.parseError(response);
            throw error;
        }

        return response.json();
    }

    /**
     * Download file
     */
    async download(url, filename) {
        await this.checkInstallationAccess(url);
        const token = authService.getToken();

        const options = {
            method: 'GET',
            headers: {}
        };

        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }

        const response = await fetch(`${this.baseUrl}${url}`, options);
        this.rejectUnauthorized(response);

        if (!response.ok) {
            const error = await this.parseError(response);
            throw error;
        }

        const blob = await response.blob();
        const blobUrl = window.URL.createObjectURL(blob);

        const link = document.createElement('a');
        link.href = blobUrl;
        link.download = filename || 'download';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        window.URL.revokeObjectURL(blobUrl);
    }

    /**
     * POST request returning raw blob (for binary downloads)
     */
    async postForBlob(url, data = {}) {
        await this.checkInstallationAccess(url);
        const token = authService.getToken();
        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        };
        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }
        const response = await fetch(`${this.baseUrl}${url}`, options);
        this.rejectUnauthorized(response);
        if (!response.ok) {
            const error = await this.parseError(response);
            throw error;
        }
        return response.blob();
    }

    /**
     * Check compatibility with API and agents
     */
    async checkCompatibility() {
        try {
            const result = await this.get('/api/v1/compatibility');
            if (result?.contract_version !== 6 ||
                result.scope !== 'organization-online-agents' ||
                !result.organization_id || !Array.isArray(result.agents) ||
                !['aligned', 'degraded', 'incompatible'].includes(result.status) ||
                result.degraded_mode !== (result.status !== 'aligned')) {
                throw new Error('Unsupported compatibility contract');
            }
            this.compatibilityStatus = result;
            return result;
        } catch (error) {
            this.compatibilityStatus = {
                status: 'unverified', degraded_mode: true,
                warnings: ['Organization compatibility unavailable; no alignment verdict.'],
                agents: [],
            };
            return this.compatibilityStatus;
        }
    }

    /**
     * Get cached compatibility status
     */
    getCompatibilityStatus() {
        return this.compatibilityStatus;
    }

    /**
     * Check if system is in degraded mode
     */
    isDegradedMode() {
        return this.compatibilityStatus?.degraded_mode ?? true;
    }
}

// Singleton instance
export const apiClient = new ApiClient();

// Add logging interceptor
if (import.meta.env.DEV) {
    apiClient.addRequestInterceptor(async (url, options) => {
        console.log(`API Request: ${options.method || 'GET'} ${url}`);
        return options;
    });

    apiClient.addResponseInterceptor(async (response) => {
        console.log(`API Response: ${response.status} ${response.url}`);
        return response;
    });
}
