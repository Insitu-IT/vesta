/**
 * Elastic RUM (Real User Monitoring) — APM Stage 1 (#33).
 *
 * Reports to the APM server via a same-origin `/apm` reverse proxy (see
 * frontend/nginx.conf) so RUM POSTs avoid CORS. `distributedTracingOrigins` adds
 * the W3C `traceparent` header to same-origin /api/v1 XHRs, linking the browser
 * RUM transaction to the backend's OTel trace — one cross-tier trace
 * (browser → backend → agent). Mirrors iris-core/frontend's RUM setup.
 */
import { getVersion } from '../version.js';
import { rumEnabled } from './site-config.js';

export async function setupApm(siteConfig) {
    if (!rumEnabled(siteConfig)) {
        return null;
    }
    try {
        const { init: initApm } = await import('@elastic/apm-rum');
        return initApm({
            serviceName: 'vnbui-frontend',
            // A site-owned nginx configuration may proxy /apm to its APM server.
            serverUrl: window.location.origin + '/apm',
            serviceVersion: getVersion(),
            environment: 'production',
            // Continue the trace into the backend on same-origin API calls.
            distributedTracingOrigins: [window.location.origin],
        });
    } catch (error) {
        console.warn('Site APM initialization failed:', error);
        return null;
    }
}
