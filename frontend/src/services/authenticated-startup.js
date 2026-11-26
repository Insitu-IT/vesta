import { apiClient } from '../api/client.js';
import { authService } from './auth.service.js';
import { updateService } from './updates.service.js';

let transportInitialization, startup;

// Restored sessions (including OIDC callbacks) and password sign-in both enter
// through App.init. Repeated renders share the same authenticated startup.
export function startAuthenticatedServices(app) {
    const token = authService.getToken();
    if (!token) return Promise.resolve();
    window.vnbui.updates = updateService;
    const initialization = updateService.initialize();
    if (initialization === transportInitialization) return startup;
    transportInitialization = initialization;
    startup = (async () => {
        await initialization;
        if (authService.getToken() !== token || updateService.initialization !== initialization) return;
        try {
            const compatibility = await apiClient.checkCompatibility();
            if (authService.getToken() !== token || updateService.initialization !== initialization || !compatibility) return;
            window.vnbui.compatibility = compatibility;
            if (compatibility.degraded_mode) app.showCompatibilityWarning(compatibility);
        } catch (error) {
            console.warn('Could not check compatibility:', error);
        }
    })();
    return startup;
}
