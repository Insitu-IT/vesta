import { installationService } from './services/installation.service.js';
import { themeService } from './services/theme.service.js';
import { normalizeUiPath } from './utils/ui-path.js';
import { installContextHelp } from './components/context-help.js';
/**
 * vnbui Frontend - Main Application Entry Point
 * Built with Tabler UI and modern JavaScript
 */

// Import styles
import '@tabler/core/dist/css/tabler.min.css';
import '@tabler/core/dist/css/tabler-vendors.min.css';
import './styles/tabler-icons.min.css';
import './styles/custom.scss';

// Import Bootstrap (needed for modals, toasts, dropdowns)
// NOTE: Do NOT import Tabler JS - it bundles its own Bootstrap which conflicts
// with our Bootstrap import, causing dropdown click handlers to call preventDefault twice
import * as bootstrap from 'bootstrap';
// Make Bootstrap available globally
window.bootstrap = bootstrap;

// Import services
import { authService } from './services/auth.service.js';
import { apiClient } from './api/client.js';
import { keyManagementService } from './services/key-management.service.js';
import { setupCspReporting } from './utils/security.js';

// Import version (single source of truth)
import { getVersion } from './version.js';

// Import i18n
import { Translator } from './i18n/translator.js';

// Import asset resolver
import { assetResolver } from './assets/resolver.js';

// Import application
import { App } from './app.js';
import editionExtension from '@edition';

// APM RUM (#33) — init as early as possible to capture page-load timing.
import { setupApm } from './utils/apm.js';
import { loadSiteConfig } from './utils/site-config.js';
import { detectAndStartDemo } from './pages/demo.js';

/**
 * Initialize application
 */
async function init() {
    themeService.initialize();
    themeService.listen();
    normalizeUiPath();
    installContextHelp();
    // Remove callback credentials before asynchronous startup or telemetry.
    authService.consumeCallbackFragment();
    console.log('Vesta initializing...');

    // Setup CSP violation reporting
    setupCspReporting();

    // Initialize i18n before anything renders
    const translator = new Translator('en', editionExtension?.loadLocale);
    await translator.load(translator.detectLanguage());
    window.t = translator.t.bind(translator);
    window.vnbuiTranslator = translator;

    // Initialize asset resolver after i18n
    await assetResolver.init(undefined, {bundledAssets: editionExtension?.assets});
    await assetResolver.apply();
    await assetResolver.preload(['brand-logo', 'stat-vms', 'stat-backups', 'stat-agents', 'stat-running', 'empty-state']);

    // Demo detection precedes auth, APM, compatibility, and realtime setup. The
    // public sandbox is anonymous and must not initialize production integrations.
    if (await detectAndStartDemo(document.getElementById('app'))) {
        console.log('Vesta public demo initialized');
        return;
    }

    try {
        const installation = await installationService.load();
        assetResolver.edition = installation.edition === 'commercial' ? 'commercial' : 'oss';
        await assetResolver.apply();
    } catch {
        new App(editionExtension).showBootstrapError();
        return;
    }

    // Site-owned RUM is disabled unless the runtime config explicitly opts in.
    await setupApm(await loadSiteConfig());

    // Make services globally available (required for onclick handlers and debugging)
    window.vnbui = {
        auth: authService,
        api: apiClient,
        keyManagement: keyManagementService,
        version: getVersion(),  // From package.json via vite.config.js
        assets: assetResolver,
        // Shortcut methods for onclick handlers
        createOrchestratorKey: () => keyManagementService.createOrchestratorKey(),
        editOrchestratorKey: (id) => keyManagementService.editOrchestratorKey(id),
        deleteOrchestratorKey: (id, name) => keyManagementService.deleteOrchestratorKey(id, name),
        createRegistrationKey: () => keyManagementService.createRegistrationKey(),
        editRegistrationKey: (id) => keyManagementService.editRegistrationKey(id),
        deleteRegistrationKey: (id, name) => keyManagementService.deleteRegistrationKey(id, name),
        editAgentDisplayName: (id, name) => keyManagementService.editAgentDisplayName(id, name),
        rotateAgentKey: (id, name) => keyManagementService.rotateAgentKey(id, name)
    };

    // Check authentication
    if (!await authService.restoreSession()) {
        console.log('Not authenticated, showing login');
        // Show login page in SPA
        const app = new App(editionExtension);
        app.showLogin();
        return;
    }

    // Initialize application
    const app = new App(editionExtension);
    await app.init();

    console.log('Vesta initialized successfully');
}

// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);

    // Show user-friendly error using Bootstrap toast if available
    const toastHtml = `
        <div class="toast align-items-center text-white bg-danger border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">An unexpected error occurred</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;

    const container = document.querySelector('.toast-container') || createToastContainer();
    container.insertAdjacentHTML('beforeend', toastHtml);
    const toastEl = container.lastElementChild;
    const toast = new bootstrap.Toast(toastEl);
    toast.show();
});

function createToastContainer() {
    const container = document.createElement('div');
    container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    document.body.appendChild(container);
    return container;
}
