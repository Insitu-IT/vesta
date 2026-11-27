import { startAuthenticatedServices } from './services/authenticated-startup.js';
import { LicensingPanel, refreshLicenseBanner, renderLicenseSummary } from './components/licensing.js';
import { licensingService } from './services/licensing.service.js';
import { installationService } from './services/installation.service.js';
import { themeService } from './services/theme.service.js';
import { renderDiskSummary, renderCbtObservation } from './utils/vm-inventory.js';
import { bindBackupGuidance, loadBackupGuidance, renderBackupGuidance } from './utils/backup-guidance.js';
import { agentProvider, selectedNamespaces } from './utils/agent-scope.js';
import { enumLabel } from './utils/status-labels.js';
/**
 * Main Application Class
 */
import { authService } from './services/auth.service.js';
import { escapeHtml } from './utils/security.js';
import { apiClient } from './api/client.js';
import { assetResolver } from './assets/resolver.js';

export class App {
    constructor(extension = null) {
        this.extension = extension;
        this.currentPage = null;
        this.user = null;
        this.features = {};  // Feature flags from backend
        this.verificationRequests = new Map();
        this.verificationInFlight = new Set();
    }

    /**
     * Initialize application
     */
    async init() {
        // Get current user
        this.user = await authService.fetchUserData();

        if (!this.user) {
            await this.showLogin();
            return;
        }

        // Fetch feature flags from backend
        await this.loadFeatures();

        // Render application
        this.render();

        // Setup event listeners
        this.setupEventListeners();
        refreshLicenseBanner();
        if (this.licensingInterval) clearInterval(this.licensingInterval);
        this.licensingInterval = setInterval(() => refreshLicenseBanner(), 60000);

        await this.extension?.initialize?.(this.features);

        // Navigate to current page
        const path = window.location.hash.substring(1) || 'dashboard';
        this.navigate(path);
        await startAuthenticatedServices(this);
    }

    /**
     * Render main application layout
     */
    render() {
        const app = document.getElementById('app');
        const t = window.t;
        const translator = window.vnbuiTranslator;
        const locales = translator?.getAvailableLocales() || [];
        const langMenuItems = locales.map(l =>
            `<a href="#" class="dropdown-item${l.active ? ' active' : ''}" onclick="window.vnbui.setLanguage('${l.code}')">`
            + `<i class="ti ti-language icon dropdown-item-icon"></i>`
            + `${l.name}</a>`
        ).join('');

        app.innerHTML = `
            <div class="page">
                <!-- Sidebar -->
                <aside class="navbar navbar-vertical navbar-expand-lg" data-bs-theme="dark">
                    <div class="container-fluid">
                        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#sidebar-menu" aria-controls="sidebar-menu" aria-expanded="false" aria-label="Toggle navigation">
                            <span class="navbar-toggler-icon"></span>
                        </button>
                        <h1 class="navbar-brand">
                            <a href="#dashboard">
                                ${assetResolver.inlineSvg('brand-logo', { class: 'navbar-brand-image', width: 24, height: 24, dimensions: {theme: 'dark'} })}
                                <span class="brand-name">${escapeHtml(assetResolver.productName)}</span>
                            </a>
                        </h1>
                        <div class="navbar-nav flex-row d-lg-none align-items-center gap-2">
                            ${themeService.button()}
                            <div class="nav-item dropdown">
                                <a href="#" class="nav-link d-flex gap-2 lh-1 text-reset p-0" data-bs-toggle="dropdown">
                                    <span class="avatar avatar-sm">${this.getUserInitials()}</span>
                                </a>
                                <div class="dropdown-menu dropdown-menu-end dropdown-menu-arrow">
                                    <a href="#" class="dropdown-item" id="profile-btn-mobile">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon dropdown-item-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                            <circle cx="12" cy="7" r="4" />
                                            <path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />
                                        </svg>
                                        ${t('profile.title')}
                                    </a>
                                    ${langMenuItems}
                                    <div class="dropdown-divider"></div>
                                    <a href="#" class="dropdown-item" id="logout-btn-mobile">
                                        ${assetResolver.icon('action-logout', { class: 'icon dropdown-item-icon' })}
                                        ${t('profile.logout')}
                                    </a>
                                </div>
                            </div>
                        </div>
                        <div class="collapse navbar-collapse" id="sidebar-menu">
                            <ul class="navbar-nav pt-lg-3">
                                ${this.renderNavigation()}
                            </ul>
                        </div>
                    </div>
                </aside>

                <!-- Page wrapper -->
                <div class="page-wrapper">
                    <!-- Compatibility warning banner (populated by showCompatibilityWarning) -->
                    <div id="compatibility-banner"></div>
                    <div id="licensing-banner"></div>
                    <div id="operator-recovery"></div>

                    <!-- Top navbar for desktop -->
                    <header class="navbar navbar-expand-md d-none d-lg-flex d-print-none">
                        <div class="container-xl">
                            <div class="navbar-nav flex-row ms-auto order-md-last align-items-center gap-2">
                                ${this.extension?.renderHeader?.(this.features) || ''}

                                ${themeService.button()}
                                <!-- User Menu -->
                                <div class="nav-item dropdown">
                                    <a href="#" class="nav-link d-flex gap-2 lh-1 text-reset p-0" data-bs-toggle="dropdown">
                                        <span class="avatar avatar-sm">${this.getUserInitials()}</span>
                                        <div class="d-none d-xl-block">
                                            <div>${escapeHtml(this.user?.username || 'User')}</div>
                                            <div class="mt-1 small text-secondary">${escapeHtml(enumLabel(this.user?.role || 'viewer', 'role'))}</div>
                                        </div>
                                    </a>
                                    <div class="dropdown-menu dropdown-menu-end dropdown-menu-arrow">
                                        <a href="#" class="dropdown-item" id="profile-btn">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon dropdown-item-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <circle cx="12" cy="7" r="4" />
                                                <path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />
                                            </svg>
                                            ${t('profile.title')}
                                        </a>
                                        ${langMenuItems}
                                        <div class="dropdown-divider"></div>
                                        <a href="#" class="dropdown-item" id="logout-btn">
                                            ${assetResolver.icon('action-logout', { class: 'icon dropdown-item-icon' })}
                                            ${t('profile.logout')}
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </header>

                    <div class="page-body">
                        <div class="container-xl">
                            <div id="page-content">
                                <!-- Page content loaded here -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Profile Modal (global, available on all pages) -->
            <div class="modal modal-blur fade" id="modal-profile" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${t('profile.title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="profile-user-id">

                            <!-- OIDC User Info (shown only for SSO users) -->
                            <div id="profile-oidc-info" class="alert alert-azure mb-3" style="display: none;">
                                <div class="d-flex align-items-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon icon-lg me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <path d="M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2" />
                                        <path d="M20 12h-13l3 -3m0 6l-3 -3" />
                                    </svg>
                                    <div>
                                        <strong>${t('profile.sso_user')}</strong>
                                        <div class="text-secondary small">${t('profile.sso_user_detail')}</div>
                                    </div>
                                </div>
                                <hr class="my-2">
                                <div class="row small">
                                    <div class="col-md-6">
                                        <strong>${t('users.role_source_label')}</strong>
                                        <div id="profile-role-source" class="text-secondary text-break"></div>
                                    </div>
                                    <div class="col-md-6">
                                        <strong>${t('profile.oidc_issuer')}</strong>
                                        <div id="profile-oidc-issuer" class="text-secondary text-break"></div>
                                    </div>
                                </div>
                            </div>

                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label class="form-label">${t('profile.username')}</label>
                                    <input type="text" class="form-control" id="profile-username" readonly>
                                    <div id="profile-organization" class="text-secondary small text-break"></div>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">${t('profile.role')}</label>
                                    <input type="text" class="form-control" id="profile-role" readonly>
                                </div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('profile.full_name')}</label>
                                <input type="text" class="form-control" id="profile-fullname" placeholder="${t('profile.full_name_placeholder')}">
                                <small id="profile-fullname-hint" class="form-hint text-secondary" style="display: none;">
                                    ${t('profile.managed_by_provider')}
                                </small>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('profile.email')}</label>
                                <input type="email" class="form-control" id="profile-email" placeholder="${t('profile.email_placeholder')}">
                                <small id="profile-email-hint" class="form-hint text-secondary" style="display: none;">
                                    ${t('profile.managed_by_provider')}
                                </small>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('profile.last_login')}</label>
                                <input type="text" class="form-control" id="profile-last-login" readonly>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.close')}</button>
                            <button type="button" id="profile-save" class="btn btn-primary" onclick="window.vnbui.saveProfile()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <polyline points="9 11 12 14 20 6" />
                                    <path d="M20 12v6a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h9" />
                                </svg>
                                ${t('common.save_changes')}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        apiClient.renderRequestRecovery();
    }

    /**
     * Get user initials for avatar
     */
    getUserInitials() {
        if (!this.user || !this.user.username) return 'U';
        return escapeHtml(this.user.username.substring(0, 2).toUpperCase());
    }

    /**
     * Load feature flags from backend
     * Inspired by Unleash pattern - fetch once, cache locally
     */
    async loadFeatures() {
        try {
            const response = await apiClient.get('/api/v1/features');
            this.features = {...response.flags, client_encryption: true};
            if (!this.extension) {
                for (const name of ['multi_tenancy', 'white_labeling', 'billing_api',
                    'advanced_rbac', 'compliance_reports']) {
                    this.features[name] = false;
                }
            }
            console.log(`Features loaded: ${response.edition} (${Object.keys(this.features).filter(k => this.features[k]).join(', ') || 'none'})`);
        } catch (error) {
            console.warn('Failed to load features, using defaults:', error);
            // Shared encryption is installed in every artifact.
            this.features = {
                multi_tenancy: false,
                white_labeling: false,
                billing_api: false,
                advanced_rbac: false,
                compliance_reports: false,
                client_encryption: true,
            };
        }
    }

    /**
     * Render navigation menu with grouped sections
     */
    renderNavigation() {
        const t = window.t;
        const menuSections = [
            {
                title: t('nav.overview'),
                items: [
                    { id: 'dashboard', label: t('nav.dashboard'), icon: 'nav-dashboard', roles: ['admin', 'operator', 'viewer'] },
                ]
            },
            {
                title: t('nav.backup_ops'),
                items: [
                    { id: 'vms', label: t('nav.vms'), icon: 'nav-vms', roles: ['admin', 'operator', 'viewer'] },
                    { id: 'backups', label: t('nav.backups'), icon: 'nav-backups', roles: ['admin', 'operator', 'viewer'] },
                    { id: 'restores', label: t('nav.restores'), icon: 'nav-restores', roles: ['admin', 'operator', 'viewer'] },
                    { id: 'schedules', label: t('nav.schedules'), icon: 'nav-schedules', roles: ['admin', 'operator'] },
                    { id: 'verification', label: t('nav.verification'), icon: 'nav-verification', roles: ['admin', 'operator'] },
                ]
            },
            {
                title: t('nav.management'),
                items: [
                    { id: 'groups', label: t('nav.groups'), icon: 'nav-groups', roles: ['admin', 'operator'] },
                    { id: 'reports', label: t('nav.reports'), icon: 'nav-reports', roles: ['admin', 'operator', 'viewer'] },
                ]
            },
            {
                title: t('nav.system'),
                items: [
                    { id: 'health', label: t('nav.health'), icon: 'nav-health', roles: ['admin'] },
                    { id: 'agents', label: t('nav.agents'), icon: 'nav-agents', roles: ['admin'] },
                    { id: 'activity', label: t('nav.activity'), icon: 'nav-activity', roles: ['admin', 'operator'] },
                    { id: 'notifications', label: t('nav.notifications'), icon: 'nav-notifications', roles: ['admin', 'operator', 'viewer'] },
                ]
            },
            ...(this.extension?.navigationTitle ? [{
                title: t(this.extension.navigationTitle),
                items: this.extension.routes.map(route => ({...route, label: t(route.label)})),
            }] : []),
            {
                title: t('nav.admin'),
                items: [
                    { id: 'users', label: t('nav.users'), icon: 'nav-users', roles: ['admin'] },
                    { id: 'settings', label: t('nav.settings'), icon: 'nav-settings', installation: true },
                ]
            }
        ];

        let html = '';

        menuSections.forEach(section => {
            // Filter items by role and feature flags
            const visibleItems = section.items.filter(item => {
                if (item.installation && !authService.canManageInstallation()) return false;
                // Check role
                if (item.roles && !item.roles.includes(this.user?.role)) {
                    return false;
                }

                // Check feature flag (if specified)
                if (item.requiresFeature && !this.features[item.requiresFeature]) {
                    return false;
                }

                return true;
            });

            if (visibleItems.length === 0) return;

            // Add section header
            html += `
                <li class="nav-item">
                    <div class="nav-link-title text-uppercase small fw-bold mt-3">${section.title}</div>
                </li>
            `;

            // Add section items
            visibleItems.forEach(item => {
                html += `
                    <li class="nav-item" data-page="${item.id}">
                        <a class="nav-link" href="#${item.id}">
                            <span class="nav-link-icon">
                                ${assetResolver.icon(item.icon)}
                            </span>
                            <span class="nav-link-title">${escapeHtml(item.label)}</span>
                        </a>
                    </li>
                `;
            });
        });

        return html;
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Profile buttons (desktop and mobile)
        document.getElementById('profile-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.vnbui.openProfile();
        });
        document.getElementById('profile-btn-mobile')?.addEventListener('click', (e) => {
            e.preventDefault();
            window.vnbui.openProfile();
        });

        // Logout buttons (desktop and mobile)
        document.getElementById('logout-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            authService.logout();
        });
        document.getElementById('logout-btn-mobile')?.addEventListener('click', (e) => {
            e.preventDefault();
            authService.logout();
        });

        // Navigation links (updated selector for sidebar)
        document.querySelectorAll('#sidebar-menu a').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const page = e.currentTarget.getAttribute('href').substring(1);
                this.navigate(page);
            });
        });

        // Handle browser back/forward
        window.addEventListener('hashchange', () => {
            const page = window.location.hash.substring(1) || 'dashboard';
            this.navigate(page, false);
        });

        // Re-render on language change
        window.addEventListener('i18n:change', () => {
            const currentPage = window.location.hash.substring(1) || 'dashboard';
            this.render();
            refreshLicenseBanner();
            this.setupEventListeners();
            this.navigate(currentPage, false);
        });

        // Expose app methods globally for page actions
        // Merge with existing window.vnbui (set in main.js with key management)
        window.vnbui = {
            ...window.vnbui,  // Preserve existing methods from main.js
            refreshPage: () => this.refreshPage(),

            // Language switching (called from dropdown items)
            setLanguage: async (lang) => {
                const translator = window.vnbuiTranslator;
                if (!translator || translator.getLanguage() === lang) return;
                await translator.setLanguage(lang);
            },
            currentUserId: this.user?.id,
            currentUserRole: this.user?.role,
            currentPage: null,  // Will be set when page loads

            // Navigation
            navigateTo: (page) => this.navigate(page),

            // Settings (will be populated when settings page loads)
            saveAllSettings: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.saveAllSettings === 'function') {
                    window.vnbui.currentPage.saveAllSettings();
                } else {
                    console.error('saveAllSettings not available on current page');
                }
            },

            // v3.0: Storage settings (S3)
            saveV3Settings: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.saveV3Settings === 'function') {
                    window.vnbui.currentPage.saveV3Settings();
                }
            },
            testS3Connection: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.testS3Connection === 'function') {
                    window.vnbui.currentPage.testS3Connection();
                }
            },
            toggleS3Settings: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.toggleS3Settings === 'function') {
                    window.vnbui.currentPage.toggleS3Settings();
                }
            },

            // v3.0: OIDC settings
            saveOIDCSettings: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.saveOIDCSettings === 'function') {
                    window.vnbui.currentPage.saveOIDCSettings();
                }
            },
            toggleOIDCSettings: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.toggleOIDCSettings === 'function') {
                    window.vnbui.currentPage.toggleOIDCSettings();
                }
            },
            testOIDCConfiguration: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.testOIDCConfiguration === 'function') {
                    window.vnbui.currentPage.testOIDCConfiguration();
                }
            },
            toggleDeleteLocalDays: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.toggleDeleteLocalDays === 'function') {
                    window.vnbui.currentPage.toggleDeleteLocalDays();
                }
            },

            // v3.1: Encryption key management
            createEncryptionKey: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.createEncryptionKey === 'function') {
                    window.vnbui.currentPage.createEncryptionKey();
                }
            },
            rotateEncryptionKey: (keyId) => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.rotateEncryptionKey === 'function') {
                    window.vnbui.currentPage.rotateEncryptionKey(keyId);
                }
            },
            revokeEncryptionKey: (keyId) => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.revokeEncryptionKey === 'function') {
                    window.vnbui.currentPage.revokeEncryptionKey(keyId);
                }
            },
            exportEncryptionKeys: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.exportEncryptionKeys === 'function') {
                    window.vnbui.currentPage.exportEncryptionKeys();
                }
            },
            importEncryptionKeys: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.importEncryptionKeys === 'function') {
                    window.vnbui.currentPage.importEncryptionKeys();
                }
            },

            // Dashboard quick search
            dashboardSearch: (query) => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.dashboardSearch === 'function') {
                    window.vnbui.currentPage.dashboardSearch(query);
                }
            },
            clearDashboardSearch: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.clearDashboardSearch === 'function') {
                    window.vnbui.currentPage.clearDashboardSearch();
                }
            },

            // Helper Methods
            showToast: (message, type = 'info', duration = 3000) => {
                const toastContainer = document.querySelector('.toast-container') || window.vnbui.createToastContainer();
                const bgClass = { success: 'bg-success', error: 'bg-danger', warning: 'bg-warning', info: 'bg-info' }[type] || 'bg-info';
                const toast = document.createElement('div');
                toast.className = `toast align-items-center text-white ${bgClass} border-0`;
                toast.setAttribute('role', 'alert');
                toast.innerHTML = `
                    <div class="d-flex">
                        <div class="toast-body">${escapeHtml(message)}</div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                    </div>
                `;
                toastContainer.appendChild(toast);
                const bsToast = new bootstrap.Toast(toast, { autohide: true, delay: duration });
                bsToast.show();
                toast.addEventListener('hidden.bs.toast', () => toast.remove());
            },

            createToastContainer: () => {
                const container = document.createElement('div');
                container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                container.style.zIndex = '9999';
                document.body.appendChild(container);
                return container;
            },

            // VMs
            createBackup: async (vmId) => {
                const modal = document.getElementById('modal-backup');
                if (modal) {
                    const request = Symbol();
                    this.backupModalRequest = request;
                    try {
                        // Fetch VM details to get name and disks
                        const vm = await apiClient.get(`/api/v1/vms/${vmId}`);
                        if (this.backupModalRequest !== request) return;
                        document.getElementById('backup-vm-id').value = vmId;
                        document.getElementById('backup-vm-name').value = vm.name || 'Unknown VM';
                        // Reset form fields
                        document.getElementById('backup-type').value = 'full';
                        document.getElementById('backup-retention').value = '30';
                        document.getElementById('backup-description').value = '';

                        // Populate disk checkboxes for exclusion
                        const diskContainer = document.getElementById('backup-exclude-disks');
                        if (diskContainer && vm.disks && vm.disks.length > 0) {
                            diskContainer.innerHTML = vm.disks.map(disk => {
                                const diskName = disk.target;
                                if (typeof diskName !== 'string' || !diskName) return '';
                                return `
                                    <label class="form-check form-check-inline">
                                        <input type="checkbox" class="form-check-input" name="exclude-disk" value="${escapeHtml(diskName)}">
                                        <span class="form-check-label">${escapeHtml(diskName)}</span>
                                    </label>
                                `;
                            }).join('');
                        } else if (diskContainer) {
                            diskContainer.textContent = window.t('guidance.no_disks');
                        }

                        bindBackupGuidance(modal, vmId, apiClient);
                        new bootstrap.Modal(modal).show();
                    } catch (error) {
                        window.vnbui.showToast('Failed to load VM details: ' + error.message, 'error');
                    }
                } else {
                    window.vnbui.showToast('Backup modal not available. Navigate to VMs page first.', 'error');
                }
            },

            viewVM: async (vmId) => {
                try {
                    const [vm, guidance] = await Promise.all([
                        apiClient.get(`/api/v1/vms/${vmId}`), loadBackupGuidance(apiClient, vmId)
                    ]);

                    // Format memory
                    const formatMemory = (kb) => {
                        if (!kb) return window.t('common.na');
                        const mb = kb / 1024;
                        if (mb < 1024) return `${Math.round(mb)} MiB`;
                        return `${(mb / 1024).toFixed(1)} GiB`;
                    };

                    // Format disks
                    const formatDisks = (disks) => {
                        return renderDiskSummary(disks);
                    };

                    // Create or get modal container
                    let modalEl = document.getElementById('modal-vm-details');
                    if (!modalEl) {
                        modalEl = document.createElement('div');
                        modalEl.id = 'modal-vm-details';
                        modalEl.className = 'modal modal-blur fade';
                        modalEl.tabIndex = -1;
                        document.body.appendChild(modalEl);
                    }

                    modalEl.innerHTML = `
                        <div class="modal-dialog modal-lg modal-dialog-centered">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title">VM Details: ${escapeHtml(vm.name)}</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                </div>
                                <div class="modal-body">
                                    <div class="row g-3">
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">Name</label>
                                            <div class="fw-medium">${escapeHtml(vm.name)}</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">State</label>
                                            <div><span class="badge bg-${vm.state === 'running' ? 'success' : 'secondary'}">${escapeHtml(enumLabel(vm.state || 'unknown'))}</span></div>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">UUID</label>
                                            <div class="text-secondary small">${escapeHtml(vm.uuid || 'N/A')}</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">Agent</label>
                                            <div>${escapeHtml(vm.agent_hostname || 'Unknown')}</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">Memory</label>
                                            <div>${formatMemory(vm.memory_kb)}</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">vCPUs</label>
                                            <div>${vm.vcpu_count || 0}</div>
                                        </div>
                                        <div class="col-12">
                                            <label class="form-label text-secondary">Disks</label>
                                            <div>${formatDisks(vm.disks)}</div>
                                            ${vm.provider === 'kubevirt' ? `<div class="small text-secondary">${renderCbtObservation(vm)}</div>` : ''}
                                        </div>
                                        <div class="col-12">
                                            <label class="form-label text-secondary">${window.t('guidance.title')}</label>
                                            ${renderBackupGuidance(guidance)}
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">Backups</label>
                                            <div>${vm.backup_count || 0}</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label text-secondary">Created</label>
                                            <div>${vm.created_at ? new Date(vm.created_at).toLocaleString() : 'N/A'}</div>
                                        </div>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn" data-bs-dismiss="modal">Close</button>
                                    <button type="button" class="btn btn-primary" onclick="window.vnbui.createBackup('${escapeHtml(vm.id)}'); bootstrap.Modal.getInstance(document.getElementById('modal-vm-details')).hide();">
                                        Create Backup
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;

                    new bootstrap.Modal(modalEl).show();
                } catch (error) {
                    window.vnbui.showToast('Failed to load VM details: ' + error.message, 'error');
                }
            },

            submitBackupFromModal: async () => {
                try {
                    const vmId = document.getElementById('backup-vm-id').value;
                    const backupType = document.getElementById('backup-type').value;
                    const retentionDays = parseInt(document.getElementById('backup-retention').value) || 30;
                    const description = document.getElementById('backup-description').value;

                    // Collect excluded disks
                    const excludeDisks = [];
                    document.querySelectorAll('input[name="exclude-disk"]:checked').forEach(cb => {
                        excludeDisks.push(cb.value);
                    });

                    const tags = {};
                    if (description) {
                        tags.description = description;
                    }

                    const result = await apiClient.post('/api/v1/backups', {
                        vm_id: vmId,
                        backup_type: backupType,
                        retention_days: retentionDays,
                        tags: tags,
                        exclude_disks: excludeDisks
                    });
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-backup'));
                    modal.hide();
                    if (result.status === 'queued') {
                        window.vnbui.showToast(t('vms.backup_queued', { vm: result.vm_name || vmId }), 'info');
                    } else {
                        window.vnbui.showToast(t('vms.backup_started'), 'success');
                    }
                    apiClient.acknowledge(result);
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast(error.operatorRecovery ? error.message : 'Failed to create backup: ' + error.message, 'error');
                }
            },

            // Backups
            restoreBackup: async (backupId, vmName) => {
                const modal = document.getElementById('modal-restore');
                if (modal) {
                    document.getElementById('restore-backup-id').value = backupId;
                    document.getElementById('restore-vm-name').value = vmName;
                    document.getElementById('restore-target').value = 'original';
                    document.getElementById('restore-new-name').value = '';
                    document.getElementById('restore-auto-define').checked = false;
                    modal.dataset.provider = '';
                    document.getElementById('restore-standard-options')?.classList.remove('d-none');
                    document.getElementById('restore-kubevirt-options')?.classList.add('d-none');
                    document.getElementById('restore-kubevirt-selection').textContent = '';

                    // Try to fetch backup details for checkpoints and disks
                    try {
                        const backup = await apiClient.get(`/api/v1/backups/${backupId}`);
                        const vm = await apiClient.get(`/api/v1/vms/${backup.vm_id}`);
                        modal.dataset.provider = vm.provider || '';
                        if (vm.provider === 'kubevirt') {
                            const bundle = await apiClient.get(`/api/v1/backups/${backupId}/restore-bundle`);
                            const selected = bundle.members[bundle.members.length - 1].request.plan;
                            const newName = `${selected.vm_name.slice(0, 28).replace(/[^a-z0-9-]/g, '-')}-restore-${Date.now().toString(36)}`;
                            const mapping = {
                                namespace: selected.source.namespace,
                                vm_name: newName,
                                disks: selected.source.volumes.map((volume, index) => ({
                                    volume_name: volume.name, pvc_name: `${newName}-${index}`,
                                    storage_class: '', access_mode: 'ReadWriteOnce',
                                    volume_mode: 'Filesystem', capacity_bytes: Math.ceil(volume.capacity_bytes * 1.1)
                                })),
                                networks: [{ name: 'default', type: 'pod', network_name: '' }],
                                dependencies: {}
                            };
                            document.getElementById('restore-kubevirt-target').value = JSON.stringify(mapping, null, 2);
                            document.getElementById('restore-standard-options').classList.add('d-none');
                            document.getElementById('restore-kubevirt-options').classList.remove('d-none');
                            document.getElementById('restore-fresh-hint').textContent = t('restore_modal.kubevirt_hint');
                            const protectedNames = selected.source.volumes.map(volume => volume.name);
                            const omittedNames = (selected.source.native_volumes || selected.source.volumes)
                                .filter(volume => !protectedNames.includes(volume.name)).map(volume => volume.name);
                            document.getElementById('restore-kubevirt-selection').textContent =
                                t('restore_modal.kubevirt_selection', { protected: protectedNames.join(', ') }) +
                                (omittedNames.length ? ' ' + t('restore_modal.kubevirt_omitted', { omitted: omittedNames.join(', ') }) : '');
                        } else if (vm.provider === 'libvirt') {
                            const bundle = await apiClient.get(`/api/v1/backups/${backupId}/restore-bundle`);
                            const manifest = bundle.members[bundle.members.length - 1].push_result.manifest;
                            const mapping = {
                                vm_name: `${vm.name.slice(0, 48)}-restore-${Date.now().toString(36)}`,
                                disks: manifest.disks.map(disk => disk.target),
                                drop_excluded_disks: manifest.exclusions,
                                networks: [{ source_mac: '', network: '' }]
                            };
                            document.getElementById('restore-kubevirt-target').value = JSON.stringify(mapping, null, 2);
                            document.getElementById('restore-standard-options').classList.add('d-none');
                            document.getElementById('restore-kubevirt-options').classList.remove('d-none');
                            document.getElementById('restore-fresh-hint').textContent = t('restore_modal.native_hint');
                        }

                        // Populate checkpoints dropdown
                        const checkpointSelect = document.getElementById('restore-checkpoint');
                        checkpointSelect.innerHTML = '<option value="">Latest (full restore)</option>';
                        if (backup.checkpoints && backup.checkpoints.length > 0) {
                            backup.checkpoints.forEach(cpt => {
                                checkpointSelect.innerHTML += `<option value="${escapeHtml(cpt)}">${escapeHtml(cpt)}</option>`;
                            });
                        }

                        // Populate disks if available from VM
                        const diskContainer = document.getElementById('restore-disks');
                        if (backup.vm_disks && backup.vm_disks.length > 0) {
                            diskContainer.innerHTML = backup.vm_disks.map(disk => {
                                const diskName = disk.device || disk.name || 'disk';
                                return `
                                    <label class="form-check form-check-inline">
                                        <input type="checkbox" class="form-check-input" name="restore-disk" value="${escapeHtml(diskName)}">
                                        <span class="form-check-label">${escapeHtml(diskName)}</span>
                                    </label>
                                `;
                            }).join('');
                        } else {
                            diskContainer.innerHTML = '<span class="text-secondary small">All disks will be restored</span>';
                        }
                    } catch (error) {
                        window.vnbui.showToast(window.t('restore_modal.restore_failed', { error: error.message }), 'error');
                        return;
                    }

                    new bootstrap.Modal(modal).show();
                }
            },

            downloadBackup: async (backupId) => {
                try {
                    const token = authService.getToken();
                    window.location.href = `/api/v1/backups/${backupId}/download?token=${token}`;
                    window.vnbui.showToast('Download started', 'info');
                } catch (error) {
                    window.vnbui.showToast('Download failed: ' + error.message, 'error');
                }
            },

            deleteBackup: (backupId, vmName) => {
                document.getElementById('delete-backup-id').value = backupId;
                document.getElementById('delete-backup-vm-name').textContent = vmName;
                new bootstrap.Modal(document.getElementById('modal-delete-backup')).show();
            },

            submitRestore: async () => {
                try {
                    const backupId = document.getElementById('restore-backup-id').value;
                    const target = document.getElementById('restore-target').value;
                    const newName = document.getElementById('restore-new-name').value;
                    const untilCheckpoint = document.getElementById('restore-checkpoint')?.value || null;
                    const autoDefine = document.getElementById('restore-auto-define')?.checked || false;

                    // Collect selected disks
                    const selectedDisks = [];
                    document.querySelectorAll('input[name="restore-disk"]:checked').forEach(cb => {
                        selectedDisks.push(cb.value);
                    });

                    const restoreModal = document.getElementById('modal-restore');
                    const payload = restoreModal.dataset.provider === 'kubevirt' ? {
                        backup_id: backupId,
                        restore_to_original: false,
                        kubevirt_target: JSON.parse(document.getElementById('restore-kubevirt-target').value)
                    } : restoreModal.dataset.provider === 'libvirt' ? {
                        backup_id: backupId,
                        restore_to_original: false,
                        native_target: JSON.parse(document.getElementById('restore-kubevirt-target').value)
                    } : {
                        backup_id: backupId,
                        restore_to_original: target === 'original',
                        target_vm_name: newName || null,
                        until_checkpoint: untilCheckpoint || null,
                        auto_define: autoDefine,
                        adjust_config: autoDefine,  // Usually used together with auto_define
                        selected_disks: selectedDisks.length > 0 ? selectedDisks : []
                    };
                    const result = await apiClient.post('/api/v1/restores', payload);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-restore'));
                    modal.hide();
                    window.vnbui.showToast('Restore started successfully!', 'success');
                    window.vnbui.navigateTo('restores');
                    apiClient.acknowledge(result);
                } catch (error) {
                    window.vnbui.showToast(error.operatorRecovery ? error.message : 'Failed to start restore: ' + error.message, 'error');
                }
            },

            submitDeleteBackup: async (force = false) => {
                try {
                    const backupId = document.getElementById('delete-backup-id').value;
                    const url = force ? `/api/v1/backups/${backupId}?force=true` : `/api/v1/backups/${backupId}`;
                    await apiClient.delete(url);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-delete-backup'));
                    modal.hide();
                    window.vnbui.showToast('Backup deleted successfully', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to delete backup: ' + error.message, 'error');
                }
            },

            filterBackups: (filter) => {
                if (window.vnbui.currentPage && window.vnbui.currentPage.filter !== undefined) {
                    window.vnbui.currentPage.filter = filter;
                    window.vnbui.refreshPage();
                }
            },

            resumeBackup: async (backupId) => {
                if (!confirm(t('backups.resume_confirm'))) return;
                try {
                    await apiClient.request(`/api/v1/backups/${backupId}/resume`, { method: 'POST' });
                    window.vnbui.showToast(t('backups.resume_accepted'), 'info');
                    window.vnbui.refreshPage();
                } catch (e) {
                    const reason = e.data?.detail?.reason || e.data?.detail || e.message;
                    window.vnbui.showToast(t('backups.resume_held', { reason: String(reason) }), 'warning');
                }
            },

            closeUnreservedBackup: async (backupId) => {
                if (!confirm(t('backups.close_unreserved_confirm'))) return;
                try {
                    const result = await apiClient.post(`/api/v1/backups/${backupId}/close-unreserved`, {});
                    window.vnbui.showToast(t('backups.close_unreserved_closed'), 'info');
                    apiClient.acknowledge(result);
                    window.vnbui.refreshPage();
                } catch (e) {
                    const code = e.data?.detail?.code;
                    const reason = e.operatorRecovery ? `${e.message}${code ? ` (${code})` : ''}` : code || e.message;
                    window.vnbui.showToast(t('backups.close_unreserved_error', { reason: String(reason) }), 'warning');
                }
            },

            showBackupError: (backupId, vmName, error) => {
                // Create a modal to show the full error details
                const modalId = 'modal-backup-error';
                let modal = document.getElementById(modalId);

                if (!modal) {
                    // Create modal HTML if it doesn't exist
                    modal = document.createElement('div');
                    modal.id = modalId;
                    modal.className = 'modal modal-blur fade';
                    modal.tabIndex = -1;
                    modal.innerHTML = `
                        <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
                            <div class="modal-content">
                                <div class="modal-header bg-danger text-white">
                                    <h5 class="modal-title">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/><circle cx="12" cy="12" r="9" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                                        </svg>
                                        Backup Failed
                                    </h5>
                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                </div>
                                <div class="modal-body">
                                    <div class="mb-3">
                                        <label class="form-label">VM</label>
                                        <div class="form-control-plaintext" id="error-vm-name"></div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Backup ID</label>
                                        <div class="form-control-plaintext text-secondary small" id="error-backup-id"></div>
                                    </div>
                                    <div>
                                        <label class="form-label">Error Details</label>
                                        <pre class="bg-dark text-danger p-3 rounded" style="white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto;" id="error-details"></pre>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn" data-bs-dismiss="modal">Close</button>
                                </div>
                            </div>
                        </div>
                    `;
                    document.body.appendChild(modal);
                }

                // Populate and show
                document.getElementById('error-vm-name').textContent = vmName || 'Unknown';
                document.getElementById('error-backup-id').textContent = backupId || '';
                // Decode HTML entities, strip ANSI escape codes, format with line breaks
                const decodedError = error.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
                const cleanError = decodedError.replace(/\u001b\[[0-9;]*m/g, '').replace(/ \| /g, '\n\n');
                document.getElementById('error-details').textContent = cleanError;

                new bootstrap.Modal(modal).show();
            },

            // Schedules
            createSchedule: () => {
                document.getElementById('schedule-modal-title').textContent = 'Create Schedule';
                document.getElementById('schedule-id').value = '';
                document.getElementById('schedule-name').value = '';
                document.getElementById('schedule-description').value = '';
                document.getElementById('schedule-target-type').value = 'vm';
                document.getElementById('schedule-vm-id').value = '';
                document.getElementById('schedule-group-id').value = '';
                document.getElementById('schedule-backup-type').value = 'full';
                document.getElementById('schedule-full-every-days').value = '7';
                document.getElementById('schedule-max-incrementals').value = '6';
                window.vnbui.updateSchedulePolicy();
                document.getElementById('schedule-target-type').disabled = false;
                document.getElementById('schedule-vm-id').disabled = false;
                document.getElementById('schedule-group-id').disabled = false;
                document.getElementById('schedule-frequency').value = 'daily';
                document.getElementById('schedule-daily-hour').value = '2';
                document.getElementById('schedule-cron').value = '0 2 * * *';
                document.getElementById('schedule-retention').value = '30';
                document.getElementById('schedule-exclude-disks').value = '';
                document.getElementById('schedule-enabled').checked = false;
                window.vnbui.updateScheduleTarget();
                window.vnbui.updateScheduleOptions();
                new bootstrap.Modal(document.getElementById('modal-schedule')).show();
            },

            updateSchedulePolicy: () => {
                document.getElementById('schedule-policy-options').hidden =
                    document.getElementById('schedule-backup-type').value !== 'automatic';
            },

            updateScheduleTarget: () => {
                const targetType = document.getElementById('schedule-target-type').value;
                document.getElementById('schedule-vm-group').style.display = targetType === 'vm' ? 'block' : 'none';
                document.getElementById('schedule-group-group').style.display = targetType === 'group' ? 'block' : 'none';
            },

            editSchedule: async (scheduleId) => {
                try {
                    const schedule = await apiClient.get(`/api/v1/schedules/${scheduleId}`);
                    document.getElementById('schedule-modal-title').textContent = 'Edit Schedule';
                    document.getElementById('schedule-id').value = schedule.id;
                    document.getElementById('schedule-name').value = schedule.name || '';
                    document.getElementById('schedule-description').value = schedule.description || '';
                    document.getElementById('schedule-retention').value = schedule.retention_days || 30;
                    document.getElementById('schedule-enabled').checked = schedule.enabled;
                    document.getElementById('schedule-backup-type').value = schedule.backup_type || 'full';
                    document.getElementById('schedule-full-every-days').value = schedule.backup_policy?.full_every_days ?? 7;
                    document.getElementById('schedule-max-incrementals').value = schedule.backup_policy?.max_incrementals ?? 6;
                    window.vnbui.updateSchedulePolicy();
                    document.getElementById('schedule-exclude-disks').value = (schedule.exclude_disks || []).join(', ');
                    const targetType = schedule.vm_id ? 'vm' : 'group';
                    document.getElementById('schedule-target-type').value = targetType;
                    document.getElementById('schedule-vm-id').value = schedule.vm_id || '';
                    document.getElementById('schedule-group-id').value = schedule.vm_group_id || '';
                    document.getElementById('schedule-target-type').disabled = true;
                    document.getElementById('schedule-vm-id').disabled = true;
                    document.getElementById('schedule-group-id').disabled = true;
                    window.vnbui.updateScheduleTarget();

                    // Parse cron expression to set UI
                    const cron = schedule.cron_expression || '0 2 * * *';
                    document.getElementById('schedule-cron').value = cron;
                    window.vnbui.parseCronToUI(cron);

                    new bootstrap.Modal(document.getElementById('modal-schedule')).show();
                } catch (error) {
                    window.vnbui.showToast('Failed to load schedule: ' + error.message, 'error');
                }
            },

            // Parse cron expression and set UI elements
            parseCronToUI: (cron) => {
                const parts = cron.split(' ');
                if (parts.length < 5) {
                    document.getElementById('schedule-frequency').value = 'custom';
                    window.vnbui.updateScheduleOptions();
                    return;
                }
                const [min, hour, day, month, dow] = parts;

                // Daily: "0 H * * *"
                if (min === '0' && !hour.includes('*') && !hour.includes('/') && day === '*' && month === '*' && dow === '*') {
                    document.getElementById('schedule-frequency').value = 'daily';
                    document.getElementById('schedule-daily-hour').value = hour;
                }
                // Hourly: "0 */N * * *"
                else if (min === '0' && hour.startsWith('*/') && day === '*' && month === '*' && dow === '*') {
                    document.getElementById('schedule-frequency').value = 'hourly';
                    document.getElementById('schedule-hourly-interval').value = hour.substring(2);
                }
                // Weekly: "0 H * * D"
                else if (min === '0' && !hour.includes('*') && day === '*' && month === '*' && dow !== '*') {
                    document.getElementById('schedule-frequency').value = 'weekly';
                    document.getElementById('schedule-weekly-hour').value = hour;
                    document.getElementById('schedule-weekly-day').value = dow;
                }
                // Monthly: "0 H D * *"
                else if (min === '0' && !hour.includes('*') && day !== '*' && month === '*' && dow === '*') {
                    document.getElementById('schedule-frequency').value = 'monthly';
                    document.getElementById('schedule-monthly-hour').value = hour;
                    document.getElementById('schedule-monthly-day').value = day;
                }
                // Custom
                else {
                    document.getElementById('schedule-frequency').value = 'custom';
                }
                window.vnbui.updateScheduleOptions();
            },

            // Update schedule options visibility and preview
            updateScheduleOptions: () => {
                const freq = document.getElementById('schedule-frequency').value;

                // Hide all option groups
                ['daily', 'hourly', 'weekly', 'monthly', 'custom'].forEach(f => {
                    const el = document.getElementById(`schedule-${f}-options`);
                    if (el) el.style.display = 'none';
                });

                // Show selected option group
                const selected = document.getElementById(`schedule-${freq}-options`);
                if (selected) selected.style.display = freq === 'weekly' || freq === 'monthly' ? 'flex' : 'block';

                // Build cron expression and preview
                let cron = '';
                let preview = '';

                switch (freq) {
                    case 'daily': {
                        const hour = document.getElementById('schedule-daily-hour').value;
                        cron = `0 ${hour} * * *`;
                        preview = `Daily at ${hour.padStart(2, '0')}:00`;
                        break;
                    }
                    case 'hourly': {
                        const interval = document.getElementById('schedule-hourly-interval').value;
                        cron = `0 */${interval} * * *`;
                        preview = `Every ${interval} hour${interval > 1 ? 's' : ''}`;
                        break;
                    }
                    case 'weekly': {
                        const day = document.getElementById('schedule-weekly-day').value;
                        const hour = document.getElementById('schedule-weekly-hour').value;
                        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
                        cron = `0 ${hour} * * ${day}`;
                        preview = `Weekly on ${days[day]} at ${hour.padStart(2, '0')}:00`;
                        break;
                    }
                    case 'monthly': {
                        const mday = document.getElementById('schedule-monthly-day').value;
                        const hour = document.getElementById('schedule-monthly-hour').value;
                        cron = `0 ${hour} ${mday} * *`;
                        preview = `Monthly on day ${mday} at ${hour.padStart(2, '0')}:00`;
                        break;
                    }
                    case 'custom': {
                        cron = document.getElementById('schedule-cron').value || '0 2 * * *';
                        preview = 'Custom schedule';
                        break;
                    }
                }

                // Update hidden cron field (for non-custom) and preview
                if (freq !== 'custom') {
                    document.getElementById('schedule-cron').value = cron;
                }
                document.getElementById('schedule-preview').textContent = preview;
            },

            deleteSchedule: (scheduleId, name) => {
                document.getElementById('delete-schedule-id').value = scheduleId;
                document.getElementById('delete-schedule-name').textContent = name;
                new bootstrap.Modal(document.getElementById('modal-delete-schedule')).show();
            },

            toggleSchedule: async (scheduleId, enabled) => {
                try {
                    await apiClient.put(`/api/v1/schedules/${scheduleId}`, { enabled });
                    window.vnbui.showToast('Schedule ' + (enabled ? 'enabled' : 'disabled'), 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to toggle schedule: ' + error.message, 'error');
                    window.vnbui.refreshPage();
                }
            },

            enrollScheduleGrant: async (scheduleId) => {
                try {
                    if (this.user?.role !== 'admin') throw new Error(window.t('schedules.admin_grant_required'));
                    const preview = await apiClient.get(`/api/v1/schedules/${scheduleId}/grant`);
                    if (!window.confirm(window.t('schedules.grant_confirm') + '\n\n' + JSON.stringify(preview.scope, null, 2))) return;
                    await apiClient.post(`/api/v1/schedules/${scheduleId}/grant`, {
                        request_id: crypto.randomUUID(), expected_revision: preview.revision,
                        scope_sha256: preview.scope_sha256, replace_grant_id: preview.current_grant_id, enable: true
                    });
                    window.vnbui.showToast(window.t('schedules.grant_enrolled'), 'success');
                    window.vnbui.refreshPage();
                } catch (error) {
                    window.vnbui.showToast(error.message, 'error');
                }
            },

            revokeScheduleGrant: async (scheduleId) => {
                try {
                    if (!window.confirm(window.t('schedules.revoke_confirm'))) return;
                    await apiClient.delete(`/api/v1/schedules/${scheduleId}/grant`);
                    window.vnbui.refreshPage();
                } catch (error) {
                    window.vnbui.showToast(error.message, 'error');
                }
            },

            submitSchedule: async () => {
                try {
                    const scheduleId = document.getElementById('schedule-id').value;
                    const data = {
                        name: document.getElementById('schedule-name').value,
                        cron_expression: document.getElementById('schedule-cron').value,
                        backup_type: document.getElementById('schedule-backup-type').value,
                        exclude_disks: document.getElementById('schedule-exclude-disks').value.split(',').map(name => name.trim()).filter(Boolean),
                        retention_days: parseInt(document.getElementById('schedule-retention').value),
                        enabled: document.getElementById('schedule-enabled').checked
                    };
                    // Always clear the policy when leaving automatic mode. Omitting
                    // it would retain the previous sealed policy on an update.
                    data.backup_policy = null;
                    if (data.backup_type === 'automatic') {
                        const days = document.getElementById('schedule-full-every-days').value;
                        const count = document.getElementById('schedule-max-incrementals').value;
                        if (!/^[1-9][0-9]{0,4}$/.test(days) || Number(days) > 36500 ||
                            !/^[1-9][0-9]{0,2}$/.test(count) || Number(count) > 255) {
                            throw new Error(window.t('schedules.invalid_policy'));
                        }
                        data.backup_policy = {schema: 1, full_every_days: Number(days), max_incrementals: Number(count)};
                    }
                    if (!scheduleId) {
                        data.enabled = false;
                        const targetType = document.getElementById('schedule-target-type').value;
                        data[targetType === 'vm' ? 'vm_id' : 'vm_group_id'] = document.getElementById(
                            targetType === 'vm' ? 'schedule-vm-id' : 'schedule-group-id'
                        ).value;
                    }
                    if (scheduleId) {
                        await apiClient.put(`/api/v1/schedules/${scheduleId}`, data);
                    } else {
                        await apiClient.post('/api/v1/schedules', data);
                    }
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-schedule'));
                    modal.hide();
                    window.vnbui.showToast('Schedule saved successfully', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to save schedule: ' + error.message, 'error');
                }
            },

            submitDeleteSchedule: async () => {
                try {
                    const scheduleId = document.getElementById('delete-schedule-id').value;
                    await apiClient.delete(`/api/v1/schedules/${scheduleId}`);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-delete-schedule'));
                    modal.hide();
                    window.vnbui.showToast('Schedule deleted', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to delete schedule: ' + error.message, 'error');
                }
            },

            // Agents
            viewAgentDetails: async (agentId) => {
                try {
                    const agent = await apiClient.get(`/api/v1/agents/${agentId}`);

                    // Populate Details tab
                    document.getElementById('agent-detail-hostname').textContent = agent.hostname;
                    document.getElementById('agent-detail-status').textContent = enumLabel(agent.status);
                    document.getElementById('agent-detail-platform').textContent = agent.platform || 'N/A';
                    document.getElementById('agent-detail-version').textContent = agent.version || 'N/A';
                    document.getElementById('agent-detail-ip').textContent = agent.ip_address || 'N/A';
                    document.getElementById('agent-detail-vms').textContent = agent.vm_count || 0;
                    document.getElementById('agent-detail-heartbeat').textContent = agent.last_heartbeat
                        ? new Date(agent.last_heartbeat).toLocaleString()
                        : 'Never';
                    document.getElementById('agent-detail-id').textContent = agent.id;

                    // Populate Settings tab
                    document.getElementById('agent-settings-id').value = agent.id;
                    const config = agent.config || {};
                    this.editingAgent = agent;
                    const provider = agentProvider(agent);
                    const scope = agent.metrics?.scope || {};
                    const installed = scope.source_namespaces;
                    const selected = config.selected_source_namespaces ?? scope.selected_source_namespaces;
                    const t = window.t;
                    const list = value => Array.isArray(value) ? (value.length ? value.map(escapeHtml).join(', ') : t('agents.scope_none')) : enumLabel(null);
                    const scratchList = value => {
                        if (!value || typeof value !== 'object' || Array.isArray(value)) return enumLabel(null);
                        const pairs = Object.entries(value);
                        if (pairs.some(([namespace, pvc]) => !namespace.trim() || typeof pvc !== 'string' || !pvc.trim())) return enumLabel(null);
                        return pairs.length ? pairs.map(([namespace, pvc]) => `${escapeHtml(namespace)}: ${escapeHtml(pvc)}`).join(', ') : t('agents.scope_none');
                    };
                    const providerBox = document.getElementById('agent-provider-settings');
                    if (provider === 'kubevirt') {
                        providerBox.innerHTML = `<h4>KubeVirt</h4><dl class="row"><dt class="col-sm-4">${t('agents.scope_installed')}</dt><dd class="col-sm-8">${list(installed)}</dd><dt class="col-sm-4">${t('agents.scope_restore')}</dt><dd class="col-sm-8">${list(scope.restore_namespaces)}</dd><dt class="col-sm-4">${t('agents.scope_scratch')}</dt><dd class="col-sm-8">${scratchList(scope.scratch_pvcs)}</dd><dt class="col-sm-4">${t('agents.scope_applied')}</dt><dd class="col-sm-8">${escapeHtml(String(scope.applied_revision ?? '—'))} / ${escapeHtml(String(config.scope_revision ?? '—'))}</dd></dl><div class="mb-3"><label class="form-label" for="agent-setting-selected_source_namespaces">${t('agents.scope_selected')}</label><textarea class="form-control" id="agent-setting-selected_source_namespaces" ${Array.isArray(installed) && Array.isArray(selected) ? '' : 'disabled'}>${escapeHtml(Array.isArray(selected) ? selected.join(', ') : '')}</textarea><div class="form-hint">${t('agents.scope_hint')}</div></div><p class="text-secondary">${t('agents.kubevirt_paths')}</p><p class="text-secondary">${t('agents.scope_expand')}</p><code class="d-block text-break mb-3" dir="ltr">python3 install/reconfigure.py plan --previous site.previous.json --config site.proposed.json --state change-001</code><div class="alert alert-info">${t('agents.shared_destination')}</div>`;
                    } else {
                        providerBox.innerHTML = `<h4>${provider === 'libvirt' ? 'Native libvirt' : enumLabel(null)}</h4><p class="text-secondary">${t(provider === 'libvirt' ? 'agents.native_paths' : 'agents.provider_unknown')}</p><div class="alert alert-info">${t('agents.shared_destination')}</div>`;
                    }
                    const missing = agent.metrics?.health_issues || [];
                    if (missing.length) providerBox.insertAdjacentHTML('beforeend', `<div class="alert alert-warning">${t('agents.permission_issues')}: ${missing.map(escapeHtml).join(', ')}</div>`);
                    const settingFields = [
                        'heartbeat_interval', 'log_level'
                    ];
                    settingFields.forEach(field => {
                        const el = document.getElementById(`agent-setting-${field}`);
                        if (el) el.value = config[field] || '';
                    });

                    // Reset to Details tab and hide save button
                    const detailsTab = document.getElementById('agent-details-tab');
                    if (detailsTab) new bootstrap.Tab(detailsTab).show();
                    document.getElementById('agent-settings-save-btn')?.classList.add('d-none');

                    // Show/hide save button based on active tab
                    const modal = document.getElementById('modal-agent-details');
                    modal.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
                        tab.addEventListener('shown.bs.tab', (e) => {
                            const saveBtn = document.getElementById('agent-settings-save-btn');
                            if (e.target.id === 'agent-settings-tab') {
                                saveBtn?.classList.remove('d-none');
                            } else {
                                saveBtn?.classList.add('d-none');
                            }
                        });
                    });

                    new bootstrap.Modal(modal).show();
                } catch (error) {
                    window.vnbui.showToast('Failed to load agent details: ' + error.message, 'error');
                }
            },

            saveAgentSettings: async () => {
                const agentId = document.getElementById('agent-settings-id').value;
                if (!agentId) {
                    window.vnbui.showToast('No agent selected', 'error');
                    return;
                }

                // Collect non-empty values from form
                const settings = {};
                const settingFields = [
                    { field: 'heartbeat_interval', type: 'int' },
                    { field: 'log_level', type: 'string' },
                ];

                settingFields.forEach(({ field, type }) => {
                    const el = document.getElementById(`agent-setting-${field}`);
                    if (el && !el.disabled && el.value) {
                        if (type === 'int') {
                            settings[field] = parseInt(el.value, 10);
                        } else {
                            settings[field] = el.value;
                        }
                    }
                });

                const namespaces = document.getElementById('agent-setting-selected_source_namespaces');
                if (namespaces && !namespaces.disabled) {
                    try {settings.selected_source_namespaces = selectedNamespaces(namespaces.value, this.editingAgent?.metrics?.scope?.source_namespaces);}
                    catch (error) {window.vnbui.showToast(window.t(error.message), 'error'); return;}
                }
                if (!document.getElementById('agent-settings-form').reportValidity()) return;
                if (Object.keys(settings).length === 0) {
                    window.vnbui.showToast('No settings to save', 'warning');
                    return;
                }

                // Confirm before saving
                if (!confirm(window.t('agents.confirm_settings'))) {
                    return;
                }

                try {
                    await apiClient.patch(`/api/v1/agents/${agentId}/settings`, settings);
                    window.vnbui.showToast(window.t('agents.settings_pending'), 'success');
                    bootstrap.Modal.getInstance(document.getElementById('modal-agent-details'))?.hide();
                } catch (error) {
                    // 409 = backup running
                    if (error.message && error.message.includes('backup')) {
                        window.vnbui.showToast('Cannot update: backups running on this agent', 'error');
                    } else {
                        window.vnbui.showToast('Failed to save settings: ' + error.message, 'error');
                    }
                }
            },

            removeAgent: async (agentId, hostname) => {
                if (!confirm(window.t('agents.confirm_remove', {name: hostname}))) return;
                try {
                    // First try without cascade
                    await apiClient.delete(`/api/v1/agents/${agentId}`);
                    window.vnbui.showToast('Agent removed', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    // If error mentions VMs, offer cascade delete
                    if (error.message && error.message.includes('VMs')) {
                        const confirmMsg = `${error.message}\n\nDelete agent and its VMs? This is allowed only after all backups are retired and cannot be undone.`;
                        if (confirm(confirmMsg)) {
                            try {
                                await apiClient.delete(`/api/v1/agents/${agentId}?cascade=true`);
                                window.vnbui.showToast('Agent and VMs removed', 'success');
                                setTimeout(() => window.vnbui.refreshPage(), 500);
                            } catch (cascadeError) {
                                window.vnbui.showToast('Failed to remove agent: ' + cascadeError.message, 'error');
                            }
                        }
                    } else {
                        window.vnbui.showToast('Failed to remove agent: ' + error.message, 'error');
                    }
                }
            },

            // Reports
            generateReport: () => {
                document.getElementById('report-form')?.reset();
                new bootstrap.Modal(document.getElementById('modal-generate-report')).show();
            },

            quickReport: async (type) => {
                try {
                    window.vnbui.showToast('Generating report...', 'info');
                    const typeLabel = type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                    const name = `${typeLabel} - ${new Date().toISOString().split('T')[0]}`;
                    const report = await apiClient.post('/api/v1/reports', { name, report_type: type, date_range: 'week' });
                    const execution = await apiClient.post(`/api/v1/reports/${report.id}/generate`);
                    window.vnbui.showToast('Report generated!', 'success');
                    if (execution.status === 'completed') {
                        await window.vnbui.downloadExecution(execution.execution_id);
                    }
                } catch (error) {
                    window.vnbui.showToast('Failed to generate report: ' + error.message, 'error');
                }
            },

            downloadReport: async (reportId) => {
                try {
                    const report = await apiClient.get(`/api/v1/reports/${reportId}`);
                    if (report.last_execution) {
                        await window.vnbui.downloadExecution(report.last_execution);
                    } else {
                        window.vnbui.showToast('No execution available for this report', 'warning');
                    }
                } catch (error) {
                    window.vnbui.showToast('Download failed: ' + error.message, 'error');
                }
            },

            downloadExecution: async (executionId) => {
                try {
                    const token = authService.getToken();
                    const response = await fetch(`/api/v1/report-executions/${executionId}/download`, {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });

                    if (!response.ok) {
                        if (response.status === 404) {
                            throw new Error('Report file no longer available. Please regenerate the report.');
                        }
                        throw new Error('Download failed');
                    }

                    const contentType = response.headers.get('Content-Type') || '';
                    const blob = await response.blob();
                    const contentDisposition = response.headers.get('Content-Disposition');
                    const filenameMatch = contentDisposition && contentDisposition.match(/filename="?(.+?)"?$/);
                    const filename = filenameMatch ? filenameMatch[1] : `report_${executionId}`;

                    const url = window.URL.createObjectURL(blob);

                    if (contentType.includes('text/html')) {
                        // Open HTML reports in a new tab for rendering
                        const tab = window.open(url, '_blank');
                        if (tab) {
                            tab.focus();
                            // Revoke after tab has loaded
                            setTimeout(() => window.URL.revokeObjectURL(url), 10000);
                        } else {
                            // Fallback to download if popup blocked
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = filename;
                            document.body.appendChild(a);
                            a.click();
                            window.URL.revokeObjectURL(url);
                            document.body.removeChild(a);
                        }
                        window.vnbui.showToast('Report opened in new tab', 'success');
                    } else {
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                        window.vnbui.showToast('Download started', 'success');
                    }
                } catch (error) {
                    window.vnbui.showToast(error.message, 'error');
                }
            },

            deleteReport: async (reportId, name) => {
                if (confirm(`Delete report "${name}"?`)) {
                    try {
                        await apiClient.delete(`/api/v1/reports/${reportId}`);
                        window.vnbui.showToast('Report deleted', 'success');
                        setTimeout(() => window.vnbui.refreshPage(), 500);
                    } catch (error) {
                        window.vnbui.showToast('Failed to delete report: ' + error.message, 'error');
                    }
                }
            },

            submitGenerateReport: async () => {
                try {
                    const type = document.getElementById('report-type').value;
                    const dateRange = document.getElementById('report-date-range').value;
                    const format = document.getElementById('report-format').value;
                    const typeLabel = type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                    const name = `${typeLabel} - ${new Date().toISOString().split('T')[0]}`;
                    const report = await apiClient.post('/api/v1/reports', { name, report_type: type, date_range: dateRange, format });
                    const execution = await apiClient.post(`/api/v1/reports/${report.id}/generate`);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-generate-report'));
                    modal.hide();
                    window.vnbui.showToast('Report generation started', 'success');
                    if (execution.status === 'completed') {
                        await window.vnbui.downloadExecution(execution.execution_id);
                    }
                } catch (error) {
                    window.vnbui.showToast('Failed to generate report: ' + error.message, 'error');
                }
            },

            // Users
            createUser: () => {
                document.getElementById('user-form')?.reset();
                document.getElementById('user-modal-title').textContent = 'Create User';
                document.getElementById('user-id').value = '';
                document.getElementById('user-auth-source').value = 'local';
                document.getElementById('user-password-group').style.display = 'block';
                // Hide OIDC-specific fields for new users
                document.getElementById('oidc-user-info').style.display = 'none';
                document.getElementById('role-source-group').style.display = 'none';
                document.getElementById('user-status-group').style.display = 'block';
                document.getElementById('user-username').readOnly = false;
                for (const id of ['user-username', 'user-fullname', 'user-email']) {
                    const input = document.getElementById(id);
                    input.readOnly = false;
                    input.classList.remove('bg-light', 'pe-none');
                }
                document.getElementById('user-role').disabled = false;
                document.getElementById('user-role-source').onchange = null;
                document.getElementById('user-fullname-hint').style.display = 'none';
                document.getElementById('user-email-hint').style.display = 'none';
                new bootstrap.Modal(document.getElementById('modal-user')).show();
            },

            editUser: async (userId) => {
                try {
                    const user = await apiClient.get(`/api/v1/users/${userId}`);
                    if (!['local', 'oidc'].includes(user.auth_source)) throw new Error('Unknown identity source');
                    document.getElementById('user-form')?.reset();
                    document.getElementById('user-modal-title').textContent = 'Edit User';
                    document.getElementById('user-id').value = user.id;
                    document.getElementById('user-auth-source').value = user.auth_source || 'local';
                    document.getElementById('user-username').value = user.username;
                    document.getElementById('user-fullname').value = user.full_name || '';
                    document.getElementById('user-email').value = user.email || '';
                    document.getElementById('user-role').value = user.role;
                    document.getElementById('user-active').checked = user.is_active;

                    const isOIDC = user.auth_source === 'oidc';
                    const roleSource = document.getElementById('user-role-source');
                    const syncRole = () => {
                        document.getElementById('user-role').disabled = isOIDC && roleSource.value !== 'local';
                    };
                    roleSource.value = user.role_source || 'oidc';
                    roleSource.onchange = syncRole;
                    syncRole();

                    // Show/hide OIDC-specific sections
                    document.getElementById('oidc-user-info').style.display = isOIDC ? 'block' : 'none';
                    document.getElementById('role-source-group').style.display = isOIDC ? 'block' : 'none';
                    document.getElementById('user-status-group').style.display = isOIDC ? 'none' : 'block';
                    document.getElementById('user-password-group').style.display = 'none';

                    // For OIDC users, make identity fields readonly
                    const fullnameInput = document.getElementById('user-fullname');
                    const emailInput = document.getElementById('user-email');
                    const usernameInput = document.getElementById('user-username');
                    const fullnameHint = document.getElementById('user-fullname-hint');
                    const emailHint = document.getElementById('user-email-hint');

                    if (isOIDC) {
                        // Populate OIDC details
                        document.getElementById('oidc-subject').textContent = user.oidc_subject || 'N/A';
                        document.getElementById('oidc-issuer').textContent = user.oidc_issuer || 'N/A';
                        document.getElementById('user-role-source').value = user.role_source || 'oidc';

                        // Make identity fields readonly for OIDC users (use Bootstrap classes)
                        [usernameInput, fullnameInput, emailInput].forEach(input => {
                            input.readOnly = true;
                            input.classList.add('bg-light', 'pe-none');
                        });
                        if (fullnameHint) fullnameHint.style.display = 'block';
                        if (emailHint) emailHint.style.display = 'block';
                    } else {
                        [usernameInput, fullnameInput, emailInput].forEach(input => {
                            input.readOnly = false;
                            input.classList.remove('bg-light', 'pe-none');
                        });
                        if (fullnameHint) fullnameHint.style.display = 'none';
                        if (emailHint) emailHint.style.display = 'none';
                    }

                    new bootstrap.Modal(document.getElementById('modal-user')).show();
                } catch (error) {
                    window.vnbui.showToast('Failed to load user', 'error');
                }
            },

            deleteUser: (userId, username) => {
                document.getElementById('delete-user-id').value = userId;
                document.getElementById('delete-user-name').textContent = username;
                new bootstrap.Modal(document.getElementById('modal-delete-user')).show();
            },

            resetPassword: (userId, username) => {
                document.getElementById('reset-new-password').value = '';
                document.getElementById('reset-confirm-password').value = '';
                document.getElementById('reset-user-id').value = userId;
                document.getElementById('reset-username').value = username;
                new bootstrap.Modal(document.getElementById('modal-reset-password')).show();
            },

            submitUser: async () => {
                try {
                    const userId = document.getElementById('user-id').value;
                    const authSource = document.getElementById('user-auth-source').value;
                    const isOIDC = authSource === 'oidc';

                    let data;
                    if (isOIDC && userId) {
                        data = {role_source: document.getElementById('user-role-source').value};
                        if (!['local', 'oidc'].includes(data.role_source)) throw new Error('Invalid role source');
                        if (data.role_source === 'local') data.role = document.getElementById('user-role').value;
                    } else {
                        data = {
                            username: document.getElementById('user-username').value.trim(),
                            full_name: document.getElementById('user-fullname').value.trim(),
                            email: document.getElementById('user-email').value.trim(),
                            role: document.getElementById('user-role').value,
                            is_active: document.getElementById('user-active').checked
                        };
                        if (!data.username) throw new Error('Username required');
                    }
                    if (data.role !== undefined && !['admin', 'operator', 'viewer'].includes(data.role)) throw new Error('Invalid role');

                    if (!userId) {
                        data.password = document.getElementById('user-password').value;
                    }
                    if (userId) {
                        await apiClient.put(`/api/v1/users/${userId}`, data);
                    } else {
                        await apiClient.post('/api/v1/users', data);
                    }
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-user'));
                    modal.hide();
                    window.vnbui.showToast('User saved successfully', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to save user', 'error');
                }
            },

            submitResetPassword: async () => {
                try {
                    const userId = document.getElementById('reset-user-id').value;
                    const newPassword = document.getElementById('reset-new-password').value;
                    const confirmPassword = document.getElementById('reset-confirm-password').value;
                    if (newPassword !== confirmPassword) {
                        window.vnbui.showToast('Passwords do not match', 'error');
                        return;
                    }
                    await apiClient.put(`/api/v1/users/${userId}`, { password: newPassword });
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-reset-password'));
                    modal.hide();
                    window.vnbui.showToast('Password reset successfully', 'success');
                } catch (error) {
                    window.vnbui.showToast('Failed to reset password', 'error');
                }
            },

            submitDeleteUser: async () => {
                try {
                    const userId = document.getElementById('delete-user-id').value;
                    await apiClient.delete(`/api/v1/users/${userId}`);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-delete-user'));
                    modal.hide();
                    window.vnbui.showToast('User deleted', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to delete user', 'error');
                }
            },

            // Profile
            openProfile: async () => {
                try {
                    const user = await authService.fetchUserData();
                    if (!user) throw new Error('Unable to verify profile');

                    // Populate profile modal
                    document.getElementById('profile-user-id').value = user.id;
                    document.getElementById('profile-username').value = user.username || '';
                    document.getElementById('profile-organization').textContent = user.org_id || '';
                    document.getElementById('profile-role').value = enumLabel(user.role || 'viewer', 'role');
                    document.getElementById('profile-fullname').value = user.full_name || '';
                    document.getElementById('profile-email').value = user.email || '';
                    document.getElementById('profile-last-login').value = user.last_login
                        ? new Date(user.last_login).toLocaleString()
                        : 'Never';

                    const isOIDC = user.auth_source === 'oidc';
                    document.getElementById('profile-oidc-info').style.display = isOIDC ? 'block' : 'none';
                    if (isOIDC) {
                        document.getElementById('profile-role-source').textContent = user.role_source || 'N/A';
                        document.getElementById('profile-oidc-issuer').textContent = user.oidc_issuer || 'N/A';
                    }

                    // For OIDC users, make name/email readonly with visual indication
                    const fullnameInput = document.getElementById('profile-fullname');
                    const emailInput = document.getElementById('profile-email');
                    const fullnameHint = document.getElementById('profile-fullname-hint');
                    const emailHint = document.getElementById('profile-email-hint');

                    [fullnameInput, emailInput].forEach(input => {
                        input.readOnly = isOIDC || user.role !== 'admin';
                        input.classList.toggle('bg-light', isOIDC);
                        input.classList.toggle('pe-none', isOIDC);
                    });
                    fullnameHint.style.display = isOIDC ? 'block' : 'none';
                    emailHint.style.display = isOIDC ? 'block' : 'none';
                    document.getElementById('profile-save').disabled = isOIDC || user.role !== 'admin';

                    new bootstrap.Modal(document.getElementById('modal-profile')).show();
                } catch (error) {
                    window.vnbui.showToast('Failed to load profile: ' + error.message, 'error');
                }
            },

            saveProfile: async () => {
                try {
                    const user = await authService.fetchUserData();
                    if (!user || user.role !== 'admin' || user.auth_source !== 'local') {
                        throw new Error('Profile update is unavailable');
                    }
                    const userId = user.id;
                    const data = {
                        full_name: document.getElementById('profile-fullname').value,
                        email: document.getElementById('profile-email').value
                    };
                    await apiClient.put(`/api/v1/users/${userId}`, data);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-profile'));
                    modal.hide();
                    window.vnbui.showToast('Profile updated', 'success');
                } catch (error) {
                    window.vnbui.showToast('Failed to update profile: ' + error.message, 'error');
                }
            },

            // VM Page — pagination and selection
            vmPageNav: (page) => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.goToPage === 'function') {
                    window.vnbui.currentPage.goToPage(page);
                }
            },

            toggleVMSelection: (vmId) => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.toggleVMSelection === 'function') {
                    window.vnbui.currentPage.toggleVMSelection(vmId);
                }
            },

            toggleSelectAllPage: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.toggleSelectAllPage === 'function') {
                    window.vnbui.currentPage.toggleSelectAllPage();
                }
            },

            selectAllMatching: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.selectAllMatching === 'function') {
                    window.vnbui.currentPage.selectAllMatching();
                }
            },

            clearSelection: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.clearSelection === 'function') {
                    window.vnbui.currentPage.clearSelection();
                }
            },

            bulkBackupSelected: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.bulkBackupSelected === 'function') {
                    window.vnbui.currentPage.bulkBackupSelected();
                }
            },

            bulkAddToGroup: () => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.bulkAddToGroup === 'function') {
                    window.vnbui.currentPage.bulkAddToGroup();
                }
            },

            // Groups — pagination
            groupPageNav: (page) => {
                if (window.vnbui.currentPage && typeof window.vnbui.currentPage.goToPage === 'function') {
                    window.vnbui.currentPage.goToPage(page);
                }
            },

            // Groups — CRUD
            createGroup: async () => {
                document.getElementById('group-modal-title').textContent = 'Create Group';
                document.getElementById('group-id').value = '';
                document.getElementById('group-name').value = '';
                document.getElementById('group-description').value = '';
                document.getElementById('group-tags').value = '';
                // Reset type to static
                document.getElementById('group-type-static').checked = true;
                window.vnbui.toggleGroupType();
                // Clear rules
                document.getElementById('group-rules-list').innerHTML = '';
                document.getElementById('group-rules-preview').innerHTML = '';
                document.getElementById('group-rules-match').value = 'all';
                await window.vnbui.loadVMsForGroupModal([]);
                new bootstrap.Modal(document.getElementById('modal-group')).show();
            },

            editGroup: async (groupId) => {
                try {
                    const group = await apiClient.get(`/api/v1/groups/${groupId}`);
                    document.getElementById('group-modal-title').textContent = 'Edit Group';
                    document.getElementById('group-id').value = group.id;
                    document.getElementById('group-name').value = group.name;
                    document.getElementById('group-description').value = group.description || '';
                    document.getElementById('group-tags').value = (group.tags || []).join(', ');

                    // Set group type
                    const groupType = group.group_type || 'static';
                    document.getElementById(`group-type-${groupType}`).checked = true;
                    window.vnbui.toggleGroupType();

                    // Set rules
                    document.getElementById('group-rules-match').value = group.rules_match || 'all';
                    document.getElementById('group-rules-list').innerHTML = '';
                    document.getElementById('group-rules-preview').innerHTML = '';
                    if (group.rules && group.rules.length > 0) {
                        group.rules.forEach(rule => window.vnbui.addGroupRule(rule));
                    }

                    // Load VMs for static selection
                    const vmIds = group.vms?.items?.map(v => v.id) || [];
                    await window.vnbui.loadVMsForGroupModal(vmIds);
                    new bootstrap.Modal(document.getElementById('modal-group')).show();
                } catch (error) {
                    window.vnbui.showToast('Failed to load group: ' + error.message, 'error');
                }
            },

            loadVMsForGroupModal: async (selectedVmIds) => {
                const select = document.getElementById('group-vms');
                if (!select) return;
                select.innerHTML = '<option value="">Loading VMs...</option>';
                try {
                    const data = await apiClient.get('/api/v1/vms?limit=100');
                    const vms = data.items || [];
                    if (vms.length === 0) {
                        select.innerHTML = '<option value="" disabled>No VMs available</option>';
                        return;
                    }
                    select.innerHTML = vms.map(vm => {
                        const selected = selectedVmIds.includes(vm.id) ? 'selected' : '';
                        const state = vm.state ? ` (${vm.state})` : '';
                        return `<option value="${vm.id}" ${selected}>${vm.name}${state}</option>`;
                    }).join('');
                } catch (error) {
                    console.error('Failed to load VMs:', error);
                    select.innerHTML = '<option value="" disabled>Error loading VMs</option>';
                }
            },

            toggleGroupType: () => {
                const selectedType = document.querySelector('input[name="group-type"]:checked')?.value || 'static';
                const staticSection = document.getElementById('group-static-section');
                const rulesSection = document.getElementById('group-rules-section');
                if (staticSection) staticSection.style.display = (selectedType === 'static' || selectedType === 'hybrid') ? '' : 'none';
                if (rulesSection) rulesSection.style.display = (selectedType === 'dynamic' || selectedType === 'hybrid') ? '' : 'none';
            },

            addGroupRule: (rule) => {
                const list = document.getElementById('group-rules-list');
                if (!list) return;

                const row = document.createElement('div');
                row.className = 'd-flex gap-2 mb-2 align-items-center group-rule-row';
                const field = rule?.field || 'name';
                const op = rule?.op || 'regex';
                const value = rule?.value || '';
                const valueStr = Array.isArray(value) ? value.join(', ') : value;

                row.innerHTML = `
                    <select class="form-select form-select-sm rule-field" style="width: 120px;">
                        <option value="name" ${field === 'name' ? 'selected' : ''}>Name</option>
                        <option value="state" ${field === 'state' ? 'selected' : ''}>State</option>
                        <option value="agent_id" ${field === 'agent_id' ? 'selected' : ''}>Agent ID</option>
                    </select>
                    <select class="form-select form-select-sm rule-op" style="width: 120px;">
                        <option value="eq" ${op === 'eq' ? 'selected' : ''}>equals</option>
                        <option value="neq" ${op === 'neq' ? 'selected' : ''}>not equals</option>
                        <option value="regex" ${op === 'regex' ? 'selected' : ''}>regex</option>
                        <option value="glob" ${op === 'glob' ? 'selected' : ''}>glob</option>
                        <option value="in" ${op === 'in' ? 'selected' : ''}>in list</option>
                    </select>
                    <input type="text" class="form-control form-control-sm rule-value" placeholder="Value" value="${escapeHtml(valueStr)}">
                    <button class="btn btn-sm btn-ghost-danger" onclick="this.closest('.group-rule-row').remove()">
                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="16" height="16" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                    </button>
                `;
                list.appendChild(row);
            },

            _collectGroupRules: () => {
                const rows = document.querySelectorAll('.group-rule-row');
                const rules = [];
                rows.forEach(row => {
                    const field = row.querySelector('.rule-field').value;
                    const op = row.querySelector('.rule-op').value;
                    let value = row.querySelector('.rule-value').value;
                    if (op === 'in') {
                        value = value.split(',').map(v => v.trim()).filter(v => v);
                    }
                    if (value && (Array.isArray(value) ? value.length > 0 : true)) {
                        rules.push({ field, op, value });
                    }
                });
                return rules;
            },

            previewGroupRules: async () => {
                const rules = window.vnbui._collectGroupRules();
                const rulesMatch = document.getElementById('group-rules-match')?.value || 'all';
                const previewEl = document.getElementById('group-rules-preview');

                if (rules.length === 0) {
                    previewEl.innerHTML = '<div class="text-secondary small">Add at least one rule to preview.</div>';
                    return;
                }

                previewEl.innerHTML = '<div class="text-secondary small">Loading preview...</div>';

                try {
                    const groupId = document.getElementById('group-id').value || 'new';
                    const result = await apiClient.post(`/api/v1/groups/${groupId}/preview`, { rules, rules_match: rulesMatch });
                    const vms = result.vms || [];
                    if (vms.length === 0) {
                        previewEl.innerHTML = '<div class="text-secondary small">No VMs match these rules.</div>';
                    } else {
                        const truncated = result.truncated ? `<div class="text-secondary small">...and ${result.total - vms.length} more</div>` : '';
                        previewEl.innerHTML = `
                            <div class="text-secondary small mb-1">${result.total} VM(s) match:</div>
                            <div class="d-flex flex-wrap gap-1">
                                ${vms.slice(0, 20).map(vm => `<span class="badge bg-secondary-lt">${escapeHtml(vm.name)}</span>`).join('')}
                                ${vms.length > 20 ? `<span class="badge bg-muted-lt">+${vms.length - 20} more</span>` : ''}
                            </div>
                            ${truncated}
                        `;
                    }
                } catch (error) {
                    previewEl.innerHTML = `<div class="text-danger small">${escapeHtml(error.message)}</div>`;
                }
            },

            deleteGroup: (groupId, name) => {
                document.getElementById('delete-group-id').value = groupId;
                document.getElementById('delete-group-name').textContent = name;
                new bootstrap.Modal(document.getElementById('modal-delete-group')).show();
            },

            viewGroup: (groupId) => {
                window.vnbui.navigateTo(`groups/${groupId}`);
            },

            backupGroup: async (groupId, name) => {
                if (confirm(`Start backup for all VMs in group "${name}"?`)) {
                    try {
                        const result = await apiClient.post('/api/v1/backups/bulk-create', { filter: { group_id: groupId } });
                        window.vnbui.showToast('Group backup started', 'success');
                        apiClient.acknowledge(result);
                    } catch (error) {
                        window.vnbui.showToast(error.operatorRecovery ? error.message : 'Failed to start group backup: ' + error.message, 'error');
                    }
                }
            },

            submitGroup: async () => {
                try {
                    const groupId = document.getElementById('group-id').value;
                    const tagsInput = document.getElementById('group-tags')?.value || '';
                    const tags = tagsInput.split(',')
                        .map(t => t.trim())
                        .filter(t => t.length > 0);

                    const groupType = document.querySelector('input[name="group-type"]:checked')?.value || 'static';

                    const data = {
                        name: document.getElementById('group-name').value,
                        description: document.getElementById('group-description').value,
                        tags: tags,
                        group_type: groupType,
                    };

                    // Add rules for dynamic/hybrid
                    if (groupType === 'dynamic' || groupType === 'hybrid') {
                        data.rules = window.vnbui._collectGroupRules();
                        data.rules_match = document.getElementById('group-rules-match')?.value || 'all';
                    }

                    if (groupId) {
                        await apiClient.put(`/api/v1/groups/${groupId}`, data);
                    } else {
                        const result = await apiClient.post('/api/v1/groups', data);
                        // Add static VMs if any selected
                        if (groupType !== 'dynamic') {
                            const select = document.getElementById('group-vms');
                            const vmIds = Array.from(select?.selectedOptions || []).map(o => o.value).filter(v => v);
                            if (vmIds.length > 0) {
                                await apiClient.post(`/api/v1/groups/${result.id}/vms`, { vm_ids: vmIds });
                            }
                        }
                    }

                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-group'));
                    modal.hide();
                    window.vnbui.showToast('Group saved successfully', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to save group: ' + error.message, 'error');
                }
            },

            submitDeleteGroup: async () => {
                try {
                    const groupId = document.getElementById('delete-group-id').value;
                    await apiClient.delete(`/api/v1/groups/${groupId}`);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('modal-delete-group'));
                    modal.hide();
                    window.vnbui.showToast('Group deleted', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to delete group: ' + error.message, 'error');
                }
            },

            // Search
            performSearch: () => {
                const query = document.getElementById('search-input').value;
                if (query && window.vnbui.currentPage && window.vnbui.currentPage.search) {
                    window.vnbui.currentPage.search(query);
                    window.vnbui.refreshPage();
                }
            },

            // Verification
            startVerification: async (backupId) => {
                backupId ||= document.getElementById('verification-backup')?.value;
                if (!backupId) {
                    window.vnbui.showToast(window.t('verification.select_backup'), 'warning');
                    return;
                }
                if (this.verificationInFlight.has(backupId)) return;
                this.verificationInFlight.add(backupId);
                try {
                    // Keep the original ID after a lost reply; a retry must not
                    // silently enroll another independent full read.
                    if (!this.verificationRequests.has(backupId)) this.verificationRequests.set(backupId, crypto.randomUUID());
                    await apiClient.post(`/api/v1/backups/${encodeURIComponent(backupId)}/verify`,
                        {verification_id: this.verificationRequests.get(backupId)});
                    this.verificationRequests.delete(backupId);
                    window.vnbui.showToast(window.t('verification.queued'), 'info');
                    window.vnbui.refreshPage();
                } catch (error) {
                    window.vnbui.showToast(window.t('verification.start_failed', {error: error.message}), 'error');
                } finally {
                    this.verificationInFlight.delete(backupId);
                }
            },

            verificationControl: async (id, action) => {
                try {
                    if (!['resume', 'cancel'].includes(action)) return;
                    const saved = await apiClient.get(`/api/v1/verifications/${encodeURIComponent(id)}`);
                    await apiClient.post(`/api/v1/backups/${encodeURIComponent(saved.backup_id)}/verify`,
                        {verification_id: id, action});
                    window.vnbui.showToast(window.t('verification.queued'), 'info');
                    window.vnbui.refreshPage();
                } catch (error) {
                    window.vnbui.showToast(error.message, 'error');
                }
            },

            viewVerificationDetails: async (id) => {
                try {
                    const verification = await apiClient.get(`/api/v1/verifications/${id}`);
                    alert(JSON.stringify({id: verification.id, backup_id: verification.backup_id,
                        status: verification.status, message: verification.result_message,
                        started_at: verification.started_at, completed_at: verification.completed_at,
                        read_attempts: verification.read_attempts, read_limit: verification.read_limit,
                        cancel_requested: verification.cancel_requested}, null, 2));
                } catch (error) {
                    window.vnbui.showToast('Failed to load verification details: ' + error.message, 'error');
                }
            },

            // Restores
            resumeRestore: async (id) => {
                try {
                    await apiClient.post(`/api/v1/restores/${id}/resume`, {});
                    window.vnbui.showToast(window.t('restores.resume_queued'), 'info');
                    window.vnbui.refreshPage();
                } catch (error) {
                    window.vnbui.showToast(error.message, 'error');
                }
            },
            cancelRestore: async (id) => {
                if (confirm('Cancel this restore operation?')) {
                    try {
                        await apiClient.patch(`/api/v1/restores/${id}/cancel`);
                        window.vnbui.showToast('Restore cancelled', 'success');
                        setTimeout(() => window.vnbui.refreshPage(), 500);
                    } catch (error) {
                        window.vnbui.showToast('Failed to cancel restore: ' + error.message, 'error');
                    }
                }
            },

            viewRestoreDetails: async (id) => {
                try {
                    const restore = await apiClient.get(`/api/v1/restores/${id}`);
                    alert(JSON.stringify({ id: restore.id, target: restore.kubevirt_target || restore.native_target || restore.target_vm_name,
                        status: restore.status, progress: restore.progress, result: restore.result,
                        error: restore.error_message, started_at: restore.started_at,
                        operator_dispatch: restore.operator_dispatch ? {...restore.operator_dispatch,
                            message: window.t(`operator_recovery.dispatch_${['pending', 'dispatching', 'held', 'delivered'].includes(restore.operator_dispatch.state) ? restore.operator_dispatch.state : 'unknown'}`)} : null }, null, 2));
                } catch (error) {
                    window.vnbui.showToast('Failed to load restore details: ' + error.message, 'error');
                }
            },

            // Notifications
            markAllRead: async () => {
                try {
                    await apiClient.post('/api/v1/notifications/mark-all-read');
                    window.vnbui.showToast('All notifications marked as read', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to mark notifications as read: ' + error.message, 'error');
                }
            },

            markAsRead: async (id) => {
                try {
                    await apiClient.put(`/api/v1/notifications/${id}/read`);
                    window.vnbui.showToast('Notification marked as read', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to mark notification as read: ' + error.message, 'error');
                }
            },

            deleteNotification: async (id) => {
                try {
                    await apiClient.delete(`/api/v1/notifications/${id}`);
                    window.vnbui.showToast('Notification deleted', 'success');
                    setTimeout(() => window.vnbui.refreshPage(), 500);
                } catch (error) {
                    window.vnbui.showToast('Failed to delete notification: ' + error.message, 'error');
                }
            },

            saveNotificationSettings: async () => {
                try {
                    const settings = {
                        email_enabled: document.getElementById('notif-email').checked,
                        backup_success: document.getElementById('notif-backup-success').checked,
                        backup_failure: document.getElementById('notif-backup-failure').checked,
                        agent_offline: document.getElementById('notif-agent-offline').checked,
                        storage_low: document.getElementById('notif-storage-low').checked
                    };
                    await apiClient.put('/api/v1/notifications/settings', settings);
                    window.vnbui.showToast('Notification settings saved', 'success');
                } catch (error) {
                    window.vnbui.showToast('Failed to save notification settings: ' + error.message, 'error');
                }
            },

            // Activity — use renderList() so filter state is preserved without reloading data
            filterActivity: (filter) => {
                const page = window.vnbui.currentPage;
                if (page && page.setFilter && page.renderList) {
                    page.setFilter(filter);
                    page.renderList();
                }
            },

            searchActivity: (query) => {
                const page = window.vnbui.currentPage;
                if (page && page.setSearchQuery && page.renderList) {
                    page.setSearchQuery(query);
                    clearTimeout(window.vnbui._searchTimeout);
                    window.vnbui._searchTimeout = setTimeout(() => page.renderList(), 300);
                }
            },

            filterTimeRange: (range) => {
                const page = window.vnbui.currentPage;
                if (page && page.setTimeRange && page.renderList) {
                    page.setTimeRange(range);
                    page.renderList();
                }
            },

            filterActivitySource: (source) => {
                const page = window.vnbui.currentPage;
                if (page && page.setSourceFilter && page.renderList) {
                    page.setSourceFilter(source);
                    page.renderList();
                }
            },

            toggleActivityDetails: (idx) => {
                const el = document.getElementById(`activity-details-${idx}`);
                if (el) {
                    el.classList.toggle('show');
                    // Update the expand button text
                    const btn = el.previousElementSibling?.querySelector('.activity-expand');
                    if (btn) {
                        btn.textContent = el.classList.contains('show') ? '−details' : '+details';
                    }
                }
            },

            // Notification filtering and details toggle
            filterNotifications: (filter) => {
                const page = window.vnbui.currentPage;
                if (page && page.setFilter && page.renderList) {
                    page.setFilter(filter);
                    page.renderList();
                }
            },

            toggleNotificationDetails: (idx) => {
                const el = document.getElementById(`notif-details-${idx}`);
                if (el) {
                    el.classList.toggle('show');
                    // Update the expand button text
                    const row = el.previousElementSibling;
                    const btn = row?.querySelector('.notif-expand');
                    if (btn) {
                        btn.textContent = el.classList.contains('show') ? '−details' : '+details';
                    }
                }
            },
        };
    }

    /**
     * Refresh current page
     */
    async refreshPage() {
        const page = window.location.hash.substring(1) || 'dashboard';
        await this.navigate(page, false);
    }

    /**
     * Navigate to page
     */
    async navigate(page, updateHistory = true) {
        console.log('Navigating to:', page);

        // Update URL
        if (updateHistory) {
            window.location.hash = page;
        }

        // Update active nav (sidebar) — remove all highlights, then set the correct one
        document.querySelectorAll('#sidebar-menu .nav-link').forEach(link => {
            link.classList.remove('active');
            link.style.backgroundColor = '';
            link.style.color = '';
        });
        const activeLink = document.querySelector(`#sidebar-menu a[href="#${page}"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }

        // Load page content
        const contentArea = document.getElementById('page-content');
        contentArea.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-primary"></div></div>';

        try {
            await this.loadPage(page);
        } catch (error) {
            console.error('Failed to load page:', error);
            contentArea.innerHTML = `
                <div class="empty">
                    <div class="empty-icon">
                        ${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}
                    </div>
                    <p class="empty-title">${window.t('common.failed_to_load')}</p>
                    <p class="empty-subtitle text-secondary">${escapeHtml(error.message)}</p>
                </div>
            `;
        }
    }

    /**
     * Load page content
     */
    async loadPage(page) {
        this.currentPage?.destroy?.();
        const contentArea = document.getElementById('page-content');
        try {
            let pageInstance = null;

            // Dynamically import and instantiate page modules
            switch (page) {
                case 'dashboard': {
                    const { DashboardPage } = await import('./pages/dashboard.js');
                    pageInstance = new DashboardPage();
                    break;
                }
                case 'vms': {
                    const { VMsPage } = await import('./pages/vms.js');
                    pageInstance = new VMsPage();
                    break;
                }
                case 'backups': {
                    const { BackupsPage } = await import('./pages/backups.js');
                    pageInstance = new BackupsPage();
                    break;
                }
                case 'schedules': {
                    const { SchedulesPage } = await import('./pages/schedules.js');
                    pageInstance = new SchedulesPage();
                    break;
                }
                case 'agents': {
                    const { AgentsPage } = await import('./pages/agents.js');
                    pageInstance = new AgentsPage();
                    break;
                }
                case 'reports': {
                    const { ReportsPage } = await import('./pages/reports.js');
                    pageInstance = new ReportsPage();
                    break;
                }
                case 'users': {
                    const { UsersPage } = await import('./pages/users.js');
                    pageInstance = new UsersPage();
                    break;
                }
                case 'licensing': {
                    const summary = await licensingService.summary();
                    pageInstance = summary.can_manage ? new LicensingPanel() : {render: () => renderLicenseSummary(summary)};
                    break;
                }
                case 'settings': {
                    const { SettingsPage } = await import('./pages/settings.js');
                    pageInstance = new SettingsPage();
                    break;
                }
                case 'groups': {
                    const { GroupsPage } = await import('./pages/groups.js');
                    pageInstance = new GroupsPage();
                    break;
                }
                case 'health': {
                    const { HealthPage } = await import('./pages/health.js');
                    pageInstance = new HealthPage();
                    break;
                }
                case 'verification': {
                    const { VerificationPage } = await import('./pages/verification.js');
                    pageInstance = new VerificationPage();
                    break;
                }
                case 'restores': {
                    const { RestoresPage } = await import('./pages/restores.js');
                    pageInstance = new RestoresPage();
                    break;
                }
                case 'notifications': {
                    const { NotificationsPage } = await import('./pages/notifications.js');
                    pageInstance = new NotificationsPage();
                    break;
                }
                case 'activity': {
                    const { ActivityPage } = await import('./pages/activity.js');
                    pageInstance = new ActivityPage();
                    break;
                }
                default: {
                    const route = this.extension?.routes.find(route => route.id === page);
                    if (route && this.features[route.requiresFeature]) {
                        pageInstance = await route.load();
                        break;
                    }
                    contentArea.innerHTML = `
                        <div class="empty">
                            <div class="empty-icon">
                                ${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}
                            </div>
                            <p class="empty-title">${window.t('common.page_not_found')}</p>
                            <p class="empty-subtitle text-secondary">${window.t('common.page_not_found_detail', {page: escapeHtml(page)})}</p>
                        </div>
                    `;
                    return;
                }
            }

            // Render the page
            if (pageInstance && pageInstance.render) {
                const html = await pageInstance.render();
                if (html !== undefined) contentArea.innerHTML = html;
                pageInstance.afterRender?.();

                // Initialize Bootstrap dropdowns for dynamically rendered content
                // Use requestAnimationFrame to ensure DOM is fully rendered
                requestAnimationFrame(() => {
                    const dropdowns = contentArea.querySelectorAll('[data-bs-toggle="dropdown"]');
                    dropdowns.forEach(dropdownToggle => {
                        // Dispose existing instance to prevent duplicates
                        const existing = bootstrap.Dropdown.getInstance(dropdownToggle);
                        if (existing) {
                            existing.dispose();
                        }
                        // Create new dropdown instance - Bootstrap handles click events automatically
                        new bootstrap.Dropdown(dropdownToggle, {
                            popperConfig: {
                                ...(window.matchMedia('(max-width: 991.98px)').matches && dropdownToggle.closest('.table-responsive') ? {strategy: 'fixed'} : {}),
                                placement: 'bottom-end',
                                modifiers: [
                                    {
                                        name: 'preventOverflow',
                                        options: { boundary: 'viewport' }
                                    }
                                ]
                            }
                        });
                    });
                });

                // Store page instance for later use
                this.currentPage = pageInstance;
                window.vnbui.currentPage = pageInstance;  // Also expose globally for methods like saveAllSettings()
            }
        } catch (error) {
            console.error('Error loading page:', error);
            throw error;
        }
    }

    loginLanguageControl() {
        const locales = window.vnbuiTranslator?.getAvailableLocales() || [];
        return `<select id="login-language" class="form-select form-select-sm w-auto" aria-label="${escapeHtml(window.t('profile.language'))}">${locales.map(locale => `<option value="${escapeHtml(locale.code)}" ${locale.active ? 'selected' : ''}>${escapeHtml(locale.name)}</option>`).join('')}</select>`;
    }

    bindLoginLanguage(retry = false) {
        document.getElementById('login-language')?.addEventListener('change', async event => {
            await window.vnbuiTranslator.setLanguage(event.target.value);
            if (retry) this.showBootstrapError(); else await this.showLogin();
        });
    }

    showBootstrapError() {
        const t = window.t;
        document.getElementById('app').innerHTML = `<div class="page page-center"><div class="container-tight py-4"><div class="d-flex justify-content-end gap-2 mb-3">${this.loginLanguageControl()}${themeService.button()}</div><div class="alert alert-danger" role="alert">${escapeHtml(t('login.bootstrap_error'))}</div><button id="bootstrap-retry" class="btn btn-primary w-100">${escapeHtml(t('login.bootstrap_retry'))}</button></div></div>`;
        this.bindLoginLanguage(true);
        document.getElementById('bootstrap-retry').addEventListener('click', () => window.location.reload());
    }

    /**
     * Show login page
     */
    async showLogin() {
        const app = document.getElementById('app');

        let installation;
        try {
            installation = await installationService.load();
            assetResolver.edition = installation.edition === 'commercial' ? 'commercial' : 'oss';
            await assetResolver.apply();
        } catch {
            this.showBootstrapError();
            return;
        }
        const oidcEnabled = installation.login_methods.oidc;
        const organizationLogin = installation.auth_mode === 'multi_organization';
        const t = window.t;
        const ssoButton = oidcEnabled ? `
            ${installation.login_methods.password ? `<div class="hr-text">${t('common.or')}</div>` : ''}
            <a href="/api/v1/auth/oidc/login" class="btn btn-outline-primary w-100">
                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0" /><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" /></svg>
                ${t('login.sso')}
            </a>
        ` : '';

        app.innerHTML = `
            <div class="page page-center">
                <div class="container container-tight py-4">
                    <div class="d-flex justify-content-end gap-2 mb-2">${this.loginLanguageControl()}${themeService.button()}</div>
                    <div class="text-center mb-4">
                        <h1 class="navbar-brand d-flex justify-content-center gap-2">
                            ${assetResolver.inlineSvg('brand-logo', {class: 'navbar-brand-image', width: 32, height: 32})}
                            <span class="text-primary">${escapeHtml(assetResolver.productName)}</span>
                        </h1>
                        <p class="text-secondary">${t('login.subtitle')}</p>
                    </div>
                    <div class="card card-md">
                        <div class="card-body">
                            <h2 class="h2 text-center mb-4">${t('login.title')}</h2>
                            ${installation.login_methods.password ? `<form id="login-form">
                                ${organizationLogin ? `<div class="mb-3">
                                    <label for="login-organization" class="form-label">${t('login.organization')}</label>
                                    <input id="login-organization" type="text" name="org_id" class="form-control" autocomplete="off" aria-describedby="login-organization-help">
                                    <div id="login-organization-help" class="form-hint">${t('login.organization_help')}</div>
                                </div>` : ''}
                                <div class="mb-3">
                                    <label class="form-label">${t('login.username')}</label>
                                    <input type="text" name="username" class="form-control" placeholder="${t('login.username_placeholder')}" required autofocus>
                                </div>
                                <div class="mb-2">
                                    <label class="form-label">${t('login.password')}</label>
                                    <input type="password" name="password" class="form-control" required>
                                </div>
                                <div class="form-footer">
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="ti ti-login me-2"></i>
                                        ${t('login.sign_in')}
                                    </button>
                                </div>
                            </form>` : ''}
                            ${ssoButton}
                            <div id="login-error" class="alert alert-danger mt-3" style="display: none;"></div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Setup login form handler
        this.bindLoginLanguage();
        document.getElementById('login-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = e.target.username.value;
            const password = e.target.password.value;
            const errorDiv = document.getElementById('login-error');
            const submitBtn = e.target.querySelector('button[type="submit"]');
            
            try {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>${t('login.signing_in')}`;
                errorDiv.style.display = 'none';
                
                await authService.login(username, password, organizationLogin ? e.target.org_id?.value || '' : '');
                
                // Reinitialize app after successful login
                await this.init();
                
            } catch (error) {
                errorDiv.textContent = t('login.error');
                errorDiv.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.innerHTML = `<i class="ti ti-login me-2"></i>${t('login.sign_in')}`;
            }
        });
    }

    /**
     * Show compatibility warning banner when version mismatch detected
     */
    showCompatibilityWarning(compatibility) {
        const banner = document.getElementById('compatibility-banner');
        if (!banner) return;

        const warnings = compatibility.warnings || [];
        const status = compatibility.status || 'unknown';

        const t = window.t;

        // Build warning message
        let message = t('compat_banner.version_mismatch') + ' ';
        if (warnings.length > 0) {
            message += warnings.join(' ');
        } else {
            message += t('compat_banner.some_incompatible');
        }

        // Determine severity based on status
        const isIncompatible = status === 'incompatible';
        const bgClass = isIncompatible ? 'bg-danger' : 'bg-warning';
        const icon = isIncompatible ? 'alert-triangle' : 'alert-circle';

        banner.innerHTML = `
            <div class="alert ${bgClass} alert-dismissible mb-0 rounded-0" role="alert">
                <div class="container-xl d-flex align-items-center">
                    <i class="ti ti-${icon} me-2"></i>
                    <div class="flex-grow-1">
                        <strong>${isIncompatible ? t('compat_banner.incompatible_title') : t('compat_banner.degraded_title')}:</strong>
                        ${escapeHtml(message)}
                        <a href="#settings" class="alert-link ms-2">${t('compat_banner.view_details')}</a>
                    </div>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            </div>
        `;
    }
}
