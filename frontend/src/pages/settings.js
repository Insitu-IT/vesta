import { LicensingPanel } from '../components/licensing.js';
import { contextHelp } from '../components/context-help.js';
/**
 * Settings Page
 * System and application settings
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { authService } from '../services/auth.service.js';

export class SettingsPage {
    constructor() {
        this.licensingPanel = new LicensingPanel();
        this.settings = {};
        this.loading = false;
        this.orchestratorKeys = [];
        this.registrationKeys = [];
        this.showKeyModal = false;
        this.newKeyData = null;
        this.versionInfo = null;
        this.compatibilityInfo = null;
        // v3.0: S3 and OIDC settings
        this.v3Settings = {};
        this.v3Loaded = false;
        this.admissionSaving = false;
        this.v3Secrets = {};
        this.encryptionConfigured = false;
        // v3.1: Encryption key management
        this.encryptionKeys = [];
        this.encryptionProvider = null;
        // v3.1: PKI / mTLS
        this.pkiStatus = null;
        this.pkiCertificates = [];
        // Dirty state tracking
        this.isDirty = false;
        this.originalSettings = null;
    }

    /**
     * Track form changes for dirty state
     */
    setupDirtyTracking() {
        // Store original settings for comparison
        this.originalSettings = JSON.stringify({
            settings: this.settings,
            v3Settings: this.v3Settings
        });
        this.isDirty = false;
        this.updateSaveAllButton();

        // Callers invoke this after mounting. Bind before checking button state;
        // delayed listeners lose early edits, notably repair of a legacy role.
        const inputs = document.querySelectorAll('#settings-general input, #settings-general select, ' +
            '#settings-backup input, #settings-backup select, ' +
            '#settings-storage input, #settings-storage select, ' +
            '#settings-notifications input, #settings-notifications select, ' +
            '#settings-security input, #settings-security select, ' +
            '#settings-api input, #settings-api select');

        inputs.forEach(input => {
            input.addEventListener('change', () => this.markDirty());
            input.addEventListener('input', () => this.markDirty());
        });
    }

    markDirty() {
        this.isDirty = true;
        this.updateSaveAllButton();
        this.updateS3ButtonStates();
        this.updateOIDCButtonStates();
    }

    updateSaveAllButton() {
        const saveAllBtn = document.querySelector('button[onclick="window.vnbui.saveAllSettings()"]');
        if (saveAllBtn) {
            saveAllBtn.disabled = !this.isDirty;
            if (!this.isDirty) {
                saveAllBtn.classList.add('btn-secondary');
                saveAllBtn.classList.remove('btn-primary');
            } else {
                saveAllBtn.classList.remove('btn-secondary');
                saveAllBtn.classList.add('btn-primary');
            }
        }
    }

    /**
     * Check if S3 required fields are filled
     */
    isS3ConfigValid() {
        const storageType = document.getElementById('setting-v3-storage-type')?.value;
        if (storageType !== 's3') return false;

        const bucket = document.getElementById('setting-v3-s3-bucket')?.value?.trim();
        const accessKeyStatus = this.v3Secrets['storage.s3.access_key'];
        const secretKeyStatus = this.v3Secrets['storage.s3.secret_key'];
        const accessKeyInput = document.getElementById('setting-v3-s3-access-key')?.value?.trim();
        const secretKeyInput = document.getElementById('setting-v3-s3-secret-key')?.value?.trim();

        const hasAccessKey = accessKeyStatus?.configured || accessKeyInput;
        const hasSecretKey = secretKeyStatus?.configured || secretKeyInput;

        return bucket && hasAccessKey && hasSecretKey;
    }

    isS3ConfigSaved() {
        const savedType = this.v3Settings['storage.type'];
        if (savedType !== 's3') return false;

        const savedBucket = this.v3Settings['storage.s3.bucket'];
        const accessKeySaved = this.v3Secrets['storage.s3.access_key']?.configured;
        const secretKeySaved = this.v3Secrets['storage.s3.secret_key']?.configured;

        return savedBucket && accessKeySaved && secretKeySaved;
    }

    updateS3ButtonStates() {
        const testBtn = document.getElementById('btn-test-s3');
        const saveBtn = document.getElementById('btn-save-storage');
        const isValid = this.isS3ConfigValid();
        const isSaved = this.isS3ConfigSaved();
        const storageType = document.getElementById('setting-v3-storage-type')?.value;

        if (testBtn) {
            testBtn.disabled = !isSaved;
            testBtn.title = isSaved ? window.t('experience.test_s3') : window.t('experience.save_s3_first');
        }
        if (saveBtn) {
            // Save is enabled if storage type is local OR S3 config is valid
            const canSave = storageType === 'local' || isValid;
            saveBtn.disabled = !canSave;
            saveBtn.title = canSave ? window.t('experience.save_storage') : window.t('experience.required_s3');
        }
    }

    /**
     * Check if OIDC required fields are filled
     */
    isOIDCConfigValid() {
        const enabled = document.getElementById('setting-v3-oidc-enabled')?.checked;
        if (!enabled) return false;

        const issuer = document.getElementById('setting-v3-oidc-issuer')?.value?.trim();
        const clientId = document.getElementById('setting-v3-oidc-client-id')?.value?.trim();
        const clientSecretStatus = this.v3Secrets['oidc.client_secret'];
        const clientSecretInput = document.getElementById('setting-v3-oidc-client-secret')?.value?.trim();

        const hasClientSecret = clientSecretStatus?.configured ||
            (clientSecretInput && !/^[*•]+$/.test(clientSecretInput));
        const scopes = document.getElementById('setting-v3-oidc-scopes')?.value?.trim().split(/\s+/) || [];
        const role = document.getElementById('setting-v3-oidc-default-role')?.value;
        return this.isOIDCDiscoveryValid() && !!clientId && !!hasClientSecret &&
            scopes.includes('openid') && scopes.every(scope => /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope)) &&
            ['viewer', 'operator'].includes(role);
    }

    isOIDCDiscoveryValid() {
        try {
            const url = new URL(document.getElementById('setting-v3-oidc-issuer')?.value?.trim());
            return url.protocol === 'https:' && !!url.hostname && !url.username && !url.password && !url.search && !url.hash;
        } catch { return false; }
    }

    isOIDCTestValid() {
        const role = document.getElementById('setting-v3-oidc-default-role')?.value;
        const legacyDefault = !['viewer', 'operator'].includes(this.v3Settings['oidc.default_role'] || 'viewer');
        return ['viewer', 'operator'].includes(role) && this.isOIDCDiscoveryValid() &&
            (!legacyDefault || this.isOIDCConfigValid());
    }

    updateOIDCButtonStates() {
        const testBtn = document.getElementById('btn-test-oidc');
        const saveBtn = document.getElementById('btn-save-oidc');
        const isValid = this.isOIDCConfigValid();
        const enabled = document.getElementById('setting-v3-oidc-enabled')?.checked;

        const supportedRole = ['viewer', 'operator'].includes(
            document.getElementById('setting-v3-oidc-default-role')?.value);
        if (testBtn) {
            testBtn.disabled = !this.isOIDCTestValid();
            testBtn.title = 'Test issuer discovery only; client credentials are not tested';
        }
        if (saveBtn) {
            // Save is enabled if OIDC is disabled OR config is valid
            const canSave = supportedRole && (!enabled || isValid);
            saveBtn.disabled = !canSave;
            saveBtn.title = canSave ? 'Save OIDC settings' : 'Fill in required OIDC fields first';
        }
        const disabledSave = document.getElementById('btn-save-disabled-oidc');
        if (disabledSave) disabledSave.disabled = !supportedRole;
    }

    async saveAllSettings() {
        try {
            // Collect all form values
            const settingsData = {
                // General settings
                log_level: document.getElementById('setting-log-level')?.value,
                maintenance_mode: document.getElementById('setting-maintenance-mode')?.checked,

                // Backup settings
                default_retention_days: parseInt(document.getElementById('setting-default-retention')?.value),
                max_concurrent_backups: parseInt(document.getElementById('setting-concurrent-backups')?.value),
                sustained_failure_threshold: parseInt(document.getElementById('setting-sustained-failure-threshold')?.value),
                compression_level: document.getElementById('setting-compression')?.value,
                auto_cleanup: document.getElementById('setting-auto-cleanup')?.checked,
                retention_hour: parseInt(document.getElementById('setting-retention-hour')?.value),

                // Storage settings
                storage_backend: document.getElementById('setting-storage-backend')?.value,
                backup_storage_path: document.getElementById('setting-storage-path')?.value,
                min_free_space_gb: parseInt(document.getElementById('setting-min-free-space')?.value),

                // Notification settings
                email_enabled: document.getElementById('setting-email-enabled')?.checked,
                smtp_server: document.getElementById('setting-smtp-server')?.value,
                smtp_port: parseInt(document.getElementById('setting-smtp-port')?.value),
                smtp_from: document.getElementById('setting-smtp-from')?.value,
                notification_recipients: document.getElementById('setting-notification-emails')?.value,
                notify_on_success: document.getElementById('setting-notify-success')?.checked,
                notify_on_failure: document.getElementById('setting-notify-failure')?.checked,
                notify_agent_offline: document.getElementById('setting-notify-agent-offline')?.checked,

                // Security settings
                session_timeout_minutes: parseInt(document.getElementById('setting-session-timeout')?.value),
                password_min_length: parseInt(document.getElementById('setting-password-min-length')?.value),
                require_password_complexity: document.getElementById('setting-require-password-complexity')?.checked,
                force_password_change: document.getElementById('setting-force-password-change')?.checked,
                max_login_attempts: parseInt(document.getElementById('setting-max-login-attempts')?.value),
                audit_logging: document.getElementById('setting-audit-logging')?.checked,

                // API settings
                rate_limit_per_minute: parseInt(document.getElementById('setting-rate-limit')?.value),
                cors_origins: document.getElementById('setting-cors-origins')?.value,
                api_docs_enabled: document.getElementById('setting-api-docs-enabled')?.checked,

                // Health monitoring thresholds
                health_storage_free_gb: parseFloat(document.getElementById('setting-health-storage-gb')?.value),
                health_storage_free_percent: parseFloat(document.getElementById('setting-health-storage-percent')?.value),
                health_load_percent: parseFloat(document.getElementById('setting-health-load-percent')?.value)
            };

            // Remove undefined/null values
            Object.keys(settingsData).forEach(key => {
                if (settingsData[key] === undefined || settingsData[key] === null ||
                    (typeof settingsData[key] === 'number' && isNaN(settingsData[key]))) {
                    delete settingsData[key];
                }
            });

            await apiClient.put('/api/v1/settings', settingsData);

            // Show success toast
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.settings_saved'), 'success');
            }

            // Reload after delay
            setTimeout(() => window.location.reload(), 2000);
        } catch (error) {
            console.error('Failed to save settings:', error);
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.settings_save_failed', {error: error.message}), 'error');
            }
        }
    }

    async loadData() {
        this.loading = true;
        try {
            const data = await apiClient.get('/api/v1/settings');
            this.settings = data.settings || {};
        } catch (error) {
            console.error('Failed to load settings:', error);
            this.settings = {};
        }
        this.loading = false;
    }

    async loadAPIKeys() {
        try {
            const [orchKeys, regKeys] = await Promise.all([
                apiClient.get('/api/v1/orchestrator-keys'),
                apiClient.get('/api/v1/registration-keys')
            ]);
            this.orchestratorKeys = orchKeys.items || [];
            this.registrationKeys = regKeys.items || [];
        } catch (error) {
            console.error('Failed to load API keys:', error);
        }
    }

    async loadVersionInfo() {
        try {
            this.versionInfo = await apiClient.get('/api/v1/version');
        } catch (error) {
            console.error('Failed to load version:', error);
            this.versionInfo = { version: 'unknown', service: 'vesta-api' };
        }
    }

    async loadCompatibility() {
        try {
            this.compatibilityInfo = await apiClient.checkCompatibility();
        } catch (error) {
            console.error('Failed to load compatibility:', error);
            this.compatibilityInfo = null;
        }
    }

    async loadV3Settings() {
        this.v3Loaded = false;
        try {
            const data = await apiClient.get('/api/v1/settings/v3');
            this.v3Settings = data.settings || {};
            this.v3Secrets = data.secrets || {};
            this.encryptionConfigured = data.encryption_configured || false;
            this.v3Loaded = data.settings !== null && typeof data.settings === 'object' &&
                !Array.isArray(data.settings) &&
                Object.prototype.hasOwnProperty.call(data.settings, 'backup.capacity_admission') &&
                Object.prototype.hasOwnProperty.call(data.settings, 'backup.admission_pause');
        } catch (error) {
            console.error('Failed to load v3 settings:', error);
            this.v3Settings = {};
            this.v3Secrets = {};
            this.encryptionConfigured = false;
        }
    }

    async saveV3Settings() {
        try {
            const settingsData = {
                // Storage settings
                'storage.type': document.getElementById('setting-v3-storage-type')?.value,
                'storage.s3.endpoint': document.getElementById('setting-v3-s3-endpoint')?.value,
                'storage.s3.bucket': document.getElementById('setting-v3-s3-bucket')?.value,
                'storage.s3.region': document.getElementById('setting-v3-s3-region')?.value,
                'storage.s3.prefix': document.getElementById('setting-v3-s3-prefix')?.value,
            };

            // Include secrets only if provided (non-empty)
            const accessKey = document.getElementById('setting-v3-s3-access-key')?.value;
            const secretKey = document.getElementById('setting-v3-s3-secret-key')?.value;

            if (accessKey) {
                settingsData['storage.s3.access_key'] = accessKey;
            }
            if (secretKey) {
                settingsData['storage.s3.secret_key'] = secretKey;
            }

            // Remove undefined/null/empty values
            Object.keys(settingsData).forEach(key => {
                if (settingsData[key] === undefined || settingsData[key] === null ||
                    (typeof settingsData[key] === 'string' && settingsData[key] === '')) {
                    delete settingsData[key];
                }
            });

            await apiClient.put('/api/v1/settings/v3', settingsData);

            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.storage_saved'), 'success');
            }

            // Reload v3 settings to refresh secret status
            await this.loadV3Settings();
            // Re-render storage section
            const storagePane = document.getElementById('settings-storage');
            if (storagePane) {
                storagePane.innerHTML = this.renderStorageSettings();
                // Re-attach dirty tracking and update button states on new DOM
                setTimeout(() => {
                    this.setupDirtyTracking();
                    this.updateS3ButtonStates();
                }, 100);
            }

            // Propose S3 discovery if storage type is S3
            if (settingsData['storage.type'] === 's3') {
                this.checkS3Discovery();
            }
        } catch (error) {
            console.error('Failed to save v3 settings:', error);
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.storage_save_failed', {error: error.message}), 'error');
            }
        }
    }

    async checkS3Discovery() {
        try {
            const data = await apiClient.get('/api/v1/s3/discover');
            const importable = (data.chains || []).filter(c => c.status === 'available' || c.status === 'partial');
            if (importable.length === 0) return;

            const t = window.t;
            // Remove any existing discovery banner
            document.getElementById('s3-discovery-banner')?.remove();

            const banner = document.createElement('div');
            banner.id = 's3-discovery-banner';
            banner.className = 'alert alert-info alert-dismissible fade show mt-3';
            banner.innerHTML = `
                ${t('s3_import.settings_discovery', { count: importable.length })}
                <a href="#" onclick="window.vnbui.navigate('/backups'); return false;" class="alert-link ms-1">${t('s3_import.settings_discovery_link')} →</a>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;

            const storagePane = document.getElementById('settings-storage');
            if (storagePane) {
                storagePane.appendChild(banner);
            }
        } catch (e) {
            // Silent — don't break save flow
        }
    }

    async testS3Connection() {
        const btn = document.getElementById('btn-test-s3');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>${window.t('settings.s3_testing')}`;
        }

        try {
            const result = await apiClient.post('/api/v1/settings/test-s3', {});

            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.s3_test_success', {bucket: result.bucket}), 'success');
            }
        } catch (error) {
            console.error('S3 test failed:', error);
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.s3_test_failed', {error: error.message}), 'error');
            }
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10" /></svg>${window.t('settings.test_connection')}`;
            }
        }
    }

    afterRender() { return this.licensingPanel.mount(); }

    destroy() { this.licensingPanel.destroy(); }

    async render() {
        await authService.requireInstallationAccess();
        await this.loadData();
        await this.loadAPIKeys();
        await this.loadVersionInfo();
        await this.loadCompatibility();
        await this.loadV3Settings();
        await this.loadEncryptionKeys();
        await this.loadPKIStatus();
        const t = window.t;

        // Restore previously active tab (if any)
        const savedTab = sessionStorage.getItem('activeSettingsTab');
        if (savedTab) {
            sessionStorage.removeItem('activeSettingsTab');  // Clear after use
            // Will restore tab after render via setTimeout
            setTimeout(() => {
                const tabTrigger = document.querySelector(`a[href="${savedTab}"]`);
                if (tabTrigger) {
                    new bootstrap.Tab(tabTrigger).show();
                }
            }, 100);
        }

        // Setup dirty tracking and button states after DOM render
        setTimeout(() => {
            this.setupDirtyTracking();
            this.updateS3ButtonStates();
            this.updateOIDCButtonStates();
        }, 200);

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z" />
                                    <circle cx="12" cy="12" r="3" />
                                </svg>
                                ${t('settings.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('settings.page_subtitle')}</div>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
                            <div class="btn-list">
                                <button class="btn btn-secondary d-none d-sm-inline-block" disabled onclick="window.vnbui.saveAllSettings()" title="Make changes to enable">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <path d="M6 4h10l4 4v10a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2" />
                                        <circle cx="12" cy="14" r="2" />
                                        <polyline points="14 4 14 8 8 8 8 4" />
                                    </svg>
                                    ${t('settings.save_all')}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    <div class="row row-cards">
                        <!-- Settings Navigation -->
                        <div class="col-lg-2">
                            <div class="card">
                                <div class="card-body">
                                    <div class="nav flex-column nav-pills" role="tablist">
                                        <a class="nav-link active" data-bs-toggle="pill" href="#settings-general" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <polyline points="12 3 20 7.5 20 16.5 12 21 4 16.5 4 7.5 12 3" />
                                                <line x1="12" y1="12" x2="20" y2="7.5" />
                                                <line x1="12" y1="12" x2="12" y2="21" />
                                                <line x1="12" y1="12" x2="4" y2="7.5" />
                                            </svg>
                                            ${t('settings.tab_general')}
                                        </a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-backup" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <ellipse cx="12" cy="6" rx="8" ry="3"></ellipse>
                                                <path d="M4 6v6a8 3 0 0 0 16 0v-6" />
                                                <path d="M4 12v6a8 3 0 0 0 16 0v-6" />
                                            </svg>
                                            ${t('settings.tab_backup')}
                                        </a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-storage" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <path d="M4 6h16v-1a1 1 0 0 0 -1 -1h-14a1 1 0 0 0 -1 1v1z" />
                                                <path d="M4 6v6a1 1 0 0 0 1 1h14a1 1 0 0 0 1 -1v-6" />
                                                <path d="M4 12v6a1 1 0 0 0 1 1h14a1 1 0 0 0 1 -1v-6" />
                                            </svg>
                                            ${t('settings.tab_storage')}
                                        </a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-notifications" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <path d="M10 5a2 2 0 0 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6" />
                                                <path d="M9 17v1a3 3 0 0 0 6 0v-1" />
                                            </svg>
                                            ${t('settings.tab_notifications')}
                                        </a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-security" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" />
                                            </svg>
                                            ${t('settings.tab_security')}
                                        </a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-encryption" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <rect x="5" y="11" width="14" height="10" rx="2" />
                                                <circle cx="12" cy="16" r="1" />
                                                <path d="M8 11v-4a4 4 0 0 1 8 0v4" />
                                            </svg>
                                            ${t('settings.tab_encryption')}
                                        </a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-certificates" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <circle cx="15" cy="15" r="3" />
                                                <path d="M13 17.5v4.5l2 -1.5l2 1.5v-4.5" />
                                                <path d="M10 19h-5a2 2 0 0 1 -2 -2v-10c0 -1.1 .9 -2 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -1 1.73" />
                                                <line x1="6" y1="9" x2="18" y2="9" />
                                                <line x1="6" y1="12" x2="9" y2="12" />
                                                <line x1="6" y1="15" x2="8" y2="15" />
                                            </svg>
                                            ${t('settings.tab_certificates')}
                                        </a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-licensing" role="tab"><i class="ti ti-license icon me-2" aria-hidden="true"></i>${t('licensing.title')}</a>
                                        <a class="nav-link" data-bs-toggle="pill" href="#settings-api" role="tab">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                <rect x="3" y="5" width="18" height="14" rx="2" />
                                                <line x1="7" y1="10" x2="7.01" y2="10" />
                                                <line x1="11" y1="10" x2="11.01" y2="10" />
                                            </svg>
                                            ${t('settings.tab_api')}
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Settings Content -->
                        <div class="col-lg-10">
                            <div class="tab-content">
                                <!-- General Settings -->
                                <div class="tab-pane fade show active" id="settings-general" role="tabpanel">
                                    ${this.renderGeneralSettings()}
                                </div>

                                <!-- Backup Settings -->
                                <div class="tab-pane fade" id="settings-backup" role="tabpanel">
                                    ${this.renderBackupSettings()}
                                </div>

                                <!-- Storage Settings -->
                                <div class="tab-pane fade" id="settings-storage" role="tabpanel">
                                    ${this.renderStorageSettings()}
                                </div>

                                <!-- Notification Settings -->
                                <div class="tab-pane fade" id="settings-notifications" role="tabpanel">
                                    ${this.renderNotificationSettings()}
                                </div>

                                <!-- Security Settings -->
                                <div class="tab-pane fade" id="settings-security" role="tabpanel">
                                    ${this.renderSecuritySettings()}
                                </div>

                                <!-- Encryption Settings -->
                                <div class="tab-pane fade" id="settings-encryption" role="tabpanel">
                                    ${this.renderEncryptionSettings()}
                                </div>

                                <!-- Certificates Settings (mTLS) -->
                                <div class="tab-pane fade" id="settings-certificates" role="tabpanel">
                                    ${this.renderCertificatesSettings()}
                                </div>

                                <div class="tab-pane fade" id="settings-licensing" role="tabpanel">${this.licensingPanel.render()}</div>

                                <!-- API Settings -->
                                <div class="tab-pane fade" id="settings-api" role="tabpanel">
                                    ${this.renderAPISettings()}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // ── Encryption Key Management ─────────────────────────────────────────

    async loadEncryptionKeys() {
        try {
            const [keysData, providerData] = await Promise.all([
                apiClient.get('/api/v1/encryption/keys'),
                apiClient.get('/api/v1/encryption/provider'),
            ]);
            this.encryptionKeys = keysData.items || [];
            this.encryptionProvider = providerData;
        } catch (error) {
            console.error('Failed to load encryption keys:', error);
            this.encryptionKeys = [];
            this.encryptionProvider = { provider: 'local', error: error.message };
        }
    }

    renderEncryptionSettings() {
        const t = window.t;
        const provider = this.encryptionProvider || {};
        const keys = this.encryptionKeys || [];
        const notBackedUp = keys.filter(k => !k.backed_up && k.status !== 'revoked').length;

        const warningBanner = notBackedUp > 0 ? `
            <div class="alert alert-warning mb-3">
                <div class="d-flex align-items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" class="icon alert-icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                        <path d="M12 9v2m0 4v.01" />
                        <path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.84 2.75" />
                    </svg>
                    <div>
                        <strong>${notBackedUp} ${t('settings.keys_not_backed_up')}</strong>
                        ${t('settings.export_warning')}
                    </div>
                </div>
            </div>` : '';

        const errorBanner = provider.error ? `
            <div class="alert alert-danger mb-3">
                <strong>${t('settings.kms_error')}</strong> ${escapeHtml(provider.error)}
            </div>` : '';

        const keyRows = keys.length === 0 ? `
            <tr>
                <td colspan="7" class="text-center text-secondary py-4">
                    ${t('settings.no_keys_msg')}
                </td>
            </tr>` : keys.map(key => this.renderEncryptionKeyRow(key)).join('');

        const supportsExport = provider.supports_export !== false;

        return `
            ${warningBanner}
            ${errorBanner}
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.kms_provider')}</h3>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-4">
                            <label class="form-label text-secondary small">${t('settings.provider')}</label>
                            <div class="fw-bold">${t('settings.provider_local')}</div>
                            <div class="text-secondary small mt-1">${t('settings.provider_local_desc')}</div>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label text-secondary small">${t('settings.active_key')}</label>
                            <div class="fw-bold">${provider.active_key ? escapeHtml(provider.active_key.name) : `<span class="text-secondary">${t('common.na')}</span>`}</div>
                            ${provider.active_key ? `<div class="text-secondary small mt-1">Hash: ${escapeHtml(provider.active_key.key_hash)}</div>` : ''}
                        </div>
                        <div class="col-md-4">
                            <label class="form-label text-secondary small">${t('settings.total_keys')}</label>
                            <div class="fw-bold">${provider.total_keys || 0}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.encryption_keys')}</h3>
                    <div class="card-actions">
                        ${supportsExport ? `
                        <button class="btn btn-outline-secondary btn-sm me-2" onclick="window.vnbui.importEncryptionKeys()" title="Import keys from file">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-1" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <path d="M14 3v4a1 1 0 0 0 1 1h4" />
                                <path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z" />
                                <path d="M12 11v6" />
                                <path d="M9.5 13.5l2.5 -2.5l2.5 2.5" />
                            </svg>
                            ${t('settings.import_btn')}
                        </button>
                        <button class="btn btn-outline-secondary btn-sm me-2" onclick="window.vnbui.exportEncryptionKeys()" ${keys.length === 0 ? 'disabled' : ''} title="Export all keys to file">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-1" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <path d="M14 3v4a1 1 0 0 0 1 1h4" />
                                <path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z" />
                                <path d="M12 17v-6" />
                                <path d="M9.5 14.5l2.5 2.5l2.5 -2.5" />
                            </svg>
                            ${t('settings.export_btn')}
                        </button>
                        <button class="btn btn-outline-secondary btn-sm me-2" onclick="window.vnbui.confirmEncryptionExport()" title="${t('settings.confirm_export_btn')}">
                            ${t('settings.confirm_export_btn')}
                        </button>
                        ` : ''}
                        <button class="btn btn-primary btn-sm" onclick="window.vnbui.createEncryptionKey()">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon me-1" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <line x1="12" y1="5" x2="12" y2="19" />
                                <line x1="5" y1="12" x2="19" y2="12" />
                            </svg>
                            ${t('settings.create_key')}
                        </button>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-vcenter card-table">
                        <thead>
                            <tr>
                                <th>${t('settings.key_name')}</th>
                                <th>${t('settings.key_status')}</th>
                                <th>${t('settings.key_algorithm')}</th>
                                <th>${t('settings.key_created')}</th>
                                <th>${t('settings.key_backed_up')}</th>
                                <th>${t('settings.key_backups')}</th>
                                <th>${t('common.actions')}</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${keyRows}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    renderEncryptionKeyRow(key) {
        const t = window.t;
        const statusBadge = {
            'active': `<span class="badge bg-green">${t('settings.key_active')}</span>`,
            'rotated': `<span class="badge bg-yellow">${t('settings.key_rotated')}</span>`,
            'revoked': `<span class="badge bg-red">${t('settings.key_revoked')}</span>`,
        }[key.status] || `<span class="badge">${escapeHtml(key.status)}</span>`;

        const createdAt = key.created_at ? new Date(key.created_at).toLocaleDateString() : '-';
        const backedUpIcon = key.backed_up
            ? '<svg xmlns="http://www.w3.org/2000/svg" class="icon text-green" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10" /></svg>'
            : '<svg xmlns="http://www.w3.org/2000/svg" class="icon text-yellow" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 9v2m0 4v.01" /><path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.84 2.75" /></svg>';

        const canRotate = key.status === 'active';
        const canRevoke = key.status !== 'revoked' && key.backup_count === 0;

        return `
            <tr>
                <td>
                    <div class="fw-bold">${escapeHtml(key.name)}</div>
                    <div class="text-secondary small">${escapeHtml(key.key_hash)}</div>
                </td>
                <td>${statusBadge}</td>
                <td class="text-secondary">${escapeHtml(key.algorithm)}</td>
                <td class="text-secondary">${createdAt}</td>
                <td>${backedUpIcon}</td>
                <td>${key.backup_count || 0}</td>
                <td>
                    <div class="btn-group btn-group-sm" role="group">
                        ${canRotate ? `
                        <button class="btn" onclick="window.vnbui.rotateEncryptionKey('${key.id}')" title="${t('settings.rotate_key')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4" /><path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4" /></svg>
                        </button>` : ''}
                        ${canRevoke ? `
                        <button class="btn" onclick="window.vnbui.revokeEncryptionKey('${key.id}')" title="${t('settings.revoke_key')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon text-danger" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                        </button>` : ''}
                    </div>
                </td>
            </tr>
        `;
    }

    async createEncryptionKey() {
        const name = prompt(window.t('settings.create_key_prompt'));
        if (!name || !name.trim()) return;

        try {
            const result = await apiClient.post('/api/v1/encryption/keys', { name: name.trim() });
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.create_key_success'), 'success');
            }
            // Reload encryption data and re-render tab
            await this.loadEncryptionKeys();
            const tabContent = document.getElementById('settings-encryption');
            if (tabContent) tabContent.innerHTML = this.renderEncryptionSettings();
            apiClient.acknowledge(result);
        } catch (error) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(error.operatorRecovery ? error.message : window.t('settings.create_key_error', {error: error.message}), 'error');
            }
        }
    }

    async rotateEncryptionKey(keyId) {
        const newName = prompt(window.t('settings.rotate_key_prompt'));
        if (!newName || !newName.trim()) return;

        try {
            const result = await apiClient.post(`/api/v1/encryption/keys/${keyId}/rotate`, { new_name: newName.trim() });
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.rotate_key_success'), 'success');
            }
            await this.loadEncryptionKeys();
            const tabContent = document.getElementById('settings-encryption');
            if (tabContent) tabContent.innerHTML = this.renderEncryptionSettings();
            apiClient.acknowledge(result);
        } catch (error) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(error.operatorRecovery ? error.message : window.t('settings.rotate_key_error', {error: error.message}), 'error');
            }
        }
    }

    async revokeEncryptionKey(keyId) {
        if (!confirm(window.t('settings.revoke_confirm'))) return;

        try {
            await apiClient.post(`/api/v1/encryption/keys/${keyId}/revoke`);
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.revoke_success'), 'success');
            }
            await this.loadEncryptionKeys();
            const tabContent = document.getElementById('settings-encryption');
            if (tabContent) tabContent.innerHTML = this.renderEncryptionSettings();
        } catch (error) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.revoke_error', {error: error.message}), 'error');
            }
        }
    }

    async exportEncryptionKeys() {
        const password = prompt(window.t('settings.export_password'));
        if (!password || password.length < 8) {
            if (password !== null) {
                if (window.vnbui && window.vnbui.showToast) {
                    window.vnbui.showToast(window.t('settings.export_password_error'), 'error');
                }
            }
            return;
        }

        try {
            const keyIds = this.encryptionKeys.filter(k => k.status !== 'revoked').map(k => k.id);
            if (keyIds.length === 0) {
                if (window.vnbui && window.vnbui.showToast) {
                    window.vnbui.showToast(window.t('settings.export_no_keys'), 'warning');
                }
                return;
            }

            const blob = await apiClient.postForBlob('/api/v1/encryption/keys/export', {
                key_ids: keyIds, password
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vesta-keys-${new Date().toISOString().split('T')[0]}.bin`;
            a.click();
            URL.revokeObjectURL(url);

            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.export_success', {count: keyIds.length}), 'success');
            }
        } catch (error) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.export_error', {error: error.message}), 'error');
            }
        }
    }

    async confirmEncryptionExport() {
        const password = prompt(window.t('settings.import_password'));
        if (!password) return;
        const location = prompt(window.t('settings.confirm_export_location'));
        if (!location || !location.trim()) return;

        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.bin';
        fileInput.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            try {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('password', password);
                formData.append('location', location.trim());
                const result = await apiClient.upload('/api/v1/encryption/keys/confirm-export', formData);
                if (window.vnbui && window.vnbui.showToast) {
                    window.vnbui.showToast(window.t('settings.confirm_export_success', {count: result.key_ids.length}), 'success');
                }
                await this.loadEncryptionKeys();
                const tabContent = document.getElementById('settings-encryption');
                if (tabContent) tabContent.innerHTML = this.renderEncryptionSettings();
            } catch (error) {
                if (window.vnbui && window.vnbui.showToast) {
                    window.vnbui.showToast(window.t('settings.confirm_export_error', {error: error.message}), 'error');
                }
            }
        };
        fileInput.click();
    }

    async importEncryptionKeys() {
        const password = prompt(window.t('settings.import_password'));
        if (!password) return;

        // Create file input
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.bin';
        fileInput.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            try {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('password', password);

                const response = await apiClient.upload('/api/v1/encryption/keys/import', formData);
                if (window.vnbui && window.vnbui.showToast) {
                    window.vnbui.showToast(window.t('settings.import_success', {count: response.count}), 'success');
                }
                await this.loadEncryptionKeys();
                const tabContent = document.getElementById('settings-encryption');
                if (tabContent) tabContent.innerHTML = this.renderEncryptionSettings();
            } catch (error) {
                if (window.vnbui && window.vnbui.showToast) {
                    window.vnbui.showToast(window.t('settings.import_error', {error: error.message}), 'error');
                }
            }
        };
        fileInput.click();
    }

    // ── PKI / Certificates (mTLS) ─────────────────────────────────────────

    async loadPKIStatus() {
        try {
            const [statusData, certsData] = await Promise.all([
                apiClient.get('/api/v1/pki/status').catch(() => ({ initialized: false })),
                apiClient.get('/api/v1/pki/certificates').catch(() => ({ items: [] })),
            ]);
            this.pkiStatus = statusData;
            this.pkiCertificates = certsData.items || [];
        } catch (error) {
            console.error('Failed to load PKI status:', error);
            this.pkiStatus = { initialized: false };
            this.pkiCertificates = [];
        }
    }

    renderCertificatesSettings() {
        const t = window.t;
        const pki = this.pkiStatus || {};
        const certs = this.pkiCertificates || [];

        const statusBadge = pki.initialized
            ? `<span class="badge bg-green">${t('settings.ca_initialized')}</span>`
            : `<span class="badge bg-secondary">${t('settings.ca_not_initialized')}</span>`;

        const caInfo = pki.ca || {};
        const caDetails = pki.initialized ? `
            <div class="datagrid">
                <div class="datagrid-item">
                    <div class="datagrid-title">${t('settings.ca_subject')}</div>
                    <div class="datagrid-content">${escapeHtml(caInfo.subject || '')}</div>
                </div>
                <div class="datagrid-item">
                    <div class="datagrid-title">${t('settings.ca_fingerprint')}</div>
                    <div class="datagrid-content"><code>${escapeHtml((caInfo.fingerprint || '').substring(0, 16))}...</code></div>
                </div>
                <div class="datagrid-item">
                    <div class="datagrid-title">${t('settings.ca_expires')}</div>
                    <div class="datagrid-content">${caInfo.not_after ? new Date(caInfo.not_after).toLocaleDateString() : t('common.na')}</div>
                </div>
                <div class="datagrid-item">
                    <div class="datagrid-title">${t('settings.ca_issued_certs')}</div>
                    <div class="datagrid-content">${pki.certificates?.total || 0} (${pki.certificates?.active || 0} active)</div>
                </div>
            </div>
        ` : '';

        const certRows = certs.length === 0 ? `<tr>
                <td colspan="6" class="text-center text-secondary">
                    ${t('settings.no_certs_msg')}
                </td>
            </tr>` : certs.map(cert => {
            const statusClass = cert.status === 'active' ? 'bg-green' :
                cert.status === 'revoked' ? 'bg-red' : 'bg-yellow';
            const expiringBadge = cert.expiring_soon ? ` <span class="badge bg-yellow">${t('settings.expiring_soon')}</span>` : '';
            return `<tr>
                <td>${escapeHtml(cert.common_name || '')}</td>
                <td><code>${escapeHtml((cert.fingerprint || '').substring(0, 16))}...</code></td>
                <td>${cert.issued_at ? new Date(cert.issued_at).toLocaleDateString() : t('common.na')}</td>
                <td>${cert.expires_at ? new Date(cert.expires_at).toLocaleDateString() : t('common.na')}</td>
                <td><span class="badge ${statusClass}">${cert.status}</span>${expiringBadge}</td>
                <td>
                    ${cert.status === 'active' ? `
                        <button class="btn btn-sm" onclick="window.vnbui.revokePKICert('${cert.id}')" title="${t('settings.revoke_cert')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                            </svg>
                        </button>
                    ` : ''}
                </td>
            </tr>`;
        }).join('');

        return `
            <!-- CA Status Card -->
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.ca_title')}</h3>
                    <div class="card-actions">
                        ${pki.initialized ? `
                            <a href="/api/v1/pki/ca" class="btn btn-outline-secondary btn-sm me-2" download="vesta-ca.crt" title="Download CA certificate">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2" /><polyline points="7 11 12 16 17 11" /><line x1="12" y1="4" x2="12" y2="16" />
                                </svg>
                                ${t('settings.download_ca')}
                            </a>
                        ` : `
                            <button class="btn btn-primary btn-sm" onclick="window.vnbui.initializeCA()">
                                ${t('settings.initialize_ca')}
                            </button>
                        `}
                    </div>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <strong>${t('common.status')}:</strong> ${statusBadge}
                    </div>
                    ${caDetails}
                    ${!pki.initialized ? `
                        <div class="alert alert-info">
                            ${t('settings.ca_not_init_msg')}
                        </div>
                    ` : ''}
                </div>
            </div>

            <!-- Certificates Table -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.issued_certs')}</h3>
                </div>
                <div class="table-responsive">
                    <table class="table table-vcenter card-table">
                        <thead>
                            <tr>
                                <th>${t('settings.cert_hostname')}</th>
                                <th>${t('settings.cert_fingerprint')}</th>
                                <th>${t('settings.cert_issued')}</th>
                                <th>${t('settings.cert_expires')}</th>
                                <th>${t('settings.cert_status')}</th>
                                <th>${t('common.actions')}</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${certRows}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    async initializeCA() {
        if (!confirm(window.t('settings.init_ca_confirm'))) return;
        try {
            await apiClient.post('/api/v1/pki/initialize');
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.init_ca_success'), 'success');
            }
            await this.loadPKIStatus();
            const tabContent = document.getElementById('settings-certificates');
            if (tabContent) tabContent.innerHTML = this.renderCertificatesSettings();
        } catch (error) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.init_ca_error', {error: error.message}), 'error');
            }
        }
    }

    async revokePKICert(certId) {
        if (!confirm(window.t('settings.revoke_cert_confirm'))) return;
        try {
            await apiClient.post(`/api/v1/pki/certificates/${certId}/revoke`);
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.revoke_cert_success'), 'success');
            }
            await this.loadPKIStatus();
            const tabContent = document.getElementById('settings-certificates');
            if (tabContent) tabContent.innerHTML = this.renderCertificatesSettings();
        } catch (error) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.revoke_cert_error', {error: error.message}), 'error');
            }
        }
    }

    renderGeneralSettings() {
        const t = window.t;
        const frontendVersion = window.vnbui?.version || '2.0.0';
        const backendVersion = this.versionInfo?.version || t('common.loading');
        const buildDate = this.versionInfo?.build_date || t('common.unknown');

        return `
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.system_info')}</h3>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label text-secondary small">${t('settings.backend_version')}</label>
                                <div class="h4">${escapeHtml(backendVersion)}</div>
                                <div class="text-secondary small">${t('settings.build')}: ${escapeHtml(buildDate)}</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label text-secondary small">${t('settings.frontend_version')}</label>
                                <div class="h4">${escapeHtml(frontendVersion)}</div>
                                <div class="text-secondary small">${t('settings.spa_note')}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.renderCompatibilityCard()}

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.general_settings')}</h3>
                </div>
                <div class="card-body">
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.log_level')}</label>
                        <div class="col-sm-8">
                            <select class="form-select" id="setting-log-level">
                                <option value="DEBUG" ${this.settings.log_level === 'DEBUG' ? 'selected' : ''}>${t('settings.log_debug')}</option>
                                <option value="INFO" ${this.settings.log_level === 'INFO' || !this.settings.log_level ? 'selected' : ''}>${t('settings.log_info')}</option>
                                <option value="WARNING" ${this.settings.log_level === 'WARNING' ? 'selected' : ''}>${t('settings.log_warning')}</option>
                                <option value="ERROR" ${this.settings.log_level === 'ERROR' ? 'selected' : ''}>${t('settings.log_error')}</option>
                            </select>
                            <div class="form-hint">${t('settings.log_level_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <label class="form-check">
                                <input type="checkbox" class="form-check-input" id="setting-maintenance-mode" ${this.settings.maintenance_mode ? 'checked' : ''}>
                                <span class="form-check-label">${t('settings.maintenance_mode')}</span>
                            </label>
                            <div class="form-hint">${t('settings.maintenance_hint')}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card mt-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.health_thresholds')}</h3>
                </div>
                <div class="card-body">
                    <p class="text-secondary mb-3">${t('settings.health_thresholds_desc')}</p>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.storage_free_gb')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-health-storage-gb" value="${this.settings.health_storage_free_gb || 10}" min="1" max="1000" step="1">
                            <div class="form-hint">${t('settings.storage_free_gb_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.storage_free_pct')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-health-storage-percent" value="${this.settings.health_storage_free_percent || 10}" min="1" max="50" step="1">
                            <div class="form-hint">${t('settings.storage_free_pct_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.load_avg_pct')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-health-load-percent" value="${this.settings.health_load_percent || 80}" min="50" max="200" step="5">
                            <div class="form-hint">${t('settings.load_avg_pct_hint')}</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderCompatibilityCard() {
        const t = window.t;
        if (!this.compatibilityInfo) {
            return `
                <div class="card mb-3">
                    <div class="card-header">
                        <h3 class="card-title">${t('settings.compatibility')}</h3>
                    </div>
                    <div class="card-body text-secondary">
                        <i class="ti ti-loader me-2"></i>${t('settings.compat_loading')}
                    </div>
                </div>
            `;
        }

        const compat = this.compatibilityInfo;
        const statusBadge = {
            aligned: `<span class="badge bg-success">${t('settings.compat_aligned')}</span>`,
            degraded: `<span class="badge bg-warning">${t('settings.compat_degraded')}</span>`,
            incompatible: `<span class="badge bg-danger">${t('settings.compat_incompatible')}</span>`
        }[compat.status] || `<span class="badge bg-secondary">${t('common.unknown')}</span>`;

        // Build agents table
        const agents = compat.agents || [];
        const agentsHtml = agents.length > 0 ? `
            <div class="table-responsive mt-3">
                <table class="table table-vcenter table-sm">
                    <thead>
                        <tr>
                            <th>${t('settings.compat_agent')}</th>
                            <th>${t('settings.compat_version')}</th>
                            <th>${t('common.status')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${agents.map(agent => {
                            const agentBadge = agent.compatible
                                ? `<span class="badge bg-success">${t('settings.compat_ok')}</span>`
                                : `<span class="badge bg-warning">${t('settings.compat_mismatch')}</span>`;
                            return `
                                <tr>
                                    <td>${escapeHtml(agent.hostname || t('common.unknown'))}</td>
                                    <td><code>${escapeHtml(agent.version || t('common.na'))}</code></td>
                                    <td>${agentBadge}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        ` : `<p class="text-secondary mt-3">${compat.status === 'unverified' ? 'Inventory unavailable; alignment unverified.' : 'No online agents in this organization; offline agents are not assessed.'}</p>`;

        // Build warnings list
        const warnings = compat.warnings || [];
        const warningsHtml = warnings.length > 0 ? `
            <div class="alert alert-warning mt-3 mb-0">
                <h4 class="alert-title">${t('settings.compat_warnings')}</h4>
                <ul class="mb-0">
                    ${warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
                </ul>
            </div>
        ` : '';

        const apiVersion = compat.api?.version || t('common.na');

        return `
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.compatibility')} (organization online agents)</h3>
                    <div class="card-actions">
                        ${statusBadge}
                    </div>
                </div>
                <div class="card-body">
                    <div class="row mb-2">
                        <div class="col-4"><strong>${t('settings.compat_api_version')}</strong></div>
                        <div class="col-8"><code>${escapeHtml(apiVersion)}</code></div>
                    </div>
                    <div class="row mb-2">
                        <div class="col-4"><strong>${t('settings.compat_expected')}</strong></div>
                        <div class="col-8"><code>${escapeHtml(compat.expected_version || t('common.na'))}</code></div>
                    </div>
                    ${agentsHtml}
                    ${warningsHtml}
                </div>
            </div>
        `;
    }

    admissionPolicy() {
        const policy = this.v3Settings['backup.capacity_admission'];
        if (policy === null || policy === undefined) return null;
        if (typeof policy !== 'object' || Array.isArray(policy) || Object.keys(policy).length !== 4 ||
            policy.schema !== 1 || !Number.isSafeInteger(policy.revision) || policy.revision < 1 ||
            !Number.isSafeInteger(policy.limit) || policy.limit < 1 || policy.limit > 100000 ||
            typeof policy.maintenance !== 'boolean') return undefined;
        return policy;
    }

    admissionPausePolicy() {
        const policy = this.v3Settings['backup.admission_pause'];
        if (policy === null) return null;
        if (!policy || typeof policy !== 'object' || Array.isArray(policy) || Object.keys(policy).length !== 3 ||
            policy.schema !== 1 || !Number.isSafeInteger(policy.revision) || policy.revision < 1 ||
            typeof policy.paused !== 'boolean') return undefined;
        return policy;
    }

    renderAdmissionSettings() {
        const t = window.t;
        const policy = this.admissionPolicy();
        const pause = this.admissionPausePolicy();
        const available = this.v3Loaded && policy !== undefined && pause !== undefined;
        return `
            <div class="card mb-3">
                <div class="card-header"><h3 class="card-title">${t('settings.admission_title')}</h3></div>
                <div class="card-body">
                    <p class="form-hint">${t('settings.admission_hint')}</p>
                    <label class="form-label" for="setting-admission-limit">${t('settings.admission_limit')}</label>
                    <input class="form-control mb-2" id="setting-admission-limit" type="number" min="1" max="100000"
                        value="${policy?.limit ?? 1}" ${available ? '' : 'disabled'}>
                    <label class="form-check mb-2">
                        <input class="form-check-input" id="setting-admission-paused" type="checkbox"
                            ${pause?.paused ? 'checked' : ''} ${available ? '' : 'disabled'}>
                        <span class="form-check-label">${t('settings.admission_paused')}</span>
                    </label>
                    <label class="form-check mb-2">
                        <input class="form-check-input" id="setting-admission-maintenance" type="checkbox"
                            ${policy?.maintenance !== false ? 'checked' : ''} ${available ? '' : 'disabled'}>
                        <span class="form-check-label">${t('settings.admission_maintenance')}</span>
                    </label>
                    <p class="form-hint">${t('settings.admission_maintenance_hint')}</p>
                    <button class="btn btn-outline-primary" id="save-admission-policy" ${available ? '' : 'disabled'}
                        onclick="window.vnbui.currentPage.saveAdmissionPolicy()">${t('settings.admission_save')}</button>
                    <span class="text-secondary ms-2" id="admission-policy-result" role="status">${available ? '' : t('settings.admission_unavailable')}</span>
                </div>
            </div>
        `;
    }

    async saveAdmissionPolicy() {
        if (this.admissionSaving || !this.v3Loaded) return;
        const prior = this.admissionPolicy();
        const priorPause = this.admissionPausePolicy();
        const limitText = document.getElementById('setting-admission-limit')?.value?.trim();
        const limit = Number(limitText);
        const paused = document.getElementById('setting-admission-paused');
        const maintenanceInput = document.getElementById('setting-admission-maintenance');
        const result = document.getElementById('admission-policy-result');
        if (prior === undefined || priorPause === undefined || !/^\d+$/.test(limitText || '') || !Number.isSafeInteger(limit) ||
            limit < 1 || limit > 100000 || !paused || !maintenanceInput ||
            (prior && !Number.isSafeInteger(prior.revision + 1)) ||
            (priorPause && !Number.isSafeInteger(priorPause.revision + 1))) {
            if (result) result.textContent = window.t('settings.admission_invalid');
            return;
        }
        const maintenance = maintenanceInput.checked;
        if ((!maintenance && prior?.maintenance !== false || !paused.checked && priorPause?.paused === true) &&
            !window.confirm(window.t('settings.admission_enable_confirm'))) return;
        if (maintenance && prior?.maintenance === false &&
            !window.confirm(window.t('settings.admission_maintenance_confirm'))) return;
        const policy = prior && prior.limit === limit && prior.maintenance === maintenance ? prior :
            {schema: 1, revision: (prior?.revision ?? 0) + 1, limit, maintenance};
        const pause = priorPause && priorPause.paused === paused.checked ? priorPause :
            {schema: 1, revision: (priorPause?.revision ?? 0) + 1, paused: paused.checked};
        const button = document.getElementById('save-admission-policy');
        this.admissionSaving = true;
        if (button) button.disabled = true;
        try {
            // This operation is separate from Save Settings. No automatic retry
            // or rebase after a concurrent edit/lost response.
            await apiClient.put('/api/v1/settings/v3', {
                'backup.capacity_admission': policy, 'backup.admission_pause': pause,
            });
            this.v3Settings['backup.capacity_admission'] = policy;
            this.v3Settings['backup.admission_pause'] = pause;
            if (result) result.textContent = window.t('settings.admission_saved');
        } catch {
            this.v3Loaded = false; // Refresh before another write; outcome may be unknown.
            if (result) result.textContent = window.t('settings.admission_save_failed');
        } finally {
            this.admissionSaving = false;
            if (button) button.disabled = !this.v3Loaded;
        }
    }

    renderBackupSettings() {
        const t = window.t;
        return `
            ${this.renderAdmissionSettings()}
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.backup_settings')}</h3>
                </div>
                <div class="card-body">
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.default_retention')} ${contextHelp('retention')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-default-retention" value="${this.settings.default_retention_days || 30}" min="1" max="365">
                            <div class="form-hint">${t('settings.default_retention_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.concurrent_backups')} ${contextHelp('concurrency')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-concurrent-backups" value="${this.settings.max_concurrent_backups || 3}" min="1" max="10">
                            <div class="form-hint">${t('settings.concurrent_backups_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.sustained_failure_threshold')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-sustained-failure-threshold" value="${this.settings.sustained_failure_threshold ?? 3}" min="0" max="100">
                            <div class="form-hint">${t('settings.sustained_failure_threshold_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.compression_level')}</label>
                        <div class="col-sm-8">
                            <select class="form-select" id="setting-compression">
                                <option value="none" ${this.settings.compression_level === 'none' ? 'selected' : ''}>${t('settings.compression_none')}</option>
                                <option value="fast" ${this.settings.compression_level === 'fast' ? 'selected' : ''}>${t('settings.compression_fast')}</option>
                                <option value="balanced" ${this.settings.compression_level === 'balanced' ? 'selected' : ''}>${t('settings.compression_balanced')}</option>
                                <option value="maximum" ${this.settings.compression_level === 'maximum' ? 'selected' : ''}>${t('settings.compression_maximum')}</option>
                            </select>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <div class="form-hint" id="backup-verification-manual">${t('settings.backup_verification_manual')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <label class="form-check">
                                <input type="checkbox" class="form-check-input" id="setting-auto-cleanup" ${this.settings.auto_cleanup === true ? 'checked' : ''}>
                                <span class="form-check-label">${t('settings.auto_cleanup')}</span>
                            </label>
                            <div class="form-hint">${t('settings.auto_cleanup_hint')}</div>
                        </div>
                    </div>
                    ${this.settings.auto_cleanup === true ? '' : `
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <div class="alert alert-warning mb-0 py-2" role="alert">
                                <i class="ti ti-player-pause me-1"></i>${t('settings.retention_paused')}
                            </div>
                        </div>
                    </div>`}
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.retention_hour')}</label>
                        <div class="col-sm-8">
                            <select class="form-select" id="setting-retention-hour">
                                ${Array.from({ length: 24 }, (_, h) => `<option value="${h}" ${(this.settings.retention_hour ?? 3) === h ? 'selected' : ''}>${String(h).padStart(2, '0')}:00</option>`).join('')}
                            </select>
                            <div class="form-hint">${t('settings.retention_hour_hint')}</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderStorageSettings() {
        const t = window.t;
        const storageType = 's3';
        const isS3 = storageType === 's3';

        // Secret status indicators
        const accessKeyStatus = this.v3Secrets['storage.s3.access_key'];
        const secretKeyStatus = this.v3Secrets['storage.s3.secret_key'];

        const accessKeyBadge = accessKeyStatus?.configured
            ? `<span class="badge bg-success ms-2">${accessKeyStatus.source === 'env' ? 'ENV' : t('experience.saved')}</span>`
            : `<span class="badge bg-secondary ms-2">${t('common.not_configured')}</span>`;
        const secretKeyBadge = secretKeyStatus?.configured
            ? `<span class="badge bg-success ms-2">${secretKeyStatus.source === 'env' ? 'ENV' : t('experience.saved')}</span>`
            : `<span class="badge bg-secondary ms-2">${t('common.not_configured')}</span>`;

        const encryptionWarning = !this.encryptionConfigured
            ? `<div class="alert alert-warning mb-3">
                <svg xmlns="http://www.w3.org/2000/svg" class="icon alert-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 9v2m0 4v.01" /><path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75" /></svg>
                <div class="alert-content">
                    <strong>${t('settings.encryption_warning')}</strong> ${t('settings.encryption_warning_desc')}
                    <br><small class="text-secondary">${t('settings.encryption_warning_env')}</small>
                </div>
            </div>`
            : '';

        return `
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.storage_backend')}</h3>
                </div>
                <div class="card-body">
                    ${encryptionWarning}
                    ${this.v3Settings['storage.type'] && this.v3Settings['storage.type'] !== 's3' ? `<div class="alert alert-warning">${t('experience.legacy_destination')}</div>` : ''}
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.storage_type')} ${contextHelp('storage')}</label>
                        <div class="col-sm-8">
                            <select class="form-select" id="setting-v3-storage-type" onchange="window.vnbui.toggleS3Settings()">

                                <option value="s3" ${storageType === 's3' ? 'selected' : ''}>${t('settings.storage_s3')}</option>
                            </select>
                            <div class="form-hint">${t('settings.storage_type_hint')}</div>
                        </div>
                    </div>

                    <div class="alert alert-info">${t('agents.shared_destination')}</div>
                    <!-- S3 Configuration (shown when S3 selected) -->
                    <div id="s3-settings" style="display: ${isS3 ? 'block' : 'none'}">
                        <hr class="my-4">
                        <h4 class="mb-3">${t('settings.s3_config')}</h4>

                        <div class="row">
                            <div class="col-md-8">
                                <div class="mb-3">
                                    <label class="form-label">${t('settings.s3_endpoint')}</label>
                                    <input type="text" class="form-control font-monospace" id="setting-v3-s3-endpoint"
                                        value="${escapeHtml(this.v3Settings['storage.s3.endpoint'] || '')}"
                                        placeholder="${t('settings.s3_endpoint_placeholder')}">
                                    <div class="form-hint">${t('settings.s3_endpoint_hint')}</div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label class="form-label">${t('settings.s3_region')}</label>
                                    <input type="text" class="form-control" id="setting-v3-s3-region"
                                        value="${escapeHtml(this.v3Settings['storage.s3.region'] || 'us-east-1')}"
                                        placeholder="us-east-1">
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-8">
                                <div class="mb-3">
                                    <label class="form-label">${t('settings.s3_bucket')}</label>
                                    <input type="text" class="form-control" id="setting-v3-s3-bucket"
                                        value="${escapeHtml(this.v3Settings['storage.s3.bucket'] || '')}"
                                        placeholder="${t('settings.s3_bucket_placeholder')}">
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="mb-3">
                                    <label class="form-label">${t('settings.s3_prefix')}</label>
                                    <input type="text" class="form-control" id="setting-v3-s3-prefix"
                                        value="${escapeHtml(this.v3Settings['storage.s3.prefix'] || 'backups')}"
                                        placeholder="${t('settings.s3_prefix_placeholder')}">
                                    <div class="form-hint">${t('settings.s3_prefix_hint')}</div>
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">${t('settings.s3_access_key')} ${accessKeyBadge}</label>
                                    <input type="text" class="form-control font-monospace" id="setting-v3-s3-access-key"
                                        placeholder="${accessKeyStatus?.configured ? t('experience.keep_existing') : t('settings.s3_access_key_placeholder')}">
                                    <div class="form-hint">${t('settings.s3_access_key_hint')}</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label class="form-label">${t('settings.s3_secret_key')} ${secretKeyBadge}</label>
                                    <input type="password" class="form-control font-monospace" id="setting-v3-s3-secret-key"
                                        placeholder="${secretKeyStatus?.configured ? t('experience.keep_existing') : t('settings.s3_secret_key_placeholder')}">
                                </div>
                            </div>
                        </div>

                        <!-- Action buttons at bottom of S3 section -->
                        <div class="mt-4 d-flex gap-2">
                            <button class="btn btn-outline-primary" id="btn-test-s3" onclick="window.vnbui.testS3Connection()" disabled title="${t('experience.required_s3')}">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10" /></svg>
                                ${t('settings.test_connection')}
                            </button>
                            <button class="btn btn-primary" id="btn-save-storage" onclick="window.vnbui.saveV3Settings()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M6 4h10l4 4v10a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2" /><circle cx="12" cy="14" r="2" /><polyline points="14 4 14 8 8 8 8 4" /></svg>
                                ${t('settings.save_storage')}
                            </button>
                        </div>
                    </div>

                </div>
            </div>

            <!-- Storage Thresholds -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.storage_thresholds')}</h3>
                </div>
                <div class="card-body">
                    <p class="text-secondary mb-3">${t('settings.storage_thresholds_desc')}</p>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.min_free_space')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-min-free-space" value="${this.settings.min_free_space_gb || 50}" min="1">
                            <div class="form-hint">${t('settings.min_free_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.retention_policy')}</label>
                        <div class="col-sm-8">
                            <div class="form-control-plaintext">${t('experience.remote_retention', {days: this.settings.default_retention_days || 30})}</div>
                            <div class="form-hint">${t('experience.remote_retention_hint')}</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    toggleS3Settings() {
        const storageType = document.getElementById('setting-v3-storage-type')?.value;
        const s3Settings = document.getElementById('s3-settings');
        const localSaveBtn = document.getElementById('local-save-btn');
        const isS3 = storageType === 's3';

        if (s3Settings) {
            s3Settings.style.display = isS3 ? 'block' : 'none';
        }
        if (localSaveBtn) {
            localSaveBtn.style.display = isS3 ? 'none' : 'block';
        }

        this.updateS3ButtonStates();
    }

    toggleDeleteLocalDays() {
        const mode = document.getElementById('setting-v3-s3-delete-local-mode')?.value;
        const daysDiv = document.getElementById('delete-local-days-setting');
        if (daysDiv) {
            daysDiv.style.display = mode === 'delayed' ? 'block' : 'none';
        }
    }

    renderNotificationSettings() {
        const t = window.t;
        return `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.notif_settings')}</h3>
                </div>
                <div class="card-body">
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <label class="form-check">
                                <input type="checkbox" class="form-check-input" id="setting-email-enabled" ${this.settings.email_enabled ? 'checked' : ''}>
                                <span class="form-check-label">${t('settings.notif_email_enable')}</span>
                            </label>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.smtp_server')}</label>
                        <div class="col-sm-8">
                            <input type="text" class="form-control" id="setting-smtp-server" value="${escapeHtml(this.settings.smtp_server || '')}" placeholder="${t('settings.smtp_server_placeholder')}">
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.smtp_port')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-smtp-port" value="${this.settings.smtp_port || 587}" min="1" max="65535">
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.from_email')}</label>
                        <div class="col-sm-8">
                            <input type="email" class="form-control" id="setting-smtp-from" value="${escapeHtml(this.settings.smtp_from || '')}" placeholder="${t('settings.from_email_placeholder')}">
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.notif_recipients')}</label>
                        <div class="col-sm-8">
                            <input type="text" class="form-control" id="setting-notification-emails" value="${escapeHtml(this.settings.notification_recipients || '')}" placeholder="${t('settings.notif_recipients_placeholder')}">
                            <div class="form-hint">${t('settings.recipients_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.notify_on')}</label>
                        <div class="col-sm-8">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="setting-notify-success" ${this.settings.notify_on_success ? 'checked' : ''}>
                                <label class="form-check-label" for="setting-notify-success">${t('settings.notify_backup_success')}</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="setting-notify-failure" ${this.settings.notify_on_failure !== false ? 'checked' : ''}>
                                <label class="form-check-label" for="setting-notify-failure">${t('settings.notify_backup_failure')}</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="setting-notify-agent-offline" ${this.settings.notify_agent_offline ? 'checked' : ''}>
                                <label class="form-check-label" for="setting-notify-agent-offline">${t('settings.notify_agent_offline')}</label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderSecuritySettings() {
        const t = window.t;
        const oidcEnabled = this.v3Settings['oidc.enabled'] || false;
        const clientSecretStatus = this.v3Secrets['oidc.client_secret'];
        const clientSecretBadge = clientSecretStatus?.configured
            ? `<span class="badge bg-success ms-2">${clientSecretStatus.source === 'env' ? 'ENV' : t('experience.saved')}</span>`
            : `<span class="badge bg-secondary ms-2">${t('common.not_configured')}</span>`;

        return `
            <!-- OIDC / SSO Settings (v3.0) - FIRST for better UX -->
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.sso_title')}</h3>
                </div>
                <div class="card-body">
                    <p class="text-secondary mb-3">${t('settings.oidc_desc')}</p>

                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <label class="form-check">
                                <input type="checkbox" class="form-check-input" id="setting-v3-oidc-enabled"
                                    ${oidcEnabled ? 'checked' : ''}
                                    onchange="window.vnbui.toggleOIDCSettings()">
                                <span class="form-check-label">${t('settings.enable_oidc')}</span>
                            </label>
                        </div>
                    </div>

                    <div id="oidc-settings" style="display: ${oidcEnabled ? 'block' : 'none'}">
                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.issuer_url')}</label>
                            <div class="col-sm-8">
                                <input type="text" class="form-control font-monospace" id="setting-v3-oidc-issuer"
                                    value="${escapeHtml(this.v3Settings['oidc.issuer'] || '')}"
                                    placeholder="${t('settings.issuer_placeholder')}">
                                <div class="form-hint">${t('settings.issuer_hint')}</div>
                            </div>
                        </div>

                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.client_id')}</label>
                            <div class="col-sm-8">
                                <input type="text" class="form-control" id="setting-v3-oidc-client-id"
                                    value="${escapeHtml(this.v3Settings['oidc.client_id'] || '')}"
                                    placeholder="${t('settings.client_id_placeholder')}">
                            </div>
                        </div>

                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.client_secret')} ${clientSecretBadge}</label>
                            <div class="col-sm-8">
                                <input type="password" class="form-control font-monospace" id="setting-v3-oidc-client-secret"
                                    placeholder="${clientSecretStatus?.configured ? t('experience.keep_existing') : t('settings.client_secret_placeholder')}">
                            </div>
                        </div>

                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.scopes')}</label>
                            <div class="col-sm-8">
                                <input type="text" class="form-control" id="setting-v3-oidc-scopes"
                                    value="${escapeHtml(this.v3Settings['oidc.scopes'] || 'openid profile email')}"
                                    placeholder="${t('settings.scopes_placeholder')}">
                                <div class="form-hint">${t('settings.scopes_hint')}</div>
                            </div>
                        </div>

                        <hr class="my-3">
                        <h4 class="mb-3">${t('settings.role_mapping')}</h4>
                        <p class="text-secondary small mb-3">${t('settings.role_mapping_desc')}</p>

                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.role_claim')}</label>
                            <div class="col-sm-8">
                                <input type="text" class="form-control" id="setting-v3-oidc-role-claim"
                                    value="${escapeHtml(this.v3Settings['oidc.role_claim'] || '')}"
                                    placeholder="${t('settings.role_claim_placeholder')}">
                                <div class="form-hint">${t('settings.role_claim_hint')}</div>
                            </div>
                        </div>

                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.admin_values')}</label>
                            <div class="col-sm-8">
                                <input type="text" class="form-control" id="setting-v3-oidc-admin-values"
                                    value="${escapeHtml(this.v3Settings['oidc.admin_values'] || '')}"
                                    placeholder="${t('settings.admin_placeholder')}">
                                <div class="form-hint">${t('settings.admin_hint')}</div>
                            </div>
                        </div>

                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.operator_values')}</label>
                            <div class="col-sm-8">
                                <input type="text" class="form-control" id="setting-v3-oidc-operator-values"
                                    value="${escapeHtml(this.v3Settings['oidc.operator_values'] || '')}"
                                    placeholder="${t('settings.operator_placeholder')}">
                                <div class="form-hint">${t('settings.operator_hint')}</div>
                            </div>
                        </div>

                        <div class="mb-3 row">
                            <label class="col-form-label col-sm-4">${t('settings.default_role')}</label>
                            <div class="col-sm-8">
                                <select class="form-select" id="setting-v3-oidc-default-role">
                                    ${!['viewer', 'operator'].includes(this.v3Settings['oidc.default_role'] || 'viewer') ? '<option value="" selected disabled>Unsupported persisted default role; select viewer or operator to repair</option>' : ''}
                                    <option value="viewer" ${(this.v3Settings['oidc.default_role'] || 'viewer') === 'viewer' ? 'selected' : ''}>${t('settings.default_viewer')}</option>
                                    <option value="operator" ${this.v3Settings['oidc.default_role'] === 'operator' ? 'selected' : ''}>${t('settings.default_operator')}</option>
                                </select>
                                <div class="form-hint">${t('settings.default_role_hint')}</div>
                            </div>
                        </div>

                        <!-- OIDC Test Result Display -->
                        <div id="oidc-test-result" class="mb-3" style="display: none;"></div>

                        <!-- Action buttons at bottom of OIDC section -->
                        <div class="mt-4 d-flex gap-2">
                            <button class="btn btn-outline-primary" id="btn-test-oidc" onclick="window.vnbui.testOIDCConfiguration()" disabled title="Issuer discovery only; client credentials are not tested">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10" /></svg>
                                ${t('settings.test_oidc')}
                            </button>
                            <button class="btn btn-primary" id="btn-save-oidc" onclick="window.vnbui.saveOIDCSettings()" disabled>
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M6 4h10l4 4v10a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2" /><circle cx="12" cy="14" r="2" /><polyline points="14 4 14 8 8 8 8 4" /></svg>
                                ${t('settings.save_oidc')}
                            </button>
                        </div>
                    </div>

                    <!-- Save button when OIDC is disabled -->
                    <div id="oidc-disabled-save" style="display: ${oidcEnabled ? 'none' : 'block'}">
                        <div class="mt-3">
                            <button class="btn btn-primary" id="btn-save-disabled-oidc" onclick="window.vnbui.saveOIDCSettings()" disabled>
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M6 4h10l4 4v10a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2" /><circle cx="12" cy="14" r="2" /><polyline points="14 4 14 8 8 8 8 4" /></svg>
                                ${t('settings.save_oidc')}
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Password & Session Security -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.security_settings')}</h3>
                </div>
                <div class="card-body">
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.session_timeout')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-session-timeout" value="${this.settings.session_timeout_minutes || 60}" min="5" max="1440">
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.password_min_length')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-password-min-length" value="${this.settings.password_min_length || 8}" min="8" max="32">
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <label class="form-check">
                                <input type="checkbox" class="form-check-input" id="setting-require-password-complexity" ${this.settings.require_password_complexity !== false ? 'checked' : ''}>
                                <span class="form-check-label">${t('settings.require_complexity')}</span>
                            </label>
                            <div class="form-hint">${t('settings.complexity_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <label class="form-check">
                                <input type="checkbox" class="form-check-input" id="setting-force-password-change" ${this.settings.force_password_change ? 'checked' : ''}>
                                <span class="form-check-label">${t('settings.force_change')}</span>
                            </label>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <label class="col-form-label col-sm-4">${t('settings.failed_attempts')}</label>
                        <div class="col-sm-8">
                            <input type="number" class="form-control" id="setting-max-login-attempts" value="${this.settings.max_login_attempts || 5}" min="3" max="10">
                            <div class="form-hint">${t('settings.failed_attempts_hint')}</div>
                        </div>
                    </div>
                    <div class="mb-3 row">
                        <div class="col-sm-8 offset-sm-4">
                            <label class="form-check">
                                <input type="checkbox" class="form-check-input" id="setting-audit-logging" ${this.settings.audit_logging !== false ? 'checked' : ''}>
                                <span class="form-check-label">${t('settings.audit_logging')}</span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    async saveOIDCSettings() {
        try {
            if (document.getElementById('setting-v3-oidc-enabled')?.checked && !this.isOIDCConfigValid()) {
                throw new Error('Invalid OIDC configuration');
            }
            const settingsData = {
                'oidc.enabled': document.getElementById('setting-v3-oidc-enabled')?.checked,
                'oidc.issuer': document.getElementById('setting-v3-oidc-issuer')?.value,
                'oidc.client_id': document.getElementById('setting-v3-oidc-client-id')?.value,
                'oidc.scopes': document.getElementById('setting-v3-oidc-scopes')?.value,
                'oidc.role_claim': document.getElementById('setting-v3-oidc-role-claim')?.value,
                'oidc.admin_values': document.getElementById('setting-v3-oidc-admin-values')?.value,
                'oidc.operator_values': document.getElementById('setting-v3-oidc-operator-values')?.value,
                'oidc.default_role': document.getElementById('setting-v3-oidc-default-role')?.value,
            };

            // Include secret only if provided
            const clientSecret = document.getElementById('setting-v3-oidc-client-secret')?.value;
            if (clientSecret?.trim() && !/^[*•]+$/.test(clientSecret.trim())) {
                settingsData['oidc.client_secret'] = clientSecret.trim();
            }
            for (const key of Object.keys(settingsData)) {
                if (typeof settingsData[key] === 'string') settingsData[key] = settingsData[key].trim();
            }
            settingsData['oidc.scopes'] = [...new Set(settingsData['oidc.scopes'].split(/\s+/))].join(' ');
            if (!['viewer', 'operator'].includes(settingsData['oidc.default_role']) ||
                !settingsData['oidc.scopes'].split(' ').includes('openid') ||
                !settingsData['oidc.scopes'].split(' ').every(scope => /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))) {
                throw new Error('Invalid OIDC role or scopes');
            }

            await apiClient.put('/api/v1/settings/v3', settingsData);

            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(window.t('settings.oidc_saved'), 'success');
            }

            // Reload to refresh secret status
            await this.loadV3Settings();
            const securityPane = document.getElementById('settings-security');
            if (securityPane) {
                securityPane.innerHTML = this.renderSecuritySettings();
                this.setupDirtyTracking();
                this.updateOIDCButtonStates();
            }
        } catch (error) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast('Unable to save OIDC settings', 'error');
            }
        }
    }

    toggleOIDCSettings() {
        const oidcEnabled = document.getElementById('setting-v3-oidc-enabled')?.checked;
        const oidcSettings = document.getElementById('oidc-settings');
        const oidcDisabledSave = document.getElementById('oidc-disabled-save');

        if (oidcSettings) {
            oidcSettings.style.display = oidcEnabled ? 'block' : 'none';
        }
        if (oidcDisabledSave) {
            oidcDisabledSave.style.display = oidcEnabled ? 'none' : 'block';
        }

        this.updateOIDCButtonStates();
    }

    async testOIDCConfiguration() {
        const btn = document.getElementById('btn-test-oidc');
        const resultDiv = document.getElementById('oidc-test-result');
        if (btn) btn.disabled = true;
        let message = 'OIDC discovery failed';
        try {
            if (!this.isOIDCTestValid()) {
                throw new Error('Invalid OIDC configuration');
            }
            const issuer = document.getElementById('setting-v3-oidc-issuer').value.trim();
            const result = await apiClient.post('/api/v1/auth/oidc/test', {issuer});
            if (result.check !== 'discovery_only' || result.credentials_verified !== false) {
                throw new Error('Unexpected discovery response');
            }
            message = 'Issuer discovery verified. Client credentials were not tested.';
        } catch {
            // Do not expose provider bodies, URLs, or transport error details.
        } finally {
            if (resultDiv) {
                resultDiv.style.display = 'block';
                resultDiv.textContent = message;
            }
            if (btn) btn.textContent = 'Test issuer discovery';
            this.updateOIDCButtonStates();
        }
    }

    renderAPISettings() {
        const t = window.t;
        return `
            <!-- Orchestrator API Keys -->
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.orch_api_keys')}</h3>
                    <div class="card-actions">
                        <button class="btn btn-primary btn-sm" onclick="window.vnbui.createOrchestratorKey()">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
                            ${t('common.new_key')}
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <p class="text-secondary mb-3">${t('settings.orch_keys_desc')}</p>
                    ${this.renderOrchestratorKeysTable()}
                </div>
            </div>

            <!-- Agent Registration Keys -->
            <div class="card mb-3">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.reg_keys_title')}</h3>
                    <div class="card-actions">
                        <button class="btn btn-primary btn-sm" onclick="window.vnbui.createRegistrationKey()">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
                            ${t('common.new_key')}
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <p class="text-secondary mb-3">${t('settings.reg_keys_desc')}</p>
                    ${this.renderRegistrationKeysTable()}
                </div>
            </div>

            <!-- API Integration Settings -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('settings.api_settings')}</h3>
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <label class="form-label">${t('settings.rate_limiting')}</label>
                        <input type="number" class="form-control" id="setting-rate-limit" value="${this.settings.rate_limit_per_minute || 100}" min="10" max="1000">
                        <div class="form-hint">${t('settings.rate_limit_hint')}</div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">${t('settings.cors_origins')}</label>
                        <input type="text" class="form-control" id="setting-cors-origins" value="${escapeHtml(this.settings.cors_origins || 'http://localhost:3000')}" placeholder="${t('settings.cors_placeholder')}">
                        <div class="form-hint">${t('settings.cors_hint')}</div>
                    </div>
                    <div class="mb-3">
                        <label class="form-check">
                            <input type="checkbox" class="form-check-input" id="setting-api-docs-enabled" ${this.settings.api_docs_enabled !== false ? 'checked' : ''}>
                            <span class="form-check-label">${t('settings.api_docs_enable')}</span>
                        </label>
                    </div>
                </div>
            </div>
        `;
    }

    renderOrchestratorKeysTable() {
        const t = window.t;
        if (!this.orchestratorKeys.length) {
            return `
                <div class="empty">
                    <p class="empty-title">${t('settings.no_orch_keys')}</p>
                    <p class="empty-subtitle text-secondary">${t('settings.no_orch_keys_desc')}</p>
                </div>
            `;
        }

        return `
            <div class="table-responsive">
                <table class="table table-vcenter card-table">
                    <thead>
                        <tr>
                            <th>${t('common.name')}</th>
                            <th>${t('settings.key_prefix')}</th>
                            <th>${t('common.status')}</th>
                            <th>${t('settings.key_expires')}</th>
                            <th>${t('settings.key_last_used')}</th>
                            <th class="w-1"></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.orchestratorKeys.map(key => this.renderOrchestratorKeyRow(key)).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    renderOrchestratorKeyRow(key) {
        const t = window.t;
        const statusBadge = key.is_valid
            ? `<span class="badge bg-success">${t('settings.key_valid')}</span>`
            : key.is_expired
                ? `<span class="badge bg-danger">${t('settings.key_expired')}</span>`
                : `<span class="badge bg-secondary">${t('settings.key_disabled')}</span>`;

        const expiresText = key.expires_at
            ? new Date(key.expires_at).toLocaleDateString()
            : `<span class="text-secondary">${t('common.never')}</span>`;

        const lastUsedText = key.last_used_at
            ? new Date(key.last_used_at).toLocaleString()
            : `<span class="text-secondary">${t('common.never')}</span>`;

        return `
            <tr>
                <td>${escapeHtml(key.name)}</td>
                <td><code>${escapeHtml(key.key_prefix)}...</code></td>
                <td>${statusBadge}</td>
                <td>${expiresText}</td>
                <td class="text-secondary">${lastUsedText}</td>
                <td>
                    <div class="btn-group btn-group-sm" role="group">
                        <button class="btn" onclick="window.vnbui.editOrchestratorKey('${key.id}')" title="Edit">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M4 20h4l10.5 -10.5a1.5 1.5 0 0 0 -4 -4l-10.5 10.5v4" /><line x1="13.5" y1="6.5" x2="17.5" y2="10.5" /></svg>
                        </button>
                        <button class="btn" onclick="window.vnbui.deleteOrchestratorKey('${key.id}', '${escapeHtml(key.name)}')" title="Delete">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon text-danger" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><line x1="4" y1="7" x2="20" y2="7" /><line x1="10" y1="11" x2="10" y2="17" /><line x1="14" y1="11" x2="14" y2="17" /><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12" /><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3" /></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }

    renderRegistrationKeysTable() {
        const t = window.t;
        if (!this.registrationKeys.length) {
            return `
                <div class="empty">
                    <p class="empty-title">${t('settings.no_reg_keys')}</p>
                    <p class="empty-subtitle text-secondary">${t('settings.no_reg_keys_desc')}</p>
                </div>
            `;
        }

        return `
            <div class="table-responsive">
                <table class="table table-vcenter card-table">
                    <thead>
                        <tr>
                            <th>${t('common.name')}</th>
                            <th>${t('settings.key_prefix')}</th>
                            <th>${t('common.status')}</th>
                            <th>${t('settings.key_uses')}</th>
                            <th>${t('settings.key_expires')}</th>
                            <th>${t('settings.key_last_used')}</th>
                            <th class="w-1"></th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.registrationKeys.map(key => this.renderRegistrationKeyRow(key)).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    renderRegistrationKeyRow(key) {
        const t = window.t;
        const statusBadge = key.is_valid
            ? `<span class="badge bg-success">${t('settings.key_valid')}</span>`
            : key.is_expired
                ? `<span class="badge bg-danger">${t('settings.key_expired')}</span>`
                : key.is_max_uses_reached
                    ? `<span class="badge bg-warning">${t('settings.key_max_uses')}</span>`
                    : `<span class="badge bg-secondary">${t('settings.key_disabled')}</span>`;

        const usesText = key.max_uses
            ? `${key.use_count}/${key.max_uses}`
            : `${key.use_count}`;

        const expiresText = key.expires_at
            ? new Date(key.expires_at).toLocaleDateString()
            : `<span class="text-secondary">${t('common.never')}</span>`;

        const lastUsedText = key.last_used_at
            ? new Date(key.last_used_at).toLocaleString()
            : `<span class="text-secondary">${t('common.never')}</span>`;

        return `
            <tr>
                <td>${escapeHtml(key.name)}<br><small>${escapeHtml(key.agent_hostname || 'Unscoped — disabled')}</small></td>
                <td><code>${escapeHtml(key.key_prefix)}...</code></td>
                <td>${statusBadge}</td>
                <td>${usesText}</td>
                <td>${expiresText}</td>
                <td class="text-secondary">${lastUsedText}</td>
                <td>
                    <div class="btn-group btn-group-sm" role="group">
                        <button class="btn" onclick="window.vnbui.editRegistrationKey('${key.id}')" title="Edit">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M4 20h4l10.5 -10.5a1.5 1.5 0 0 0 -4 -4l-10.5 10.5v4" /><line x1="13.5" y1="6.5" x2="17.5" y2="10.5" /></svg>
                        </button>
                        <button class="btn" onclick="window.vnbui.deleteRegistrationKey('${key.id}', '${escapeHtml(key.name)}')" title="Delete">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon text-danger" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><line x1="4" y1="7" x2="20" y2="7" /><line x1="10" y1="11" x2="10" y2="17" /><line x1="14" y1="11" x2="14" y2="17" /><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12" /><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3" /></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }
}
