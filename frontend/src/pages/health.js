import { enumLabel } from '../utils/status-labels.js';
/**
 * Health Page
 * System health monitoring and diagnostics
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { getStatusColor } from '../utils/status-colors.js';
import { authService } from '../services/auth.service.js';

export class HealthPage {
    constructor() {
        this.health = {};
        this.loading = false;
        this.diagnosticsDownloading = false;
    }

    async downloadDiagnostics(button) {
        if (this.diagnosticsDownloading) return;
        this.diagnosticsDownloading = true;
        button.disabled = true;
        const error = document.getElementById('health-diagnostics-error');
        if (error) error.textContent = '';
        try {
            await apiClient.download('/api/v1/health/diagnostics', 'vnbui-diagnostics.json');
        } catch {
            if (error) error.textContent = window.t('health.diagnostics_failed');
        } finally {
            this.diagnosticsDownloading = false;
            button.disabled = false;
        }
    }

    async loadData() {
        this.loading = true;
        try {
            // Use consolidated health endpoint
            const data = await apiClient.get('/api/v1/health');
            this.health = data || {};
        } catch (error) {
            console.error('Failed to load health data:', error);
            this.health = { status: 'unhealthy', error: error.message };
        }
        this.loading = false;
    }

    async render() {
        const t = window.t;
        await this.loadData();

        const overallStatus = this.health.status || 'unknown';
        const statusColor = getStatusColor(overallStatus);

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M3 12h4l3 8l4 -16l3 8h4" />
                                </svg>
                                ${t('health.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('health.page_subtitle')}</div>
                        </div>
                        <div class="col-auto d-none d-md-flex gap-3 align-items-center ms-auto">
                            <div class="btn-list">
                                <button class="btn btn-primary d-none d-sm-inline-block" onclick="window.vnbui.refreshPage()">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <path d="M20 11a8.1 8.1 0 0 0 -15.5 -2m-.5 -4v4h4" />
                                        <path d="M4 13a8.1 8.1 0 0 0 15.5 2m.5 4v-4h-4" />
                                    </svg>
                                    ${t('common.refresh')}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    <!-- Overall Status -->
                    ${authService.hasRole('admin') ? `
                        <div class="card mb-3">
                            <div class="card-body">
                                <button class="btn btn-outline-primary" onclick="window.vnbui.currentPage.downloadDiagnostics(this)">
                                    ${t('health.download_diagnostics')}
                                </button>
                                <div class="text-secondary small mt-2">${t('health.diagnostics_scope')}</div>
                                <div id="health-diagnostics-error" class="text-danger mt-2" role="alert"></div>
                            </div>
                        </div>
                    ` : ''}
                    <div class="row mb-2">
                        <div class="col">
                            <div class="card">
                                <div class="card-body">
                                    <div class="row align-items-center g-3" id="health-overall">
                                        <div class="col-auto">
                                            <span class="avatar avatar-lg bg-${statusColor}">
                                                ${this.getStatusIcon(overallStatus)}
                                            </span>
                                        </div>
                                        <div class="col">
                                            <h1 class="mb-0">
                                                ${escapeHtml(enumLabel(overallStatus))}
                                            </h1>
                                            <div class="text-secondary">${t('health.overall_status')}</div>
                                        </div>
                                        <div class="col-12 col-sm-auto" id="health-last-check">
                                            <div class="text-sm-end">
                                                <div class="text-secondary small">${t('health.last_check')}</div>
                                                <div class="h3">${this.formatDate(this.health.timestamp)}</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Component Health -->
                    <div class="row row-cards row-cols-1 row-cols-md-2 row-cols-xl-5" id="health-components">
                        ${this.renderS3Health()}
                        ${this.renderAgentsHealth()}
                        ${this.renderStorageHealth()}
                        ${this.renderDatabaseHealth()}
                        ${this.renderAPIHealth()}
                    </div>

                    <!-- System Metrics -->
                    <div class="row row-cards mt-3">
                        <div class="col-md-6">
                            ${this.renderMetrics()}
                        </div>
                        <div class="col-md-6">
                            ${this.renderServices()}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderDatabaseHealth() {
        const db = this.health.database || {};
        const status = db.status || 'unknown';
        const color = getStatusColor(status);

        return `
            <div class="col">
                <div class="card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-auto">
                                <span class="avatar bg-${color}-lt">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <ellipse cx="12" cy="6" rx="8" ry="3"></ellipse>
                                        <path d="M4 6v6a8 3 0 0 0 16 0v-6" />
                                        <path d="M4 12v6a8 3 0 0 0 16 0v-6" />
                                    </svg>
                                </span>
                            </div>
                            <div class="col">
                                <div class="font-weight-medium">${t('health.database')}</div>
                                <div class="text-secondary small">
                                    <span class="badge bg-${color}">${escapeHtml(enumLabel(status))}</span>
                                </div>
                            </div>
                        </div>
                        ${db.response_time ? `
                            <div class="mt-3">
                                <div class="text-secondary small">${t('health.response_time')}</div>
                                <div>${db.response_time}ms</div>
                            </div>
                        ` : ''}
                        ${db.connections !== undefined ? `
                            <div class="mt-2">
                                <div class="text-secondary small">${t('health.connections')}</div>
                                <div>${db.connections}/${db.max_connections || '?'}</div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    renderAgentsHealth() {
        const agents = this.health.agents || {};
        const status = agents.status || 'unknown';
        const color = getStatusColor(status);
        const degraded = agents.degraded || [];

        return `
            <div class="col">
                <div class="card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-auto">
                                <span class="avatar bg-${color}-lt">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <rect x="4" y="4" width="6" height="6" rx="1" />
                                        <rect x="14" y="4" width="6" height="6" rx="1" />
                                        <rect x="4" y="14" width="6" height="6" rx="1" />
                                        <rect x="14" y="14" width="6" height="6" rx="1" />
                                    </svg>
                                </span>
                            </div>
                            <div class="col">
                                <div class="font-weight-medium">${t('health.agents_title')}</div>
                                <div class="text-secondary small">
                                    <span class="badge bg-${color}">${escapeHtml(enumLabel(status))}</span>
                                </div>
                            </div>
                        </div>
                        <div class="mt-3">
                            <div class="text-secondary small">${t('health.online')}</div>
                            <div>${agents.online || 0} / ${agents.total || 0}</div>
                        </div>
                        <div class="mt-2">
                            <div class="text-secondary small">${t('health.healthy')}</div>
                            <div>${agents.healthy || 0} / ${agents.online || 0}</div>
                        </div>
                        ${degraded.length > 0 ? `
                            <div class="mt-2">
                                <div class="text-secondary small">${t('health.issues')}</div>
                                ${degraded.map(a => `<div class="text-warning small">${escapeHtml(a.name)}: ${escapeHtml(a.issues?.[0] || 'degraded')}</div>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    renderStorageHealth() {
        const storage = this.health.storage || {};
        const status = storage.status || 'unknown';
        const color = getStatusColor(status);

        return `
            <div class="col">
                <div class="card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-auto">
                                <span class="avatar bg-${color}-lt">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <path d="M4 6h16v-1a1 1 0 0 0 -1 -1h-14a1 1 0 0 0 -1 1v1z" />
                                        <path d="M4 6v6a1 1 0 0 0 1 1h14a1 1 0 0 0 1 -1v-6" />
                                        <path d="M4 12v6a1 1 0 0 0 1 1h14a1 1 0 0 0 1 -1v-6" />
                                    </svg>
                                </span>
                            </div>
                            <div class="col">
                                <div class="font-weight-medium">${t('health.storage')}</div>
                                <div class="text-secondary small">
                                    <span class="badge bg-${color}">${escapeHtml(enumLabel(status))}</span>
                                </div>
                            </div>
                        </div>
                        ${storage.used_space !== undefined ? `
                            <div class="mt-3">
                                <div class="text-secondary small">${t('health.backup_storage_used')}</div>
                                <div>${this.formatBytes(storage.used_space)}</div>
                            </div>
                        ` : ''}
                        ${storage.backup_count !== undefined ? `
                            <div class="mt-2">
                                <div class="text-secondary small">${t('health.completed_backups')}</div>
                                <div>${storage.backup_count}</div>
                            </div>
                        ` : ''}
                        ${storage.note ? `
                            <div class="mt-2 text-secondary small">${storage.note === 'Storage managed by agents' ? t('experience.storage_managed') : escapeHtml(storage.note)}</div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    renderS3Health() {
        const s3 = this.health.s3 || {};
        const status = s3.status || 'not_configured';
        const color = getStatusColor(status);

        // Not configured - show minimal card
        if (status === 'not_configured' || !s3.configured) {
            return `
                <div class="col">
                    <div class="card">
                        <div class="card-body">
                            <div class="row align-items-center">
                                <div class="col-auto">
                                    <span class="avatar bg-secondary-lt">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                            <path d="M6.657 18c-2.572 0 -4.657 -2.007 -4.657 -4.483c0 -2.475 2.085 -4.482 4.657 -4.482c.393 -1.762 1.794 -3.2 3.675 -3.773c1.88 -.572 3.956 -.193 5.444 1c1.488 1.19 2.162 3.007 1.77 4.769h.99c1.913 0 3.464 1.56 3.464 3.486c0 1.927 -1.551 3.487 -3.464 3.487l-11.879 -.004z" />
                                        </svg>
                                    </span>
                                </div>
                                <div class="col">
                                    <div class="font-weight-medium">${t('health.s3_storage')}</div>
                                    <div class="text-secondary small">
                                        <span class="badge bg-secondary">${t('health.s3_not_configured')}</span>
                                    </div>
                                </div>
                            </div>
                            <div class="mt-3 text-secondary small">
                                ${t('health.s3_not_configured_msg')}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        return `
            <div class="col">
                <div class="card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-auto">
                                <span class="avatar bg-${color}-lt">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <path d="M6.657 18c-2.572 0 -4.657 -2.007 -4.657 -4.483c0 -2.475 2.085 -4.482 4.657 -4.482c.393 -1.762 1.794 -3.2 3.675 -3.773c1.88 -.572 3.956 -.193 5.444 1c1.488 1.19 2.162 3.007 1.77 4.769h.99c1.913 0 3.464 1.56 3.464 3.486c0 1.927 -1.551 3.487 -3.464 3.487l-11.879 -.004z" />
                                    </svg>
                                </span>
                            </div>
                            <div class="col">
                                <div class="font-weight-medium">${t('health.s3_storage')}</div>
                                <div class="text-secondary small">
                                    <span class="badge bg-${color}">${escapeHtml(enumLabel(status))}</span>
                                </div>
                            </div>
                        </div>
                        ${s3.endpoint ? `
                            <div class="mt-3">
                                <div class="text-secondary small">${t('health.endpoint')}</div>
                                <div>${escapeHtml(s3.endpoint)}</div>
                            </div>
                        ` : ''}
                        ${s3.bucket ? `
                            <div class="mt-2">
                                <div class="text-secondary small">${t('health.bucket')}</div>
                                <div>${escapeHtml(s3.bucket)}</div>
                            </div>
                        ` : ''}
                        ${s3.last_check ? `
                            <div class="mt-2">
                                <div class="text-secondary small">${t('health.last_check')}</div>
                                <div>${this.formatDate(s3.last_check)}</div>
                            </div>
                        ` : ''}
                        ${s3.error ? `
                            <div class="mt-2">
                                <div class="text-danger small">${escapeHtml(s3.error)}</div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    renderAPIHealth() {
        const api = this.health.api || {};
        const status = api.status || 'healthy';
        const color = getStatusColor(status);

        return `
            <div class="col">
                <div class="card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-auto">
                                <span class="avatar bg-${color}-lt">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <rect x="3" y="4" width="18" height="12" rx="1" />
                                        <line x1="7" y1="10" x2="7.01" y2="10" />
                                        <line x1="11" y1="10" x2="11.01" y2="10" />
                                    </svg>
                                </span>
                            </div>
                            <div class="col">
                                <div class="font-weight-medium">${t('health.api_title')}</div>
                                <div class="text-secondary small">
                                    <span class="badge bg-${color}">${escapeHtml(enumLabel(status))}</span>
                                </div>
                            </div>
                        </div>
                        ${api.version ? `
                            <div class="mt-3">
                                <div class="text-secondary small">${t('health.api_version')}</div>
                                <div>${escapeHtml(api.version)}</div>
                            </div>
                        ` : ''}
                        ${api.uptime ? `
                            <div class="mt-2">
                                <div class="text-secondary small">${t('health.uptime')}</div>
                                <div>${this.formatUptime(api.uptime)}</div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    renderMetrics() {
        const metrics = this.health.metrics || {};

        return `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('health.system_metrics')}</h3>
                </div>
                <div class="card-table table-responsive">
                    <table class="table table-vcenter">
                        <tbody>
                            <tr>
                                <td>${t('health.active_backups')}</td>
                                <td class="text-end font-weight-medium">${metrics.active_backups || 0}</td>
                            </tr>
                            <tr>
                                <td>${t('health.pending_jobs')}</td>
                                <td class="text-end font-weight-medium">${metrics.pending_jobs || 0}</td>
                            </tr>
                            <tr>
                                <td>${t('health.failed_jobs_24h')}</td>
                                <td class="text-end font-weight-medium">${metrics.failed_jobs_24h || 0}</td>
                            </tr>
                            <tr>
                                <td>${t('health.online_agents')}</td>
                                <td class="text-end font-weight-medium">${metrics.online_agents || 0}</td>
                            </tr>
                            <tr>
                                <td>${t('health.total_vms')}</td>
                                <td class="text-end font-weight-medium">${metrics.total_vms || 0}</td>
                            </tr>
                            <tr>
                                <td>${t('health.total_backups')}</td>
                                <td class="text-end font-weight-medium">${metrics.total_backups || 0}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    renderServices() {
        const services = this.health.services || [];

        return `
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">${t('health.service_status')}</h3>
                </div>
                <div class="card-table table-responsive">
                    <table class="table table-vcenter">
                        <tbody>
                            ${services.length > 0 ? services.map(service => `
                                <tr>
                                    <td>
                                        <div class="font-weight-medium">${escapeHtml(service.name || 'Unknown')}</div>
                                        <div class="text-secondary small">${escapeHtml(service.description || '')}</div>
                                    </td>
                                    <td class="text-end">
                                        <span class="badge bg-${getStatusColor(service.status)}">
                                            ${escapeHtml(enumLabel(service.status || 'unknown'))}
                                        </span>
                                    </td>
                                </tr>
                            `).join('') : `
                                <tr>
                                    <td colspan="2" class="text-secondary text-center">${t('health.no_service_data')}</td>
                                </tr>
                            `}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    getStatusIcon(status) {
        if (status === 'healthy') {
            return `
                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                    <circle cx="12" cy="12" r="9" />
                    <path d="M9 12l2 2l4 -4" />
                </svg>
            `;
        } else if (status === 'degraded') {
            return `
                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                    <path d="M12 9v2m0 4v.01" />
                    <path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75" />
                </svg>
            `;
        } else {
            return `
                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
            `;
        }
    }

    formatBytes(bytes) {
        if (!bytes && bytes !== 0) return 'N/A';
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        if (bytes === 0) return '0 B';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    formatDate(date) {
        if (!date) return 'N/A';
        return new Date(date).toLocaleString();
    }

    formatUptime(seconds) {
        if (!seconds) return 'N/A';
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);

        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    }
}
