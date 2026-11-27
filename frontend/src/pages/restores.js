import { renderOperatorDispatch } from '../utils/operator-dispatch.js';
import { enumLabel } from '../utils/status-labels.js';
/**
 * Restores Page
 * Manage restore operations
 */
import { loadSnapshot } from '../services/snapshot.service.js';
import { updateService } from '../services/updates.service.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime, formatDate } from '../utils/format.js';
import { getStatusColor } from '../utils/status-colors.js';
import { authService } from '../services/auth.service.js';
import { BucketRecovery } from './bucket-recovery.js';
import { assetResolver } from '../assets/resolver.js';

export class RestoresPage {
    constructor() {
        this.restores = [];
        this.loading = false;
        this.recovery = new BucketRecovery();
    }

    async loadData() {
        this.loading = true;
        try {
            this.restores = await loadSnapshot('/api/v1/restores');
        } catch (error) {
            console.error('Failed to load restores:', error);
            this.loading = false;
            return false;
        }
        this.loading = false;
        return true;
    }

    async render() {
        const t = window.t;
        await this.loadData();
        this.subscribeToUpdates();

        const completed = this.restores.filter(r => r.status === 'completed').length;
        const running = this.restores.filter(r => r.status === 'running').length;

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M9 13l-4 -4l4 -4m-4 4h11a4 4 0 0 1 0 8h-1" />
                                </svg>
                                ${t('restores.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('restores.page_subtitle')}</div>
                        </div>
                        ${authService.canManageInstallation() ? `
                            <div class="col-auto">
                                <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#modal-bucket-recovery">
                                    Recover from S3
                                </button>
                            </div>` : ''}
                        <div class="col-auto d-none d-md-flex gap-3 align-items-center">
                            <span class="text-secondary">
                                <span class="badge bg-success me-1">${completed}</span> ${t('common.completed')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-info me-1">${running}</span> ${t('common.running')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-primary me-1">${this.restores.length}</span> ${t('restores.page_title')}
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">${t('restores.page_title')}</h3>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-vcenter card-table table-striped">
                                <thead>
                                    <tr>
                                        <th>${t('restores.col_vm_name')}</th>
                                        <th>${t('restores.col_backup')}</th>
                                        <th>${t('restores.col_target')}</th>
                                        <th>${t('restores.col_status')}</th>
                                        <th>${t('restores.col_progress')}</th>
                                        <th>${t('restores.col_started')}</th>
                                        <th class="w-1">${t('common.actions')}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${this.renderRestoreRows()}
                                </tbody>
                            </table>
                        </div>
                        ${this.restores.length === 0 ? this.renderEmptyState() : ''}
                    </div>
                </div>
            </div>
            ${authService.canManageInstallation() ? this.recovery.render() : ''}
        `;
    }

    afterRender() {
        const modal = document.getElementById('modal-bucket-recovery');
        if (modal) this.recovery.bind(modal);
    }

    renderRestoreRows() {
        const t = window.t;
        if (this.restores.length === 0) return '';

        return this.restores.map(restore => `
            <tr>
                <td>
                    <div class="font-weight-medium">${escapeHtml(restore.recovery_source?.name || restore.backup?.vm_name || 'Unknown')}</div>
                    <div class="text-secondary small">${escapeHtml(restore.id || '')}</div>
                </td>
                <td>${restore.recovery_source ? '<span class="badge bg-info-lt me-1">Verified S3</span>' : ''}${escapeHtml(restore.recovery_source?.backup_id || restore.backup_name || restore.backup_id || 'N/A')}</td>
                <td>
                    ${!restore.restore_to_original ? `
                        <span class="badge bg-info-lt">${t('restores.target_clone')}: ${escapeHtml(restore.target_vm_name || 'N/A')}</span>
                        ${restore.kubevirt_target ? `<div class="text-secondary small">${escapeHtml(restore.kubevirt_target.namespace)} · Halted</div>` : ''}
                        ${restore.native_target ? `<div class="text-secondary small">${escapeHtml(restore.native_target.vm_uuid)} · shutoff</div>` : ''}
                    ` : `
                        <span class="badge bg-warning-lt">${t('restores.target_original')}</span>
                    `}
                </td>
                <td>
                    <span class="badge bg-${getStatusColor(restore.status, 'backup')}">
                        ${escapeHtml(enumLabel(restore.status || 'unknown'))}
                    </span>
                    ${renderOperatorDispatch(restore.operator_dispatch)}
                    ${restore.error_message ? `<div class="text-danger small">${escapeHtml(restore.error_message)}</div>` : ''}
                </td>
                <td>
                    ${restore.status === 'running' ? `
                        <div class="progress progress-sm">
                            <div class="progress-bar" style="width: ${restore.progress || 0}%" role="progressbar">
                                <span class="visually-hidden">${restore.progress || 0}%</span>
                            </div>
                        </div>
                        <small class="text-secondary">${restore.progress || 0}%</small>
                    ` : `<span class="text-secondary">—</span>`}
                </td>
                <td>
                    <div>${formatDate(restore.started_at)}</div>
                    <div class="text-secondary small">${formatRelativeTime(restore.started_at)}</div>
                </td>
                <td>
                    ${restore.status === 'running' && !restore.kubevirt_target && !restore.native_target ? `
                        <button class="btn btn-sm btn-ghost-danger" onclick="window.vnbui.cancelRestore('${escapeHtml(restore.id)}')" title="${t('common.cancel')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <line x1="18" y1="6" x2="6" y2="18" />
                                <line x1="6" y1="6" x2="18" y2="18" />
                            </svg>
                        </button>
                    ` : `
                        <button class="btn btn-sm btn-ghost-secondary" onclick="window.vnbui.viewRestoreDetails('${escapeHtml(restore.id)}')" title="${t('common.view_details')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <circle cx="12" cy="12" r="2" />
                                <path d="M22 12c-2.667 4.667 -6 7 -10 7s-7.333 -2.333 -10 -7c2.667 -4.667 6 -7 10 -7s7.333 2.333 10 7" />
                            </svg>
                        </button>
                    `}
                    ${(restore.kubevirt_target || restore.native_target) && ['pending', 'dispatching', 'running'].includes(restore.status) ? `
                        <button class="btn btn-sm btn-outline-primary mt-1" onclick="window.vnbui.resumeRestore('${escapeHtml(restore.id)}')">${t('restores.resume')}</button>
                    ` : ''}
                </td>
            </tr>
        `).join('');
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty">
                <div class="empty-img">
                    <div class="empty-icon">${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}</div>
                </div>
                <p class="empty-title">${t('restores.empty_title')}</p>
                <p class="empty-subtitle text-secondary">${t('restores.empty_subtitle')}</p>
            </div>
        `;
    }

    subscribeToUpdates() {
        this.destroy();
        const updateGeneration = this.updateGeneration;
        const reload = async () => {
            if (await this.loadData() === false) throw new Error('Restore resynchronization failed');
            if (this.updateGeneration !== updateGeneration) return;
            if (!document.querySelector('.modal.show')) await window.vnbui.refreshPage();
        };
        this.resyncSubscription = updateService.subscribeResync(reload);
        this.pollingInterval = setInterval(() => reload().catch(error => console.error(error)), 10000);
        this.updateSubscription = updateService.subscribe('*', ({type}) => {
            if (type?.startsWith('restore_')) reload().catch(error => console.error(error));
        });
    }

    destroy() {
        if (this.pollingInterval) clearInterval(this.pollingInterval);
        this.pollingInterval = null;
        this.updateGeneration = (this.updateGeneration || 0) + 1;
        this.resyncSubscription?.();
        this.updateSubscription?.();
        this.resyncSubscription = this.updateSubscription = null;
    }

}
