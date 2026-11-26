import { contextHelp } from '../components/context-help.js';
import { enumLabel } from '../utils/status-labels.js';
/**
 * Verification Page
 * Verify backup integrity
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime, formatDate } from '../utils/format.js';
import { getStatusColor } from '../utils/status-colors.js';
import { assetResolver } from '../assets/resolver.js';

export class VerificationPage {
    constructor() {
        this.verifications = [];
        this.loading = false;
        this.backups = [];
        this.error = null;
    }

    async loadData() {
        this.loading = true;
        this.error = null;
        try {
            const data = await apiClient.get('/api/v1/verifications');
            this.verifications = data.items || [];
            if (this.canOperate()) {
                const choices = await apiClient.get('/api/v1/backups?status=completed&limit=100');
                this.backups = choices.items || [];
            }
        } catch (error) {
            console.error('Failed to load verifications:', error);
            this.verifications = [];
            this.error = window.t('verification.load_failed');
        }
        this.loading = false;
    }

    async render() {
        const t = window.t;
        await this.loadData();

        const passed = this.verifications.filter(v => v.status === 'passed').length;
        const failed = this.verifications.filter(v => v.status === 'failed').length;

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M9 12l2 2l4 -4" />
                                    <path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" />
                                </svg>
                                ${t('verification.page_title')} ${contextHelp('verification')}
                            </h2>
                            <div class="text-secondary mt-1">${t('verification.page_subtitle')}</div>
                        </div>
                        <div class="col-auto d-none d-md-flex gap-3 align-items-center">
                            <span class="text-secondary">
                                <span class="badge bg-success me-1">${passed}</span> ${t('common.passed')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-danger me-1">${failed}</span> ${t('common.failed')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-primary me-1">${this.verifications.length}</span> ${t('common.total')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-info me-1">${this.getSuccessRate() === null ? '—' : this.getSuccessRate() + '%'}</span> ${t('common.success_rate')}
                            </span>
                        </div>
                        <div class="col-12 col-xl-auto ms-auto d-print-none verification-actions">
                            ${this.canOperate() ? `
                            <select id="verification-backup" class="form-select" aria-label="${t('verification.select_backup')}">
                                <option value="">${t('verification.select_backup')}</option>
                                ${this.backups.map(b => `<option value="${escapeHtml(b.id)}">${escapeHtml(b.vm_name || b.vm_id || b.id)} — ${escapeHtml(b.id)}</option>`).join('')}
                            </select>
                            <button class="btn btn-primary" onclick="window.vnbui.startVerification()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M7 12l5 5l10 -10" />
                                    <path d="M2 12l5 5m5 -5l5 -5" />
                                </svg>
                                ${t('verification.start_verification')}
                            </button>` : ''}
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    ${this.error ? `<div class="alert alert-danger">${escapeHtml(this.error)}</div>` : ''}
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">${t('verification.page_title')} ${contextHelp('verification')}</h3>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-vcenter card-table table-striped">
                                <thead>
                                    <tr>
                                        <th>${t('verification.col_backup')}</th>
                                        <th>${t('common.type')}</th>
                                        <th>${t('verification.col_status')}</th>
                                        <th>${t('verification.col_completed')}</th>
                                        <th>${t('common.duration')}</th>
                                        <th class="w-1">${t('common.actions')}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${this.renderVerificationRows()}
                                </tbody>
                            </table>
                        </div>
                        ${this.verifications.length === 0 ? this.renderEmptyState() : ''}
                    </div>
                </div>
            </div>
        `;
    }

    renderVerificationRows() {
        const t = window.t;
        if (this.verifications.length === 0) return '';

        return this.verifications.map(v => `
            <tr>
                <td>
                    <div class="font-weight-medium">${escapeHtml(v.backup_name || v.backup_id || 'Unknown')}</div>
                    <div class="text-secondary small">${escapeHtml(v.vm_name || '')}</div>
                </td>
                <td>${escapeHtml(v.verification_type || 'integrity')}</td>
                <td>
                    <span class="badge bg-${getStatusColor(v.status)}">
                        ${escapeHtml(enumLabel(v.status || 'unknown'))}
                    </span>
                </td>
                <td>
                    <div>${v.completed_at ? formatDate(v.completed_at) : '—'}</div>
                    <div class="text-secondary small">${v.completed_at ? formatRelativeTime(v.completed_at) : ''}</div>
                </td>
                <td>${v.started_at && v.completed_at ? Math.max(0, Math.round((new Date(v.completed_at) - new Date(v.started_at)) / 1000)) + 's' : '—'}</td>
                <td>
                    ${this.controls(v)}
                    ${/^[0-9a-f-]{36}$/.test(v.id) ? `
                    <button class="btn btn-sm btn-ghost-secondary" onclick="window.vnbui.viewVerificationDetails('${escapeHtml(v.id)}')" title="${t('verification.view_details')}">
                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                            <circle cx="12" cy="12" r="2" />
                            <path d="M22 12c-2.667 4.667 -6 7 -10 7s-7.333 -2.333 -10 -7c2.667 -4.667 6 -7 10 -7s7.333 2.333 10 7" />
                        </svg>
                    </button>` : ''}
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
                <p class="empty-title">${t('verification.empty_title')}</p>
                <p class="empty-subtitle text-secondary">${t('verification.empty_subtitle')}</p>
            </div>
        `;
    }

    getSuccessRate() {
        if (this.error || this.verifications.length === 0) return null;
        const passed = this.verifications.filter(v => v.status === 'passed').length;
        return Math.round((passed / this.verifications.length) * 100);
    }

    canOperate() {
        return ['admin', 'operator'].includes(window.vnbui?.currentUserRole);
    }

    controls(v) {
        if (!this.canOperate() || v.verification_type !== 'artifact_scrub' || !/^[0-9a-f-]{36}$/.test(v.id)
            || v.cancel_requested || ['passed', 'failed', 'cancelled'].includes(v.status)) return '';
        const resume = v.status === 'held' && !v.cancel_requested && v.created_by === window.vnbui.currentUserId;
        return `${resume ? `<button class="btn btn-sm btn-outline-primary" onclick="window.vnbui.verificationControl('${v.id}', 'resume')">${window.t('verification.resume')}</button>` : ''}
            ${!v.cancel_requested ? `<button class="btn btn-sm btn-outline-danger" onclick="window.vnbui.verificationControl('${v.id}', 'cancel')">${window.t('verification.cancel')}</button>` : ''}`;
    }

}
