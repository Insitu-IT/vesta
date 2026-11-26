import { renderOperatorDispatch } from '../utils/operator-dispatch.js';
import { renderBackupSafety } from '../utils/backup-safety.js';
import { contextHelp } from '../components/context-help.js';
import { enumLabel } from '../utils/status-labels.js';
/**
 * Backups Page
 * Lists and manages backups
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { loadSnapshot } from '../services/snapshot.service.js';
import { updateService } from '../services/updates.service.js';
import { formatRelativeTime, formatDate, formatSize, stripAnsi } from '../utils/format.js';
import { getStatusColor } from '../utils/status-colors.js';
import { assetResolver } from '../assets/resolver.js';

const activeStatuses = ['pending', 'running', 'uploading'];

export class BackupsPage {
    constructor() {
        this.backups = [];
        this.loading = false;
        this.filter = 'all'; // all, completed, failed, running
        this.searchQuery = '';
        this.updateSubscription = null;
        this.pollingInterval = null;
        this.s3Configured = false;
        this._searchTimeout = null;
        this.schedulerDecisionRequests = new Map();
    }

    async loadData() {
        this.loading = true;
        let loaded = false;
        try {
            this.backups = await loadSnapshot('/api/v1/backups');
            loaded = true;
        } catch (error) {
            console.error('Failed to load backups:', error);
            this.backups = [];
        }
        // Check if S3 is configured (for import button visibility)
        try {
            const settings = await apiClient.get('/api/v1/settings/v3');
            this.s3Configured = (settings.settings || {})['storage.type'] === 's3';
        } catch (e) {
            this.s3Configured = false;
        }
        this.loading = false;
        return loaded;
    }

    async render() {
        const t = window.t;
        await this.loadData();

        // Subscribe to real-time updates (Phase 1)
        this.subscribeToUpdates();

        setTimeout(() => this.setupEventListeners(), 0);

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <ellipse cx="12" cy="6" rx="8" ry="3"></ellipse>
                                    <path d="M4 6v6a8 3 0 0 0 16 0v-6" />
                                    <path d="M4 12v6a8 3 0 0 0 16 0v-6" />
                                </svg>
                                ${t('backups.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('backups.page_subtitle')}</div>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
                            <div class="btn-list">
                                ${this.s3Configured ? `
                                <button class="btn btn-ghost-primary d-none d-sm-inline-block" onclick="window.vnbui.openS3Import()">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2" />
                                        <polyline points="7 9 12 4 17 9" />
                                        <line x1="12" y1="4" x2="12" y2="16" />
                                    </svg>
                                    ${t('s3_import.button')}
                                </button>
                                ` : ''}
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
                    <!-- Filter Tabs -->
                    <div class="card mb-3">
                        <div class="card-body">
                            <div class="row g-2">
                                <div class="col">
                                    <div class="btn-group" role="group">
                                        <input type="radio" class="btn-check" name="backup-filter" id="filter-all" autocomplete="off" ${this.filter === 'all' ? 'checked' : ''} onchange="window.vnbui.filterBackups('all')">
                                        <label class="btn" for="filter-all">${t('backups.filter_all')} (${this.backups.length})</label>

                                        <input type="radio" class="btn-check" name="backup-filter" id="filter-completed" autocomplete="off" ${this.filter === 'completed' ? 'checked' : ''} onchange="window.vnbui.filterBackups('completed')">
                                        <label class="btn" for="filter-completed">${t('backups.filter_completed')} (${this.getFilteredCount('completed')})</label>

                                        <input type="radio" class="btn-check" name="backup-filter" id="filter-running" autocomplete="off" ${this.filter === 'running' ? 'checked' : ''} onchange="window.vnbui.filterBackups('running')">
                                        <label class="btn" for="filter-running">${t('backups.filter_running')} (${this.getFilteredCount('running')})</label>

                                        <input type="radio" class="btn-check" name="backup-filter" id="filter-failed" autocomplete="off" ${this.filter === 'failed' ? 'checked' : ''} onchange="window.vnbui.filterBackups('failed')">
                                        <label class="btn" for="filter-failed">${t('backups.filter_failed')} (${this.getFilteredCount('failed')})</label>

                                        <input type="radio" class="btn-check" name="backup-filter" id="filter-uploading" autocomplete="off" ${this.filter === 'uploading' ? 'checked' : ''} onchange="window.vnbui.filterBackups('uploading')">
                                        <label class="btn" for="filter-uploading">${t('backups.filter_uploading')} (${this.getFilteredCount('uploading')})</label>

                                        <input type="radio" class="btn-check" name="backup-filter" id="filter-upload_failed" autocomplete="off" ${this.filter === 'upload_failed' ? 'checked' : ''} onchange="window.vnbui.filterBackups('upload_failed')">
                                        <label class="btn" for="filter-upload_failed">${t('backups.filter_upload_failed')} (${this.getFilteredCount('upload_failed')})</label>
                                    </div>
                                </div>
                                <div class="col-auto">
                                    <div class="input-group search-control">
                                        <input type="text" class="form-control" placeholder="${t('backups.search_placeholder')}" id="backup-search">
                                        <span class="input-group-text">
                                            <i class="ti ti-search icon" aria-hidden="true"></i>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Backups Table -->
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">${t('backups.all_backups')}</h3>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-vcenter card-table table-striped">
                                <thead>
                                    <tr>
                                        <th>${t('backups.col_vm_name')}</th>
                                        <th>${t('backups.col_status')}</th>
                                        <th>${t('backups.col_type')}</th>
                                        <th>${t('backups.col_size')}</th>
                                        <th>${t('backups.col_progress')}</th>
                                        <th>${t('backups.col_created')}</th>
                                        <th>${t('backups.col_expires')}</th>
                                        <th class="w-1">${t('common.actions')}</th>
                                    </tr>
                                </thead>
                                <tbody id="backups-table-body">
                                    ${this.renderBackupRows()}
                                </tbody>
                            </table>
                        </div>
                        ${this.backups.length === 0 ? this.renderEmptyState() : ''}
                    </div>
                </div>
            </div>

            ${this.renderRestoreModal()}
            ${this.renderDeleteModal()}
            ${this.renderS3ImportModal()}
        `;
    }

    setupEventListeners() {
        const table = document.getElementById('backups-table-body');
        table?.addEventListener('click', (event) => {
            if (event.target.closest?.('button, a, input, select, .backup-error-preview')) return;
            const row = event.target.closest?.('tr[data-backup-id]');
            const details = row?.nextElementSibling;
            if (details && !details.classList.contains('d-none')) {
                return this.loadSchedulerDecision(row.dataset.backupId, details);
            }
        });
        const searchInput = document.getElementById('backup-search');
        if (searchInput) {
            searchInput.value = this.searchQuery;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this._searchTimeout);
                this._searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value;
                    const tbody = document.getElementById('backups-table-body');
                    if (tbody) tbody.innerHTML = this.renderBackupRows();
                }, 300);
            });
        }
    }

    async loadSchedulerDecision(id, details) {
        const target = details.querySelector('[data-scheduler-decision]');
        if (!target) return;
        target.hidden = false;
        target.textContent = window.t('backups.scheduler_decision_loading');
        try {
            if (!this.schedulerDecisionRequests.has(id)) {
                this.schedulerDecisionRequests.set(id, apiClient.get(`/api/v1/backups/${encodeURIComponent(id)}`));
            }
            const backup = await this.schedulerDecisionRequests.get(id);
            if (backup?.id !== id || !Object.hasOwn(backup, 'scheduler_decision')) {
                throw new Error('Missing saved scheduler decision');
            }
            if (backup.scheduler_decision === null) {
                target.hidden = true; // Manual and fixed-mode runs have no automatic decision.
            } else {
                target.innerHTML = this.renderSchedulerDecision(backup.scheduler_decision);
            }
        } catch {
            this.schedulerDecisionRequests.delete(id); // Re-expansion can retry a failed read.
            target.textContent = window.t('backups.scheduler_decision_unavailable');
        }
    }

    renderSchedulerDecision(decision) {
        const t = window.t;
        if (decision?.schema !== 1 || !['full', 'incremental'].includes(decision.backup_type)
            || typeof decision.reason !== 'string'
            || !Number.isInteger(decision.policy?.full_every_days)
            || !Number.isInteger(decision.policy?.max_incrementals)) {
            throw new Error('Unsupported saved scheduler decision');
        }
        const reasons = new Set(['parent_unavailable', 'new_grant', 'source_changed',
            'root_time_unavailable', 'previous_failure', 'max_incrementals', 'full_interval', 'within_policy']);
        const reason = reasons.has(decision.reason)
            ? t(`backups.scheduler_reason_${decision.reason}`)
            : t('backups.scheduler_reason_unknown', {reason: decision.reason});
        const facts = decision.root_date !== null && Number.isInteger(decision.incremental_count)
            ? t('backups.scheduler_decision_parent', {root: decision.root_date, count: decision.incremental_count})
            : t('backups.scheduler_decision_no_parent');
        return `<div class="small mt-2">
            <strong>${escapeHtml(t('backups.scheduler_decision_title'))}</strong>
            <div>${escapeHtml(t('backups.scheduler_decision_summary', {
                type: t(`backups.scheduler_type_${decision.backup_type}`), reason}))}</div>
            <div class="text-secondary">${escapeHtml(t('backups.scheduler_decision_policy', {
                days: decision.policy.full_every_days, count: decision.policy.max_incrementals}))}</div>
            <div class="text-secondary">${escapeHtml(facts)} ${escapeHtml(t('backups.scheduler_decision_date', {
                date: decision.observed_date}))}</div>
        </div>`;
    }

    renderBackupRows() {
        const t = window.t;
        if (this.backups.length === 0) {
            return '';
        }

        const filteredBackups = this.getFilteredBackups();

        if (filteredBackups.length === 0) {
            return `<tr><td colspan="8" class="text-center text-secondary py-4">${t('common.no_results', { query: this.searchQuery })}</td></tr>`;
        }

        return filteredBackups.map(backup => `
            <tr data-backup-id="${escapeHtml(backup.id)}" style="cursor:pointer" onclick="this.nextElementSibling?.classList.toggle('d-none')">
                <td>
                    <div class="d-flex align-items-center">
                        <span class="avatar avatar-sm me-2 bg-secondary-lt">
                            ${escapeHtml((backup.vm_name || 'VM').substring(0, 2).toUpperCase())}
                        </span>
                        <div>
                            <div class="font-weight-medium">${escapeHtml(backup.vm_name || 'Unknown')}</div>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge backup-status bg-${getStatusColor(backup.status, 'backup')}">
                        ${escapeHtml(enumLabel(backup.status || 'unknown'))}
                    </span>
                    <div class="backup-dispatch">${renderOperatorDispatch(backup.operator_dispatch)}</div>
                    ${renderBackupSafety(backup.safety_diagnostic)}
                    ${backup.capacity_state === 'reserved' && backup.tags?.native_hold ? `
                        <div class="text-warning small mt-1">${t('backups.native_hold_reported')}</div>
                    ` : ''}
                    ${backup.capacity_state === 'reserved' && ['admin', 'operator'].includes(window.vnbui?.currentUserRole) ? `
                        <button class="btn btn-sm btn-warning mt-1"
                                onclick="event.stopPropagation(); window.vnbui.resumeBackup('${escapeHtml(backup.id)}')">
                            <i class="ti ti-refresh me-1"></i>${t('backups.resume_attempt')}
                        </button>
                        ${backup.tags?.upload_error ? `<div class="text-warning small mt-1">${escapeHtml(backup.tags.upload_error.substring(0, 80))}</div>` : ''}
                    ` : ''}
                    ${backup.status === 'pending' && backup.capacity_state === 'unreserved' && ['admin', 'operator'].includes(window.vnbui?.currentUserRole) ? `
                        <button class="btn btn-sm btn-warning mt-1"
                                onclick="event.stopPropagation(); window.vnbui.closeUnreservedBackup('${escapeHtml(backup.id)}')">
                            ${t('backups.close_unreserved')}
                        </button>
                    ` : ''}
                    ${(backup.status === 'failed' || backup.status === 'upload_failed') && backup.tags?.error ? `
                        <div class="text-danger small mt-1 backup-error-preview"
                             style="cursor: pointer; max-width: 300px;"
                             title="${t('backups.error_details')}"
                             onclick="window.vnbui.showBackupError('${escapeHtml(backup.id)}', '${escapeHtml(backup.vm_name)}', this.dataset.error)"
                             data-error="${escapeHtml(stripAnsi(backup.tags.error))}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon icon-sm me-1" width="16" height="16" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/><circle cx="12" cy="12" r="9" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                            </svg>
                            ${escapeHtml(stripAnsi(backup.tags.error).substring(0, 80))}${backup.tags.error.length > 80 ? '...' : ''}
                        </div>
                    ` : ''}
                </td>
                <td>
                    <span class="text-secondary">${escapeHtml(enumLabel(backup.backup_type || 'full', 'backup_type'))}</span>
                </td>
                <td>${formatSize(backup.size_bytes)}</td>
                <td>
                    ${activeStatuses.includes(backup.status) ? `
                        <div class="d-flex align-items-center">
                            <div class="flex-grow-1 me-2">
                                <div class="progress progress-sm">
                                    <div class="progress-bar bg-info" style="width: ${backup.progress || 0}%" role="progressbar"></div>
                                </div>
                            </div>
                            <span class="text-nowrap backup-progress-text">${backup.progress || 0}%${this.formatETA(backup.tags?.estimated_completion)}</span>
                        </div>
                        <div class="small text-secondary backup-transfer-text" dir="ltr">${this.transferText(backup.storage_progress)}</div>
                    ` : `<span class="text-secondary">—</span>`}
                </td>
                <td>
                    <div>${formatDate(backup.created_at)}</div>
                    <div class="text-secondary small">${formatRelativeTime(backup.created_at)}</div>
                </td>
                <td>
                    ${backup.retention_days ? `
                        <div class="text-secondary small">${this.formatExpiryDate(backup.created_at, backup.retention_days)}</div>
                    ` : `<span class="text-secondary">—</span>`}
                </td>
                <td>
                    <div class="btn-list flex-nowrap">
                        ${backup.status === 'completed' ? `
                            <button class="btn btn-sm btn-success" onclick="window.vnbui.restoreBackup('${escapeHtml(backup.id)}', '${escapeHtml(backup.vm_name)}')" title="${t('backups.restore_tooltip')}" data-bs-toggle="tooltip">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M9 13l-4 -4l4 -4m-4 4h11a4 4 0 0 1 0 8h-1" />
                                </svg>
                            </button>
                            <button class="btn btn-sm btn-ghost-secondary" onclick="window.vnbui.downloadBackup('${escapeHtml(backup.id)}')" title="${t('backups.download_tooltip')}" data-bs-toggle="tooltip">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2" />
                                    <polyline points="7 11 12 16 17 11" />
                                    <line x1="12" y1="4" x2="12" y2="16" />
                                </svg>
                            </button>
                        ` : ''}
                        ${backup.status === 'running' ? `
                            <button class="btn btn-sm btn-ghost-warning" onclick="window.vnbui.cancelBackup('${escapeHtml(backup.id)}')" title="${t('backups.cancel_tooltip')}" data-bs-toggle="tooltip">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <rect x="6" y="6" width="12" height="12" rx="2" />
                                </svg>
                            </button>
                        ` : ''}
                        <button class="btn btn-sm btn-ghost-danger" onclick="window.vnbui.deleteBackup('${escapeHtml(backup.id)}', '${escapeHtml(backup.vm_name)}')" title="${t('backups.delete_tooltip')}" data-bs-toggle="tooltip">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <line x1="4" y1="7" x2="20" y2="7" />
                                <line x1="10" y1="11" x2="10" y2="17" />
                                <line x1="14" y1="11" x2="14" y2="17" />
                                <path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12" />
                                <path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3" />
                            </svg>
                        </button>
                    </div>
                </td>
            </tr>
            <tr class="d-none bg-light">
                <td colspan="8" class="py-2 px-3">
                    <div class="d-flex gap-3 align-items-center">
                        ${this.phaseIndicator('backup', backup)}
                        ${this.phaseIndicator('encrypt', backup)}
                        ${this.phaseIndicator('upload', backup)}
                    </div>
                    <div class="small text-secondary mt-1">
                        ${t('common.status')}: ${escapeHtml(enumLabel(backup.status))} |
                        ${t('backups.col_size')}: ${formatSize(backup.size_bytes)} |
                        ${escapeHtml(backup.storage_path || '')}
                        ${backup.tags?.upload_error ? ` | ${escapeHtml(backup.tags.upload_error.substring(0, 120))}` : ''}
                        ${backup.storage_progress?.phase || backup.tags?.current_operation ? ` | ${escapeHtml(backup.storage_progress?.phase || backup.tags.current_operation)}` : ''}
                    </div>
                    <div class="backup-dispatch-details">${renderOperatorDispatch(backup.operator_dispatch)}</div>
                    ${renderBackupSafety(backup.safety_diagnostic, true)}
                    <div data-scheduler-decision hidden aria-live="polite"></div>
                </td>
            </tr>
        `).join('');
    }

    phaseIndicator(phase, backup) {
        const t = window.t;
        const s = backup.status;
        const hasS3 = backup.storage_path?.startsWith('s3://');
        const labels = { backup: t('backups.phase_backup'), encrypt: t('backups.phase_encrypt'), upload: t('backups.phase_upload') };

        if (['pending', 'dispatching'].includes(s)) return `<span class="text-secondary small">— ${labels[phase]}</span>`;
        let icon, color;
        if (phase === 'backup') {
            if (s === 'failed') { icon = '✗'; color = 'danger'; }
            else if (s === 'running' && (!backup.tags?.current_operation || backup.tags.current_operation === 'backing up')) { icon = '⏳'; color = 'info'; }
            else { icon = '✓'; color = 'success'; }
        } else if (phase === 'encrypt') {
            if (s === 'failed') { icon = '—'; color = 'secondary'; }
            else if (s === 'running' && backup.tags?.current_operation === 'encrypting') { icon = '⏳'; color = 'info'; }
            else if (s === 'running') { icon = '—'; color = 'secondary'; }
            else { icon = '✓'; color = 'success'; }
        } else {
            if (s === 'upload_failed') { icon = '✗'; color = 'danger'; }
            else if (s === 'uploading') { icon = '⏳'; color = 'info'; }
            else if (hasS3) { icon = '✓'; color = 'success'; }
            else if (['completed', 'upload_failed'].includes(s)) { icon = '—'; color = 'secondary'; }
            else { icon = '—'; color = 'secondary'; }
        }
        return `<span class="badge bg-${color} me-1">${icon}</span><span class="small">${labels[phase]}</span>`;
    }

    renderEmptyState() {
        const t = window.t;
        const hasFilters = this.searchQuery || this.filter !== 'all';
        return `
            <div class="empty">
                <div class="empty-img">
                    <div class="empty-icon">${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}</div>
                </div>
                <p class="empty-title">${t('backups.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${hasFilters
                        ? t('backups.empty_filtered', { filter: this.filter })
                        : t('backups.empty_all')}
                </p>
            </div>
        `;
    }

    renderRestoreModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-restore" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${t('restore_modal.title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label">${t('restore_modal.backup_id')}</label>
                                <input type="text" class="form-control" id="restore-backup-id" readonly>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">${t('restore_modal.vm_name')}</label>
                                <input type="text" class="form-control" id="restore-vm-name" readonly>
                            </div>
                            <div id="restore-standard-options">
                            <div class="mb-3">
                                <label class="form-label">${t('restore_modal.target')} ${contextHelp('restore')}</label>
                                <select class="form-select" id="restore-target">
                                    <option value="original">${t('restore_modal.target_original')}</option>
                                    <option value="new">${t('restore_modal.target_new')}</option>
                                </select>
                            </div>
                            <div class="mb-3" id="restore-new-name-group" style="display: none;">
                                <label class="form-label">${t('restore_modal.new_vm_name')}</label>
                                <input type="text" class="form-control" id="restore-new-name" placeholder="${t('restore_modal.new_vm_placeholder')}">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">${t('restore_modal.restore_point')}</label>
                                <select class="form-select" id="restore-checkpoint">
                                    <option value="">${t('restore_modal.restore_latest')}</option>
                                </select>
                                <small class="text-secondary">${t('restore_modal.restore_point_hint')}</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">${t('restore_modal.disks')}</label>
                                <div id="restore-disks" class="d-flex flex-wrap gap-2">
                                    <span class="text-secondary small">${t('restore_modal.all_disks')}</span>
                                </div>
                                <small class="text-secondary">${t('restore_modal.disks_hint')}</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-check">
                                    <input type="checkbox" class="form-check-input" id="restore-auto-define">
                                    <span class="form-check-label">${t('restore_modal.auto_define')}</span>
                                </label>
                                <small class="text-secondary d-block">${t('restore_modal.auto_define_hint')}</small>
                            </div>
                            <div class="alert alert-warning" role="alert">
                                <div class="d-flex">
                                    <div>
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon alert-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                            <path d="M12 9v2m0 4v.01" />
                                            <path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75" />
                                        </svg>
                                    </div>
                                    <div>
                                        <h4 class="alert-title">${t('restore_modal.warning_title')}</h4>
                                        <div class="text-secondary">${t('restore_modal.warning_text')}</div>
                                    </div>
                                </div>
                            </div>
                            </div>
                            <div id="restore-kubevirt-options" class="d-none">
                                <div id="restore-fresh-hint" class="alert alert-info">${t('restore_modal.kubevirt_hint')}</div>
                                <p id="restore-kubevirt-selection" class="text-secondary"></p>
                                <label class="form-label" for="restore-kubevirt-target">${t('restore_modal.kubevirt_mappings')}</label>
                                <textarea id="restore-kubevirt-target" class="form-control font-monospace" rows="20" dir="ltr" spellcheck="false"></textarea>
                                <small class="text-secondary">${t('restore_modal.kubevirt_mapping_hint')}</small>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-success" onclick="window.vnbui.submitRestore()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M9 13l-4 -4l4 -4m-4 4h11a4 4 0 0 1 0 8h-1" />
                                </svg>
                                ${t('restore_modal.restore_button')}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderDeleteModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-delete-backup" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-sm modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-body">
                            <input type="hidden" id="delete-backup-id">
                            <div class="modal-title">${t('backups.delete_confirm_title')}</div>
                            <div>${t('backups.delete_confirm_msg', { vm_name: '<strong id="delete-backup-vm-name"></strong>' })}</div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-danger" onclick="window.vnbui.submitDeleteBackup()">${t('backups.delete_button')}</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderS3ImportModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-s3-import" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-xl modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${t('s3_import.title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <p class="text-secondary mb-3">${t('s3_import.context')}</p>
                            <div id="s3-import-content">
                                <div class="text-center py-4">
                                    <span class="spinner-border spinner-border-sm me-2"></span>
                                    ${t('s3_import.discovering')}
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.close')}</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    async openS3Import() {
        const modal = new bootstrap.Modal(document.getElementById('modal-s3-import'));
        modal.show();

        const container = document.getElementById('s3-import-content');
        const t = window.t;

        // Show loading
        container.innerHTML = `
            <div class="text-center py-4">
                <span class="spinner-border spinner-border-sm me-2"></span>
                ${t('s3_import.discovering')}
            </div>
        `;

        try {
            const data = await apiClient.get('/api/v1/s3/discover');
            const chains = data.chains || [];

            if (chains.length === 0) {
                container.innerHTML = `
                    <div class="empty py-4">
                        <p class="empty-title">${t('s3_import.no_chains')}</p>
                        <p class="empty-subtitle text-secondary">${t('s3_import.no_chains_hint')}</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="table-responsive">
                    <table class="table table-vcenter table-striped">
                        <thead>
                            <tr>
                                <th>${t('s3_import.col_vm_name')}</th>
                                <th>${t('s3_import.col_backups')}</th>
                                <th>${t('s3_import.col_size')}</th>
                                <th>${t('s3_import.col_date_range')}</th>
                                <th>${t('s3_import.col_encrypted')}</th>
                                <th>${t('s3_import.col_status')}</th>
                                <th>${t('s3_import.col_actions')}</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${chains.map(chain => this.renderS3ChainRow(chain)).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (error) {
            console.error('S3 discover failed:', error);
            container.innerHTML = `
                <div class="alert alert-danger">${t('s3_import.error_discover', { error: error.message })}</div>
            `;
        }
    }

    renderS3ChainRow(chain) {
        const t = window.t;
        const statusBadge = this.getS3ImportStatusBadge(chain.status);
        const dateRange = chain.oldest_backup && chain.newest_backup
            ? `${new Date(chain.oldest_backup).toLocaleDateString()} — ${new Date(chain.newest_backup).toLocaleDateString()}`
            : '—';

        let actionHtml = '';
        if (chain.status === 'available') {
            actionHtml = `<button class="btn btn-sm btn-primary" onclick="window.vnbui.importS3Chain('${escapeHtml(chain.chain_id)}')" data-chain-id="${escapeHtml(chain.chain_id)}">${t('s3_import.import_button')}</button>`;
        } else if (chain.status === 'partial') {
            actionHtml = `<button class="btn btn-sm btn-info" onclick="window.vnbui.importS3Chain('${escapeHtml(chain.chain_id)}')" data-chain-id="${escapeHtml(chain.chain_id)}">${t('s3_import.resume_button')}</button>`;
        } else if (chain.status === 'kek_missing') {
            actionHtml = `<span class="text-secondary small" title="${t('s3_import.kek_hint')}" data-bs-toggle="tooltip">${t('s3_import.kek_hint')}</span>`;
        }

        const conflictRows = chain.status === 'conflict' && chain.conflicts?.length
            ? `<tr class="bg-danger-lt"><td colspan="7" class="small text-danger ps-4">
                ${chain.conflicts.map(c => t('s3_import.conflict_detail', { backup_id: c.backup_id.substring(0, 8) })).join('<br>')}
               </td></tr>`
            : '';

        return `
            <tr data-chain-id="${escapeHtml(chain.chain_id)}">
                <td><strong>${escapeHtml(chain.vm_name)}</strong></td>
                <td>${chain.status === 'partial' ? `${chain.imported_count}/${chain.backup_count}` : chain.backup_count}</td>
                <td>${formatSize(chain.total_size_bytes)}</td>
                <td class="text-secondary small">${dateRange}</td>
                <td>${chain.encrypted
                    ? `<span class="badge bg-yellow-lt">${chain.kek_available ? t('common.yes') : 'KEK ✗'}</span>`
                    : `<span class="text-secondary">—</span>`}</td>
                <td>${statusBadge}</td>
                <td>${actionHtml}</td>
            </tr>
            ${conflictRows}
        `;
    }

    getS3ImportStatusBadge(status) {
        const t = window.t;
        const badges = {
            'available': `<span class="badge bg-success-lt">${t('s3_import.status_available')}</span>`,
            'imported': `<span class="badge bg-secondary">${t('s3_import.status_imported')}</span>`,
            'partial': `<span class="badge bg-info-lt">${t('s3_import.status_partial')}</span>`,
            'conflict': `<span class="badge bg-danger-lt">${t('s3_import.status_conflict')}</span>`,
            'kek_missing': `<span class="badge bg-warning-lt">${t('s3_import.status_kek_missing')}</span>`,
        };
        return badges[status] || `<span class="badge bg-secondary">${escapeHtml(enumLabel(status))}</span>`;
    }

    async importS3Chain(chainId) {
        const t = window.t;
        const btn = document.querySelector(`button[data-chain-id="${chainId}"]`);
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner-border spinner-border-sm"></span>`;
        }

        try {
            const result = await apiClient.post('/api/v1/s3/import', { chain_id: chainId });
            window.vnbui.showToast('success', t('s3_import.success', {
                count: result.imported_count,
                vm_name: result.vm_name
            }));

            // Update the row status
            const row = document.querySelector(`tr[data-chain-id="${chainId}"]`);
            if (row) {
                const statusCell = row.querySelector('td:nth-child(6)');
                const actionCell = row.querySelector('td:nth-child(7)');
                if (statusCell) statusCell.innerHTML = this.getS3ImportStatusBadge('imported');
                if (actionCell) actionCell.innerHTML = '';
            }

            // Refresh backup list behind the modal
            this.loadData();
        } catch (error) {
            console.error('S3 import failed:', error);
            window.vnbui.showToast('error', t('s3_import.error_import', { error: error.message }));
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = t('s3_import.import_button');
            }
        }
    }

    getFilteredBackups() {
        let filtered = this.filter === 'all'
            ? this.backups
            : this.backups.filter(b => this.filter === 'running' ? activeStatuses.includes(b.status) : b.status === this.filter);

        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            filtered = filtered.filter(b =>
                (b.vm_name || '').toLowerCase().includes(q)
            );
        }

        return filtered;
    }

    getFilteredCount(status) {
        return this.backups.filter(b => status === 'running' ? activeStatuses.includes(b.status) : b.status === status).length;
    }

    formatExpiryDate(createdAt, retentionDays) {
        const t = window.t;
        if (!createdAt || !retentionDays) return t('common.never');
        const expiry = new Date(createdAt);
        expiry.setDate(expiry.getDate() + retentionDays);
        const now = new Date();
        const diffDays = Math.ceil((expiry - now) / 86400000);

        if (diffDays < 0) return t('backups.expired');
        if (diffDays === 0) return t('backups.today');
        if (diffDays === 1) return t('backups.tomorrow');
        return t('backups.expiry_days', { count: diffDays });
    }

    formatETA(isoString) {
        if (!isoString) return '';
        try {
            const eta = new Date(isoString);
            const now = new Date();
            const diffMs = eta - now;
            if (diffMs < 0) return '';

            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMs / 3600000);

            if (diffHours > 0) {
                const mins = diffMins % 60;
                return ` (${diffHours}h ${mins}m)`;
            }
            return ` (${diffMins}m)`;
        } catch (e) {
            return '';
        }
    }

    /**
     * Subscribe to real-time backup updates (Phase 1)
     */
    subscribeToUpdates() {
        // Clean up old subscription
        if (this.updateSubscription) {
            this.updateSubscription();
        }
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
        }

        if (this.resyncSubscription) this.resyncSubscription();
        const updateGeneration = this.updateGeneration = (this.updateGeneration || 0) + 1;
        this.resyncSubscription = updateService.subscribeResync(async () => {
            if (await this.loadData() === false) throw new Error('Backup resynchronization failed');
            if (this.updateGeneration !== updateGeneration) return;
            if (!document.querySelector('.modal.show')) await window.vnbui.refreshPage();
        });

        // Subscribe to all backup events
        this.updateSubscription = updateService.subscribe('*', (data) => {
            console.log('Backup update received:', data);

            // Handle different backup events
            if (data.type === 'backup_started') {
                this.handleBackupStarted(data.payload);
            } else if (data.type === 'backup_progress') {
                this.handleBackupProgress(data.payload);
            } else if (data.type === 'backup_completed') {
                this.handleBackupCompleted(data.payload);
            } else if (data.type === 'backup_failed') {
                this.handleBackupFailed(data.payload);
            }
        });

        // Set up polling fallback (every 30s) for progress updates
        this.pollingInterval = setInterval(async () => {
            // Reconcile snapshots even with a connected socket: an event can
            // be missed during reconnect or another backend worker's delivery.
            await this.refreshProgress();
        }, 30000);
    }

    /**
     * Refresh progress data via API (polling fallback)
     */
    async refreshProgress() {
        try {
            const responses = await Promise.all(activeStatuses.map(status =>
                loadSnapshot(`/api/v1/backups?status=${status}`)));
            const backups = responses.flat();

            const currentIds = new Set(backups.map(b => b.id));

            // Reconcile starts and finishes whose socket notification was lost.
            const knownActiveIds = new Set([
                ...(this._knownRunningIds || []),
                ...this.backups.filter(b => activeStatuses.includes(b.status)).map(b => b.id)
            ]);
            const finished = [...knownActiveIds].some(id => !currentIds.has(id));
            const started = backups.some(backup => !knownActiveIds.has(backup.id));
            if (finished || started) {
                if (await this.loadData() === false) return;
                this._knownRunningIds = currentIds;
                if (!document.querySelector('.modal.show')) {
                    window.vnbui.refreshPage();
                }
                return;
            }
            this._knownRunningIds = currentIds;

            backups.forEach(backup => {
                this.handleBackupProgress({
                    backup_id: backup.id,
                    status: backup.status,
                    ...(Object.hasOwn(backup, 'operator_dispatch') ? {operator_dispatch: backup.operator_dispatch} : {}),
                    progress: backup.progress,
                    bytes_transferred: backup.storage_progress?.bytes_transferred,
                    total_bytes: backup.storage_progress?.total_bytes,
                    phase: backup.storage_progress?.phase,
                    estimated_completion: backup.tags?.estimated_completion
                });
            });
        } catch (e) {
            console.debug('Failed to refresh progress:', e);
        }
    }

    /**
     * Handle backup started event
     */
    handleBackupStarted(data) {
        // Reload data to show new backup - check for modal first
        this.loadData().then(() => {
            if (!document.querySelector('.modal.show')) {
                window.vnbui.refreshPage();
            }
        });
    }

    /**
     * Handle backup progress event - update DOM directly without full reload
     */
    handleBackupProgress(data) {
        const { backup_id, progress, estimated_completion, status } = data;
        if (Object.hasOwn(data, 'operator_dispatch')) {
            const current = this.backups.find(item => item.id === backup_id);
            if (current) current.operator_dispatch = data.operator_dispatch;
            const row = document.querySelector(`tr[data-backup-id="${backup_id}"]`);
            const notice = row?.querySelector('.backup-dispatch');
            if (notice) notice.innerHTML = renderOperatorDispatch(data.operator_dispatch);
            const details = row?.nextElementSibling?.querySelector('.backup-dispatch-details');
            if (details) details.innerHTML = renderOperatorDispatch(data.operator_dispatch);
        }
        if (!Number.isInteger(progress) || progress < 0 || progress > 100) return;
        const backup = this.backups.find(item => item.id === backup_id);
        if (backup) {
            if (!activeStatuses.includes(backup.status)) return;
            backup.progress = progress;
            if (activeStatuses.includes(status)) backup.status = status;
            if (Number.isSafeInteger(data.bytes_transferred) && Number.isSafeInteger(data.total_bytes)
                && data.bytes_transferred >= 0 && data.bytes_transferred <= data.total_bytes) {
                backup.storage_progress = {...backup.storage_progress,
                    bytes_transferred: data.bytes_transferred, total_bytes: data.total_bytes};
                if (['pending', 'preparing', 'uploading', 'finalizing'].includes(data.phase)) {
                    backup.storage_progress.phase = data.phase;
                }
            }
        }

        // Find and update the row
        const row = document.querySelector(`tr[data-backup-id="${backup_id}"]`);
        if (row) {
            const progressBar = row.querySelector('.progress-bar');
            const progressText = row.querySelector('.backup-progress-text');

            if (progressBar) {
                progressBar.style.width = `${progress}%`;
                progressBar.setAttribute('aria-valuenow', String(progress));
            }
            if (progressText) {
                progressText.textContent = `${progress}%${this.formatETA(estimated_completion)}`;
            }
            const badge = row.querySelector('.backup-status');
            if (badge && activeStatuses.includes(status)) {
                badge.className = `badge backup-status bg-${getStatusColor(status, 'backup')}`;
                badge.textContent = enumLabel(status);
            }
            const transfer = row.querySelector('.backup-transfer-text');
            if (transfer && data.total_bytes !== undefined) transfer.textContent = this.transferText(data);
        }
    }

    transferText(data) {
        if (!Number.isSafeInteger(data?.bytes_transferred) || !Number.isSafeInteger(data?.total_bytes)
            || data.bytes_transferred < 0 || data.total_bytes <= 0 || data.bytes_transferred > data.total_bytes) return '';
        // A non-breaking space keeps the unit attached to its value when a
        // narrow console would otherwise wrap e.g. "786.25" and "MB" apart.
        const joined = value => formatSize(value).replace(' ', '\u00a0');
        return `${joined(data.bytes_transferred)} / ${joined(data.total_bytes)}`;
    }

    /**
     * Handle backup completed event
     */
    handleBackupCompleted(data) {
        // Show success notification
        window.vnbui.showToast('success', `Backup ${data.backup_id.substring(0, 8)} completed`);

        // Reload to show completed status - check for modal first
        this.loadData().then(() => {
            if (!document.querySelector('.modal.show')) {
                window.vnbui.refreshPage();
            }
        });
    }

    /**
     * Handle backup failed event
     */
    handleBackupFailed(data) {
        // Show error notification with details
        const id = data.backup_id ? data.backup_id.substring(0, 8) : '?';
        const reason = data.error ? `: ${data.error}` : '';
        window.vnbui.showToast(`Backup ${id} failed${reason}`, 'error');

        // Reload to show failed status - check for modal first
        this.loadData().then(() => {
            if (!document.querySelector('.modal.show')) {
                window.vnbui.refreshPage();
            }
        });
    }

    /**
     * Cleanup when leaving page
     */
    destroy() {
        this.updateGeneration = (this.updateGeneration || 0) + 1;
        this.resyncSubscription?.();
        this.resyncSubscription = null;
        if (this.updateSubscription) {
            this.updateSubscription();
            this.updateSubscription = null;
        }
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }
    }
}
