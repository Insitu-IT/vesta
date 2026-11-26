import { contextHelp } from '../components/context-help.js';
/**
 * Schedules Page
 * Manage backup schedules with cron expressions
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime, formatDate } from '../utils/format.js';
import { assetResolver } from '../assets/resolver.js';

export class SchedulesPage {
    constructor() {
        this.schedules = [];
        this.vms = [];
        this.groups = [];
        this.loading = false;
        this.searchQuery = '';
        this._searchTimeout = null;
    }

    async loadData() {
        this.loading = true;
        try {
            const [scheduleData, vmData, groupData] = await Promise.all([
                apiClient.get('/api/v1/schedules'),
                apiClient.get('/api/v1/vms?limit=100'),
                apiClient.get('/api/v1/groups?limit=100')
            ]);
            this.schedules = scheduleData.items || scheduleData.schedules || [];
            this.vms = vmData.items || [];
            this.groups = groupData.items || [];
        } catch (error) {
            console.error('Failed to load schedules:', error);
            this.schedules = [];
            this.vms = [];
            this.groups = [];
        }
        this.loading = false;
    }

    async render() {
        await this.loadData();
        const t = window.t;

        setTimeout(() => this.setupEventListeners(), 0);

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <rect x="4" y="5" width="16" height="16" rx="2" />
                                    <line x1="16" y1="3" x2="16" y2="7" />
                                    <line x1="8" y1="3" x2="8" y2="7" />
                                    <line x1="4" y1="11" x2="20" y2="11" />
                                    <rect x="8" y="15" width="2" height="2" />
                                </svg>
                                ${t('schedules.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('schedules.page_subtitle')} · UTC</div>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
                            <div class="btn-list">
                                <button class="btn btn-primary d-none d-sm-inline-block" onclick="window.vnbui.createSchedule()">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <line x1="12" y1="5" x2="12" y2="19" />
                                        <line x1="5" y1="12" x2="19" y2="12" />
                                    </svg>
                                    ${t('schedules.new_schedule')}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">${t('schedules.all_schedules', { count: this.schedules.length })}</h3>
                            <div class="ms-auto">
                                <div class="input-group search-control">
                                    <input type="text" class="form-control form-control-sm" placeholder="${t('schedules.search_placeholder')}" id="schedule-search">
                                    <span class="input-group-text">
                                        <i class="ti ti-search icon" aria-hidden="true"></i>
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-vcenter card-table table-striped">
                                <thead>
                                    <tr>
                                        <th>${t('schedules.col_name')}</th>
                                        <th>${t('schedules.col_vm_group')}</th>
                                        <th>${t('schedules.col_schedule')}</th>
                                        <th>${t('schedules.col_type')}</th>
                                        <th>${t('schedules.col_retention')}</th>
                                        <th>${t('schedules.col_next_run')}</th>
                                        <th>${t('schedules.col_status')}</th>
                                        <th class="w-1">${t('common.actions')}</th>
                                    </tr>
                                </thead>
                                <tbody id="schedules-table-body">
                                    ${this.renderScheduleRows()}
                                </tbody>
                            </table>
                        </div>
                        ${this.schedules.length === 0 ? this.renderEmptyState() : ''}
                    </div>
                </div>
            </div>

            ${this.renderScheduleModal()}
            ${this.renderDeleteModal()}
        `;
    }

    setupEventListeners() {
        const searchInput = document.getElementById('schedule-search');
        if (searchInput) {
            searchInput.value = this.searchQuery;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this._searchTimeout);
                this._searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value;
                    const tbody = document.getElementById('schedules-table-body');
                    if (tbody) tbody.innerHTML = this.renderScheduleRows();
                }, 300);
            });
        }
    }

    renderScheduleRows() {
        if (this.schedules.length === 0) {
            return '';
        }
        const t = window.t;

        let filtered = this.schedules;
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            filtered = filtered.filter(s =>
                (s.name || '').toLowerCase().includes(q) ||
                (s.vm_name || '').toLowerCase().includes(q) ||
                (s.vm_group_name || '').toLowerCase().includes(q)
            );
        }

        if (filtered.length === 0) {
            return `<tr><td colspan="8" class="text-center text-secondary py-4">${t('common.no_results', { query: this.searchQuery })}</td></tr>`;
        }

        return filtered.map(schedule => `
            <tr>
                <td>
                    <div>
                        <div class="font-weight-medium">${escapeHtml(schedule.name || t('schedules.unnamed'))}</div>
                        <div class="text-secondary small">${escapeHtml(schedule.description || '')}</div>
                    </div>
                </td>
                <td>
                    ${schedule.vm_id ? `
                        <span class="badge bg-blue-lt">${escapeHtml(schedule.vm_name || schedule.vm_id)}</span>
                    ` : `
                        <span class="badge bg-purple-lt">${escapeHtml(schedule.vm_group_name || schedule.vm_group_id || t('schedules.all_vms'))}</span>
                    `}
                </td>
                <td>
                    <div class="font-monospace small">${escapeHtml(schedule.cron_expression || '')}</div>
                    <div class="text-secondary small">${this.formatCronDescription(schedule.cron_expression)}</div>
                </td>
                <td>
                    <span class="text-secondary">${escapeHtml(schedule.backup_type || 'full')}</span>
                    ${schedule.backup_type === 'automatic' ? `
                        <div class="text-secondary small">${escapeHtml(t('schedules.policy_summary', {
                            days: schedule.backup_policy?.full_every_days,
                            count: schedule.backup_policy?.max_incrementals
                        }))}</div>
                    ` : ''}
                </td>
                <td>${t('schedules.retention_days', { days: schedule.retention_days || 0 })}</td>
                <td>
                    ${schedule.enabled && schedule.next_run_at ? `
                        <div>${formatDate(schedule.next_run_at)}</div>
                        <div class="text-secondary small">${formatRelativeTime(schedule.next_run_at)}</div>
                    ` : `
                        <span class="text-secondary">—</span>
                    `}
                </td>
                <td>
                    <label class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" ${schedule.enabled ? 'checked' : ''}
                               onchange="window.vnbui.toggleSchedule('${escapeHtml(schedule.id)}', this.checked)">
                    </label>
                    <div class="text-secondary small">${escapeHtml(schedule.authority_state || 'unenrolled')}</div>
                </td>
                <td>
                    <div class="btn-list flex-nowrap">
                        ${window.vnbui?.currentUserRole === 'admin' ? `
                            <button class="btn btn-sm btn-outline-primary" onclick="window.vnbui.enrollScheduleGrant('${escapeHtml(schedule.id)}')">${t('schedules.enroll_grant')}</button>
                            ${schedule.current_grant_id ? `<button class="btn btn-sm btn-outline-warning" onclick="window.vnbui.revokeScheduleGrant('${escapeHtml(schedule.id)}')">${t('schedules.revoke_grant')}</button>` : ''}
                        ` : ''}
                        <button class="btn btn-sm btn-ghost-secondary" onclick="window.vnbui.editSchedule('${escapeHtml(schedule.id)}')" title="${t('schedules.edit_tooltip')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <path d="M9 7h-3a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-3" />
                                <path d="M9 15h3l8.5 -8.5a1.5 1.5 0 0 0 -3 -3l-8.5 8.5v3" />
                                <line x1="16" y1="5" x2="19" y2="8" />
                            </svg>
                        </button>
                        <button class="btn btn-sm btn-ghost-danger" onclick="window.vnbui.deleteSchedule('${escapeHtml(schedule.id)}', '${escapeHtml(schedule.name)}')" title="${t('schedules.delete_tooltip')}">
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
        `).join('');
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty">
                <div class="empty-img">
                    <div class="empty-icon">${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}</div>
                </div>
                <p class="empty-title">${t('schedules.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${t('schedules.empty_subtitle')}
                </p>
                <div class="empty-action">
                    <button class="btn btn-primary" onclick="window.vnbui.createSchedule()">
                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                            <line x1="12" y1="5" x2="12" y2="19" />
                            <line x1="5" y1="12" x2="19" y2="12" />
                        </svg>
                        ${t('schedules.new_schedule')}
                    </button>
                </div>
            </div>
        `;
    }

    renderScheduleModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-schedule" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="schedule-modal-title">${t('schedules.create_title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="schedule-id">

                            <div class="mb-3">
                                <label class="form-label required">${t('schedules.name_label')}</label>
                                <input type="text" class="form-control" id="schedule-name" placeholder="${t('schedules.name_placeholder')}">
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('schedules.description_label')}</label>
                                <input type="text" class="form-control" id="schedule-description" placeholder="${t('schedules.description_placeholder')}">
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label required">${t('schedules.target_label')} ${contextHelp('schedule')}</label>
                                        <select class="form-select" id="schedule-target-type" onchange="window.vnbui.updateScheduleTarget()">
                                            <option value="vm">${t('schedules.target_vm')}</option>
                                            <option value="group">${t('schedules.target_group')}</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3" id="schedule-vm-group">
                                        <label class="form-label required">${t('schedules.select_vm')}</label>
                                        <select class="form-select" id="schedule-vm-id">
                                            <option value="">${t('schedules.select_vm')}</option>
                                            ${this.vms.map(vm => `<option value="${escapeHtml(vm.id)}">${escapeHtml(vm.name)} (${escapeHtml(vm.agent_hostname || '')})</option>`).join('')}
                                        </select>
                                    </div>
                                    <div class="mb-3" id="schedule-group-group" style="display: none;">
                                        <label class="form-label required">${t('schedules.select_group')}</label>
                                        <select class="form-select" id="schedule-group-id">
                                            <option value="">${t('schedules.select_group')}</option>
                                            ${this.groups.map(group => `<option value="${escapeHtml(group.id)}">${escapeHtml(group.name)} (${group.vm_count || 0})</option>`).join('')}
                                        </select>
                                    </div>
                                </div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label required">${t('schedules.frequency_label')}</label>
                                <select class="form-select" id="schedule-frequency" onchange="window.vnbui.updateScheduleOptions()">
                                    <option value="daily">${t('schedules.freq_daily')}</option>
                                    <option value="hourly">${t('schedules.freq_hourly')}</option>
                                    <option value="weekly">${t('schedules.freq_weekly')}</option>
                                    <option value="monthly">${t('schedules.freq_monthly')}</option>
                                    <option value="custom">${t('schedules.freq_custom')}</option>
                                </select>
                            </div>

                            <!-- Daily options -->
                            <div class="mb-3" id="schedule-daily-options">
                                <label class="form-label">${t('schedules.time_label')}</label>
                                <select class="form-select" id="schedule-daily-hour" onchange="window.vnbui.updateScheduleOptions()">
                                    ${Array.from({length: 24}, (_, i) => `<option value="${i}" ${i === 2 ? 'selected' : ''}>${i.toString().padStart(2, '0')}:00</option>`).join('')}
                                </select>
                            </div>

                            <!-- Hourly options -->
                            <div class="mb-3" id="schedule-hourly-options" style="display: none;">
                                <label class="form-label">${t('schedules.run_every')}</label>
                                <select class="form-select" id="schedule-hourly-interval" onchange="window.vnbui.updateScheduleOptions()">
                                    <option value="1">1 hour</option>
                                    <option value="2">2 hours</option>
                                    <option value="3">3 hours</option>
                                    <option value="4">4 hours</option>
                                    <option value="6" selected>6 hours</option>
                                    <option value="8">8 hours</option>
                                    <option value="12">12 hours</option>
                                </select>
                            </div>

                            <!-- Weekly options -->
                            <div class="row mb-3" id="schedule-weekly-options" style="display: none;">
                                <div class="col-md-6">
                                    <label class="form-label">${t('schedules.day_label')}</label>
                                    <select class="form-select" id="schedule-weekly-day" onchange="window.vnbui.updateScheduleOptions()">
                                        <option value="0">${t('schedules.day_sun')}</option>
                                        <option value="1">${t('schedules.day_mon')}</option>
                                        <option value="2">${t('schedules.day_tue')}</option>
                                        <option value="3">${t('schedules.day_wed')}</option>
                                        <option value="4">${t('schedules.day_thu')}</option>
                                        <option value="5">${t('schedules.day_fri')}</option>
                                        <option value="6">${t('schedules.day_sat')}</option>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">${t('schedules.time_label')}</label>
                                    <select class="form-select" id="schedule-weekly-hour" onchange="window.vnbui.updateScheduleOptions()">
                                        ${Array.from({length: 24}, (_, i) => `<option value="${i}" ${i === 0 ? 'selected' : ''}>${i.toString().padStart(2, '0')}:00</option>`).join('')}
                                    </select>
                                </div>
                            </div>

                            <!-- Monthly options -->
                            <div class="row mb-3" id="schedule-monthly-options" style="display: none;">
                                <div class="col-md-6">
                                    <label class="form-label">${t('schedules.day_of_month')}</label>
                                    <select class="form-select" id="schedule-monthly-day" onchange="window.vnbui.updateScheduleOptions()">
                                        ${Array.from({length: 28}, (_, i) => `<option value="${i + 1}" ${i === 0 ? 'selected' : ''}>${i + 1}</option>`).join('')}
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">${t('schedules.time_label')}</label>
                                    <select class="form-select" id="schedule-monthly-hour" onchange="window.vnbui.updateScheduleOptions()">
                                        ${Array.from({length: 24}, (_, i) => `<option value="${i}" ${i === 0 ? 'selected' : ''}>${i.toString().padStart(2, '0')}:00</option>`).join('')}
                                    </select>
                                </div>
                            </div>

                            <!-- Custom cron -->
                            <div class="mb-3" id="schedule-custom-options" style="display: none;">
                                <label class="form-label">${t('schedules.cron_label')}</label>
                                <input type="text" class="form-control font-monospace" id="schedule-cron" placeholder="0 2 * * *" oninput="window.vnbui.updateScheduleOptions()">
                                <div class="form-hint">
                                    ${t('schedules.cron_hint')} (e.g., <code>0 2 * * *</code>)
                                </div>
                            </div>

                            <!-- Preview -->
                            <div class="mb-3">
                                <div class="d-flex align-items-center text-secondary">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon me-1" width="16" height="16" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <circle cx="12" cy="12" r="9" />
                                        <polyline points="12 7 12 12 15 15" />
                                    </svg>
                                    <span id="schedule-preview">${t('schedules.preview_daily', { hour: '02' })}</span>
                                </div>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label required">${t('schedules.backup_type_label')} ${contextHelp('backup_type')}</label>
                                        <select class="form-select" id="schedule-backup-type" onchange="window.vnbui.updateSchedulePolicy()">
                                            <option value="full">${t('schedules.type_full')}</option>
                                            <option value="incremental">${t('schedules.type_incremental')}</option>
                                            <option value="automatic">${t('schedules.type_automatic')}</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label required">${t('schedules.retention_label')} ${contextHelp('retention')}</label>
                                        <input type="number" class="form-control" id="schedule-retention" value="30" min="1" max="365">
                                    </div>
                                </div>
                            </div>

                            <div id="schedule-policy-options" class="mb-3" hidden>
                                <div class="row">
                                    <div class="col-md-6">
                                        <label class="form-label" for="schedule-full-every-days">${t('schedules.full_every_days')}</label>
                                        <input type="number" class="form-control" id="schedule-full-every-days" value="7" min="1" max="36500" step="1">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" for="schedule-max-incrementals">${t('schedules.max_incrementals')}</label>
                                        <input type="number" class="form-control" id="schedule-max-incrementals" value="6" min="1" max="255" step="1">
                                    </div>
                                </div>
                                <div class="form-hint">${t('schedules.policy_hint')}</div>
                            </div>

                            <div class="row">
                                <div class="col-md-8">
                                    <div class="mb-3">
                                        <label class="form-label" for="schedule-exclude-disks">${t('schedules.exclude_disks_label')}</label>
                                        <input type="text" class="form-control" id="schedule-exclude-disks" placeholder="boot, data-extra">
                                        <div class="form-hint">${t('schedules.exclude_disks_hint')}</div>
                                    </div>
                                </div>
                            </div>

                            <div class="mb-3">
                                <label class="form-check">
                                    <input type="checkbox" class="form-check-input" id="schedule-enabled">
                                    <span class="form-check-label">${t('schedules.enable_schedule')}</span>
                                </label>
                                <div class="form-hint">${t('schedules.enrollment_hint')}</div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-primary" onclick="window.vnbui.submitSchedule()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <polyline points="9 11 12 14 20 6" />
                                    <path d="M20 12v6a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h9" />
                                </svg>
                                ${t('schedules.save_schedule')}
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
            <div class="modal modal-blur fade" id="modal-delete-schedule" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-sm modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-body">
                            <div class="modal-title">${t('schedules.delete_title')}</div>
                            <div>${t('schedules.delete_msg', { name: '<strong id="delete-schedule-name"></strong>' })}</div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-danger" onclick="window.vnbui.submitDeleteSchedule()">${t('schedules.delete_button')}</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    formatCronDescription(cron) {
        if (!cron) return '';
        const t = window.t;
        const dayNames = [
            t('schedules.day_sun'), t('schedules.day_mon'), t('schedules.day_tue'),
            t('schedules.day_wed'), t('schedules.day_thu'), t('schedules.day_fri'),
            t('schedules.day_sat')
        ];

        // Parse basic patterns
        const parts = cron.split(' ');
        if (parts.length >= 5) {
            const [min, hour, day, month, dow] = parts;

            if (min === '0' && hour !== '*' && day === '*' && month === '*' && dow === '*') {
                return t('schedules.preview_daily', { hour: hour.padStart(2, '0') });
            }
            if (min === '0' && hour.startsWith('*/')) {
                return t('schedules.preview_hourly', { hours: hour.substring(2) });
            }
            if (min === '0' && hour !== '*' && day === '*' && month === '*' && dow !== '*') {
                return t('schedules.preview_weekly', { day: dayNames[parseInt(dow)] || dow, hour: hour.padStart(2, '0') });
            }
            if (min === '0' && hour !== '*' && day !== '*' && month === '*' && dow === '*') {
                return t('schedules.preview_monthly', { day: day, hour: hour.padStart(2, '0') });
            }
        }

        return t('schedules.preview_custom');
    }

}
