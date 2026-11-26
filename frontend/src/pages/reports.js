/**
 * Reports Page
 * Generate and download reports
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime, formatDate, formatSize } from '../utils/format.js';
import { assetResolver } from '../assets/resolver.js';

export class ReportsPage {
    constructor() {
        this.reports = [];
        this.loading = false;
    }

    async loadData() {
        this.loading = true;
        try {
            const data = await apiClient.get('/api/v1/reports');
            this.reports = data.items || data.reports || [];
        } catch (error) {
            console.error('Failed to load reports:', error);
            this.reports = [];
        }
        this.loading = false;
    }

    async render() {
        const t = window.t;
        await this.loadData();

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M9 5h-2a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-12a2 2 0 0 0 -2 -2h-2" />
                                    <rect x="9" y="3" width="6" height="4" rx="2" />
                                    <line x1="9" y1="12" x2="9.01" y2="12" />
                                    <line x1="13" y1="12" x2="15" y2="12" />
                                    <line x1="9" y1="16" x2="9.01" y2="16" />
                                    <line x1="13" y1="16" x2="15" y2="16" />
                                </svg>
                                ${t('reports.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('reports.page_subtitle')}</div>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
                            <div class="btn-list">
                                <button class="btn btn-primary d-none d-sm-inline-block" onclick="window.vnbui.generateReport()">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <line x1="12" y1="5" x2="12" y2="19" />
                                        <line x1="5" y1="12" x2="19" y2="12" />
                                    </svg>
                                    ${t('reports.generate_report')}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    <div class="row row-cards">
                        <!-- Report Types -->
                        <div class="col-lg-3">
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="card-title">${t('reports.quick_reports')}</h3>
                                </div>
                                <div class="card-body">
                                    <div class="list-group list-group-flush">
                                        <a href="#" class="list-group-item list-group-item-action" onclick="window.vnbui.quickReport('backup_summary'); return false;">
                                            <div class="row align-items-center">
                                                <div class="col-auto">
                                                    <span class="avatar avatar-sm bg-primary-lt">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                            <ellipse cx="12" cy="6" rx="8" ry="3"></ellipse>
                                                            <path d="M4 6v6a8 3 0 0 0 16 0v-6" />
                                                            <path d="M4 12v6a8 3 0 0 0 16 0v-6" />
                                                        </svg>
                                                    </span>
                                                </div>
                                                <div class="col">
                                                    <div class="font-weight-medium">${t('reports.report_backup_summary')}</div>
                                                    <div class="text-secondary small">Overview of all backups</div>
                                                </div>
                                            </div>
                                        </a>
                                        <a href="#" class="list-group-item list-group-item-action" onclick="window.vnbui.quickReport('vm_inventory'); return false;">
                                            <div class="row align-items-center">
                                                <div class="col-auto">
                                                    <span class="avatar avatar-sm bg-info-lt">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                            <rect x="3" y="4" width="18" height="12" rx="1" />
                                                            <line x1="7" y1="8" x2="10" y2="8" />
                                                            <line x1="7" y1="12" x2="10" y2="12" />
                                                        </svg>
                                                    </span>
                                                </div>
                                                <div class="col">
                                                    <div class="font-weight-medium">VM Inventory</div>
                                                    <div class="text-secondary small">List of all virtual machines</div>
                                                </div>
                                            </div>
                                        </a>
                                        <a href="#" class="list-group-item list-group-item-action" onclick="window.vnbui.quickReport('schedule_status'); return false;">
                                            <div class="row align-items-center">
                                                <div class="col-auto">
                                                    <span class="avatar avatar-sm bg-success-lt">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                            <rect x="4" y="5" width="16" height="16" rx="2" />
                                                            <line x1="16" y1="3" x2="16" y2="7" />
                                                            <line x1="8" y1="3" x2="8" y2="7" />
                                                            <line x1="4" y1="11" x2="20" y2="11" />
                                                        </svg>
                                                    </span>
                                                </div>
                                                <div class="col">
                                                    <div class="font-weight-medium">Schedule Status</div>
                                                    <div class="text-secondary small">Active backup schedules</div>
                                                </div>
                                            </div>
                                        </a>
                                        <a href="#" class="list-group-item list-group-item-action" onclick="window.vnbui.quickReport('failed_backups'); return false;">
                                            <div class="row align-items-center">
                                                <div class="col-auto">
                                                    <span class="avatar avatar-sm bg-danger-lt">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                            <path d="M12 9v2m0 4v.01" />
                                                            <path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75" />
                                                        </svg>
                                                    </span>
                                                </div>
                                                <div class="col">
                                                    <div class="font-weight-medium">Failed Backups</div>
                                                    <div class="text-secondary small">Backups that failed</div>
                                                </div>
                                            </div>
                                        </a>
                                        <a href="#" class="list-group-item list-group-item-action" onclick="window.vnbui.quickReport('storage_usage'); return false;">
                                            <div class="row align-items-center">
                                                <div class="col-auto">
                                                    <span class="avatar avatar-sm bg-warning-lt">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                                            <path d="M4 6h16v-1a1 1 0 0 0 -1 -1h-14a1 1 0 0 0 -1 1v1z" />
                                                            <path d="M4 6v6a1 1 0 0 0 1 1h14a1 1 0 0 0 1 -1v-6" />
                                                            <path d="M4 12v6a1 1 0 0 0 1 1h14a1 1 0 0 0 1 -1v-6" />
                                                        </svg>
                                                    </span>
                                                </div>
                                                <div class="col">
                                                    <div class="font-weight-medium">${t('reports.report_storage')}</div>
                                                    <div class="text-secondary small">Backup storage statistics</div>
                                                </div>
                                            </div>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Report History -->
                        <div class="col-lg-9">
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="card-title">${t('reports.all_reports')}</h3>
                                </div>
                                <div class="table-responsive">
                                    <table class="table table-vcenter card-table table-striped">
                                        <thead>
                                            <tr>
                                                <th>${t('reports.col_name')}</th>
                                                <th>${t('reports.col_type')}</th>
                                                <th>${t('reports.format')}</th>
                                                <th>${t('reports.col_last_generated')}</th>
                                                <th>${t('reports.col_status')}</th>
                                                <th class="w-1">${t('common.actions')}</th>
                                            </tr>
                                        </thead>
                                        <tbody id="reports-table-body">
                                            ${this.renderReportRows()}
                                        </tbody>
                                    </table>
                                </div>
                                ${this.reports.length === 0 ? this.renderEmptyState() : ''}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.renderGenerateReportModal()}
        `;
    }

    renderReportRows() {
        const t = window.t;
        if (this.reports.length === 0) {
            return '';
        }

        return this.reports.map(report => `
            <tr>
                <td>
                    <div class="font-weight-medium">${escapeHtml(report.name || 'Untitled Report')}</div>
                    <div class="text-secondary small">${escapeHtml(report.description || '')}</div>
                </td>
                <td>
                    <span class="badge bg-${this.getReportTypeColor(report.report_type)}">
                        ${escapeHtml(this.formatReportType(report.report_type))}
                    </span>
                </td>
                <td>
                    <span class="text-secondary text-uppercase">${escapeHtml(report.format || 'pdf')}</span>
                </td>
                <td>
                    <div>${formatDate(report.created_at)}</div>
                    <div class="text-secondary small">${formatRelativeTime(report.created_at)}</div>
                </td>
                <td>${formatSize(report.file_size)}</td>
                <td>
                    <div class="btn-list flex-nowrap">
                        <button class="btn btn-sm btn-primary" onclick="window.vnbui.downloadReport('${escapeHtml(report.id)}')" title="${t('reports.download')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2 -2v-2" />
                                <polyline points="7 11 12 16 17 11" />
                                <line x1="12" y1="4" x2="12" y2="16" />
                            </svg>
                        </button>
                        <button class="btn btn-sm btn-ghost-danger" onclick="window.vnbui.deleteReport('${escapeHtml(report.id)}', '${escapeHtml(report.name)}')" title="${t('reports.delete_report')}">
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
                <p class="empty-title">${t('reports.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${t('reports.empty_subtitle')}
                </p>
            </div>
        `;
    }

    renderGenerateReportModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-generate-report" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${t('reports.generate_title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label required">${t('reports.report_type')}</label>
                                <select class="form-select" id="report-type">
                                    <option value="backup_summary">${t('reports.report_backup_summary')}</option>
                                    <option value="vm_inventory">VM Inventory</option>
                                    <option value="schedule_status">Schedule Status</option>
                                    <option value="failed_backups">Failed Backups</option>
                                    <option value="storage_usage">${t('reports.report_storage')}</option>
                                    <option value="agent_health">${t('reports.report_agent_status')}</option>
                                    <option value="custom">Custom Report</option>
                                </select>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label required">${t('reports.date_range')}</label>
                                        <select class="form-select" id="report-date-range">
                                            <option value="today">Today</option>
                                            <option value="week">${t('reports.range_week')}</option>
                                            <option value="month" selected>${t('reports.range_month')}</option>
                                            <option value="quarter">${t('reports.range_quarter')}</option>
                                            <option value="year">Last 365 days</option>
                                            <option value="custom">Custom Range</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label required">${t('reports.format')}</label>
                                        <select class="form-select" id="report-format">
                                            <option value="pdf">${t('reports.format_pdf')}</option>
                                            <option value="csv">${t('reports.format_csv')}</option>
                                            <option value="json">${t('reports.format_json')}</option>
                                            <option value="html">HTML</option>
                                        </select>
                                    </div>
                                </div>
                            </div>

                            <div class="mb-3" id="custom-date-range" style="display: none;">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label class="form-label">Start Date</label>
                                        <input type="date" class="form-control" id="report-start-date">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">End Date</label>
                                        <input type="date" class="form-control" id="report-end-date">
                                    </div>
                                </div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Report Name</label>
                                <input type="text" class="form-control" id="report-name" placeholder="Auto-generated based on type and date">
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Additional Options</label>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="report-include-charts" checked>
                                    <label class="form-check-label" for="report-include-charts">
                                        Include charts and visualizations
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="report-include-details">
                                    <label class="form-check-label" for="report-include-details">
                                        Include detailed records
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="report-compress">
                                    <label class="form-check-label" for="report-compress">
                                        Compress report (ZIP)
                                    </label>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-primary" onclick="window.vnbui.submitGenerateReport()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M14 3v4a1 1 0 0 0 1 1h4" />
                                    <path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z" />
                                </svg>
                                ${t('reports.generate_button')}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getReportTypeColor(type) {
        const colors = {
            'backup_summary': 'primary',
            'vm_inventory': 'info',
            'schedule_status': 'success',
            'failed_backups': 'danger',
            'storage_usage': 'warning',
            'agent_health': 'purple'
        };
        return colors[type] || 'secondary';
    }

    formatReportType(type) {
        const types = {
            'backup_summary': 'Backup Summary',
            'vm_inventory': 'VM Inventory',
            'schedule_status': 'Schedule Status',
            'failed_backups': 'Failed Backups',
            'storage_usage': 'Storage Usage',
            'agent_health': 'Agent Health'
        };
        return types[type] || type;
    }

}
