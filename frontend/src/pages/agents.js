import { contextHelp } from '../components/context-help.js';
import { agentProvider } from '../utils/agent-scope.js';
import { enumLabel, storageCapacity } from '../utils/status-labels.js';
/**
 * Agents Page
 * Monitor and manage backup agents
 */
import { operatorText } from '../services/operator-requests.service.js';
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime, formatDate } from '../utils/format.js';
import { getStatusColor } from '../utils/status-colors.js';
import { assetResolver } from '../assets/resolver.js';

export class AgentsPage {
    constructor() {
        this.agents = [];
        this.loading = false;
        this.searchQuery = '';
        this._searchTimeout = null;
    }

    async loadData() {
        this.loading = true;
        try {
            const data = await apiClient.get('/api/v1/agents');
            this.agents = Array.isArray(data) ? data : (data.items || data.agents || []);
        } catch (error) {
            console.error('Failed to load agents:', error);
            this.agents = [];
        }
        this.loading = false;
    }

    async render() {
        const t = window.t;
        await this.loadData();

        const onlineAgents = this.agents.filter(a => a.status === 'online').length;
        const offlineAgents = this.agents.filter(a => a.status === 'offline').length;

        // Note: Dropdown initialization is handled by app.js after HTML is inserted into DOM

        setTimeout(() => this.setupEventListeners(), 0);

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <rect x="4" y="4" width="6" height="6" rx="1" />
                                    <rect x="14" y="4" width="6" height="6" rx="1" />
                                    <rect x="4" y="14" width="6" height="6" rx="1" />
                                    <rect x="14" y="14" width="6" height="6" rx="1" />
                                </svg>
                                ${t('agents.page_title')} ${contextHelp('concurrency')}
                            </h2>
                            <div class="text-secondary mt-1">${t('agents.page_subtitle')}</div>
                        </div>
                        <div class="col-auto d-none d-md-flex gap-3 align-items-center ms-auto">
                            <span class="text-secondary">
                                <span class="badge bg-success me-1">${onlineAgents}</span> ${t('agents.online')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-danger me-1">${offlineAgents}</span> ${t('agents.offline')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-info me-1">${this.getTotalVMs()}</span> ${t('agents.total_vms')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-primary me-1">${this.agents.length}</span> ${t('agents.total_agents')}
                            </span>
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
                    <!-- Agents Table -->
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">${t('agents.all_agents')}</h3>
                            <div class="ms-auto">
                                <div class="input-group search-control">
                                    <input type="text" class="form-control form-control-sm" placeholder="${t('agents.search_placeholder')}" id="agent-search">
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
                                        <th>${t('agents.col_agent_name')}</th>
                                        <th>${t('agents.col_hostname')}</th>
                                        <th>${t('agents.col_status')}</th>
                                        <th>${t('agents.col_health')}</th>
                                        <th>${t('agents.col_storage')}</th>
                                        <th>${t('agents.col_vms')}</th>
                                        <th>${t('agents.col_last_heartbeat')}</th>
                                        <th class="w-1">${t('common.actions')}</th>
                                    </tr>
                                </thead>
                                <tbody id="agents-table-body">
                                    ${this.renderAgentRows()}
                                </tbody>
                            </table>
                        </div>
                        ${this.agents.length === 0 ? this.renderEmptyState() : ''}
                    </div>
                </div>
            </div>

            ${this.renderAgentDetailsModal()}
        `;
    }

    setupEventListeners() {
        const searchInput = document.getElementById('agent-search');
        if (searchInput) {
            searchInput.value = this.searchQuery;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this._searchTimeout);
                this._searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value;
                    const tbody = document.getElementById('agents-table-body');
                    if (tbody) tbody.innerHTML = this.renderAgentRows();
                }, 300);
            });
        }
    }

    renderAgentRows() {
        const t = window.t;
        if (this.agents.length === 0) {
            return '';
        }

        let filtered = this.agents;
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            filtered = filtered.filter(a =>
                (a.display_name || '').toLowerCase().includes(q) ||
                (a.hostname || '').toLowerCase().includes(q)
            );
        }

        if (filtered.length === 0) {
            return `<tr><td colspan="8" class="text-center text-secondary py-4">${t('common.no_results', { query: this.searchQuery })}</td></tr>`;
        }

        return filtered.map(agent => {
            const displayName = agent.display_name || agent.hostname || 'Unknown';
            const hostname = agent.hostname || 'unknown';

            return `
            <tr>
                <td>
                    <div class="d-flex align-items-center">
                        <span class="avatar avatar-sm me-2 ${agent.status === 'online' ? 'bg-success-lt' : 'bg-danger-lt'}">
                            ${agent.status === 'online' ? `
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <circle cx="12" cy="12" r="9" />
                                </svg>
                            ` : `
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <line x1="18" y1="6" x2="6" y2="18" />
                                    <line x1="6" y1="6" x2="18" y2="18" />
                                </svg>
                            `}
                        </span>
                        <div>
                            <div class="font-weight-medium">${escapeHtml(displayName)}</div>
                            ${agent.display_name ? `<div class="text-secondary small">${t('agents.custom_name')}</div>` : ''}
                        </div>
                    </div>
                </td>
                <td>
                    <code class="text-secondary small">${escapeHtml(hostname)}</code><div class="text-secondary small">${agentProvider(agent) === 'unknown' ? enumLabel(null) : escapeHtml(agentProvider(agent) === 'libvirt' ? 'Native libvirt' : 'KubeVirt')}</div>
                </td>
                <td>
                    <span class="badge bg-${getStatusColor(agent.status, 'agent')}">
                        ${escapeHtml(enumLabel(agent.status))}
                    </span>
                </td>
                <td>
                    ${this.renderAgentHealth(agent)}
                </td>
                <td>
                    ${this.renderAgentStorage(agent)}
                </td>
                <td>${agent.vm_count || 0}</td>
                <td>
                    ${agent.last_heartbeat ? `
                        <div>${formatDate(agent.last_heartbeat)}</div>
                        <div class="text-secondary small">${formatRelativeTime(agent.last_heartbeat)}</div>
                    ` : `
                        <span class="text-secondary">${t('common.never')}</span>
                    `}
                </td>
                <td class="text-end">
                    <div class="dropdown">
                        <button class="btn btn-sm btn-ghost-secondary" type="button" data-bs-toggle="dropdown" data-bs-auto-close="true" aria-expanded="false">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <circle cx="12" cy="12" r="1" />
                                <circle cx="12" cy="19" r="1" />
                                <circle cx="12" cy="5" r="1" />
                            </svg>
                        </button>
                        <div class="dropdown-menu dropdown-menu-end">
                            <a class="dropdown-item" href="#" onclick="window.vnbui.viewAgentDetails('${escapeHtml(agent.id)}'); return false;">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon dropdown-item-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <circle cx="12" cy="12" r="2" />
                                    <path d="M22 12c-2.667 4.667 -6 7 -10 7s-7.333 -2.333 -10 -7c2.667 -4.667 6 -7 10 -7s7.333 2.333 10 7" />
                                </svg>
                                ${t('agents.view_details')}
                            </a>
                            <a class="dropdown-item" href="#" onclick="window.vnbui.editAgentDisplayName('${escapeHtml(agent.id)}', '${escapeHtml(displayName)}'); return false;">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon dropdown-item-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M4 20h4l10.5 -10.5a1.5 1.5 0 0 0 -4 -4l-10.5 10.5v4" />
                                    <line x1="13.5" y1="6.5" x2="17.5" y2="10.5" />
                                </svg>
                                ${t('agents.edit_name')}
                            </a>
                            <a class="dropdown-item" href="#" onclick="window.vnbui.rotateAgentKey('${escapeHtml(agent.id)}', '${escapeHtml(displayName)}'); return false;">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon dropdown-item-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1 -4.069 0l-.301 -.301l-6.558 6.558a2 2 0 0 1 -1.239 .578l-.175 .008h-1.172a1 1 0 0 1 -.993 -.883l-.007 -.117v-1.172a2 2 0 0 1 .467 -1.284l.119 -.13l.414 -.414h2v-2h2v-2l2.144 -2.144l-.301 -.301a2.877 2.877 0 0 1 0 -4.069l2.643 -2.643a2.877 2.877 0 0 1 4.069 0z" />
                                    <circle cx="15" cy="9" r="1" />
                                </svg>
                                ${t('agents.rotate_api_key')}
                            </a>
                            <a class="dropdown-item" href="#" onclick="window.vnbui.keyManagement.inspectAgentRotations('${escapeHtml(agent.id)}'); return false;">${escapeHtml(operatorText('rotation_status'))}</a>
                            <div class="dropdown-divider"></div>
                            <a class="dropdown-item text-danger" href="#" onclick="window.vnbui.removeAgent('${escapeHtml(agent.id)}', '${escapeHtml(displayName)}'); return false;">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon dropdown-item-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <line x1="4" y1="7" x2="20" y2="7" />
                                    <line x1="10" y1="11" x2="10" y2="17" />
                                    <line x1="14" y1="11" x2="14" y2="17" />
                                    <path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12" />
                                    <path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3" />
                                </svg>
                                ${t('agents.remove_agent')}
                            </a>
                        </div>
                    </div>
                </td>
            </tr>
        `}).join('');
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty">
                <div class="empty-img">
                    <div class="empty-icon">${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}</div>
                </div>
                <p class="empty-title">${t('agents.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${t('agents.empty_subtitle')}
                </p>
                <div class="empty-action">
                    <a href="#" class="btn btn-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                            <path d="M14 3v4a1 1 0 0 0 1 1h4" />
                            <path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z" />
                        </svg>
                        ${t('agents.installation_guide')}
                    </a>
                </div>
            </div>
        `;
    }

    renderAgentDetailsModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-agent-details" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${t('agents.modal_title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <!-- Tab navigation -->
                            <ul class="nav nav-tabs mb-3" role="tablist">
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link active" id="agent-details-tab" data-bs-toggle="tab" data-bs-target="#agent-details-pane" type="button" role="tab">${t('agents.tab_details')}</button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="agent-settings-tab" data-bs-toggle="tab" data-bs-target="#agent-settings-pane" type="button" role="tab">${t('agents.tab_settings')}</button>
                                </li>
                            </ul>

                            <div class="tab-content">
                                <!-- Details Tab -->
                                <div class="tab-pane fade show active" id="agent-details-pane" role="tabpanel">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">${t('agents.hostname')}</label>
                                                <div class="form-control-plaintext" id="agent-detail-hostname">—</div>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">${t('common.status')}</label>
                                                <div class="form-control-plaintext" id="agent-detail-status">—</div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">${t('agents.platform')}</label>
                                                <div class="form-control-plaintext" id="agent-detail-platform">—</div>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">${t('agents.version')}</label>
                                                <div class="form-control-plaintext" id="agent-detail-version">—</div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">${t('agents.ip_address')}</label>
                                                <div class="form-control-plaintext" id="agent-detail-ip">—</div>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">${t('agents.total_vms_label')}</label>
                                                <div class="form-control-plaintext" id="agent-detail-vms">—</div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">${t('agents.last_heartbeat')}</label>
                                        <div class="form-control-plaintext" id="agent-detail-heartbeat">—</div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">${t('agents.agent_id')}</label>
                                        <div class="form-control-plaintext font-monospace small" id="agent-detail-id">—</div>
                                    </div>
                                </div>

                                <!-- Settings Tab -->
                                <div class="tab-pane fade" id="agent-settings-pane" role="tabpanel">
                                    <form id="agent-settings-form">
                                        <input type="hidden" id="agent-settings-id">
                                        <p class="text-secondary mb-3">
                                            ${t('agents.settings_desc')}
                                        </p>

                                        <div id="agent-provider-settings"></div>
                                        <div class="mb-3">
                                            <label class="form-label">${t('agents.heartbeat_interval')}</label>
                                            <input type="number" class="form-control" id="agent-setting-heartbeat_interval" min="10" max="300" placeholder="30">
                                        </div>

                                        <h4 class="mb-3">${t('agents.section_logging')}</h4>
                                        <div class="mb-3">
                                            <label class="form-label">${t('agents.log_level')}</label>
                                            <select class="form-select" id="agent-setting-log_level">
                                                <option value="">${t('agents.log_default')}</option>
                                                <option value="DEBUG">DEBUG</option>
                                                <option value="INFO">INFO</option>
                                                <option value="WARNING">WARNING</option>
                                                <option value="ERROR">ERROR</option>
                                            </select>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.close')}</button>
                            <button type="button" class="btn btn-primary d-none" id="agent-settings-save-btn" onclick="window.vnbui.saveAgentSettings()">
                                ${t('agents.save_settings')}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getTotalVMs() {
        return this.agents.reduce((sum, agent) => sum + (agent.vm_count || 0), 0);
    }

    formatUptime(startDate) {
        if (!startDate) return 'N/A';
        const now = new Date();
        const start = new Date(startDate);
        const diffMs = now - start;
        const diffDays = Math.floor(diffMs / 86400000);
        const diffHours = Math.floor((diffMs % 86400000) / 3600000);

        if (diffDays > 0) {
            return `${diffDays}d ${diffHours}h`;
        }
        return `${diffHours}h`;
    }

    formatBytes(bytes) {
        if (bytes === null || bytes === undefined) return 'N/A';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        let size = bytes;
        while (size >= 1024 && i < units.length - 1) {
            size /= 1024;
            i++;
        }
        return `${size.toFixed(1)} ${units[i]}`;
    }

    renderAgentHealth(agent) {
        const metrics = agent.metrics || {};
        const healthStatus = metrics.health_status || 'unknown';
        const healthIssues = metrics.health_issues || [];

        if (agent.status !== 'online') {
            return '<span class="text-secondary">-</span>';
        }

        const color = healthStatus === 'healthy' ? 'success' :
                      healthStatus === 'degraded' ? 'warning' : 'secondary';

        if (healthIssues.length > 0) {
            return `
                <span class="badge bg-${color}" title="${escapeHtml(healthIssues.join(', '))}">
                    ${escapeHtml(enumLabel(healthStatus))}
                </span>
            `;
        }

        return `<span class="badge bg-${color}">${escapeHtml(enumLabel(healthStatus))}</span>`;
    }

    renderAgentStorage(agent) {
        const t = window.t;
        const metrics = agent.metrics || {};
        const freeBytes = metrics.backup_storage_free_bytes;
        const totalBytes = metrics.backup_storage_total_bytes;

        if (agent.status !== 'online') {
            return '<span class="text-secondary">-</span>';
        }

        const freePercent = storageCapacity(freeBytes, totalBytes);
        if (freePercent === null) return `<span class="text-secondary">${t('experience.capacity_unknown')}</span>`;
        const freeStr = this.formatBytes(freeBytes);
        const totalStr = this.formatBytes(totalBytes);

        // Warn if less than 10% or less than 10GB free
        const freeGb = freeBytes / (1024 * 1024 * 1024);
        const isLow = freePercent < 10 || (agentProvider(agent) !== 'kubevirt' && freeGb < 10);

        return `
            <div class="${isLow ? 'text-warning' : ''}" title="${t('agents.shared_destination')}">
                <div class="text-secondary small">${t(agentProvider(agent) === 'kubevirt' ? 'experience.journal_space' : 'experience.capture_space')}</div>
                <div>${freeStr} ${t('agents.free')}</div>
                <div class="text-secondary small">${t('experience.capacity_percent', {percent: freePercent, total: totalStr})}</div>
            </div>
        `;
    }
}
