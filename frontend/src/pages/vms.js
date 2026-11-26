import { contextHelp } from '../components/context-help.js';
import { renderDiskSummary, renderCbtObservation } from '../utils/vm-inventory.js';
import { enumLabel } from '../utils/status-labels.js';
/**
 * Virtual Machines Page
 * Server-side pagination, sorting, filtering, and multi-VM selection
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime } from '../utils/format.js';
import { getStatusColor } from '../utils/status-colors.js';
import { assetResolver } from '../assets/resolver.js';

export class VMsPage {
    constructor() {
        this.vms = [];
        this.loading = false;
        this.currentPage = 1;
        this.pageSize = 50;
        this.totalVMs = 0;
        this.sortColumn = 'name';
        this.sortDirection = 'asc';
        this.searchQuery = '';
        this.agentFilter = '';
        this.stateFilter = '';
        this.selectedIds = new Set();
        this.selectAllMatching = false;
        this.selectAllMatchingCount = 0;
        this.agents = [];
        this._searchTimeout = null;
    }

    async loadData() {
        this.loading = true;
        try {
            const skip = (this.currentPage - 1) * this.pageSize;
            const params = new URLSearchParams({
                skip: skip.toString(),
                limit: this.pageSize.toString(),
                sort_by: this.sortColumn,
                sort_order: this.sortDirection,
            });
            if (this.searchQuery) params.set('search', this.searchQuery);
            if (this.agentFilter) params.set('agent_id', this.agentFilter);
            if (this.stateFilter) params.set('state', this.stateFilter);

            const data = await apiClient.get(`/api/v1/vms?${params}`);
            this.vms = data.items || [];
            this.totalVMs = data.total || 0;

            // Load agents for filter dropdown (once)
            if (this.agents.length === 0) {
                try {
                    this.agents = await apiClient.get('/api/v1/agents');
                } catch (_) {
                    this.agents = [];
                }
            }
        } catch (error) {
            console.error('Failed to load VMs:', error);
            this.vms = [];
            this.totalVMs = 0;
        }
        this.loading = false;
    }

    setupEventListeners() {
        // Search input with debounce
        const searchInput = document.getElementById('vm-search');
        if (searchInput) {
            searchInput.value = this.searchQuery;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this._searchTimeout);
                this._searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value;
                    this.currentPage = 1;
                    this.clearSelection();
                    this._reload();
                }, 300);
            });
        }

        // Filter dropdowns
        const agentSelect = document.getElementById('vm-filter-agent');
        if (agentSelect) {
            agentSelect.value = this.agentFilter;
            agentSelect.addEventListener('change', (e) => {
                this.agentFilter = e.target.value;
                this.currentPage = 1;
                this.clearSelection();
                this._reload();
            });
        }

        const stateSelect = document.getElementById('vm-filter-state');
        if (stateSelect) {
            stateSelect.value = this.stateFilter;
            stateSelect.addEventListener('change', (e) => {
                this.stateFilter = e.target.value;
                this.currentPage = 1;
                this.clearSelection();
                this._reload();
            });
        }

        // Sortable headers
        document.querySelectorAll('[data-sort]').forEach(header => {
            header.style.cursor = 'pointer';
            header.addEventListener('click', () => {
                const column = header.dataset.sort;
                if (this.sortColumn === column) {
                    this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortColumn = column;
                    this.sortDirection = 'asc';
                }
                this._reload();
            });
        });
    }

    async _reload() {
        await this.loadData();
        this.updateTable();
        this.updatePagination();
        this.updateSortIndicators();
        this.updateBulkToolbar();
    }

    updateTable() {
        const tbody = document.getElementById('vms-table-body');
        if (tbody) tbody.innerHTML = this.renderVMRows();

        const countEl = document.getElementById('vm-count');
        if (countEl) countEl.textContent = window.t('vms.all_vms', {total: this.totalVMs});

        // Update select-all checkbox
        const selectAll = document.getElementById('vm-select-all');
        if (selectAll) {
            const pageIds = this.vms.filter(vm => vm.inventory_present !== false).map(vm => vm.id);
            const allOnPageSelected = pageIds.length > 0 && pageIds.every(id => this.selectedIds.has(id));
            selectAll.checked = allOnPageSelected;
            selectAll.indeterminate = !allOnPageSelected && pageIds.some(id => this.selectedIds.has(id));
        }
    }

    updatePagination() {
        const el = document.getElementById('vm-pagination');
        if (!el) return;

        const totalPages = Math.max(1, Math.ceil(this.totalVMs / this.pageSize));
        if (totalPages <= 1) {
            el.innerHTML = '';
            return;
        }

        let pages = [];
        const maxVisible = 5;
        let start = Math.max(1, this.currentPage - Math.floor(maxVisible / 2));
        let end = Math.min(totalPages, start + maxVisible - 1);
        if (end - start < maxVisible - 1) start = Math.max(1, end - maxVisible + 1);

        pages.push(`<li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="window.vnbui.vmPageNav(${this.currentPage - 1}); return false;">
                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><polyline points="15 6 9 12 15 18" /></svg>
            </a>
        </li>`);

        if (start > 1) {
            pages.push(`<li class="page-item"><a class="page-link" href="#" onclick="window.vnbui.vmPageNav(1); return false;">1</a></li>`);
            if (start > 2) pages.push(`<li class="page-item disabled"><span class="page-link">...</span></li>`);
        }

        for (let i = start; i <= end; i++) {
            pages.push(`<li class="page-item ${i === this.currentPage ? 'active' : ''}">
                <a class="page-link" href="#" onclick="window.vnbui.vmPageNav(${i}); return false;">${i}</a>
            </li>`);
        }

        if (end < totalPages) {
            if (end < totalPages - 1) pages.push(`<li class="page-item disabled"><span class="page-link">...</span></li>`);
            pages.push(`<li class="page-item"><a class="page-link" href="#" onclick="window.vnbui.vmPageNav(${totalPages}); return false;">${totalPages}</a></li>`);
        }

        pages.push(`<li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" onclick="window.vnbui.vmPageNav(${this.currentPage + 1}); return false;">
                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><polyline points="9 6 15 12 9 18" /></svg>
            </a>
        </li>`);

        el.innerHTML = `<ul class="pagination m-0">${pages.join('')}</ul>`;
    }

    updateSortIndicators() {
        document.querySelectorAll('[data-sort]').forEach(header => {
            header.classList.remove('sorting-asc', 'sorting-desc');
            if (header.dataset.sort === this.sortColumn) {
                header.classList.add(this.sortDirection === 'asc' ? 'sorting-asc' : 'sorting-desc');
            }
        });
    }

    updateBulkToolbar() {
        const toolbar = document.getElementById('vm-bulk-toolbar');
        if (!toolbar) return;

        const count = this.selectAllMatching ? this.selectAllMatchingCount : this.selectedIds.size;
        if (count > 0) {
            toolbar.style.display = '';
            const countEl = toolbar.querySelector('.bulk-count');
            if (countEl) countEl.textContent = window.t('vms.selected', {count: count});

            const selectAllLink = toolbar.querySelector('.select-all-matching');
            if (selectAllLink) {
                if (this.selectAllMatching) {
                    selectAllLink.innerHTML = `${window.t('vms.all_matching_selected', {count: this.selectAllMatchingCount})} <a href="#" onclick="window.vnbui.clearSelection(); return false;">${window.t('common.cancel')}</a>`;
                } else if (this.totalVMs > this.pageSize && this.selectedIds.size === this.vms.length) {
                    selectAllLink.innerHTML = `<a href="#" onclick="window.vnbui.selectAllMatching(); return false;">${window.t('vms.select_all_matching', {total: this.totalVMs})}</a>`;
                } else {
                    selectAllLink.innerHTML = '';
                }
            }
        } else {
            toolbar.style.display = 'none';
        }
    }

    // Selection methods
    toggleVMSelection(vmId) {
        if (this.vms.find(vm => vm.id === vmId)?.inventory_present === false) return;
        if (this.selectedIds.has(vmId)) {
            this.selectedIds.delete(vmId);
            this.selectAllMatching = false;
        } else {
            this.selectedIds.add(vmId);
        }
        this.updateTable();
        this.updateBulkToolbar();
    }

    toggleSelectAllPage() {
        const pageIds = this.vms.filter(vm => vm.inventory_present !== false).map(vm => vm.id);
        const allSelected = pageIds.every(id => this.selectedIds.has(id));

        if (allSelected) {
            pageIds.forEach(id => this.selectedIds.delete(id));
            this.selectAllMatching = false;
        } else {
            pageIds.forEach(id => this.selectedIds.add(id));
        }
        this.updateTable();
        this.updateBulkToolbar();
    }

    async selectAllMatching() {
        try {
            const body = {};
            if (this.searchQuery) body.search = this.searchQuery;
            if (this.agentFilter) body.agent_id = this.agentFilter;
            if (this.stateFilter) body.state = this.stateFilter;

            const result = await apiClient.post('/api/v1/vms/ids-by-filter', body);
            this.selectedIds = new Set(result.vm_ids);
            this.selectAllMatching = true;
            this.selectAllMatchingCount = result.count;
            this.updateTable();
            this.updateBulkToolbar();
        } catch (error) {
            console.error('Failed to select all matching:', error);
        }
    }

    clearSelection() {
        this.selectedIds.clear();
        this.selectAllMatching = false;
        this.selectAllMatchingCount = 0;
        this.updateTable();
        this.updateBulkToolbar();
    }

    async bulkBackupSelected() {
        const count = this.selectAllMatching ? this.selectAllMatchingCount : this.selectedIds.size;
        if (!confirm(window.t('vms.bulk_backup_confirm', {count}))) return;

        try {
            let payload;
            if (this.selectAllMatching) {
                const filter = {};
                if (this.searchQuery) filter.search = this.searchQuery;
                if (this.agentFilter) filter.agent_id = this.agentFilter;
                if (this.stateFilter) filter.state = this.stateFilter;
                payload = { filter, retention_days: 30 };
            } else {
                payload = { vm_ids: Array.from(this.selectedIds).sort(), retention_days: 30 };
            }

            const result = await apiClient.post('/api/v1/backups/bulk-create', payload);
            const summary = result.summary;
            window.vnbui.showToast(window.t('vms.bulk_backup_result', {created: summary.created, skipped: summary.skipped, failed: summary.failed}), 'success');
            this.clearSelection();
            apiClient.acknowledge(result);
        } catch (error) {
            window.vnbui.showToast(error.operatorRecovery ? error.message : window.t('vms.bulk_backup_failed', {error: error.message}), 'error');
        }
    }

    async bulkAddToGroup() {
        const count = this.selectAllMatching ? this.selectAllMatchingCount : this.selectedIds.size;

        // Resolve IDs if using select-all-matching
        let vmIds;
        if (this.selectAllMatching) {
            try {
                const body = {};
                if (this.searchQuery) body.search = this.searchQuery;
                if (this.agentFilter) body.agent_id = this.agentFilter;
                if (this.stateFilter) body.state = this.stateFilter;
                const result = await apiClient.post('/api/v1/vms/ids-by-filter', body);
                vmIds = result.vm_ids;
            } catch (error) {
                window.vnbui.showToast(window.t('vms.add_to_group_failed', {error: error.message}), 'error');
                return;
            }
        } else {
            vmIds = Array.from(this.selectedIds);
        }

        // Load groups for picker
        let groups;
        try {
            const data = await apiClient.get('/api/v1/groups?limit=100');
            groups = data.items || [];
        } catch (_) {
            groups = [];
        }

        if (groups.length === 0) {
            window.vnbui.showToast(window.t('vms.no_groups_available'), 'warning');
            return;
        }

        // Simple prompt with group selection
        const choice = prompt(`Select group to add ${count} VM(s) to:\n\n${groups.map((g, i) => `${i + 1}. ${g.name}`).join('\n')}\n\nEnter number:`);
        if (!choice) return;

        const idx = parseInt(choice) - 1;
        if (isNaN(idx) || idx < 0 || idx >= groups.length) {
            window.vnbui.showToast(window.t('vms.invalid_selection'), 'error');
            return;
        }

        try {
            const result = await apiClient.post(`/api/v1/groups/${groups[idx].id}/vms`, { vm_ids: vmIds });
            window.vnbui.showToast(window.t('vms.add_to_group_success', {added: result.added.length, group_name: groups[idx].name}), 'success');
            this.clearSelection();
        } catch (error) {
            window.vnbui.showToast(window.t('vms.add_to_group_failed', {error: error.message}), 'error');
        }
    }

    // Navigation
    async goToPage(page) {
        const totalPages = Math.max(1, Math.ceil(this.totalVMs / this.pageSize));
        if (page < 1 || page > totalPages) return;
        this.currentPage = page;
        await this._reload();
    }

    async render() {
        const t = window.t;
        await this.loadData();

        setTimeout(() => {
            this.setupEventListeners();
            this.updateSortIndicators();
            this.updateBulkToolbar();
        }, 0);

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <rect x="3" y="4" width="18" height="12" rx="1" />
                                    <line x1="7" y1="8" x2="10" y2="8" />
                                    <line x1="7" y1="12" x2="10" y2="12" />
                                </svg>
                                ${t('vms.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('vms.page_subtitle')}</div>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
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
                    <!-- Bulk Action Toolbar -->
                    <div id="vm-bulk-toolbar" class="card mb-3" style="display: none;">
                        <div class="card-body py-2">
                            <div class="d-flex align-items-center">
                                <span class="bulk-count fw-bold me-3">${t('vms.selected', {count: 0})}</span>
                                <button class="btn btn-sm btn-primary me-2" onclick="window.vnbui.bulkBackupSelected()">
                                    ${t('vms.backup_selected')}
                                </button>
                                <button class="btn btn-sm btn-outline-primary me-2" onclick="window.vnbui.bulkAddToGroup()">
                                    ${t('vms.add_to_group')}
                                </button>
                                <button class="btn btn-sm btn-ghost-secondary" onclick="window.vnbui.clearSelection()">
                                    ${t('common.cancel')}
                                </button>
                                <span class="select-all-matching ms-auto small"></span>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title" id="vm-count">${t('vms.all_vms', {total: this.totalVMs})}</h3>
                            <div class="ms-auto d-flex flex-wrap gap-2 align-items-center inventory-filters">
                                <select class="form-select form-select-sm" id="vm-filter-agent" style="width: auto;">
                                    <option value="">${t('vms.all_agents')}</option>
                                    ${this.agents.map(a => `<option value="${escapeHtml(a.id)}" ${this.agentFilter === a.id ? 'selected' : ''}>${escapeHtml(a.hostname)}</option>`).join('')}
                                </select>
                                <select class="form-select form-select-sm" id="vm-filter-state" style="width: auto;">
                                    <option value="">${t('vms.all_states')}</option>
                                    <option value="running" ${this.stateFilter === 'running' ? 'selected' : ''}>${t('vms.state_running')}</option>
                                    <option value="stopped" ${this.stateFilter === 'stopped' ? 'selected' : ''}>${t('vms.state_stopped')}</option>
                                    <option value="paused" ${this.stateFilter === 'paused' ? 'selected' : ''}>${t('vms.state_paused')}</option>
                                </select>
                                <div class="input-group search-control">
                                    <input type="text" class="form-control form-control-sm" placeholder="${t('vms.search_placeholder')}" id="vm-search" value="${escapeHtml(this.searchQuery)}">
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
                                        <th class="w-1">
                                            <input class="form-check-input" type="checkbox" id="vm-select-all" onclick="window.vnbui.toggleSelectAllPage()">
                                        </th>
                                        <th data-sort="name" class="${this.sortColumn === 'name' ? (this.sortDirection === 'asc' ? 'sorting-asc' : 'sorting-desc') : ''}">${t('vms.col_name')}</th>
                                        <th data-sort="agent_hostname">${t('vms.col_agent')}</th>
                                        <th data-sort="state">${t('vms.col_state')}</th>
                                        <th data-sort="memory_kb">${t('vms.col_memory')}</th>
                                        <th data-sort="vcpu_count">${t('vms.col_cpus')}</th>
                                        <th>${t('vms.col_disks')}</th>
                                        <th>${t('vms.col_last_backup')}</th>
                                        <th class="w-1">${t('common.actions')}</th>
                                    </tr>
                                </thead>
                                <tbody id="vms-table-body">
                                    ${this.renderVMRows()}
                                </tbody>
                            </table>
                        </div>
                        ${this.vms.length === 0 ? this.renderEmptyState() : ''}
                        <div class="card-footer d-flex align-items-center">
                            <p class="m-0 text-secondary">${this.totalVMs > 0 ? t('common.showing', {start: (this.currentPage - 1) * this.pageSize + 1, end: Math.min(this.currentPage * this.pageSize, this.totalVMs), total: this.totalVMs}) : t('vms.no_vms_found')}</p>
                            <div id="vm-pagination" class="ms-auto">
                                ${this.renderPaginationHTML()}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.renderBackupModal()}
        `;
    }

    renderPaginationHTML() {
        const totalPages = Math.max(1, Math.ceil(this.totalVMs / this.pageSize));
        if (totalPages <= 1) return '';

        let pages = [];
        const maxVisible = 5;
        let start = Math.max(1, this.currentPage - Math.floor(maxVisible / 2));
        let end = Math.min(totalPages, start + maxVisible - 1);
        if (end - start < maxVisible - 1) start = Math.max(1, end - maxVisible + 1);

        pages.push(`<li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}"><a class="page-link" href="#" onclick="window.vnbui.vmPageNav(${this.currentPage - 1}); return false;">&laquo;</a></li>`);
        for (let i = start; i <= end; i++) {
            pages.push(`<li class="page-item ${i === this.currentPage ? 'active' : ''}"><a class="page-link" href="#" onclick="window.vnbui.vmPageNav(${i}); return false;">${i}</a></li>`);
        }
        pages.push(`<li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}"><a class="page-link" href="#" onclick="window.vnbui.vmPageNav(${this.currentPage + 1}); return false;">&raquo;</a></li>`);

        return `<ul class="pagination m-0">${pages.join('')}</ul>`;
    }

    renderVMRows() {
        if (this.vms.length === 0) return '';
        const t = window.t;

        return this.vms.map(vm => `
            <tr class="${this.selectedIds.has(vm.id) ? 'table-active' : ''}">
                <td>
                    <input class="form-check-input" type="checkbox"
                        ${vm.inventory_present === false ? 'disabled' : ''}
                        ${this.selectedIds.has(vm.id) ? 'checked' : ''}
                        onclick="window.vnbui.toggleVMSelection('${escapeHtml(vm.id)}')">
                </td>
                <td>
                    <div class="d-flex align-items-center">
                        <span class="avatar avatar-sm me-2">
                            ${escapeHtml((vm.name || 'VM').substring(0, 2).toUpperCase())}
                        </span>
                        <div>
                            <a href="#" class="font-weight-medium text-reset" onclick="window.vnbui.viewVM('${escapeHtml(vm.id)}'); return false;">${escapeHtml(vm.name)}</a>
                            <div class="text-secondary small">${escapeHtml(vm.namespace || '')} ${escapeHtml(vm.vm_uid || vm.uuid || vm.id || '')}</div>
                            ${vm.vmi_uid ? `<div class="text-secondary small">VMI: ${escapeHtml(vm.vmi_uid)}</div>` : ''}
                            ${vm.replaces_vm_id ? `<div class="text-warning small">${t('inventory.replacement')}: ${escapeHtml(vm.replaces_vm_id)}</div>` : ''}
                        </div>
                    </div>
                </td>
                <td>
                    <span class="text-secondary">${escapeHtml(vm.agent_hostname || t('common.unknown'))}</span>
                </td>
                <td>
                    <span class="badge bg-${vm.inventory_present === false ? 'secondary' : getStatusColor(vm.state, 'vm')}">
                        ${escapeHtml(vm.inventory_present === false ? t('inventory.absent') : vm.state || t('common.unknown'))}
                    </span>
                    ${vm.inventory_present === false ? `<div class="text-warning small">${t('inventory.absent')}: ${escapeHtml(vm.absent_since || '')}</div>` : ''}
                    ${vm.last_observed_at ? `<div class="text-secondary small">${t('inventory.observed')}: ${escapeHtml(vm.last_observed_at)}</div>` : ''}
                </td>
                <td>${this.formatMemory(vm.memory_kb)}</td>
                <td>${vm.vcpu_count || 0}</td>
                <td>
                    ${renderDiskSummary(vm.disks)}${vm.provider === 'kubevirt' ? `<div class="small text-secondary">${renderCbtObservation(vm)}</div>` : ''}${vm.backup_eligibility && vm.backup_eligibility.warnings && vm.backup_eligibility.warnings.length > 0
                        ? ` <i class="ti ti-alert-triangle text-warning" title="${escapeHtml(vm.backup_eligibility.warnings.join('; '))}" data-bs-toggle="tooltip" style="font-size: 0.85rem;"></i>`
                        : ''}
                </td>
                <td>${this.renderLastBackup(vm)}</td>
                <td>
                    <button class="btn btn-sm btn-primary" ${vm.inventory_present === false ? 'disabled' : ''} onclick="window.vnbui.createBackup('${escapeHtml(vm.id)}')">
                        ${t('vms.backup_btn')}
                    </button>
                </td>
            </tr>
        `).join('');
    }

    getDiskCount(disks) {
        if (!disks) return 0;
        if (Array.isArray(disks)) return disks.length;
        return 0;
    }

    renderLastBackup(vm) {
        if (!vm.last_backup_at) {
            return `<span class="text-secondary">—</span>`;
        }
        const typeColors = { full: 'azure', inc: 'indigo', diff: 'purple', copy: 'cyan' };
        const statusColors = { completed: 'success', failed: 'danger' };
        const typeColor = typeColors[vm.last_backup_type] || 'secondary';
        const statusColor = statusColors[vm.last_backup_status] || 'secondary';
        const ago = formatRelativeTime(vm.last_backup_at);
        return `<div><span class="badge badge-outline text-${typeColor} me-1" style="font-size:0.7rem">${escapeHtml(enumLabel(vm.last_backup_type || '', 'backup_type'))}</span><span class="badge badge-outline text-${statusColor}" style="font-size:0.7rem">${escapeHtml(enumLabel(vm.last_backup_status || ''))}</span></div><div class="text-secondary small">${escapeHtml(ago)}</div>`;
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty">
                <div class="empty-img">
                    <div class="empty-icon">${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}</div>
                </div>
                <p class="empty-title">${t('vms.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${this.searchQuery || this.agentFilter || this.stateFilter
                        ? t('vms.empty_with_filters')
                        : t('vms.empty_no_filters')}
                </p>
            </div>
        `;
    }

    renderBackupModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-backup" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${t('backup_modal.title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="backup-vm-id">
                            <div class="mb-3">
                                <label class="form-label">${t('backup_modal.vm_name')}</label>
                                <input type="text" class="form-control" id="backup-vm-name" readonly>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">${t('backup_modal.backup_type')} ${contextHelp('backup_type')}</label>
                                <select class="form-select" id="backup-type">
                                    <option value="full">${t('backup_modal.type_full')}</option>
                                    <option value="incremental">${t('backup_modal.type_incremental')}</option>
                                </select>
                                <div class="form-hint mt-2" id="backup-mode-guidance" role="status" aria-live="polite"></div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">${t('backup_modal.retention')} ${contextHelp('retention')}</label>
                                <input type="number" class="form-control" id="backup-retention" value="30" min="1" max="365">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">${t('backup_modal.exclude_disks')}</label>
                                <div id="backup-exclude-disks" class="d-flex flex-wrap gap-2">
                                    <span class="text-secondary small">${t('backup_modal.exclude_disks_loading')}</span>
                                </div>
                                <small class="text-secondary">${t('backup_modal.exclude_disks_hint')}</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">${t('backup_modal.description')}</label>
                                <textarea class="form-control" id="backup-description" rows="2"></textarea>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-primary" id="submit-vm-backup" onclick="window.vnbui.submitBackupFromModal()">
                                ${t('backup_modal.title')}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    formatMemory(kb) {
        if (!kb) return window.t('common.na');
        const mb = kb / 1024;
        if (mb < 1024) return `${Math.round(mb)} MiB`;
        return `${Math.round(mb / 1024 * 10) / 10} GiB`;
    }
}
