/**
 * Groups Page
 * Manage VM groups (static, dynamic, hybrid) with pagination
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime, formatDate } from '../utils/format.js';
import { assetResolver } from '../assets/resolver.js';

export class GroupsPage {
    constructor() {
        this.groups = [];
        this.totalGroups = 0;
        this.currentPage = 1;
        this.pageSize = 50;
        this.searchQuery = '';
        this.typeFilter = '';
        this.loading = false;
        this._searchTimeout = null;
    }

    async loadData() {
        this.loading = true;
        try {
            const skip = (this.currentPage - 1) * this.pageSize;
            const params = new URLSearchParams({
                skip: skip.toString(),
                limit: this.pageSize.toString(),
            });
            if (this.searchQuery) params.set('search', this.searchQuery);
            if (this.typeFilter) params.set('group_type', this.typeFilter);

            const data = await apiClient.get(`/api/v1/groups?${params}`);
            this.groups = data.items || [];
            this.totalGroups = data.total || 0;
        } catch (error) {
            console.error('Failed to load groups:', error);
            this.groups = [];
            this.totalGroups = 0;
        }
        this.loading = false;
    }

    setupEventListeners() {
        const searchInput = document.getElementById('group-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this._searchTimeout);
                this._searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value;
                    this.currentPage = 1;
                    this._reload();
                }, 300);
            });
        }

        const typeSelect = document.getElementById('group-filter-type');
        if (typeSelect) {
            typeSelect.addEventListener('change', (e) => {
                this.typeFilter = e.target.value;
                this.currentPage = 1;
                this._reload();
            });
        }
    }

    async _reload() {
        await this.loadData();
        const grid = document.getElementById('groups-grid');
        if (grid) grid.innerHTML = this.renderGroupCards();

        const empty = document.getElementById('groups-empty');
        if (empty) empty.innerHTML = this.groups.length === 0 ? this.renderEmptyState() : '';

        this._updateStats();
        this.updatePagination();
    }

    _updateStats() {
        const totalEl = document.getElementById('stat-total-groups');
        if (totalEl) totalEl.textContent = this.totalGroups;

        const totalVMs = this.groups.reduce((sum, g) => sum + (g.vm_count || 0), 0);
        const vmsEl = document.getElementById('stat-total-vms');
        if (vmsEl) vmsEl.textContent = totalVMs;

        const activeEl = document.getElementById('stat-active-groups');
        if (activeEl) activeEl.textContent = this.groups.filter(g => g.vm_count > 0).length;
    }

    updatePagination() {
        const el = document.getElementById('groups-pagination');
        if (!el) return;

        const totalPages = Math.max(1, Math.ceil(this.totalGroups / this.pageSize));
        if (totalPages <= 1) { el.innerHTML = ''; return; }

        let pages = [];
        pages.push(`<li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}"><a class="page-link" href="#" onclick="window.vnbui.groupPageNav(${this.currentPage - 1}); return false;">&laquo;</a></li>`);
        for (let i = 1; i <= totalPages; i++) {
            pages.push(`<li class="page-item ${i === this.currentPage ? 'active' : ''}"><a class="page-link" href="#" onclick="window.vnbui.groupPageNav(${i}); return false;">${i}</a></li>`);
        }
        pages.push(`<li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}"><a class="page-link" href="#" onclick="window.vnbui.groupPageNav(${this.currentPage + 1}); return false;">&raquo;</a></li>`);
        el.innerHTML = `<ul class="pagination m-0">${pages.join('')}</ul>`;
    }

    async goToPage(page) {
        const totalPages = Math.max(1, Math.ceil(this.totalGroups / this.pageSize));
        if (page < 1 || page > totalPages) return;
        this.currentPage = page;
        await this._reload();
    }

    async render() {
        await this.loadData();
        const t = window.t;

        const totalVMs = this.groups.reduce((sum, g) => sum + (g.vm_count || 0), 0);

        setTimeout(() => this.setupEventListeners(), 0);

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
                                ${t('groups.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('groups.page_subtitle')}</div>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
                            <div class="d-flex align-items-center gap-3 me-3">
                                <span class="text-secondary">
                                    <span class="badge bg-primary me-1" id="stat-total-groups">${this.totalGroups}</span> ${t('groups.total_groups')}
                                </span>
                                <span class="text-secondary">
                                    <span class="badge bg-info me-1" id="stat-total-vms">${totalVMs}</span> ${t('groups.vms_in_groups')}
                                </span>
                                <span class="text-secondary">
                                    <span class="badge bg-success me-1" id="stat-active-groups">${this.groups.filter(g => g.vm_count > 0).length}</span> ${t('groups.active_groups')}
                                </span>
                            </div>
                        </div>
                        <div class="col-auto d-print-none">
                            <div class="btn-list">
                                <button class="btn btn-primary d-none d-sm-inline-block" onclick="window.vnbui.createGroup()">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <line x1="12" y1="5" x2="12" y2="19" />
                                        <line x1="5" y1="12" x2="19" y2="12" />
                                    </svg>
                                    ${t('groups.new_group')}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    <!-- Filters -->
                    <div class="card mb-3">
                        <div class="card-body py-2">
                            <div class="d-flex gap-2 align-items-center">
                                <div class="input-group search-control">
                                    <input type="text" class="form-control form-control-sm" placeholder="${t('groups.search_placeholder')}" id="group-search" value="${escapeHtml(this.searchQuery)}">
                                </div>
                                <select class="form-select form-select-sm" id="group-filter-type" style="width: auto;">
                                    <option value="">${t('groups.all_types')}</option>
                                    <option value="static" ${this.typeFilter === 'static' ? 'selected' : ''}>${t('groups.type_static')}</option>
                                    <option value="dynamic" ${this.typeFilter === 'dynamic' ? 'selected' : ''}>${t('groups.type_dynamic')}</option>
                                    <option value="hybrid" ${this.typeFilter === 'hybrid' ? 'selected' : ''}>${t('groups.type_hybrid')}</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <!-- Groups Grid -->
                    <div class="row row-cards" id="groups-grid">
                        ${this.renderGroupCards()}
                    </div>

                    <div id="groups-empty">
                        ${this.groups.length === 0 ? this.renderEmptyState() : ''}
                    </div>

                    <!-- Pagination -->
                    <div class="d-flex justify-content-end mt-3" id="groups-pagination"></div>
                </div>
            </div>

            ${this.renderGroupModal()}
            ${this.renderDeleteModal()}
        `;
    }

    renderGroupCards() {
        if (this.groups.length === 0) return '';
        const t = window.t;

        return this.groups.map(group => {
            const typeBadge = this.getTypeBadge(group.group_type || 'static');
            return `
            <div class="col-md-6 col-lg-4">
                <div class="card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-auto">
                                <span class="avatar ${this.getGroupColor(group.name)}">
                                    ${escapeHtml((group.name || 'G').substring(0, 2).toUpperCase())}
                                </span>
                            </div>
                            <div class="col">
                                <div class="font-weight-medium">
                                    <a href="#" onclick="window.vnbui.viewGroup('${escapeHtml(group.id)}'); return false;">
                                        ${escapeHtml(group.name || t('groups.unnamed_group'))}
                                    </a>
                                    ${typeBadge}
                                </div>
                                <div class="text-secondary small">${escapeHtml(group.description || '')}</div>
                            </div>
                            <div class="col-auto">
                                <div class="dropdown">
                                    <button class="btn btn-ghost-secondary btn-icon" data-bs-toggle="dropdown">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                            <circle cx="12" cy="12" r="1" />
                                            <circle cx="12" cy="19" r="1" />
                                            <circle cx="12" cy="5" r="1" />
                                        </svg>
                                    </button>
                                    <div class="dropdown-menu dropdown-menu-end">
                                        <a class="dropdown-item" href="#" onclick="window.vnbui.editGroup('${escapeHtml(group.id)}'); return false;">${t('common.edit')}</a>
                                        <a class="dropdown-item" href="#" onclick="window.vnbui.backupGroup('${escapeHtml(group.id)}', '${escapeHtml(group.name)}'); return false;">${t('groups.backup_group')}</a>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item text-danger" href="#" onclick="window.vnbui.deleteGroup('${escapeHtml(group.id)}', '${escapeHtml(group.name)}'); return false;">${t('common.delete')}</a>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="row mt-3">
                            <div class="col">
                                <div class="text-secondary small">${t('groups.col_vms')}</div>
                                <div class="h3 mb-0">${group.vm_count || 0}</div>
                            </div>
                            <div class="col">
                                <div class="text-secondary small">${t('groups.last_backup')}</div>
                                <div class="small mb-0">${group.last_backup ? formatDate(group.last_backup) : t('common.never')}</div>
                            </div>
                        </div>

                        ${group.tags && group.tags.length > 0 ? `
                            <div class="mt-3">
                                ${group.tags.map(tag => `<span class="badge bg-azure-lt me-1">${escapeHtml(tag)}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>

                    ${group.vm_count > 0 ? `
                        <div class="card-footer">
                            <div class="text-secondary small">
                                ${t('common.created')} ${formatRelativeTime(group.created_at)}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `}).join('');
    }

    getTypeBadge(type) {
        const t = window.t;
        const badges = {
            'static': `<span class="badge bg-blue-lt ms-2">${t('groups.type_static')}</span>`,
            'dynamic': `<span class="badge bg-purple-lt ms-2">${t('groups.type_dynamic')}</span>`,
            'hybrid': `<span class="badge bg-teal-lt ms-2">${t('groups.type_hybrid')}</span>`,
        };
        return badges[type] || '';
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty">
                <div class="empty-img">
                    <div class="empty-icon">${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}</div>
                </div>
                <p class="empty-title">${this.searchQuery || this.typeFilter ? t('groups.no_groups_found') : t('groups.no_groups_created')}</p>
                <p class="empty-subtitle text-secondary">
                    ${this.searchQuery || this.typeFilter
                        ? t('groups.adjust_search')
                        : t('groups.create_groups_hint')}
                </p>
                ${!this.searchQuery && !this.typeFilter ? `
                    <div class="empty-action">
                        <button class="btn btn-primary" onclick="window.vnbui.createGroup()">${t('groups.create_first_group')}</button>
                    </div>
                ` : ''}
            </div>
        `;
    }

    renderGroupModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-group" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="group-modal-title">${t('groups.create_title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="group-id">

                            <div class="mb-3">
                                <label class="form-label required">${t('groups.name_label')}</label>
                                <input type="text" class="form-control" id="group-name" placeholder="${t('groups.name_placeholder')}">
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('groups.description_label')}</label>
                                <textarea class="form-control" id="group-description" rows="2" placeholder="${t('groups.description_placeholder')}"></textarea>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('groups.tags_label')}</label>
                                <input type="text" class="form-control" id="group-tags" placeholder="${t('groups.tags_placeholder')}">
                                <div class="form-hint">${t('groups.tags_hint')}</div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('groups.type_label')}</label>
                                <div class="btn-group w-100" role="group">
                                    <input type="radio" class="btn-check" name="group-type" id="group-type-static" value="static" checked onchange="window.vnbui.toggleGroupType()">
                                    <label class="btn btn-outline-primary" for="group-type-static">${t('groups.type_static')}</label>
                                    <input type="radio" class="btn-check" name="group-type" id="group-type-dynamic" value="dynamic" onchange="window.vnbui.toggleGroupType()">
                                    <label class="btn btn-outline-primary" for="group-type-dynamic">${t('groups.type_dynamic')}</label>
                                    <input type="radio" class="btn-check" name="group-type" id="group-type-hybrid" value="hybrid" onchange="window.vnbui.toggleGroupType()">
                                    <label class="btn btn-outline-primary" for="group-type-hybrid">${t('groups.type_hybrid')}</label>
                                </div>
                                <div class="form-hint">${t('groups.type_hint')}</div>
                            </div>

                            <!-- Static VM selection -->
                            <div id="group-static-section">
                                <div class="mb-3">
                                    <label class="form-label">${t('groups.select_vms')}</label>
                                    <select class="form-select" id="group-vms" multiple size="6">
                                        <option value="">${t('groups.loading_vms')}</option>
                                    </select>
                                    <div class="form-hint">${t('groups.select_vms_hint')}</div>
                                </div>
                            </div>

                            <!-- Dynamic rules section -->
                            <div id="group-rules-section" style="display: none;">
                                <div class="mb-3">
                                    <label class="form-label">${t('groups.rules_match')}</label>
                                    <select class="form-select form-select-sm" id="group-rules-match" style="width: auto;">
                                        <option value="all">${t('groups.rules_match_all')}</option>
                                        <option value="any">${t('groups.rules_match_any')}</option>
                                    </select>
                                </div>
                                <div id="group-rules-list">
                                    <!-- Rule rows inserted here -->
                                </div>
                                <button class="btn btn-sm btn-outline-primary mt-2" onclick="window.vnbui.addGroupRule()">
                                    + ${t('groups.add_rule')}
                                </button>
                                <button class="btn btn-sm btn-outline-secondary mt-2 ms-2" onclick="window.vnbui.previewGroupRules()">
                                    ${t('groups.preview_members')}
                                </button>
                                <div id="group-rules-preview" class="mt-2"></div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-primary" onclick="window.vnbui.submitGroup()">${t('groups.save_group')}</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderDeleteModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-delete-group" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-sm modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-body">
                            <input type="hidden" id="delete-group-id">
                            <div class="modal-title">${t('groups.delete_title')}</div>
                            <div>${t('groups.delete_msg', {name: '<strong id="delete-group-name"></strong>'})} ${t('groups.delete_detail')}</div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-danger" onclick="window.vnbui.submitDeleteGroup()">${t('groups.delete_button')}</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getGroupColor(name) {
        const colors = ['bg-blue-lt', 'bg-azure-lt', 'bg-indigo-lt', 'bg-purple-lt', 'bg-pink-lt', 'bg-red-lt', 'bg-orange-lt', 'bg-yellow-lt', 'bg-lime-lt', 'bg-green-lt', 'bg-teal-lt', 'bg-cyan-lt'];
        const index = (name || '').charCodeAt(0) % colors.length;
        return colors[index];
    }

}
