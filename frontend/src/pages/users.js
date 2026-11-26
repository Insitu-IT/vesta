import { enumLabel } from '../utils/status-labels.js';
/**
 * Users Page
 * Manage users and their roles
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTime, formatDate } from '../utils/format.js';
import { assetResolver } from '../assets/resolver.js';
import { authService } from '../services/auth.service.js';

export class UsersPage {
    constructor() {
        this.users = [];
        this.loading = false;
        this.loadError = false;
        this.searchQuery = '';
        this._searchTimeout = null;
    }

    async loadData() {
        this.loading = true;
        this.loadError = false;
        try {
            const data = await apiClient.get('/api/v1/users');
            this.users = data.items || data.users || [];
        } catch (error) {
            this.loadError = true;
            this.users = [];
        }
        this.loading = false;
    }

    async render() {
        const t = window.t;
        if (authService.verifiedUser?.role !== 'admin') {
            return '<div class="alert alert-danger" role="alert">Access denied</div>';
        }
        await this.loadData();
        if (this.loadError) {
            return `<div class="alert alert-danger">${escapeHtml(t('common.failed_to_load'))}</div>`;
        }

        const activeUsers = this.users.filter(u => u.is_active === true).length;
        const adminUsers = this.users.filter(u => u.role === 'admin').length;

        setTimeout(() => this.setupEventListeners(), 0);

        return `
            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <circle cx="9" cy="7" r="4" />
                                    <path d="M3 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />
                                    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                                    <path d="M21 21v-2a4 4 0 0 0 -3 -3.85" />
                                </svg>
                                ${t('users.page_title')}
                            </h2>
                            <div class="text-secondary mt-1">${t('users.page_subtitle')}</div>
                        </div>
                        <div class="col-auto d-none d-md-flex gap-3 align-items-center ms-auto">
                            <span class="text-secondary">
                                <span class="badge bg-primary me-1">${this.users.length}</span> ${t('users.total_users')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-success me-1">${activeUsers}</span> ${t('users.active')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-warning me-1">${adminUsers}</span> ${t('users.admins')}
                            </span>
                            <span class="text-secondary">
                                <span class="badge bg-azure me-1">${this.users.filter(u => u.auth_source === 'oidc').length}</span> ${t('users.sso_users')}
                            </span>
                            <div class="btn-list">
                                <button class="btn btn-primary d-none d-sm-inline-block" onclick="window.vnbui.createUser()">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <line x1="12" y1="5" x2="12" y2="19" />
                                        <line x1="5" y1="12" x2="19" y2="12" />
                                    </svg>
                                    ${t('users.new_user')}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="page-body">
                <div class="container-xl">
                    <!-- Users Table -->
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">${t('users.all_users')}</h3>
                            <div class="ms-auto">
                                <div class="input-group search-control">
                                    <input type="text" class="form-control form-control-sm" placeholder="${t('users.search_placeholder')}" id="user-search">
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
                                        <th>${t('users.col_user')}</th>
                                        <th>${t('users.col_email')}</th>
                                        <th>${t('users.col_auth')}</th>
                                        <th>${t('users.col_role')}</th>
                                        <th>${t('users.col_status')}</th>
                                        <th>${t('users.col_last_login')}</th>
                                        <th>${t('users.col_created')}</th>
                                        <th class="w-1">${t('common.actions')}</th>
                                    </tr>
                                </thead>
                                <tbody id="users-table-body">
                                    ${this.renderUserRows()}
                                </tbody>
                            </table>
                        </div>
                        ${this.users.length === 0 ? this.renderEmptyState() : ''}
                    </div>
                </div>
            </div>

            ${this.renderUserModal()}
            ${this.renderPasswordModal()}
            ${this.renderDeleteModal()}
        `;
    }

    setupEventListeners() {
        const searchInput = document.getElementById('user-search');
        if (searchInput) {
            searchInput.value = this.searchQuery;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this._searchTimeout);
                this._searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value;
                    const tbody = document.getElementById('users-table-body');
                    if (tbody) tbody.innerHTML = this.renderUserRows();
                }, 300);
            });
        }
    }

    renderUserRows() {
        const t = window.t;
        if (this.users.length === 0) {
            return '';
        }

        let filtered = this.users;
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            filtered = filtered.filter(u =>
                (u.username || '').toLowerCase().includes(q) ||
                (u.full_name || '').toLowerCase().includes(q)
            );
        }

        if (filtered.length === 0) {
            return `<tr><td colspan="8" class="text-center text-secondary py-4">${t('common.no_results', { query: this.searchQuery })}</td></tr>`;
        }

        return filtered.map(user => {
            const isOIDC = user.auth_source === 'oidc';
            const authBadge = isOIDC
                ? `<span class="badge bg-azure" title="SSO via ${escapeHtml(user.oidc_issuer || 'OIDC')}">${t('users.auth_sso')}</span>`
                : `<span class="badge bg-secondary">${t(user.auth_source === 'local' ? 'users.auth_local' : 'common.unknown')}</span>`;
            const roleSourceInfo = isOIDC && user.role_source === 'local'
                ? `<span class="badge bg-warning-lt ms-1" title="Role assigned by admin, not OIDC claims">${t('users.role_pinned')}</span>`
                : `<span class="text-secondary small">${t(user.role_source === 'oidc' ? 'users.role_source_oidc' : user.role_source === 'local' ? 'users.role_source_local' : 'common.unknown')}</span>`;

            return `
            <tr>
                <td>
                    <div class="d-flex align-items-center">
                        <span class="avatar avatar-sm me-2 ${this.getAvatarColor(user.username)}">
                            ${escapeHtml((user.username || 'U').substring(0, 2).toUpperCase())}
                        </span>
                        <div>
                            <div class="font-weight-medium">${escapeHtml(user.username || t('common.unknown'))}</div>
                            <div class="text-secondary small">${escapeHtml(user.full_name || '')}</div>
                            <div class="text-secondary small">${escapeHtml(user.org_id || t('common.unknown'))}</div>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="text-secondary">${escapeHtml(user.email || t('common.na'))}</span>
                </td>
                <td>
                    ${authBadge}
                </td>
                <td>
                    <span class="badge bg-${this.getRoleColor(user.role)}">
                        ${escapeHtml(enumLabel(user.role || 'viewer', 'role'))}
                    </span>
                    ${roleSourceInfo}
                </td>
                <td>
                    ${user.is_active === true ? `
                        <span class="badge bg-success">${t('users.status_active')}</span>
                    ` : `
                        <span class="badge bg-secondary">${t(user.is_active === false ? 'users.status_disabled' : 'common.unknown')}</span>
                    `}
                </td>
                <td>
                    ${user.last_login ? `
                        <div>${formatDate(user.last_login)}</div>
                        <div class="text-secondary small">${formatRelativeTime(user.last_login)}</div>
                    ` : `
                        <span class="text-secondary">${t('common.never')}</span>
                    `}
                </td>
                <td>
                    <span class="text-secondary small">${formatDate(user.created_at)}</span>
                </td>
                <td>
                    <div class="btn-list flex-nowrap">
                        <button class="btn btn-sm btn-ghost-secondary" onclick="window.vnbui.editUser('${escapeHtml(user.id)}')" title="${t('users.edit_tooltip')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <path d="M9 7h-3a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-3" />
                                <path d="M9 15h3l8.5 -8.5a1.5 1.5 0 0 0 -3 -3l-8.5 8.5v3" />
                                <line x1="16" y1="5" x2="19" y2="8" />
                            </svg>
                        </button>
                        ${!isOIDC ? `
                        <button class="btn btn-sm btn-ghost-secondary" onclick="window.vnbui.resetPassword(${escapeHtml(JSON.stringify(user.id))}, ${escapeHtml(JSON.stringify(user.username))})" title="${t('users.reset_password_tooltip')}">
                            <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                <rect x="5" y="11" width="14" height="10" rx="2" />
                                <circle cx="12" cy="16" r="1" />
                                <path d="M8 11v-4a4 4 0 0 1 8 0v4" />
                            </svg>
                        </button>
                        ` : ''}
                        ${user.id !== window.vnbui?.currentUserId ? `
                            <button class="btn btn-sm btn-ghost-danger" onclick="window.vnbui.deleteUser(${escapeHtml(JSON.stringify(user.id))}, ${escapeHtml(JSON.stringify(user.username))})" title="${t('users.delete_tooltip')}">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <line x1="4" y1="7" x2="20" y2="7" />
                                    <line x1="10" y1="11" x2="10" y2="17" />
                                    <line x1="14" y1="11" x2="14" y2="17" />
                                    <path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12" />
                                    <path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3" />
                                </svg>
                            </button>
                        ` : ''}
                    </div>
                </td>
            </tr>
        `;
        }).join('');
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty">
                <div class="empty-img">
                    <div class="empty-icon">${assetResolver.inlineSvg('empty-state', { class: 'icon icon-lg text-secondary', width: 120, height: 120 })}</div>
                </div>
                <p class="empty-title">${t('users.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${t('users.empty_subtitle')}
                </p>
                <div class="empty-action">
                    <button class="btn btn-primary" onclick="window.vnbui.createUser()">
                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                            <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                            <line x1="12" y1="5" x2="12" y2="19" />
                            <line x1="5" y1="12" x2="19" y2="12" />
                        </svg>
                        ${t('users.new_user')}
                    </button>
                </div>
            </div>
        `;
    }

    renderUserModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-user" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="user-modal-title">${t('users.create_title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="user-id">
                            <input type="hidden" id="user-auth-source">

                            <!-- OIDC User Info (shown only for SSO users) -->
                            <div id="oidc-user-info" class="alert alert-azure mb-3" style="display: none;">
                                <div class="d-flex align-items-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="icon icon-lg me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                        <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                        <path d="M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2" />
                                        <path d="M20 12h-13l3 -3m0 6l-3 -3" />
                                    </svg>
                                    <div>
                                        <strong>${t('users.sso_user_title')}</strong>
                                        <div class="text-secondary small">${t('users.sso_user_subtitle')}</div>
                                    </div>
                                </div>
                                <hr class="my-2">
                                <div class="row small">
                                    <div class="col-md-6">
                                        <strong>${t('users.oidc_subject')}</strong>
                                        <div id="oidc-subject" class="text-secondary text-break"></div>
                                    </div>
                                    <div class="col-md-6">
                                        <strong>${t('users.oidc_issuer')}</strong>
                                        <div id="oidc-issuer" class="text-secondary text-break"></div>
                                    </div>
                                </div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label required">${t('users.username_label')}</label>
                                <input type="text" class="form-control" id="user-username" placeholder="${t('users.username_placeholder')}">
                                <div class="form-hint">${t('users.username_hint')}</div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">${t('users.full_name_label')}</label>
                                <input type="text" class="form-control" id="user-fullname" placeholder="${t('users.full_name_placeholder')}">
                                <small id="user-fullname-hint" class="form-hint text-secondary" style="display: none;">
                                    ${t('users.managed_by_provider')}
                                </small>
                            </div>

                            <div class="mb-3">
                                <label class="form-label required">${t('users.email_label')}</label>
                                <input type="email" class="form-control" id="user-email" placeholder="${t('users.email_placeholder')}">
                                <small id="user-email-hint" class="form-hint text-secondary" style="display: none;">
                                    ${t('users.managed_by_provider')}
                                </small>
                            </div>

                            <div class="mb-3" id="user-password-group">
                                <label class="form-label required">${t('users.password_label')}</label>
                                <input type="password" class="form-control" id="user-password" placeholder="••••••••">
                                <div class="form-hint">${t('users.password_hint')}</div>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <div class="mb-3">
                                        <label class="form-label required">${t('users.role_label')}</label>
                                        <select class="form-select" id="user-role">
                                            <option value="viewer">${t('users.role_viewer')}</option>
                                            <option value="operator">${t('users.role_operator')}</option>
                                            <option value="admin">${t('users.role_admin')}</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="mb-3" id="role-source-group" style="display: none;">
                                        <label class="form-label">${t('users.role_source_label')}</label>
                                        <select class="form-select" id="user-role-source">
                                            <option value="oidc">${t('users.role_source_oidc')}</option>
                                            <option value="local">${t('users.role_source_local')}</option>
                                        </select>
                                        <div class="form-hint">${t('users.role_source_hint')}</div>
                                    </div>
                                    <div class="mb-3" id="user-status-group">
                                        <label class="form-label">${t('users.status_label')}</label>
                                        <div class="form-check form-switch mt-2">
                                            <input class="form-check-input" type="checkbox" id="user-active" checked>
                                            <label class="form-check-label" for="user-active">${t('users.account_active')}</label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-primary" onclick="window.vnbui.submitUser()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <polyline points="9 11 12 14 20 6" />
                                    <path d="M20 12v6a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h9" />
                                </svg>
                                ${t('users.save_user')}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderPasswordModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-reset-password" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-sm modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${t('users.reset_password_title')}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="${t('common.close')}"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" id="reset-user-id">

                            <div class="mb-3">
                                <label class="form-label">${t('users.username_label')}</label>
                                <input type="text" class="form-control" id="reset-username" readonly>
                            </div>

                            <div class="mb-3">
                                <label class="form-label required">${t('users.new_password')}</label>
                                <input type="password" class="form-control" id="reset-new-password" placeholder="••••••••">
                                <div class="form-hint">${t('users.new_password_hint')}</div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label required">${t('users.confirm_password')}</label>
                                <input type="password" class="form-control" id="reset-confirm-password" placeholder="••••••••">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-primary" onclick="window.vnbui.submitResetPassword()">${t('users.reset_password_btn')}</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderDeleteModal() {
        const t = window.t;
        return `
            <div class="modal modal-blur fade" id="modal-delete-user" tabindex="-1" role="dialog" aria-hidden="true">
                <div class="modal-dialog modal-sm modal-dialog-centered" role="document">
                    <div class="modal-content">
                        <div class="modal-body">
                            <div class="modal-title">${t('users.delete_title')}</div>
                            <input type="hidden" id="delete-user-id">
                            <div>${t('users.delete_msg', {username: '<strong id="delete-user-name"></strong>'})}</div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-link link-secondary me-auto" data-bs-dismiss="modal">${t('common.cancel')}</button>
                            <button type="button" class="btn btn-danger" onclick="window.vnbui.submitDeleteUser()">${t('users.delete_button')}</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getRoleColor(role) {
        const colors = {
            'admin': 'danger',
            'operator': 'warning',
            'viewer': 'info'
        };
        return colors[role?.toLowerCase()] || 'secondary';
    }

    getAvatarColor(username) {
        const colors = ['bg-blue-lt', 'bg-azure-lt', 'bg-indigo-lt', 'bg-purple-lt', 'bg-pink-lt', 'bg-red-lt', 'bg-orange-lt', 'bg-yellow-lt', 'bg-lime-lt', 'bg-green-lt', 'bg-teal-lt', 'bg-cyan-lt'];
        const index = (username || '').charCodeAt(0) % colors.length;
        return colors[index];
    }

}
