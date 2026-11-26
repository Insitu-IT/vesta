/**
 * Activity Page
 * View activity logs and audit trail - Compact dense layout
 * Unified feed combining user actions and system events
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTimeCompact, formatAbsoluteTime, formatEventType } from '../utils/format.js';

export class ActivityPage {
    constructor() {
        this.activities = [];
        this.loading = false;
        this.filter = 'all';
        this.sourceFilter = 'all';  // 'all', 'user', 'system'
        this.searchQuery = '';
        this.timeRange = 'week';
    }

    async loadData() {
        this.loading = true;
        try {
            // Fetch all activities; source/type/search/time filtering is done client-side
            // so that filter changes don't require a round-trip to the server.
            const data = await apiClient.get('/api/v1/activity');
            this.activities = data.activities || [];
        } catch (error) {
            console.error('Failed to load activity logs:', error);
            this.activities = [];
        }
        this.loading = false;
    }

    async render() {
        const t = window.t;
        await this.loadData();
        const filteredCount = this.getFilteredActivities().length;
        const totalCount = this.activities.length;

        return `
            <style>
                .activity-compact { border-left: 3px solid var(--activity-color, #6c757d); padding: 8px 12px; margin-bottom: 2px; background: #fff; transition: background 0.15s; }
                .activity-compact:hover { background: #f8f9fa; }
                .activity-compact.type-backup { --activity-color: #066fd1; }
                .activity-compact.type-restore { --activity-color: #2fb344; }
                .activity-compact.type-user { --activity-color: #4299e1; }
                .activity-compact.type-system { --activity-color: #6c757d; }
                .activity-compact.type-error { --activity-color: #d63939; }
                .activity-compact.type-agent { --activity-color: #ae3ec9; }
                .activity-compact.type-settings { --activity-color: #f59f00; }
                .activity-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
                .activity-icon { width: 20px; height: 20px; flex-shrink: 0; color: var(--activity-color); }
                .activity-title { font-weight: 500; color: #1e293b; }
                .activity-target { color: #64748b; }
                .activity-sep { color: #cbd5e1; }
                .activity-time { margin-left: auto; text-align: right; white-space: nowrap; }
                .activity-time-rel { color: #64748b; font-size: 0.875em; }
                .activity-time-abs { color: #94a3b8; font-size: 0.75em; font-family: monospace; }
                .activity-user { background: #f1f5f9; color: #475569; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 500; }
                .activity-details-row { display: flex; align-items: center; gap: 8px; margin-top: 4px; padding-left: 32px; }
                .activity-preview { color: #64748b; font-size: 0.8em; font-family: monospace; max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                .activity-expand { color: #066fd1; cursor: pointer; font-size: 0.75em; padding: 2px 6px; border-radius: 3px; }
                .activity-expand:hover { background: #e0f2fe; }
                .activity-full-details { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; margin-top: 8px; margin-left: 32px; font-size: 0.8em; font-family: monospace; white-space: pre-wrap; display: none; }
                .activity-full-details.show { display: block; }
                .filter-bar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
                .filter-search { flex: 1; min-width: 200px; }
                .filter-count { color: #64748b; font-size: 0.875em; }
                .type-pills { display: flex; gap: 4px; flex-wrap: wrap; }
                .type-pill { padding: 4px 12px; border-radius: 16px; font-size: 0.8em; font-weight: 500; cursor: pointer; border: 1px solid #e2e8f0; background: #fff; transition: all 0.15s; }
                .type-pill:hover { border-color: #94a3b8; }
                .type-pill.active { background: #066fd1; color: #fff; border-color: #066fd1; }
                .type-pill.active-backup { background: #066fd1; border-color: #066fd1; }
                .type-pill.active-restore { background: #2fb344; border-color: #2fb344; }
                .type-pill.active-user { background: #4299e1; border-color: #4299e1; }
                .type-pill.active-system { background: #6c757d; border-color: #6c757d; }
                .type-pill.active-agent { background: #ae3ec9; border-color: #ae3ec9; }
                .type-pill.active-settings { background: #f59f00; border-color: #f59f00; color: #1e293b; }
                /* Source filter styles */
                .source-pills { display: flex; gap: 4px; border-left: 1px solid #e2e8f0; padding-left: 12px; margin-left: 8px; }
                .source-pill { padding: 4px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 500; cursor: pointer; border: 1px solid #e2e8f0; background: #fff; transition: all 0.15s; display: flex; align-items: center; gap: 4px; }
                .source-pill:hover { border-color: #94a3b8; }
                .source-pill.active { background: #1e293b; color: #fff; border-color: #1e293b; }
                .source-indicator { display: inline-flex; align-items: center; gap: 3px; font-size: 0.7em; padding: 1px 6px; border-radius: 3px; }
                .source-indicator.source-user { background: #dbeafe; color: #1e40af; }
                .source-indicator.source-system { background: #fef3c7; color: #92400e; }
            </style>

            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <polyline points="12 8 12 12 14 14" />
                                    <path d="M3.05 11a9 9 0 1 1 .5 4m-.5 5v-5h5" />
                                </svg>
                                ${t('activity.page_title')}
                                <span class="filter-count ms-2">(${filteredCount}${filteredCount !== totalCount ? ` of ${totalCount}` : ''})</span>
                            </h2>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
                            <button class="btn btn-primary" onclick="window.vnbui.refreshPage()">
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

            <div class="page-body">
                <div class="container-xl">
                    <!-- Enhanced Filter Bar -->
                    <div class="card mb-3">
                        <div class="card-body py-2">
                            <div class="filter-bar">
                                <div class="type-pills">
                                    <span class="type-pill ${this.filter === 'all' ? 'active' : ''}" data-filter="all" onclick="window.vnbui.filterActivity('all')">${t('activity.filter_all')}</span>
                                    <span class="type-pill ${this.filter === 'backup' ? 'active active-backup' : ''}" data-filter="backup" onclick="window.vnbui.filterActivity('backup')">${t('activity.filter_backup')}</span>
                                    <span class="type-pill ${this.filter === 'restore' ? 'active active-restore' : ''}" data-filter="restore" onclick="window.vnbui.filterActivity('restore')">${t('activity.filter_restore')}</span>
                                    <span class="type-pill ${this.filter === 'agent' ? 'active active-agent' : ''}" data-filter="agent" onclick="window.vnbui.filterActivity('agent')">${t('activity.filter_agent')}</span>
                                    <span class="type-pill ${this.filter === 'settings' ? 'active active-settings' : ''}" data-filter="settings" onclick="window.vnbui.filterActivity('settings')">${t('activity.filter_settings')}</span>
                                </div>
                                <div class="source-pills">
                                    <span class="source-pill ${this.sourceFilter === 'all' ? 'active' : ''}" data-source="all" onclick="window.vnbui.filterActivitySource('all')">${t('activity.source_all')}</span>
                                    <span class="source-pill ${this.sourceFilter === 'user' ? 'active' : ''}" data-source="user" onclick="window.vnbui.filterActivitySource('user')">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><circle cx="12" cy="7" r="4"/><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"/></svg>
                                        ${t('activity.source_user')}
                                    </span>
                                    <span class="source-pill ${this.sourceFilter === 'system' ? 'active' : ''}" data-source="system" onclick="window.vnbui.filterActivitySource('system')">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><rect x="3" y="4" width="18" height="12" rx="1"/><path d="M7 20h10"/><path d="M9 16v4"/><path d="M15 16v4"/></svg>
                                        ${t('activity.source_system')}
                                    </span>
                                </div>
                                <div class="filter-search">
                                    <input type="text" class="form-control form-control-sm" placeholder="${t('activity.search_placeholder')}"
                                           value="${escapeHtml(this.searchQuery)}"
                                           oninput="window.vnbui.searchActivity(this.value)"
                                           id="activity-search">
                                </div>
                                <select class="form-select form-select-sm" style="width: auto;" id="activity-timerange" onchange="window.vnbui.filterTimeRange(this.value)">
                                    <option value="today" ${this.timeRange === 'today' ? 'selected' : ''}>${t('activity.time_range_today')}</option>
                                    <option value="week" ${this.timeRange === 'week' ? 'selected' : ''}>${t('activity.time_range_7d')}</option>
                                    <option value="month" ${this.timeRange === 'month' ? 'selected' : ''}>${t('activity.time_range_30d')}</option>
                                    <option value="all" ${this.timeRange === 'all' ? 'selected' : ''}>${t('activity.time_range_all')}</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <!-- Compact Activity List -->
                    <div class="card">
                        <div class="card-body p-0" id="activity-list-container">
                            ${this.renderCompactList()}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderCompactList() {
        const filtered = this.getFilteredActivities();

        if (filtered.length === 0) {
            return this.renderEmptyState();
        }

        return `
            <div class="activity-list">
                ${filtered.map((activity, idx) => this.renderCompactItem(activity, idx)).join('')}
            </div>
        `;
    }

    /**
     * Re-render only the list and count without reloading data from the API.
     * Called by filter/search/time-range changes to avoid losing state.
     */
    renderList() {
        const listContainer = document.querySelector('#activity-list-container');
        const countEl = document.querySelector('.filter-count');
        if (!listContainer) return;

        const filtered = this.getFilteredActivities();

        // Update count badge
        if (countEl) {
            const total = this.activities.length;
            countEl.textContent = `(${filtered.length}${filtered.length !== total ? ` of ${total}` : ''})`;
        }

        // Update type pill active states
        document.querySelectorAll('.type-pill').forEach(pill => {
            const f = pill.dataset.filter;
            pill.className = 'type-pill' +
                (f === this.filter ? (f === 'all' ? ' active' : ` active active-${f}`) : '');
        });

        // Update source pill active states
        document.querySelectorAll('.source-pill').forEach(pill => {
            pill.classList.toggle('active', pill.dataset.source === this.sourceFilter);
        });

        // Update time range select value
        const timeRangeEl = document.getElementById('activity-timerange');
        if (timeRangeEl) timeRangeEl.value = this.timeRange;

        if (filtered.length === 0) {
            listContainer.innerHTML = this.renderEmptyState();
        } else {
            listContainer.innerHTML = `
                <div class="activity-list">
                    ${filtered.map((activity, idx) => this.renderCompactItem(activity, idx)).join('')}
                </div>
            `;
        }
    }

    renderCompactItem(activity, idx) {
        const t = window.t;
        // Handle unified activity format (source, source_name, event_type)
        // vs legacy format (type, user, action)
        const isUnifiedFormat = activity.source !== undefined;

        const type = isUnifiedFormat
            ? this.normalizeEventType(activity.event_type)
            : this.normalizeType(activity.type);
        const icon = this.getActivityIcon(type);
        const target = activity.description || this.getTargetFromDetails(activity.details);
        const sourceName = isUnifiedFormat ? activity.source_name : activity.user;
        const sourceType = isUnifiedFormat ? activity.source : 'user';
        const details = activity.details;
        const preview = details ? this.getDetailsPreview(details) : '';
        const relTime = formatRelativeTimeCompact(activity.created_at);
        const absTime = formatAbsoluteTime(activity.created_at);

        // Build title from event_type if in unified format
        const title = isUnifiedFormat
            ? formatEventType(activity.event_type)
            : (activity.title || 'Activity');

        // Source indicator (user icon vs system/robot icon)
        const sourceIndicator = sourceType === 'system'
            ? `<span class="source-indicator source-system" title="System Event">
                 <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><rect x="3" y="4" width="18" height="12" rx="1"/><path d="M7 20h10"/><path d="M9 16v4"/><path d="M15 16v4"/></svg>
                 ${escapeHtml(sourceName || 'System')}
               </span>`
            : `<span class="source-indicator source-user" title="User Action">
                 <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><circle cx="12" cy="7" r="4"/><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"/></svg>
                 ${escapeHtml(sourceName || 'User')}
               </span>`;

        return `
            <div class="activity-compact type-${type}">
                <div class="activity-row">
                    <span class="activity-icon">${icon}</span>
                    <span class="activity-title">${escapeHtml(title)}</span>
                    ${target ? `<span class="activity-sep">·</span><span class="activity-target">${escapeHtml(target)}</span>` : ''}
                    ${sourceIndicator}
                    <span class="activity-time">
                        <span class="activity-time-rel">${relTime}</span>
                        <span class="activity-time-abs">${absTime}</span>
                    </span>
                </div>
                ${details ? `
                    <div class="activity-details-row">
                        <span class="activity-preview">${escapeHtml(preview)}</span>
                        <span class="activity-expand" onclick="window.vnbui.toggleActivityDetails(${idx})">${t('activity.expand_details')}</span>
                    </div>
                    <pre class="activity-full-details" id="activity-details-${idx}">${escapeHtml(JSON.stringify(details, null, 2))}</pre>
                ` : ''}
            </div>
        `;
    }

    getTargetFromDetails(details) {
        if (!details) return '';
        return details.vm_name || details.hostname || details.name || '';
    }

    normalizeEventType(eventType) {
        if (!eventType) return 'system';
        const t = eventType.toLowerCase();
        if (t.includes('backup')) return 'backup';
        if (t.includes('restore')) return 'restore';
        if (t.includes('agent') || t.includes('orphan')) return 'agent';
        if (t.includes('vm_lifecycle')) return 'agent';
        if (t.includes('setting') || t.includes('config')) return 'settings';
        if (t.includes('user') || t.includes('login')) return 'user';
        if (t.includes('error') || t.includes('fail')) return 'error';
        return 'system';
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty py-4">
                <p class="empty-title h4">${t('activity.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${this.filter === 'all' && !this.searchQuery
                        ? t('activity.empty_subtitle')
                        : t('activity.empty_no_match')}
                </p>
            </div>
        `;
    }

    normalizeType(type) {
        if (!type) return 'system';
        const t = type.toLowerCase();
        // Map activity types to color categories
        if (t.includes('backup')) return 'backup';
        if (t.includes('restore')) return 'restore';
        if (t.includes('agent') || t.includes('register') || t.includes('delete')) return 'agent';
        if (t.includes('setting') || t.includes('config')) return 'settings';
        if (t.includes('user') || t.includes('login') || t.includes('auth')) return 'user';
        if (t.includes('error') || t.includes('fail')) return 'error';
        return 'system';
    }

    getFilteredActivities() {
        let filtered = this.activities;

        // Filter by type — handle both unified (event_type) and legacy (type) formats
        if (this.filter !== 'all') {
            filtered = filtered.filter(a => {
                const normalized = a.source !== undefined
                    ? this.normalizeEventType(a.event_type)
                    : this.normalizeType(a.type);
                return normalized === this.filter;
            });
        }

        // Filter by source (user vs system) — unified format only
        if (this.sourceFilter !== 'all') {
            filtered = filtered.filter(a => {
                const src = a.source !== undefined ? a.source : 'user';
                return src === this.sourceFilter;
            });
        }

        // Filter by search query — include source_name and event_type for unified format
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            filtered = filtered.filter(a =>
                (a.title || '').toLowerCase().includes(q) ||
                (a.description || '').toLowerCase().includes(q) ||
                (a.user || '').toLowerCase().includes(q) ||
                (a.source_name || '').toLowerCase().includes(q) ||
                (a.event_type || '').toLowerCase().includes(q) ||
                JSON.stringify(a.details || {}).toLowerCase().includes(q)
            );
        }

        // Filter by time range
        const now = new Date();
        if (this.timeRange === 'today') {
            const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            filtered = filtered.filter(a => new Date(a.created_at) >= todayStart);
        } else if (this.timeRange === 'week') {
            const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
            filtered = filtered.filter(a => new Date(a.created_at) >= weekAgo);
        } else if (this.timeRange === 'month') {
            const monthAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);
            filtered = filtered.filter(a => new Date(a.created_at) >= monthAgo);
        }

        return filtered;
    }

    getDetailsPreview(details) {
        if (!details) return '';
        const str = JSON.stringify(details);
        // Show key fields if available
        if (details.vm_name) return `vm: ${details.vm_name}`;
        if (details.hostname) return `host: ${details.hostname}`;
        if (details.issuer) return 'issuer: ' + details.issuer.split('/').pop();
        if (details.keys && Array.isArray(details.keys)) return `keys: ${details.keys.slice(0, 3).join(', ')}${details.keys.length > 3 ? '...' : ''}`;
        if (str.length > 80) return str.substring(0, 80) + '...';
        return str;
    }

    getActivityIcon(type) {
        const icons = {
            backup: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6a8 3 0 0 0 16 0v-6"/><path d="M4 12v6a8 3 0 0 0 16 0v-6"/></svg>`,
            restore: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path d="M9 13l-4 -4l4 -4m-4 4h11a4 4 0 0 1 0 8h-1"/></svg>`,
            agent: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><rect x="3" y="4" width="18" height="12" rx="1"/><path d="M7 20h10"/><path d="M9 16v4"/><path d="M15 16v4"/></svg>`,
            settings: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/></svg>`,
            user: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><circle cx="12" cy="7" r="4"/><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"/></svg>`,
            error: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path d="M12 9v2m0 4v.01"/><path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75"/></svg>`,
            system: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><circle cx="12" cy="12" r="9"/><path d="M12 8v4l2 2"/></svg>`
        };
        return icons[type] || icons.system;
    }

    // Called from global handlers
    setFilter(filter) {
        this.filter = filter;
    }

    setSourceFilter(source) {
        this.sourceFilter = source;
    }

    setSearchQuery(query) {
        this.searchQuery = query;
    }

    setTimeRange(range) {
        this.timeRange = range;
    }
}
