/**
 * Notifications Page
 * Manage notification settings and view notification history
 * Dense layout matching Activity Logs style
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { formatRelativeTimeCompact, formatAbsoluteTime } from '../utils/format.js';

export class NotificationsPage {
    constructor() {
        this.notifications = [];
        this.loading = false;
        this.filter = 'all';
    }

    async loadData() {
        this.loading = true;
        try {
            const notifData = await apiClient.get('/api/v1/notifications').catch(() => ({ notifications: [] }));
            this.notifications = notifData.notifications || [];
        } catch (error) {
            console.error('Failed to load notifications:', error);
            this.notifications = [];
        }
        this.loading = false;
    }

    async render() {
        const t = window.t;
        await this.loadData();

        const unread = this.notifications.filter(n => !n.read).length;
        const filtered = this.getFilteredNotifications();

        return `
            <style>
                .notif-compact { border-left: 3px solid var(--notif-color, #6c757d); padding: 8px 12px; margin-bottom: 2px; background: #fff; transition: background 0.15s; }
                .notif-compact:hover { background: #f8f9fa; }
                .notif-compact.type-success, .notif-compact.type-backup_success { --notif-color: #2fb344; }
                .notif-compact.type-error, .notif-compact.type-backup_failure { --notif-color: #d63939; }
                .notif-compact.type-warning, .notif-compact.type-agent_offline { --notif-color: #f59f00; }
                .notif-compact.type-info { --notif-color: #4299e1; }
                .notif-compact.unread { border-left-color: #f59e0b; border-left-width: 4px; }
                .notif-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
                .notif-icon { width: 20px; height: 20px; flex-shrink: 0; color: var(--notif-color); }
                .notif-title { font-weight: 500; color: #1e293b; }
                .notif-status { font-size: 0.75em; padding: 2px 8px; border-radius: 4px; font-weight: 500; }
                .notif-status.success { background: #d1fae5; color: #065f46; }
                .notif-status.failed { background: #fee2e2; color: #991b1b; }
                .notif-status.offline { background: #fef3c7; color: #92400e; }
                .notif-sep { color: #cbd5e1; }
                .notif-target { color: #64748b; font-family: monospace; font-size: 0.9em; }
                .notif-time { margin-left: auto; text-align: right; white-space: nowrap; }
                .notif-time-rel { color: #64748b; font-size: 0.875em; }
                .notif-time-abs { color: #94a3b8; font-size: 0.75em; font-family: monospace; }
                .notif-details-row { display: flex; align-items: center; gap: 8px; margin-top: 4px; padding-left: 32px; }
                .notif-preview { color: #64748b; font-size: 0.8em; max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                .notif-expand { color: #066fd1; cursor: pointer; font-size: 0.75em; padding: 2px 6px; border-radius: 3px; }
                .notif-expand:hover { background: #e0f2fe; }
                .notif-full-details { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; margin-top: 8px; margin-left: 32px; font-size: 0.8em; font-family: monospace; white-space: pre-wrap; display: none; max-height: 300px; overflow-y: auto; }
                .notif-full-details.show { display: block; }
                .notif-actions { display: flex; gap: 4px; }
                .notif-action-btn { padding: 2px 6px; border: none; background: transparent; color: #64748b; cursor: pointer; border-radius: 3px; }
                .notif-action-btn:hover { background: #f1f5f9; color: #1e293b; }
                .notif-action-btn.danger:hover { background: #fee2e2; color: #991b1b; }
                .filter-pills { display: flex; gap: 4px; flex-wrap: wrap; }
                .filter-pill { padding: 4px 12px; border-radius: 16px; font-size: 0.8em; font-weight: 500; cursor: pointer; border: 1px solid #e2e8f0; background: #fff; transition: all 0.15s; }
                .filter-pill:hover { border-color: #94a3b8; }
                .filter-pill.active { background: #066fd1; color: #fff; border-color: #066fd1; }
            </style>

            <div class="page-header d-print-none">
                <div class="container-xl">
                    <div class="row g-2 align-items-center">
                        <div class="col">
                            <h2 class="page-title">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon me-2" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                    <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                                    <path d="M10 5a2 2 0 0 1 4 0a7 7 0 0 1 4 6v3a4 4 0 0 0 2 3h-16a4 4 0 0 0 2 -3v-3a7 7 0 0 1 4 -6" />
                                    <path d="M9 17v1a3 3 0 0 0 6 0v-1" />
                                </svg>
                                ${t('notifications.page_title')}
                                <span class="text-secondary ms-2" style="font-size: 0.6em; font-weight: 400;">(${filtered.length}${filtered.length !== this.notifications.length ? ` of ${this.notifications.length}` : ''})</span>
                            </h2>
                        </div>
                        <div class="col-auto ms-auto d-print-none">
                            ${unread > 0 ? `
                                <button class="btn btn-ghost-primary me-2" onclick="window.vnbui.markAllRead()">
                                    ${t('notifications.mark_all_read')}
                                </button>
                            ` : ''}
                            <button class="btn btn-primary" onclick="window.vnbui.refreshPage()">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
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
                    <div class="row">
                        <!-- Notifications List -->
                        <div class="col-12">
                            <!-- Filter Bar -->
                            <div class="card mb-2">
                                <div class="card-body py-2">
                                    <div class="filter-pills">
                                        <span class="filter-pill ${this.filter === 'all' ? 'active' : ''}" data-filter="all" onclick="window.vnbui.filterNotifications('all')">${t('notifications.filter_all')}</span>
                                        <span class="filter-pill ${this.filter === 'backup_failure' ? 'active' : ''}" data-filter="backup_failure" onclick="window.vnbui.filterNotifications('backup_failure')">${t('notifications.notify_backup_failure')}</span>
                                        <span class="filter-pill ${this.filter === 'backup_success' ? 'active' : ''}" data-filter="backup_success" onclick="window.vnbui.filterNotifications('backup_success')">${t('notifications.notify_backup_success')}</span>
                                        <span class="filter-pill ${this.filter === 'agent_offline' ? 'active' : ''}" data-filter="agent_offline" onclick="window.vnbui.filterNotifications('agent_offline')">${t('notifications.filter_agent')}</span>
                                    </div>
                                </div>
                            </div>

                            <!-- Compact Notifications List -->
                            <div class="card">
                                <div class="card-body p-0" id="notif-list-container">
                                    ${this.renderCompactNotifications(filtered)}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getFilteredNotifications() {
        if (this.filter === 'all') return this.notifications;
        return this.notifications.filter(n => n.type === this.filter);
    }

    renderCompactNotifications(notifications) {
        if (notifications.length === 0) {
            return this.renderEmptyState();
        }

        return `
            <div class="notif-list">
                ${notifications.map((notif, idx) => this.renderCompactItem(notif, idx)).join('')}
            </div>
        `;
    }

    renderCompactItem(notif, idx) {
        const t = window.t;
        const type = notif.type || 'info';
        const icon = this.getNotificationIcon(type);
        const parsed = this.parseNotification(notif);
        const relTime = formatRelativeTimeCompact(notif.created_at);
        const absTime = formatAbsoluteTime(notif.created_at);
        const hasDetails = notif.message && notif.message.length > 50;

        return `
            <div class="notif-compact type-${type} ${notif.read ? '' : 'unread'}">
                <div class="notif-row">
                    <span class="notif-icon">${icon}</span>
                    <span class="notif-title">${escapeHtml(parsed.action)}</span>
                    ${parsed.status ? `<span class="notif-status ${parsed.statusClass}">${escapeHtml(parsed.status)}</span>` : ''}
                    ${parsed.target ? `<span class="notif-sep">·</span><span class="notif-target">${escapeHtml(parsed.target)}</span>` : ''}
                    <span class="notif-time">
                        <span class="notif-time-rel">${relTime}</span>
                        <span class="notif-time-abs">${absTime}</span>
                    </span>
                    <div class="notif-actions">
                        <button class="notif-action-btn danger" onclick="window.vnbui.deleteNotification('${escapeHtml(notif.id)}')" title="${t('notifications.delete_notif')}">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none">
                                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                            </svg>
                        </button>
                    </div>
                </div>
                ${hasDetails ? `
                    <div class="notif-details-row">
                        <span class="notif-preview">${escapeHtml(this.getPreview(notif.message))}</span>
                        <span class="notif-expand" onclick="window.vnbui.toggleNotificationDetails(${idx})">+details</span>
                    </div>
                    <pre class="notif-full-details" id="notif-details-${idx}">${escapeHtml(notif.message)}</pre>
                ` : ''}
            </div>
        `;
    }

    parseNotification(notif) {
        // Parse notification to extract structured info from title/type
        const type = notif.type || '';
        const title = notif.title || '';

        let action = 'Notification';
        let status = '';
        let statusClass = '';
        let target = '';

        // Parse [vnbui] Backup FAILED: monitor01 style titles
        if (title.includes('Backup FAILED')) {
            action = 'Backup';
            status = 'FAILED';
            statusClass = 'failed';
            const match = title.match(/:\s*(.+)$/);
            if (match) target = match[1];
        } else if (title.includes('Backup completed')) {
            action = 'Backup';
            status = 'Completed';
            statusClass = 'success';
            const match = title.match(/:\s*(.+)$/);
            if (match) target = match[1];
        } else if (title.includes('Agent OFFLINE')) {
            action = 'Agent';
            status = 'Offline';
            statusClass = 'offline';
            const match = title.match(/:\s*(.+)$/);
            if (match) target = match[1];
        } else if (type === 'backup_failure') {
            action = 'Backup';
            status = 'FAILED';
            statusClass = 'failed';
        } else if (type === 'backup_success') {
            action = 'Backup';
            status = 'Completed';
            statusClass = 'success';
        } else if (type === 'agent_offline') {
            action = 'Agent';
            status = 'Offline';
            statusClass = 'offline';
        } else {
            // Fallback to title
            action = title.replace(/^\[vnbui\]\s*/, '');
        }

        return { action, status, statusClass, target };
    }

    getPreview(message) {
        if (!message) return '';
        // Get first meaningful line that's not just "Backup FAILED!" or similar
        const lines = message.split('\n').filter(l => l.trim() && !l.match(/^(Backup|VM|Type|Status|Started|Completed):/));
        // Find error line
        const errorLine = lines.find(l => l.toLowerCase().includes('error'));
        if (errorLine) return errorLine.substring(0, 100);
        // Return first line
        return lines[0]?.substring(0, 100) || message.substring(0, 100);
    }

    renderEmptyState() {
        const t = window.t;
        return `
            <div class="empty py-4">
                <p class="empty-title h4">${t('notifications.empty_title')}</p>
                <p class="empty-subtitle text-secondary">
                    ${this.filter === 'all' ? t('notifications.empty_subtitle') : 'No matching notifications found.'}
                </p>
            </div>
        `;
    }

    getNotificationIcon(type) {
        if (type === 'backup_success' || type === 'success') {
            return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><polyline points="9 11 12 14 20 6" /><path d="M20 12v6a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2h9" /></svg>`;
        } else if (type === 'backup_failure' || type === 'error') {
            return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><circle cx="12" cy="12" r="9" /><path d="M12 9v2m0 4v.01" /></svg>`;
        } else if (type === 'agent_offline' || type === 'warning') {
            return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><rect x="3" y="4" width="18" height="12" rx="1"/><path d="M7 20h10"/><path d="M9 16v4"/><path d="M15 16v4"/></svg>`;
        } else {
            return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><circle cx="12" cy="12" r="9" /><line x1="12" y1="8" x2="12.01" y2="8" /><polyline points="11 12 12 12 12 16 13 16" /></svg>`;
        }
    }

    /**
     * Re-render only the list and count without reloading data from the API.
     * Called by filter pill clicks to avoid losing state.
     */
    renderList() {
        const listContainer = document.getElementById('notif-list-container');
        if (!listContainer) return;

        const filtered = this.getFilteredNotifications();

        // Update count badge in page title
        const countEl = document.querySelector('.page-title .text-secondary');
        if (countEl) {
            const total = this.notifications.length;
            countEl.textContent = `(${filtered.length}${filtered.length !== total ? ` of ${total}` : ''})`;
        }

        // Update filter pill active states
        document.querySelectorAll('.filter-pill').forEach(pill => {
            pill.classList.toggle('active', pill.dataset.filter === this.filter);
        });

        listContainer.innerHTML = this.renderCompactNotifications(filtered);
    }

    // Filter setter for external call
    setFilter(filter) {
        this.filter = filter;
    }
}
