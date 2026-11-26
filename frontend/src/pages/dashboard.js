import Chart from 'chart.js/auto';
import { enumLabel } from '../utils/status-labels.js';
/**
 * Dashboard Page
 * Shows overview statistics and recent activity
 */
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';
import { updateService } from '../services/updates.service.js';
import { formatRelativeTime, formatDate } from '../utils/format.js';
import { getStatusColor } from '../utils/status-colors.js';

export class DashboardPage {
    constructor() {
        this.data = null;
        this.updateSubscription = null;
        this.pollingInterval = null;
        this.searchResults = null;
        this.searchQuery = '';
    }

    async loadData() {
        this.error = null;
        try {
            const summary = await apiClient.get('/api/v1/dashboard/summary');
            if (!summary?.vms?.by_status || !summary?.backups?.by_status) throw new Error('Invalid summary');
            this.data = {...summary, runningBackups: summary.running_backups || [], recentBackups: summary.recent_backups || []};
        } catch (error) {
            console.error('Failed to load dashboard:', error);
            this.error = true;
            this.data = null;
        }
    }

    async render() {
        await this.loadData();
        const t = window.t;
        const header = `<div class="page-header"><div class="container-xl"><h2 class="page-title">${t('dashboard.page_title')}</h2></div></div>`;
        if (this.error) return `${header}<div class="page-body"><div class="container-xl"><div class="alert alert-danger" role="alert">${t('dashboard.load_failed')} <button class="btn btn-sm" onclick="window.vnbui.refreshPage()">${t('common.refresh')}</button></div></div></div>`;
        this.subscribeToUpdates();
        const d = this.data;
        this.chartData = [];
        let body = '';
        if (d.agents.total === 0) {
            body += `<div class="card mb-3"><div class="card-body"><h3>${t('dashboard.setup_title')}</h3><p>${t('dashboard.setup_agent')}</p><a href="#agents" class="btn btn-primary">${t('nav.agents')}</a></div></div>`;
        } else if (d.vms.total === 0) {
            body += `<div class="card mb-3"><div class="card-body"><h3>${t('dashboard.setup_inventory')}</h3><p>${t('dashboard.setup_inventory_hint')}</p><a href="#agents" class="btn">${t('nav.agents')}</a></div></div>`;
        }
        body += `<div class="row row-cards mb-3">`;
        if (d.vms.total > 0) body += this.chartCard('vm-states', t('dashboard.vm_states'), Object.entries(d.vms.by_status).map(([state, count]) => ({state, domain: 'vm', label: enumLabel(state), count, href: '#vms'})));
        if (d.agents.total > 1 && d.vms.total > 0) body += this.chartCard('vm-agents', t('dashboard.vm_agents'), this.agentEntries(d.vms.by_agent));
        if (d.backups.last_24h > 0) body += this.chartCard('backup-states', t('dashboard.backup_states'), Object.entries(d.backups.by_status).filter(([, n]) => n > 0).map(([state, count]) => ({state, label: enumLabel(state), count, href: '#backups'})), `${formatDate(d.backups.period_start)} — ${formatDate(d.backups.period_end)}`);
        body += '</div>';
        if (d.backups.last_24h === 0) body += `<div class="card mb-3"><div class="card-body text-secondary">${t(d.backups.total === 0 ? 'dashboard.setup_backup' : 'dashboard.no_period_backups')}</div></div>`;
        body += `<div class="card mb-3"><div class="card-body d-flex flex-wrap gap-3"><a href="#agents">${t('dashboard.agents_online', {online: d.agents.online, total: d.agents.total})}</a><a href="#schedules">${t('dashboard.upcoming', {count: d.schedules.upcoming})}</a></div></div>`;
        const attention = Object.entries(d.attention).filter(([, n]) => n > 0);
        if (attention.length) body += `<div class="card mb-3 border-warning"><div class="card-body"><h3>${t('dashboard.needs_attention')}</h3><ul class="mb-0">${attention.map(([key, count]) => `<li><a href="#${key === 'offline_agents' ? 'agents' : 'backups'}">${t('dashboard.attention_' + key, {count})}</a></li>`).join('')}</ul></div></div>`;
        if (d.runningBackups.length) body += `<div class="card mb-3"><div class="card-header"><h3 class="card-title">${t('dashboard.running_backups')} (${d.backups.running_count})</h3></div><div class="table-responsive"><table class="table card-table"><thead><tr><th>${t('dashboard.vm_name')}</th><th>${t('dashboard.agent')}</th><th>${t('common.type')}</th><th>${t('dashboard.progress')}</th><th>${t('dashboard.started')}</th></tr></thead><tbody>${d.runningBackups.map(b => this.renderRunningBackupRow(b)).join('')}</tbody></table></div></div>`;
        if (d.recentBackups.length) body += `<div class="card"><div class="card-header"><h3 class="card-title">${t('dashboard.recent_backups')}</h3></div><div class="table-responsive"><table class="table card-table"><thead><tr><th>${t('dashboard.vm_name')}</th><th>${t('common.status')}</th><th>${t('common.created')}</th></tr></thead><tbody>${d.recentBackups.map(b => `<tr><td>${escapeHtml(b.vm_name || enumLabel(null))}</td><td><span class="badge bg-${getStatusColor(b.status)}">${escapeHtml(enumLabel(b.status))}</span></td><td>${formatDate(b.created_at)}</td></tr>`).join('')}</tbody></table></div></div>`;
        return `${header}<div class="page-body"><div class="container-xl">${body}</div></div>`;
    }

    chartColor(state) {
        // Categorical identity is independent from badge severity.
        const colors = {running: '#2F8C50', completed: '#2F8C50', stopped: '#95613A', shutoff: '#4467AC', paused: '#B58712', unavailable: '#B74458', unknown: '#737D87', pending: '#BA702F', queued: '#547BA0', uploading: '#A1627D', failed: '#BD4141', cancelled: '#687B41', held: '#4A548C'};
        return colors[String(state || 'unknown').toLowerCase()] || '#737D87';
    }

    agentEntries(agents) {
        this.agentStyles ||= new Map();
        const palette = ['#4467AC', '#B58712', '#B74458', '#2F8C50', '#95613A', '#4A548C', '#A1627D', '#547BA0', '#BA702F', '#687B41', '#737D87', '#953E2F'];
        for (const agent of [...agents].sort((a, b) => String(a.agent_id || a.id || a.name).localeCompare(String(b.agent_id || b.id || b.name)))) {
            const key = agent.agent_id || agent.id || agent.name;
            if (!this.agentStyles.has(key)) {
                const index = this.agentStyles.size;
                this.agentStyles.set(key, {color: palette[index % palette.length], pattern: Math.floor(index / palette.length)});
            }
        }
        return agents.map(a => ({label: a.name, count: a.count, ...this.agentStyles.get(a.agent_id || a.id || a.name), href: '#vms'}));
    }

    chartCard(id, title, entries, subtitle = '') {
        const total = entries.reduce((sum, entry) => sum + entry.count, 0);
        const colors = entries.map(entry => entry.color || this.chartColor(entry.state));
        this.chartData.push({id, entries, colors});
        return `<div class="col-12 col-md-6 col-xxl-4"><div class="card h-100"><div class="card-header"><div><h3 class="card-title">${escapeHtml(title)}</h3>${subtitle ? `<div class="text-secondary small">${escapeHtml(subtitle)}</div>` : ''}</div></div><div class="card-body dashboard-chart-layout"><div class="dashboard-chart-canvas"><canvas id="${id}" role="img" aria-label="${escapeHtml(title)}"></canvas></div><div class="dashboard-chart-legend">${entries.map((entry, i) => `<a class="d-flex justify-content-between gap-2 mb-2 text-reset" href="${entry.href}"><span><span class="dashboard-chart-swatch" style="background-color:${colors[i]};${entry.pattern ? `background-image:repeating-linear-gradient(45deg,transparent 0 ${2 + entry.pattern}px,#ffffffbb ${2 + entry.pattern}px ${3 + entry.pattern}px);` : ''}"></span>${escapeHtml(entry.label)}</span><span class="text-nowrap">${entry.count} (${total ? Math.round(entry.count / total * 100) : 0}%)</span></a>`).join('')}</div></div></div></div>`;
    }

    chartFill(color, pattern) {
        if (!pattern) return color;
        const size = 3 + pattern;
        const tile = document.createElement('canvas'); tile.width = tile.height = size;
        const ctx = tile.getContext('2d');
        ctx.fillStyle = color; ctx.fillRect(0, 0, size, size);
        ctx.strokeStyle = '#ffffffbb'; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(0, size); ctx.lineTo(size, 0); ctx.stroke();
        return ctx.createPattern(tile, 'repeat');
    }

    afterRender() {
        this.charts = (this.chartData || []).map(({id, entries, colors}) => new Chart(document.getElementById(id), {
            type: 'doughnut', data: {labels: entries.map(e => e.label), datasets: [{data: entries.map(e => e.count), backgroundColor: colors.map((color, i) => this.chartFill(color, entries[i].pattern)), borderColor: getComputedStyle(document.documentElement).getPropertyValue('--tblr-bg-surface').trim() || '#fff', borderWidth: 2}]},
            options: {animation: false, responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, onClick: (_, elements) => {if (elements.length) window.location.hash = entries[elements[0].index].href;}}
        }));
        this.themeListener ||= () => this.refreshTheme();
        window.addEventListener('vnbui:theme-change', this.themeListener);
    }

    refreshTheme() {
        const borderColor = getComputedStyle(document.documentElement).getPropertyValue('--tblr-bg-surface').trim() || '#fff';
        this.charts?.forEach(chart => { chart.data.datasets[0].borderColor = borderColor; chart.update('none'); });
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
                return `${diffHours}h ${mins}m`;
            }
            return `${diffMins}m`;
        } catch (e) {
            return '';
        }
    }

    renderRunningBackupRow(backup) {
        const eta = backup.tags?.estimated_completion;
        const etaDisplay = eta ? ` (${this.formatETA(eta)} remaining)` : '';

        return `
            <tr data-backup-id="${escapeHtml(backup.id)}">
                <td>
                    <div class="d-flex align-items-center">
                        <span class="avatar avatar-sm me-2 bg-warning-lt">
                            ${escapeHtml((backup.vm_name || 'VM').substring(0, 2).toUpperCase())}
                        </span>
                        <div class="font-weight-medium">${escapeHtml(backup.vm_name || 'Unknown')}</div>
                    </div>
                </td>
                <td>
                    <span class="text-secondary">${escapeHtml(backup.agent_name || '—')}</span>
                </td>
                <td>
                    <span class="badge bg-primary-lt">${escapeHtml(backup.backup_type || 'full')}</span>
                </td>
                <td>
                    <div class="d-flex align-items-center">
                        <div class="flex-grow-1 me-2">
                            <div class="progress progress-sm">
                                <div class="progress-bar bg-warning" style="width: ${backup.progress || 0}%" role="progressbar"></div>
                            </div>
                        </div>
                        <span class="text-nowrap backup-progress-text">${backup.progress || 0}%${etaDisplay}</span>
                    </div>
                </td>
                <td>
                    <span class="text-secondary">${formatRelativeTime(backup.created_at)}</span>
                </td>
            </tr>
        `;
    }

    /**
     * Subscribe to real-time backup updates
     */
    subscribeToUpdates() {
        // Clean up old subscriptions
        if (this.updateSubscription) {
            this.updateSubscription();
        }
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
        }

        if (this.resyncSubscription) this.resyncSubscription();
        const updateGeneration = this.updateGeneration = (this.updateGeneration || 0) + 1;
        this.resyncSubscription = updateService.subscribeResync(async () => {
            await this.loadData();
            if (this.error) throw new Error('Dashboard resynchronization failed');
            if (this.updateGeneration !== updateGeneration) return;
            if (!document.querySelector('.modal.show')) await window.vnbui.refreshPage();
        });

        // Subscribe to all events using '*' wildcard, then filter for backup events
        // Note: updateService doesn't support pattern matching like 'backup_*'
        this.updateSubscription = updateService.subscribe('*', (data) => {
            const { type, payload } = data;

            // Filter for backup-related events
            if (!type || !type.startsWith('backup_')) {
                return;
            }

            console.log('Dashboard backup update:', type, payload);

            if (type === 'backup_progress') {
                this.handleProgressUpdate(payload);
            } else if (type === 'backup_started' || type === 'backup_completed' || type === 'backup_failed') {
                // Reload for status changes
                this.loadData().then(() => {
                    // Only refresh if no modal is open
                    if (!document.querySelector('.modal.show')) {
                        window.vnbui.refreshPage();
                    }
                });
            }
        });

        // Set up polling fallback (every 10s) for progress updates
        // This ensures progress updates even if WebSocket isn't delivering
        this.pollingInterval = setInterval(async () => {
            await this.refreshProgress();
        }, 10000);

        // Also poll immediately to catch any running backups
        this.refreshProgress();
    }

    /**
     * Handle progress update - update DOM directly without full refresh
     */
    handleProgressUpdate(data) {
        const { backup_id, progress, estimated_completion } = data;

        // Update running backups table
        const row = document.querySelector(`tr[data-backup-id="${backup_id}"]`);
        if (row) {
            const progressBar = row.querySelector('.progress-bar');
            const progressText = row.querySelector('.backup-progress-text');

            if (progressBar) {
                progressBar.style.width = `${progress}%`;
            }
            if (progressText) {
                const etaDisplay = estimated_completion ? ` (${this.formatETA(estimated_completion)} remaining)` : '';
                progressText.textContent = `${progress}%${etaDisplay}`;
            }
        }

        // Update recent backups table too
        const recentRow = document.querySelector(`#recent-backups-table tr[data-backup-id="${backup_id}"]`);
        if (recentRow) {
            const progressCell = recentRow.querySelector('.backup-progress');
            if (progressCell) {
                progressCell.textContent = `${progress}%`;
            }
        }
    }

    /**
     * Refresh progress data via API (polling fallback)
     */
    async refreshProgress() {
        try {
            const resp = await apiClient.get('/api/v1/backups?status=running');
            const backups = resp.items || resp.backups || [];

            const currentIds = new Set(backups.map(b => b.id));

            // Detect backups that were running but are no longer — they completed/failed
            if (this._knownRunningIds && this._knownRunningIds.size > 0) {
                const finished = [...this._knownRunningIds].filter(id => !currentIds.has(id));
                if (finished.length > 0) {
                    console.log('Backups finished during polling:', finished);
                    this._knownRunningIds = currentIds;
                    // Reload page data to reflect completed state
                    this.loadData().then(() => {
                        if (!document.querySelector('.modal.show')) {
                            window.vnbui.refreshPage();
                        }
                    });
                    return;
                }
            }
            this._knownRunningIds = currentIds;

            backups.forEach(backup => {
                this.handleProgressUpdate({
                    backup_id: backup.id,
                    progress: backup.progress,
                    estimated_completion: backup.tags?.estimated_completion
                });
            });
        } catch (e) {
            console.debug('Failed to refresh progress:', e);
        }
    }

    /**
     * Cleanup when leaving page
     */
    destroy() {
        this.updateGeneration = (this.updateGeneration || 0) + 1;
        this.resyncSubscription?.();
        this.resyncSubscription = null;
        this.charts?.forEach(chart => chart.destroy());
        if (this.themeListener) window.removeEventListener('vnbui:theme-change', this.themeListener);
        if (this.updateSubscription) {
            this.updateSubscription();
            this.updateSubscription = null;
        }
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }
    }

    /**
     * Perform quick search from dashboard
     */
    async dashboardSearch(query) {
        const t = window.t;
        if (!query || query.trim().length < 2) {
            if (window.vnbui && window.vnbui.showToast) {
                window.vnbui.showToast(t('dashboard.search_min_chars'), 'warning');
            }
            return;
        }

        this.searchQuery = query.trim();
        const section = document.getElementById('search-results-section');
        const content = document.getElementById('search-results-content');

        if (!section || !content) return;

        // Show loading
        section.style.display = 'block';
        content.innerHTML = `
            <div class="text-center text-secondary py-4">
                <span class="spinner-border spinner-border-sm me-2"></span>
                ${t('dashboard.searching')}
            </div>
        `;

        try {
            const data = await apiClient.post('/api/v1/search', {
                query: this.searchQuery,
                filters: { vms: true, backups: true }
            });

            const vms = data.vms || [];
            const backups = data.backups || [];
            const total = vms.length + backups.length;

            if (total === 0) {
                content.innerHTML = `
                    <div class="text-center text-secondary py-4">
                        <i class="ti ti-search icon" aria-hidden="true"></i>
                        <p class="mb-0">${t('dashboard.no_results', {query: escapeHtml(this.searchQuery)})}</p>
                        <p class="small">${t('dashboard.try_different')}</p>
                    </div>
                `;
                return;
            }

            let html = `<p class="text-secondary mb-3">${t('dashboard.found_results', {total, query: escapeHtml(this.searchQuery)})}</p>`;

            if (vms.length > 0) {
                html += `
                    <h4 class="mb-2">${t('dashboard.vms_section', {count: vms.length})}</h4>
                    <div class="list-group list-group-flush mb-3">
                        ${vms.slice(0, 5).map(vm => `
                            <a href="#" onclick="window.vnbui.navigate('/vms'); return false;" class="list-group-item list-group-item-action">
                                <div class="d-flex align-items-center">
                                    <span class="avatar avatar-sm me-2 bg-primary-lt">${escapeHtml((vm.name || 'V').substring(0, 2).toUpperCase())}</span>
                                    <div class="flex-fill">
                                        <div class="font-weight-medium">${escapeHtml(vm.name || 'Unknown')}</div>
                                        <div class="text-secondary small">${escapeHtml(vm.hostname || vm.agent_id || '')}</div>
                                    </div>
                                    <span class="badge bg-${vm.state === 'running' ? 'success' : 'secondary'}">${escapeHtml(enumLabel(vm.state || 'unknown'))}</span>
                                </div>
                            </a>
                        `).join('')}
                        ${vms.length > 5 ? `<div class="list-group-item text-secondary text-center">${t('dashboard.more_vms', {count: vms.length - 5})}</div>` : ''}
                    </div>
                `;
            }

            if (backups.length > 0) {
                html += `
                    <h4 class="mb-2">${t('dashboard.backups_section', {count: backups.length})}</h4>
                    <div class="list-group list-group-flush">
                        ${backups.slice(0, 5).map(backup => `
                            <a href="#" onclick="window.vnbui.navigate('/backups'); return false;" class="list-group-item list-group-item-action">
                                <div class="d-flex align-items-center">
                                    <div class="flex-fill">
                                        <div class="font-weight-medium">${escapeHtml(backup.vm_name || 'Unknown VM')}</div>
                                        <div class="text-secondary small">${formatDate(backup.created_at)}</div>
                                    </div>
                                    <span class="badge bg-${backup.status === 'completed' ? 'success' : backup.status === 'failed' ? 'danger' : 'secondary'}">${escapeHtml(enumLabel(backup.status || 'unknown'))}</span>
                                </div>
                            </a>
                        `).join('')}
                        ${backups.length > 5 ? `<div class="list-group-item text-secondary text-center">${t('dashboard.more_backups', {count: backups.length - 5})}</div>` : ''}
                    </div>
                `;
            }

            content.innerHTML = html;

        } catch (error) {
            console.error('Dashboard search failed:', error);
            content.innerHTML = `
                <div class="text-center text-danger py-4">
                    <p class="mb-0">${t('dashboard.search_failed', {error: escapeHtml(error.message || t('common.error_occurred'))})}</p>
                </div>
            `;
        }
    }

    /**
     * Clear search results
     */
    clearDashboardSearch() {
        this.searchQuery = '';
        this.searchResults = null;

        const section = document.getElementById('search-results-section');
        const input = document.getElementById('dashboard-search');

        if (section) section.style.display = 'none';
        if (input) input.value = '';
    }
}
