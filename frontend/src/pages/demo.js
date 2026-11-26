/** Public, synthetic-only evaluator sandbox. */
import { escapeHtml } from '../utils/security.js';

const API = '/api/v1/demo';

async function request(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        ...options,
    });
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const detail = body.detail || {};
        const error = new Error(detail.message || detail || `HTTP ${response.status}`);
        error.code = detail.code;
        throw error;
    }
    return response.status === 204 ? null : response.json();
}

function badge(status) {
    const color = {
        completed: 'green', online: 'green', running: 'blue', uploading: 'azure',
        queued: 'yellow', pending: 'yellow', degraded: 'orange', upload_failed: 'red',
        stopped: 'secondary', shutoff: 'secondary',
    }[status] || 'secondary';
    return `<span class="badge bg-${color}-lt">${escapeHtml(status)}</span>`;
}

export async function detectAndStartDemo(root) {
    let current = await fetch(`${API}/sessions/current`, { credentials: 'same-origin' });
    if (current.status === 404) return false;
    if (current.status === 401) {
        current = await fetch(`${API}/sessions`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
        });
    }
    if (!current.ok || current.headers.get('X-Vnbui-Environment') !== 'demo') return false;
    const page = new DemoPage(root);
    await page.mount();
    return true;
}

class DemoPage {
    constructor(root) {
        this.root = root;
        this.state = null;
        this.message = '';
        this.messageType = 'info';
        this.vmPage = 0;
        this.vmQuery = '';
        this.vmState = '';
        this.vmSort = 'name';
    }

    async mount() {
        await this.refresh();
    }

    async refresh(message = '', type = 'success') {
        this.state = await request('/state');
        this.message = message;
        this.messageType = type;
        this.render();
        this.bind();
    }

    async act(action) {
        try {
            const result = await action();
            await this.refresh(result.message || 'Simulated operation completed.');
        } catch (error) {
            this.message = `${error.code ? `${error.code}: ` : ''}${error.message}`;
            this.messageType = 'danger';
            this.render();
            this.bind();
        }
    }

    render() {
        const s = this.state;
        const completed = s.backups.filter(item => item.status === 'completed');
        this.root.innerHTML = `
            <div class="page">
                <header class="navbar navbar-expand-md d-print-none bg-dark" data-bs-theme="dark">
                    <div class="container-xl">
                        <div class="navbar-brand text-white">Vesta public evaluator</div>
                        <span class="badge bg-warning text-dark">DEMO / SIMULATED</span>
                    </div>
                </header>
                <main class="page-wrapper">
                    <div class="page-header"><div class="container-xl py-3">
                        <div class="row align-items-center">
                            <div class="col"><h1 class="page-title">Backup orchestration sandbox</h1>
                                <div class="text-secondary">One anonymous OSS session. No hypervisor, disk, object store, or customer system is contacted.</div>
                            </div>
                            <div class="col-auto"><button id="demo-reset" class="btn btn-outline-danger">Reset demo</button></div>
                        </div>
                    </div></div>
                    <div class="page-body"><div class="container-xl">
                        ${this.message ? `<div class="alert alert-${this.messageType}" role="alert">${escapeHtml(this.message)}</div>` : ''}
                        <div class="alert alert-info"><strong>Operator persona.</strong> ${escapeHtml(s.persona.msp_message)}</div>
                        <div class="row row-cards mb-4">
                            ${this.stat('Virtual machines', s.vms.length)}
                            ${this.stat('Agents online', `${s.agents.filter(a => a.status === 'online').length}/${s.agents.length}`)}
                            ${this.stat('Restore points', completed.length)}
                            ${this.stat('Schedules', s.schedules.length)}
                        </div>

                        <div class="card mb-4"><div class="card-header"><h2 class="card-title">1. Browse the synthetic estate</h2></div>
                            <div class="card-body"><div class="row g-2 mb-3"><div class="col-md-6"><input id="demo-search" class="form-control" placeholder="Search VMs by name or state"></div>
                                <div class="col-md-3"><select id="demo-vm-state" class="form-select"><option value="">All states</option><option>running</option><option>stopped</option><option>shutoff</option><option>pending</option></select></div>
                                <div class="col-md-3"><select id="demo-vm-sort" class="form-select"><option value="name">Sort by name</option><option value="state">Sort by state</option></select></div></div>
                                <div class="table-responsive"><table class="table table-vcenter"><thead><tr><th>VM</th><th>State</th><th>Provider</th><th>Incremental</th></tr></thead>
                                <tbody id="demo-vms">${this.vms(s.vms)}</tbody></table></div>
                                <div class="d-flex justify-content-between align-items-center"><button id="demo-vm-prev" class="btn btn-sm btn-outline-secondary">Previous</button><span id="demo-vm-page" class="text-secondary"></span><button id="demo-vm-next" class="btn btn-sm btn-outline-secondary">Next</button></div>
                            </div>
                        </div>

                        <div class="row row-cards mb-4">
                            <div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="card-title">Provider capabilities</h2></div><div class="table-responsive"><table class="table"><thead><tr><th>Agent</th><th>Provider</th><th>Status</th><th>Backup method</th></tr></thead><tbody>
                                ${s.agents.map(a => `<tr><td>${escapeHtml(a.display_name)}</td><td>${escapeHtml(a.provider)}</td><td>${badge(a.status)}</td><td>${escapeHtml(a.capabilities.backup_method)}</td></tr>`).join('')}
                            </tbody></table></div></div></div>
                            <div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="card-title">Synthetic report</h2></div><div class="card-body">
                                <p><strong>${completed.length}</strong> completed restore points across <strong>${new Set(s.backups.map(b => b.vm_id)).size}</strong> protected VMs.</p>
                                <p><strong>${s.restores.filter(r => r.status === 'completed').length}</strong> simulated restores completed; <strong>${s.backups.filter(b => b.status === 'upload_failed').length}</strong> upload failure(s) remain retriable.</p>
                                <p class="text-secondary mb-0">This report describes synthetic workflow state, not throughput, integrity, or restored bytes.</p>
                            </div></div></div>
                        </div>

                        <div class="row row-cards mb-4">
                            <div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="card-title">2. Preview and create a dynamic group</h2></div><div class="card-body">
                                <form id="demo-group-form">
                                    <label class="form-label">Create or edit</label><select name="group_id" class="form-select mb-3"><option value="">New dynamic group</option>${s.groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('')}</select>
                                    <label class="form-label">Environment</label><select name="environment" class="form-select mb-3"><option>production</option><option>testing</option><option>development</option><option>legacy</option></select>
                                    <label class="form-label">Group name</label><input name="name" maxlength="80" value="Evaluator production group" class="form-control mb-3" required>
                                    <div class="d-flex gap-2"><button name="preview" class="btn btn-outline-primary">Preview</button><button class="btn btn-primary">Create group</button></div>
                                </form><div id="demo-group-preview" class="mt-3 text-secondary"></div>
                            </div></div></div>
                            <div class="col-lg-6"><div class="card h-100"><div class="card-header"><h2 class="card-title">3. Create a schedule</h2></div><div class="card-body">
                                <form id="demo-schedule-form"><label class="form-label">VM</label><select name="vm_id" class="form-select mb-3">${this.vmOptions()}</select>
                                    <label class="form-label">Name</label><input name="name" maxlength="80" value="Evaluator weekly backup" class="form-control mb-3" required>
                                    <div class="row"><div class="col"><label class="form-label">Type</label><select name="backup_type" class="form-select"><option>full</option><option>incremental</option></select></div>
                                    <div class="col"><label class="form-label">Cron</label><input name="cron_expression" value="0 2 * * 0" class="form-control" required></div></div>
                                    <button class="btn btn-primary mt-3">Create schedule</button>
                                </form>
                            </div></div></div>
                        </div>

                        <div class="card mb-4"><div class="card-header"><h2 class="card-title">4. Run a simulated backup</h2></div><div class="card-body">
                            <form id="demo-backup-form" class="row g-3 align-items-end"><div class="col-md-5"><label class="form-label">VM</label><select name="vm_id" class="form-select">${this.vmOptions()}</select></div>
                                <div class="col-md-3"><label class="form-label">Type</label><select name="backup_type" class="form-select"><option>full</option><option>incremental</option></select></div>
                                <div class="col-md-3"><label class="form-label">Scenario</label><select name="scenario" class="form-select"><option value="success">Success</option><option value="upload_failure">Upload failure</option></select></div>
                                <div class="col-md-1"><button class="btn btn-primary">Run</button></div></form>
                            <div class="text-secondary mt-2">Unsupported incremental requests fail explicitly; they never become full backups.</div>
                        </div></div>

                        <div class="card mb-4"><div class="card-header"><h2 class="card-title">Schedules and groups</h2></div><div class="table-responsive"><table class="table"><thead><tr><th>Schedule</th><th>Type</th><th>State</th><th>Action</th></tr></thead><tbody>
                            ${s.schedules.map(item => `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.backup_type)}</td><td>${item.enabled ? badge('enabled') : badge('disabled')}</td><td>${item.enabled ? `<button class="btn btn-sm btn-outline-primary demo-run-schedule" data-id="${item.id}">Run now</button>` : ''}</td></tr>`).join('')}
                        </tbody></table></div><div class="card-footer text-secondary">${s.groups.map(group => `${escapeHtml(group.name)} (${escapeHtml(group.group_type)})`).join(' · ')}</div></div>

                        <div class="card mb-4"><div class="card-header"><h2 class="card-title">5. Inspect, retry, and restore</h2></div><div class="table-responsive"><table class="table table-vcenter"><thead><tr><th>VM</th><th>Type</th><th>Chain</th><th>Status</th><th>Action</th></tr></thead><tbody>
                            ${s.backups.map(b => `<tr><td>${escapeHtml(b.vm_name)}</td><td>${escapeHtml(b.backup_type)}</td><td>${b.chain_position}</td><td>${badge(b.status)}<div class="small text-secondary">${escapeHtml(b.events?.at(-1)?.message || b.error_message || '')}</div></td><td>
                                ${b.status === 'upload_failed' ? `<button class="btn btn-sm btn-warning demo-retry" data-id="${b.id}">Retry upload</button>` : ''}
                                ${b.status === 'completed' ? `<button class="btn btn-sm btn-outline-primary demo-restore" data-id="${b.id}">Restore</button>` : ''}
                            </td></tr>`).join('')}
                        </tbody></table></div></div>

                        <div class="card mb-4"><div class="card-header"><h2 class="card-title">Simulated restores</h2></div><div class="table-responsive"><table class="table"><thead><tr><th>Restore</th><th>Restore point</th><th>Status</th><th>Result</th></tr></thead><tbody>
                            ${s.restores.map(r => `<tr><td>${escapeHtml(r.id.slice(0, 8))}</td><td>${escapeHtml(r.backup_id.slice(0, 8))}</td><td>${badge(r.status)}</td><td>${escapeHtml(r.message || 'Synthetic fixture restore; no VM or disk was changed.')}</td></tr>`).join('')}
                        </tbody></table></div></div>

                        <div class="card mb-4"><div class="card-header"><h2 class="card-title">6. Audit trail</h2></div><div class="list-group list-group-flush">
                            ${s.activity.slice(0, 12).map(a => `<div class="list-group-item"><strong>${escapeHtml(a.action)}</strong><span class="text-secondary ms-2">${escapeHtml(a.resource_type)} · ${escapeHtml(a.created_at)}</span><span class="badge bg-azure-lt float-end">SIMULATED</span></div>`).join('')}
                        </div></div>
                        <div class="text-secondary text-center mb-4">Fixture ${escapeHtml(s.fixture_version)} · ${escapeHtml(s.persona.hands_on)} · DEMO / SIMULATED</div>
                    </div></div>
                </main>
            </div>`;
    }

    stat(label, value) {
        return `<div class="col-sm-6 col-lg-3"><div class="card card-sm"><div class="card-body"><div class="h1 mb-1">${escapeHtml(String(value))}</div><div class="text-secondary">${escapeHtml(label)}</div></div></div></div>`;
    }

    vmOptions() {
        return this.state.vms.map(vm => `<option value="${vm.id}">${escapeHtml(vm.name)} (${escapeHtml(vm.state)})</option>`).join('');
    }

    filteredVms(items) {
        return items.filter(vm => `${vm.name} ${vm.state}`.toLowerCase().includes(this.vmQuery) && (!this.vmState || vm.state === this.vmState))
            .sort((left, right) => String(left[this.vmSort]).localeCompare(String(right[this.vmSort])));
    }

    vms(items) {
        const agents = Object.fromEntries(this.state.agents.map(agent => [agent.id, agent]));
        return this.filteredVms(items).slice(this.vmPage * 5, this.vmPage * 5 + 5).map(vm => `<tr><td>${escapeHtml(vm.name)}</td><td>${badge(vm.state)}</td><td>${escapeHtml(agents[vm.agent_id]?.provider || 'unknown')}</td><td>${vm.metadata.supports_incremental ? 'Supported' : '<span class="text-danger">Explicitly unavailable</span>'}</td></tr>`).join('');
    }

    renderVms() {
        const matches = this.filteredVms(this.state.vms);
        const pages = Math.max(1, Math.ceil(matches.length / 5));
        this.vmPage = Math.min(this.vmPage, pages - 1);
        this.root.querySelector('#demo-vms').innerHTML = this.vms(this.state.vms);
        this.root.querySelector('#demo-vm-page').textContent = `Page ${this.vmPage + 1} of ${pages} · ${matches.length} VM(s)`;
        this.root.querySelector('#demo-vm-prev').disabled = this.vmPage === 0;
        this.root.querySelector('#demo-vm-next').disabled = this.vmPage >= pages - 1;
    }

    bind() {
        this.root.querySelector('#demo-search').value = this.vmQuery;
        this.root.querySelector('#demo-vm-state').value = this.vmState;
        this.root.querySelector('#demo-vm-sort').value = this.vmSort;
        this.root.querySelector('#demo-reset').addEventListener('click', () => this.act(async () => {
            await request('/reset', { method: 'POST' });
            return { message: 'Session reset to the deterministic fixture.' };
        }));
        this.renderVms();
        this.root.querySelector('#demo-search').addEventListener('input', event => { this.vmQuery = event.target.value.toLowerCase(); this.vmPage = 0; this.renderVms(); });
        this.root.querySelector('#demo-vm-state').addEventListener('change', event => { this.vmState = event.target.value; this.vmPage = 0; this.renderVms(); });
        this.root.querySelector('#demo-vm-sort').addEventListener('change', event => { this.vmSort = event.target.value; this.vmPage = 0; this.renderVms(); });
        this.root.querySelector('#demo-vm-prev').addEventListener('click', () => { this.vmPage -= 1; this.renderVms(); });
        this.root.querySelector('#demo-vm-next').addEventListener('click', () => { this.vmPage += 1; this.renderVms(); });
        const groupForm = this.root.querySelector('#demo-group-form');
        groupForm.addEventListener('submit', event => {
            event.preventDefault();
            const data = new FormData(groupForm);
            const payload = { name: data.get('name'), rules: [{ field: 'metadata.environment', op: 'eq', value: data.get('environment') }], rules_match: 'all' };
            const groupId = data.get('group_id');
            this.act(async () => { await request(groupId ? `/groups/${groupId}` : '/groups', { method: groupId ? 'PUT' : 'POST', body: JSON.stringify(payload) }); return { message: `Synthetic group ${groupId ? 'updated' : 'created'} in this session.` }; });
        });
        groupForm.querySelector('[name="preview"]').addEventListener('click', event => {
            event.preventDefault();
            const data = new FormData(groupForm);
            const payload = { name: data.get('name'), rules: [{ field: 'metadata.environment', op: 'eq', value: data.get('environment') }], rules_match: 'all' };
            this.act(async () => {
                const result = await request('/groups/preview', { method: 'POST', body: JSON.stringify(payload) });
                return { message: `Preview matched ${result.total} synthetic VM(s).` };
            });
        });
        this.root.querySelector('#demo-schedule-form').addEventListener('submit', event => {
            event.preventDefault(); const data = Object.fromEntries(new FormData(event.target));
            this.act(async () => { await request('/schedules', { method: 'POST', body: JSON.stringify({ ...data, retention_days: 30, enabled: true }) }); return { message: 'Synthetic schedule created in this session.' }; });
        });
        this.root.querySelector('#demo-backup-form').addEventListener('submit', event => {
            event.preventDefault(); const data = Object.fromEntries(new FormData(event.target));
            this.act(async () => { const result = await request('/backups', { method: 'POST', body: JSON.stringify(data) }); return { message: result.events.at(-1).message }; });
        });
        this.root.querySelectorAll('.demo-run-schedule').forEach(button => button.addEventListener('click', () => this.act(async () => { const result = await request(`/schedules/${button.dataset.id}/run`, { method: 'POST' }); return { message: `Schedule ran: ${result.events.at(-1).message}` }; })));
        this.root.querySelectorAll('.demo-retry').forEach(button => button.addEventListener('click', () => this.act(async () => { const result = await request(`/backups/${button.dataset.id}/retry`, { method: 'POST' }); return { message: result.events.at(-1).message }; })));
        this.root.querySelectorAll('.demo-restore').forEach(button => button.addEventListener('click', () => this.act(async () => { const result = await request('/restores', { method: 'POST', body: JSON.stringify({ backup_id: button.dataset.id }) }); return { message: result.events.at(-1).message }; })));
    }
}
