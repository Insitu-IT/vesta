import { apiClient } from '../api/client.js';
import { operatorRequests } from '../services/operator-requests.service.js';
import { escapeHtml } from '../utils/security.js';
import { formatDate, formatSize } from '../utils/format.js';

const api = '/api/v1';
const label = key => window.t('file_backups.' + key);
const sameSet = (first, second) => first?.agent_id === second?.agent_id && first?.file_set === second?.file_set;
const date = value => value ? escapeHtml(formatDate(value)) : '—';

/** Uses the same file-set identity for a manual backup and a scheduled one. */
export class FileBackupsPanel {
    constructor(view) {
        this.isSchedule = view === 'schedules';
        this.resource = this.isSchedule ? 'file-schedules' : 'file-backups';
    }

    mount(root) {
        this.destroy();
        if (!root) return;
        this.root = root;
        this.controller = new AbortController();
        this.sets = [];
        this.rows = [];
        this.targetSignature = null;
        this.generation = 0;
        this.offset = 0;
        this.editId = null;
        this.saving = false;
        this.isAdmin = window.vnbui?.currentUserRole === 'admin';
        this.canWrite = this.isAdmin || (!this.isSchedule && window.vnbui?.currentUserRole === 'operator');
        root.innerHTML = `<div class="card mt-3">
            <div class="card-header"><h3 class="card-title">${label(this.isSchedule ? 'schedules' : 'backups')}</h3></div>
            <div class="card-body">
                <form class="row g-2 align-items-end" hidden>
                    <label class="col-sm form-label mb-0">${label('set')}
                        <select class="form-select mt-1" name="target" required></select></label>
                    ${this.isSchedule ? `<label class="col-sm form-label mb-0">${label('name')}
                        <input class="form-control mt-1" name="name" required maxlength="100"></label>
                        <label class="col-sm form-label mb-0">${label('cron')}
                        <input class="form-control mt-1" name="cron" value="0 2 * * *" dir="ltr" required></label>` : ''}
                    <div class="col-auto"><button type="submit" class="btn btn-primary"></button></div>
                    <div class="col-auto"><button type="button" class="btn btn-link" data-action="cancel" hidden>
                        ${label('cancel')}</button></div>
                    <div class="col-12 form-hint" data-policy></div>
                </form>
                <div data-message role="status" aria-live="polite"></div>
            </div>
            <div data-records></div>
            <nav class="card-footer btn-list" data-paging hidden aria-label="${label('history')}">
                <button class="btn btn-sm btn-outline-secondary" data-action="previous">${label('previous')}</button>
                <button class="btn btn-sm btn-outline-secondary" data-action="next">${label('more')}</button>
            </nav>
        </div>`;
        const { signal } = this.controller;
        root.addEventListener('submit', event => {
            event.preventDefault();
            this.saveForm();
        }, { signal });
        root.addEventListener('change', event => {
            if (event.target.name === 'target') this.showPolicy();
        }, { signal });
        root.addEventListener('click', event => {
            const button = event.target.closest('[data-action]');
            if (button) this.act(button);
        }, { signal });
        this.refresh();
    }

    async refresh() {
        const { signal } = this.controller;
        const generation = ++this.generation;
        clearTimeout(this.poll);
        try {
            const [sets, records] = await Promise.all([
                apiClient.get(api + '/file-sets', {}, { signal }),
                apiClient.get(api + '/' + this.resource, this.isSchedule ? {} : {limit: 50, offset: this.offset}, { signal }),
            ]);
            if (signal.aborted || generation !== this.generation) return;
            this.sets = sets.items;
            this.rows = records.items;
            const paging = this.root.querySelector('[data-paging]');
            paging.hidden = this.isSchedule || (!this.offset && this.rows.length < 50);
            paging.querySelector('[data-action=previous]').disabled = this.offset === 0;
            paging.querySelector('[data-action=next]').disabled = this.rows.length < 50;
            this.root.hidden = !this.sets.length && !this.rows.length && !this.offset;
            this.updateForm();
            this.showRows();
            if (this.readError) this.message('');
            this.readError = false;
        } catch (error) {
            if (signal.aborted || generation !== this.generation) return;
            if (error.status === 404 || error.status === 403) {
                this.root.hidden = true;
                return;
            }
            this.root.hidden = false;
            this.message(label('load_error') + ' ' + error.message, true);
            this.readError = true;
        }
        if (!signal.aborted && generation === this.generation) this.poll = setTimeout(() => this.refresh(), 15000);
    }

    updateForm() {
        const form = this.root.querySelector('form');
        form.hidden = !this.canWrite || !this.sets.length;
        if (form.hidden) return;
        const targets = this.sets.map(set => [set.target.agent_id, set.target.file_set, set.host_name]);
        const signature = JSON.stringify(targets);
        const select = form.elements.target;
        if (this.targetSignature !== signature) {
            const previous = select.value;
            select.replaceChildren(...this.sets.map(set => new Option(
                set.host_name + ' / ' + set.target.file_set, JSON.stringify(set.target)
            )));
            if ([...select.options].some(option => option.value === previous)) select.value = previous;
            this.targetSignature = signature;
        }
        select.disabled = Boolean(this.editId);
        form.querySelector('[type=submit]').textContent = label(this.isSchedule ? (this.editId ? 'save' : 'create') : 'run');
        form.querySelector('[data-action=cancel]').hidden = !this.editId;
        this.showPolicy();
    }

    selectedSet() {
        const value = this.root.querySelector('form').elements.target.value;
        return this.sets.find(set => JSON.stringify(set.target) === value);
    }

    showPolicy() {
        const set = this.selectedSet();
        const details = this.root.querySelector('[data-policy]');
        details.textContent = '';
        if (!set) return;
        this.root.querySelector('[type=submit]').disabled = this.saving || !set.storage;
        if (set.storage) {
            details.textContent = [set.host_status, set.storage.endpoint, set.storage.region, 's3://' + set.storage.bucket + '/' + (set.storage.prefix || ''),
                label('recipient') + ' ' + set.storage.recipient_sha256].join(' · ');
        } else {
            details.textContent = set.host_status || '';
        }
    }

    showRows() {
        const records = this.root.querySelector('[data-records]');
        if (!this.rows.length) {
            records.innerHTML = `<p class="px-3 text-secondary">${label(this.isSchedule ? 'no_schedules' : 'no_backups')}</p>`;
            return;
        }
        const headings = this.isSchedule ? ['set', 'cron', 'next', 'last_success', 'status'] : ['set', 'started', 'status', 'recovery'];
        const body = this.rows.map(row => {
            const set = this.sets.find(item => sameSet(item.target, row.target));
            const target = `<bdi>${escapeHtml(set?.host_name || row.target.agent_id)} / ${escapeHtml(row.target.file_set)}</bdi>`;
            if (this.isSchedule) {
                const actions = this.isAdmin ? ['edit', row.authority_state === 'fenced' ? 'reauthorize' : row.enabled ? 'pause' : 'enable', 'remove'].map(action =>
                    `<button class="btn btn-sm btn-outline-secondary" type="button" data-action="${action}" data-id="${escapeHtml(row.id)}">${label(action)}</button>`
                ).join(' ') : '';
                return `<tr><td>${escapeHtml(row.name)}<div class="text-secondary small">${target}</div></td>
                    <td><bdi dir="ltr">${escapeHtml(row.cron_expression)}</bdi></td><td>${date(row.next_run_at)}</td>
                    <td>${date(row.last_success_at)}</td><td>${label(row.authority_state === 'fenced' ? 'fenced' : row.enabled ? 'enabled' : 'paused')}
                    <div class="text-secondary small">${escapeHtml(row.last_error || row.last_status || '')}</div></td>
                    ${this.isAdmin ? `<td><div class="btn-list">${actions}</div></td>` : ''}</tr>`;
            }
            const archive = row.s3_path ? `<details><summary>${label('archive')}</summary>
                <bdi dir="ltr" class="text-break">${escapeHtml(row.s3_path)}</bdi>
                ${row.s3_version_id ? `<div>${label('object_version')} <bdi>${escapeHtml(row.s3_version_id)}</bdi></div>` : ''}
                <div>${label('recipient')} <code class="text-break">${escapeHtml(row.recipient_sha256)}</code></div>
                <div>${escapeHtml(row.storage?.endpoint)} <bdi>${escapeHtml(row.storage?.region)}</bdi></div>
                <div>SHA-256 <code class="text-break">${escapeHtml(row.archive_sha256)}</code></div>
                <div>${escapeHtml(row.archive_format)} · ${escapeHtml(formatSize(row.archive_size_bytes))}</div>
                </details>` : '—';
            return `<tr><td>${target}</td><td>${date(row.started_at || row.created_at)}</td>
                <td>${escapeHtml(window.t('file_backups.states.' + row.status))}
                <div class="text-secondary small">${escapeHtml(row.error || '')}</div>
                ${row.bytes > 0 || row.status === 'completed' ? `<small>${escapeHtml(row.files)} ${label('files')} · ${escapeHtml(formatSize(row.bytes))}</small>` : ''}</td><td>${archive}</td></tr>`;
        }).join('');
        records.innerHTML = `<div class="table-responsive"><table class="table table-vcenter card-table">
            <thead><tr>${headings.map(key => `<th scope="col">${label(key)}</th>`).join('')}
            ${this.isSchedule && this.isAdmin ? `<th scope="col">${label('actions')}</th>` : ''}</tr></thead>
            <tbody>${body}</tbody></table></div>`;
    }

    message(text, error = false) {
        const message = this.root.querySelector('[data-message]');
        message.textContent = text;
        message.className = text ? (error ? 'mt-2 text-danger' : 'mt-2') : '';
    }

    async mutate(action) {
        if (this.saving || !this.canWrite) return;
        this.saving = true;
        const { signal } = this.controller;
        const submit = this.root.querySelector('[type=submit]');
        submit.disabled = true;
        try {
            const message = await action();
            if (signal.aborted) return;
            this.message(message);
            await this.refresh();
        } catch (error) {
            if (!signal.aborted) this.message(error.message, true);
        } finally {
            if (!signal.aborted) {
                this.saving = false;
                submit.disabled = false;
            }
        }
    }

    saveForm() {
        const form = this.root.querySelector('form');
        const set = this.selectedSet();
        if (!set?.storage || !form.reportValidity()) return;
        return this.mutate(async () => {
            if (!this.isSchedule) {
                const scope = operatorRequests.scope();
                const intent = new TextEncoder().encode(JSON.stringify([scope, set.target.agent_id, set.target.file_set]));
                const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', intent));
                const key = 'vesta.file-run.v1.' + Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
                const previous = sessionStorage.getItem(key);
                if (previous && !window.confirm(label('retry') + ' ' + previous)) return label('request_kept');
                const requestId = previous || crypto.randomUUID();
                sessionStorage.setItem(key, requestId);
                const received = await apiClient.request(api + '/file-backups', {
                    method: 'POST', headers: { 'Idempotency-Key': requestId },
                    body: JSON.stringify({ target: set.target }),
                });
                if (!received?.id || !sameSet(received.target, set.target)) throw new Error(label('verify_request'));
                sessionStorage.removeItem(key);
                return label('queued');
            }
            const body = { name: form.elements.name.value.trim(), cron_expression: form.elements.cron.value.trim() };
            if (this.editId) {
                await apiClient.request(api + '/file-schedules/' + encodeURIComponent(this.editId), { method: 'PATCH', body: JSON.stringify(body) });
            } else {
                await apiClient.post(api + '/file-schedules', { ...body, target: set.target, enabled: true });
            }
            this.clearEdit();
            return label('saved');
        });
    }

    clearEdit() {
        this.editId = null;
        this.root.querySelector('form').reset();
        this.updateForm();
    }

    act(button) {
        const action = button.dataset.action;
        if (!this.isSchedule && (action === 'previous' || action === 'next')) {
            this.offset = Math.max(0, this.offset + (action === 'next' ? 50 : -50));
            return this.refresh();
        }
        if (!this.isAdmin || this.saving) return;
        if (action === 'cancel') { this.clearEdit(); return; }
        const row = this.rows.find(item => item.id === button.dataset.id);
        if (!row) return;
        if (action === 'edit') {
            const set = this.sets.find(item => sameSet(item.target, row.target));
            if (!set) { this.message(label('missing_set'), true); return; }
            const form = this.root.querySelector('form');
            form.elements.target.value = JSON.stringify(set.target);
            form.elements.name.value = row.name;
            form.elements.cron.value = row.cron_expression;
            this.editId = row.id;
            this.updateForm();
            form.elements.name.focus();
            return;
        }
        if (action === 'enable' || action === 'reauthorize') {
            const set = this.sets.find(item => sameSet(item.target, row.target));
            if (!set?.storage) { this.message(label('missing_set'), true); return; }
            const policy = set.storage;
            const details = [row.name, policy.endpoint, policy.region, 's3://' + policy.bucket + '/' + policy.prefix, policy.recipient_sha256];
            if (!window.confirm(label('confirm_policy') + '\n' + details.filter(Boolean).join('\n'))) return;
        }
        if (action === 'remove' && !window.confirm(label('remove_confirm') + ' ' + row.name)) return;
        return this.mutate(async () => {
            const url = api + '/file-schedules/' + encodeURIComponent(row.id);
            if (action === 'remove') await apiClient.request(url, { method: 'DELETE' });
            else await apiClient.request(url, { method: 'PATCH', body: JSON.stringify({ enabled: action === 'enable' || action === 'reauthorize' }) });
            if (this.editId === row.id) this.clearEdit();
            return label('saved');
        });
    }

    destroy() {
        clearTimeout(this.poll);
        this.controller?.abort();
    }
}
