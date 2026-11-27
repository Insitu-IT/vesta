import { apiClient } from '../api/client.js';
import { authService } from '../services/auth.service.js';
import { escapeHtml } from '../utils/security.js';
import { formatDate } from '../utils/format.js';

const ROUTE = '/api/v1/recovery/s3';
const trustedSources = new Map();
const selectedTrust = new Map();

const labels = {
    verified: 'Signature verified',
    trust_required: 'Source trust required',
    unsigned: 'Unsigned · new disks only',
    incomplete: 'Incomplete metadata',
    invalid: 'Invalid signature or repository',
};

function shellArg(value) {
    return "'" + String(value).replaceAll("'", "'\"'\"'") + "'";
}

function field(label, name, options = '') {
    return `<label class="form-label">${escapeHtml(label)}
        <input class="form-control" name="${name}" ${options}>
    </label>`;
}

function choice(label, name, choices) {
    return `<label class="form-label">${escapeHtml(label)}
        <select class="form-select" name="${name}" required>${choices.map(([value, title]) =>
            `<option value="${escapeHtml(value)}">${escapeHtml(title)}</option>`
        ).join('')}</select>
    </label>`;
}

export class BucketRecovery {
    render() {
        return `
            <div class="modal modal-blur fade" id="modal-bucket-recovery" tabindex="-1" aria-labelledby="bucket-recovery-title">
                <div class="modal-dialog modal-lg modal-dialog-scrollable">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h2 class="modal-title" id="bucket-recovery-title">Recover from S3</h2>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <p>Connect the repository in <a href="/settings">Settings</a>, then browse its recovery points. To verify a source, load an independently saved trust file or import its recovery key export.</p>
                            <details class="mb-3">
                                <summary>Source trust and encryption keys</summary>
                                <div class="mt-2">
                                    ${field('Public source trust file', 'trust-file', 'type="file" accept=".json,application/json"')}
                                    <button type="button" class="btn btn-outline-secondary mb-3" data-save-trust>Save this site’s public trust file</button>
                                    <form data-recovery-keys>
                                        ${field('Password-protected recovery key export', 'file', 'type="file" required')}
                                        ${field('Export passphrase', 'password', 'type="password" required autocomplete="off"')}
                                        <button class="btn btn-outline-primary" type="submit">Import recovery keys</button>
                                    </form>
                                    <div data-recovery-trust class="mt-2 text-secondary" aria-live="polite"></div>
                                </div>
                            </details>
                            <div class="btn-list mb-3">
                                <button class="btn btn-primary" data-browse="signed">Browse recovery points</button>
                                <button class="btn btn-outline-secondary" data-browse="legacy">Browse historical generations</button>
                            </div>
                            <div data-recovery-message aria-live="polite"></div>
                            <div data-recovery-results></div>
                            <div data-recovery-target></div>
                        </div>
                    </div>
                </div>
            </div>`;
    }

    bind(root) {
        this.root = root;
        this.results = root.querySelector('[data-recovery-results]');
        this.target = root.querySelector('[data-recovery-target]');
        this.message = root.querySelector('[data-recovery-message]');
        const user = authService.getUser();
        this.localScope = JSON.stringify([user?.id, user?.org_id]);
        this.trust = selectedTrust.get(this.localScope);
        if (this.trust) this.showTrust();
        root.addEventListener('click', event => this.onClick(event));
        root.addEventListener('change', event => this.onChange(event));
        root.addEventListener('submit', event => this.onSubmit(event));
    }

    async busy(action, button) {
        if (this.loading) return;
        this.loading = true;
        if (button) button.disabled = true;
        this.message.innerHTML = '';
        try {
            await action();
        } catch (error) {
            this.message.innerHTML = `<div class="alert alert-danger">${escapeHtml(error.message)}</div>`;
        } finally {
            if (button) button.disabled = false;
            this.loading = false;
        }
    }

    setTrust(value) {
        const {installation_id, org_id, public_key, schema, key_id} = value ?? {};
        if (![installation_id, org_id, public_key].every(value => typeof value === 'string')) {
            throw new Error('Select an independently saved Vesta recovery trust JSON file.');
        }
        const key = JSON.stringify([this.localScope, installation_id, org_id]);
        const previouslyTrusted = trustedSources.get(key);
        if (previouslyTrusted && previouslyTrusted !== public_key) {
            throw new Error('The file contains a different signing key for this previously selected source.');
        }
        this.trust = {installation_id, org_id, public_key, schema, key_id};
        trustedSources.set(key, public_key);
        selectedTrust.set(this.localScope, this.trust);
        this.results.innerHTML = '';
        this.target.innerHTML = '';
        this.showTrust();
    }

    showTrust() {
        this.root.querySelector('[data-recovery-trust]').textContent =
            `Offline source trust loaded for ${this.trust.installation_id}.`;
    }

    async onChange(event) {
        if (event.target.name === 'trust-file') {
            await this.busy(async () => {
                const file = event.target.files[0];
                if (!file || file.size > 16384) throw new Error('Select a recovery trust JSON file up to 16 KiB.');
                this.setTrust(JSON.parse(await file.text()));
                await this.discover(false);
            });
        } else if (event.target.name === 'agent_id') {
            const agent = this.preview.destination_agents.find(agent => agent.id === event.target.value);
            const namespace = this.root.querySelector('select[name="namespace"]');
            if (namespace) {
                namespace.replaceChildren(...agent.namespaces.map(name => new Option(name, name)));
            }
        }
    }

    async onClick(event) {
        const button = event.target.closest('button');
        if (!button) return;
        if (button.hasAttribute('data-save-trust')) {
            await this.busy(() => apiClient.download('/api/v1/recovery/trust', 'vesta-recovery-trust.json'), button);
        } else if (button.dataset.browse) {
            await this.busy(() => this.discover(button.dataset.browse === 'legacy'), button);
        } else if (button.hasAttribute('data-recovery-more')) {
            await this.busy(() => this.discover(this.legacy, this.cursor), button);
        } else if (button.dataset.pointIndex !== undefined) {
            await this.busy(() => this.selectPoint(this.points[Number(button.dataset.pointIndex)]), button);
        }
    }

    async discover(legacy, cursor = null) {
        this.legacy = legacy;
        this.target.innerHTML = '';
        const result = await apiClient.post(`${ROUTE}/discover`, {trust: this.trust, cursor, legacy});
        this.cursor = result.next_cursor;
        this.points = result.points;
        this.results.innerHTML = `
            ${this.points.length ? `<div class="table-responsive"><table class="table table-vcenter">
                <thead><tr><th>Backup</th><th>Time</th><th>Provider</th><th>Trust</th><th></th></tr></thead>
                <tbody>${this.points.map((point, index) => `<tr>
                    <td>${escapeHtml(point.name || point.backup_id || 'Unknown generation')}</td>
                    <td>${point.completed_at ? formatDate(point.completed_at) : '—'}</td>
                    <td>${escapeHtml(point.provider || '—')}</td>
                    <td>${escapeHtml(labels[point.status])}</td>
                    <td>${point.status === 'verified' || point.status === 'unsigned' ?
                        `<button type="button" class="btn btn-sm btn-outline-primary" data-point-index="${index}">
                            ${point.status === 'verified' ? 'Select point' : 'Restore to new disks'}
                        </button>` : ''}
                    </td>
                </tr>`).join('')}</tbody></table></div>` :
                '<p class="text-secondary">This page contains no recovery points.</p>'}
            ${this.cursor ? '<button class="btn btn-outline-secondary" data-recovery-more>Next page</button>' : ''}`;
    }

    async selectPoint(point) {
        if (point.status === 'unsigned') {
            const scope = this.trust
                ? ` --installation-id ${shellArg(this.trust.installation_id)} --org-id ${shellArg(this.trust.org_id)}`
                : '';
            const cmd = 'vesta-restore s3 restore --s3-config repository.json --allow-unsigned-legacy'
                + ` --backup ${shellArg(point.backup_id)} --generation-key ${shellArg(point.generation_key)}`
                + (point.version_id ? ` --version-id ${shellArg(point.version_id)}` : '')
                + ` --output ${shellArg('./recovered-' + point.backup_id)}`
                + scope
                + (point.requires_kek ? ' --kek-export recovery-keys.bin' : '');
            this.target.innerHTML = `<div class="alert alert-warning mt-3">
                <h3>Restore to new disks</h3>
                <p>This historical generation has no source signature. Only use the isolated reader if you accept unverified origin. It creates disks in a new directory without registering or starting a VM.</p>
                <p>${this.trust
                    ? 'The command uses the source IDs from your selected recovery trust. Verify that they belong to this history.'
                    : 'If you have an independently saved source trust file, add --trust to narrow the check for signed history. You can also supply independently recorded --installation-id and --org-id.'}</p>
                <pre class="text-wrap mb-0">${escapeHtml(cmd)}</pre>
            </div>`;
            return;
        }
        this.preview = await apiClient.post(`${ROUTE}/points/${encodeURIComponent(point.backup_id)}/preview`, {trust: this.trust});
        this.target.innerHTML = this.renderTarget(this.preview);
    }

    renderTarget({point, source, destination_agents: agents, requires_kek: requiresKek}) {
        if (!agents.length) return '<div class="alert alert-warning mt-3">Enroll a compatible 6.2 destination agent and configure its restore scope.</div>';
        const native = point.provider === 'libvirt';
        return `
            <form class="mt-4" data-recovery-destination>
                <h3>Fresh destination for ${escapeHtml(point.name)}</h3>
                <p>The new VM will be created powered off. ${requiresKek ? 'The supplied recovery keys unlocked the captured VM definition.' : ''}</p>
                ${choice('Destination agent', 'agent_id', agents.map(agent => [agent.id, agent.name]))}
                ${native ? '' : choice('Restore namespace', 'namespace', agents[0].namespaces.map(name => [name, name]))}
                ${field('New VM name', 'vm_name', 'required maxlength="128"')}
                ${native ?
                    `<p class="text-secondary">Protected disks: ${escapeHtml(source.disks.join(', '))}${
                        source.exclusions.length ? ` · Excluded disks removed: ${escapeHtml(source.exclusions.join(', '))}` : ''
                    }</p>` :
                    source.volumes.map((disk, index) => `<fieldset class="border rounded p-2 mb-2">
                        <legend class="float-none w-auto px-1 h4">${escapeHtml(disk.name)} PVC</legend>
                        ${field('New PVC name', `pvc-${index}`, 'required maxlength="63"')}
                        ${field('Storage class', `storage-${index}`, 'required maxlength="63"')}
                        ${choice('Access mode', `access-${index}`, [['ReadWriteOnce', 'ReadWriteOnce'], ['ReadWriteMany', 'ReadWriteMany']])}
                        ${choice('Volume mode', `mode-${index}`, [['Filesystem', 'Filesystem'], ['Block', 'Block']])}
                        ${field('Capacity in bytes', `capacity-${index}`, `type="number" value="${disk.capacity_bytes}" min="${disk.capacity_bytes}" required`)}
                    </fieldset>`).join('')}
                ${this.renderNetworkMappings(source, native)}
                ${native || !source.dependencies.length ? '' : `
                    <h4>Dependency mappings</h4>
                    <div data-mappings="dependency">
                        ${source.dependencies.map(dependency => `<fieldset class="border rounded p-2 mb-2" data-mapping>
                            <legend class="float-none w-auto px-1 h4">${escapeHtml(dependency.kind + '/' + dependency.name)}</legend>
                            <input type="hidden" name="kind" value="${escapeHtml(dependency.kind)}">
                            <input type="hidden" name="source_name" value="${escapeHtml(dependency.name)}">
                            ${field('Destination name', 'destination_name', 'required maxlength="63"')}
                        </fieldset>`).join('')}
                    </div>`}
                <div><button class="btn btn-primary" type="submit">Launch fresh restore</button></div>
            </form>`;
    }

    renderNetworkMappings(source, native) {
        if (native && source.interfaces.length) {
            return `<h4>Interface mappings</h4><div data-mappings="native">
                ${source.interfaces.map(item => `<fieldset class="border rounded p-2 mb-2" data-mapping>
                    <legend class="float-none w-auto px-1 h4">${escapeHtml(item.source_mac)}
                        ${item.source_network ? `· ${escapeHtml(item.source_network)}` : ''}
                    </legend>
                    <input type="hidden" name="source_mac" value="${escapeHtml(item.source_mac)}">
                    ${field('Destination libvirt network', 'network', 'required maxlength="128"')}
                </fieldset>`).join('')}
            </div>`;
        }
        if (!native && source.networks.length) {
            return `<h4>Network mappings</h4><div data-mappings="kubevirt">
                ${source.networks.map(item => `<fieldset class="border rounded p-2 mb-2" data-mapping>
                    <legend class="float-none w-auto px-1 h4">
                        ${escapeHtml(item.name + ' · ' + item.type)}
                        ${item.source_mac ? `· ${escapeHtml(item.source_mac)}` : ''}
                    </legend>
                    <input type="hidden" name="name" value="${escapeHtml(item.name)}">
                    ${choice('Destination type', 'type', [['', 'Select a destination type'], ['pod', 'Pod'], ['multus', 'Multus']])}
                    ${field('Destination Multus NAD', 'network_name', 'maxlength="63"')}
                </fieldset>`).join('')}
            </div>`;
        }
        return '<p class="text-secondary">No network attachments were captured.</p>';
    }

    readMappings(form, kind) {
        return [...form.querySelectorAll(`[data-mappings="${kind}"] [data-mapping]`)].map(row =>
            Object.fromEntries([...row.querySelectorAll('input,select')].map(input => [input.name, input.value.trim()]))
        );
    }

    async onSubmit(event) {
        event.preventDefault();
        const form = event.target;
        const data = new FormData(form);
        if (form.hasAttribute('data-recovery-keys')) {
            await this.busy(async () => {
                const imported = await apiClient.upload('/api/v1/encryption/keys/import', data);
                if (imported.recovery_trust) this.setTrust(imported.recovery_trust);
                this.message.innerHTML = '<div class="alert alert-success">Recovery keys imported.</div>';
            }, event.submitter);
            form.reset();
            return;
        }
        const {point, source} = this.preview;
        const payload = {trust: this.trust, agent_id: data.get('agent_id')};
        const vm_name = data.get('vm_name').trim();
        if (point.provider === 'libvirt') {
            payload.native_target = {
                vm_name, disks: source.disks,
                drop_excluded_disks: source.exclusions, networks: this.readMappings(form, 'native'),
            };
        } else {
            payload.kubevirt_target = {
                vm_name, namespace: data.get('namespace'),
                disks: source.volumes.map((volume, index) => ({
                    volume_name: volume.name, pvc_name: data.get(`pvc-${index}`).trim(),
                    storage_class: data.get(`storage-${index}`).trim(),
                    access_mode: data.get(`access-${index}`), volume_mode: data.get(`mode-${index}`),
                    capacity_bytes: Number(data.get(`capacity-${index}`)),
                })),
                networks: this.readMappings(form, 'kubevirt'),
                dependencies: Object.fromEntries(this.readMappings(form, 'dependency').map(
                    mapping => [`${mapping.kind}/${mapping.source_name}`, mapping.destination_name]
                )),
            };
        }
        await this.busy(async () => {
            const result = await apiClient.post(`${ROUTE}/points/${encodeURIComponent(point.backup_id)}/restore`, payload);
            apiClient.acknowledge(result);
            bootstrap.Modal.getInstance(this.root)?.hide();
            window.vnbui?.showToast?.('Fresh S3 restore queued', 'success');
            await window.vnbui.refreshPage();
        }, event.submitter);
    }
}
