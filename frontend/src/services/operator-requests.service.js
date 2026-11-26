import { authService } from './auth.service.js';
import { escapeHtml } from '../utils/security.js';

const STORE = 'vesta.operator.requests.v1';
const ACTIONS = [
    [/^\/api\/v1\/backups$/, 'backup.create'],
    [/^\/api\/v1\/backups\/[^/]+\/close-unreserved$/, 'backup.close_unreserved'],
    [/^\/api\/v1\/backups\/queue$/, 'queue.create'],
    [/^\/api\/v1\/backups\/bulk-create$/, 'backup.bulk_create'],
    [/^\/api\/v1\/restores$/, 'restore.create'],
    [/^\/api\/v1\/orchestrator-keys$/, 'credential.orchestrator.create'],
    [/^\/api\/v1\/registration-keys$/, 'credential.registration.create'],
    [/^\/api\/v1\/agents\/[^/]+\/rotate-key$/, 'credential.agent.rotate'],
    [/^\/api\/v1\/encryption\/keys$/, 'encryption.create'],
    [/^\/api\/v1\/encryption\/keys\/[^/]+\/rotate$/, 'encryption.rotate'],
];
const COPY = {
    retry: 'Retry original request',
    retry_confirm: 'Submit the re-entered intent once using the ORIGINAL request ID? An earlier request may already exist. This will never allocate a replacement ID.',
    retry_reenter: 'To offer an original-ID retry, re-enter the same intent in its form and submit for inspection. No body or secret is restored from storage.',
    retry_received: 'Original request response received',
    title: 'Requests awaiting review',
    backup_create: 'Create backup',
    backup_close_unreserved: 'Close pending backup request',
    queue_create: 'Queue backup',
    backup_bulk_create: 'Bulk backup',
    restore_create: 'Create restore',
    credential_orchestrator_create: 'Create orchestrator key',
    credential_registration_create: 'Create registration key',
    credential_agent_rotate: 'Stage agent key',
    encryption_create: 'Create encryption key',
    encryption_rotate: 'Rotate encryption key',

    unknown: 'The outcome is unknown. The original request is retained. Inspect it below before taking further action.',
    recovered: 'The original request was admitted. Review its metadata below; this action was not submitted again.',
    unavailable: 'Secret delivery cannot be recovered. Inspect or revoke the identified credential, then deliberately create a replacement. For an agent candidate, cancel the pending candidate before staging another.',
    inspect: 'Inspect original request',
    acknowledge: 'Acknowledge reviewed outcome',
    no_record: 'No request was found at this moment. The outcome remains unknown; this does not authorize a replacement request ID.',
    capability_error: 'Recovery capability could not be verified. Keep any original request identity; no new mutation was sent.',
    storage_error: 'The request identity could not be saved. No request was submitted.',
    scope_error: 'The signed-in identity changed. Review requests under the original account.',
    unresolved: 'The original request is unresolved. Keep its identity and inspect again later.',
    denied: 'Request inspection is unavailable. Keep the original identity and check access or connectivity.',
    activation_steps: 'Save the candidate in a private 0600 file, stage configuration without reloading, explicitly run the activation helper, then perform a managed reload or restart and verify a fresh authenticated heartbeat.',
    activation_tls: 'Use installation TLS trust options as required. The helper accepts a saved raw key or original JSON. Never put the key on the command line.',
    stage: 'The old agent key remains active. Save and install this candidate, then use the explicit activation helper on the agent host. Copying or closing this dialog does not activate it.',
    rotation_status: 'Inspect staged agent keys',
    cancel_candidate: 'Cancel pending candidate',
    cancel_confirm: 'Cancel this pending candidate? The active agent key remains unchanged.',
    rotation_unavailable: 'This API does not advertise staged agent key activation. No rotation was submitted.',
};

export function operatorText(key) {
    const translated = typeof window.t === 'function' ? window.t(`operator_recovery.${key}`) : null;
    return translated && translated !== `operator_recovery.${key}` ? translated : COPY[key] || key;
}

function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => [key, canonical(value[key])]));
    }
    return value;
}

function recoveryError(message, requestId) {
    const error = new Error(message);
    error.operatorRecovery = true;
    error.requestId = requestId;
    return error;
}

export class OperatorRequests {
    constructor() {
        this.active = new Map();
        this.received = new WeakMap();
        this.inspected = new Map();
        this.capabilities = new Map();
        this.retryIntents = new Map();
        this.generation = 0;
        this.sessionIdentity = null;
    }

    configure(read, baseUrl = '') {
        this.read = read;
        this.baseUrl = baseUrl;
        if (typeof window !== 'undefined' && window.vnbui) window.vnbui.requestRecovery = this;
        if (!this.modalCleanupInstalled && typeof document !== 'undefined' && document.addEventListener) {
            const discard = () => {
                if (this.retryIntents.size) {this.retryIntents.clear(); this.render();}
            };
            document.addEventListener('hidden.bs.modal', discard);
            document.addEventListener('input', discard, true);
            document.addEventListener('change', discard, true);
            this.modalCleanupInstalled = true;
        }
    }

    clearSession() {
        this.generation++;
        this.sessionIdentity = null;
        this.capabilities.clear();
        this.inspected.clear();
        this.retryIntents.clear();
        this.active.clear();
        this.received = new WeakMap();
    }

    assertCurrent(scope, generation) {
        if (this.scope() !== scope || this.generation !== generation) throw new Error(operatorText('scope_error'));
    }

    scope() {
        const user = authService.getUser();
        const token = authService.getToken();
        if (!token || !user?.id || !user?.org_id) {
            this.clearSession();
            throw new Error(operatorText('scope_error'));
        }
        const scope = JSON.stringify([new URL(this.baseUrl || '/', window.location.origin).origin,
            this.baseUrl, user.org_id, user.id]);
        const identity = JSON.stringify([scope, token, user.role]);
        if (identity !== this.sessionIdentity) {
            this.clearSession();
            this.sessionIdentity = identity;
        }
        return scope;
    }

    records(scope = this.scope()) {
        const raw = localStorage.getItem(STORE);
        if (!raw) return [];
        const value = JSON.parse(raw);
        if (value.version !== 1 || !Array.isArray(value.records)) throw new Error(operatorText('storage_error'));
        return value.records.filter(record => record.scope === scope);
    }

    save(records, scope) {
        const existing = JSON.parse(localStorage.getItem(STORE) || '{"version":1,"records":[]}');
        if (existing.version !== 1 || !Array.isArray(existing.records)) throw new Error(operatorText('storage_error'));
        // Storage contains only identities, fixed action summaries and fingerprints.
        localStorage.setItem(STORE, JSON.stringify({version: 1,
            records: [...existing.records.filter(record => record.scope !== scope), ...records]}));
        this.render();
    }

    async capability() {
        const scope = this.scope();
        const generation = this.generation;
        const role = authService.getUser()?.role;
        const key = `${scope}:${role}`;
        if (!this.capabilities.has(key)) {
            const pending = this.read('/api/v1/operator/capabilities').then(result => {
                this.assertCurrent(scope, generation);
                if (!result || result.contract_version !== 1 || result.request_header !== 'Idempotency-Key' ||
                    result.request_identity !== 'uuid' || !Array.isArray(result.actions) || result.secret_replay !== false) {
                    throw new Error(operatorText('capability_error'));
                }
                return result;
            }).catch(error => {
                this.assertCurrent(scope, generation);
                if (this.capabilities.get(key) === pending) this.capabilities.delete(key);
                if (error.status === 404) return null; // Undeployed contract: ordinary legacy behavior only.
                throw new Error(operatorText('capability_error'));
            });
            this.capabilities.set(key, pending);
        }
        return this.capabilities.get(key);
    }

    async fingerprint(action, path, body) {
        const encoded = new TextEncoder().encode(JSON.stringify(canonical({action, path, body})));
        const digest = await crypto.subtle.digest('SHA-256', encoded);
        return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    post(path, body, send) {
        const action = ACTIONS.find(([pattern]) => pattern.test(path))?.[1];
        if (!action) return send();
        const scope = this.scope();
        const generation = this.generation;
        // Coalesce synchronous double clicks before asynchronous hashing. The
        // transient key is never written to browser storage, logs or receipts.
        const key = JSON.stringify([scope, action, path, canonical(body)]);
        if (this.active.has(key)) return this.active.get(key);
        const pending = (async () => {
            const fingerprint = await this.fingerprint(action, path, body);
            this.assertCurrent(scope, generation);
            const claim = () => this.submitOnce(scope, action, fingerprint, send, generation);
            // Cooperative same-origin callers serialize claims; server identity
            // remains the admission authority. No browser-wide once-only claim.
            if (typeof navigator !== 'undefined' && navigator.locks?.request) {
                return navigator.locks.request(`vesta.operator:${scope}:${action}:${fingerprint}`, claim);
            }
            return claim();
        })().finally(() => {
            if (this.active.get(key) === pending) this.active.delete(key);
        });
        this.active.set(key, pending);
        return pending;
    }

    async submitOnce(scope, action, fingerprint, send, generation) {
        this.assertCurrent(scope, generation);
        const supported = await this.capability();
        this.assertCurrent(scope, generation);
        let records;
        try { records = this.records(scope); }
        catch { throw new Error(operatorText('storage_error')); }
        const prior = records.find(record => record.action === action && record.fingerprint === fingerprint);
        if (prior) {
            this.retryIntents.set(`${scope}:${prior.request_id}`, {record: prior, send, generation});
            try { await this.inspect(prior.request_id); }
            catch (error) {
                if (!this.inspected.get(`${scope}:${prior.request_id}`)?.not_found) throw error;
            }
            const inspected = this.inspected.get(`${scope}:${prior.request_id}`);
            // The form's modal can cover the recovery panel. Offer the same
            // deliberate confirmation here; an inspection alone never resends.
            if ((inspected?.not_found || inspected?.state === 'unresolved') &&
                this.retryIntents.has(`${scope}:${prior.request_id}`) &&
                window.confirm(`${operatorText(inspected.not_found ? 'no_record' : 'unresolved')}\n\n${operatorText('retry_confirm')}\n${prior.request_id}`)) {
                this.retryIntents.delete(`${scope}:${prior.request_id}`);
                this.render();
                return this.sendRecord(prior, send, generation, true);
            }
            throw recoveryError(operatorText(inspected?.state === 'admitted' ? 'recovered' : 'unknown'), prior.request_id);
        }
        if (!supported) return send();
        if (!supported.actions.includes(action)) {
            // External encryption providers retain their existing, unadvertised contract.
            if (action.startsWith('encryption.')) return send();
            throw new Error(operatorText('capability_error'));
        }
        const record = {scope, request_id: crypto.randomUUID(), action, fingerprint, summary: action};
        try { this.save([...records, record], scope); }
        catch { throw new Error(operatorText('storage_error')); }
        this.assertCurrent(scope, generation);
        return this.sendRecord(record, send, generation);
    }

    async sendRecord(record, send, generation, retry = false) {
        const {scope} = record;
        this.assertCurrent(scope, generation);
        let result;
        try {
            result = await send(record.request_id);
        } catch (error) {
            this.assertCurrent(scope, generation);
            // A retry refusal cannot settle an earlier unknown admission.
            if (!retry && [400, 401, 403, 404, 413, 415, 422].includes(error.status)) {
                try { this.save(this.records(scope).filter(item => item.request_id !== record.request_id), scope); }
                catch { /* Retain identity if browser storage fails. */ }
                throw error;
            }
            const unknown = recoveryError(operatorText('unknown'), record.request_id);
            unknown.outcomeUnknown = true;
            // Preserve the server's refusal code without settling an unknown outcome.
            unknown.data = error.data;
            unknown.status = error.status;
            throw unknown;
        }
        this.assertCurrent(scope, generation);
        if (!result || result.request_id !== record.request_id) throw recoveryError(operatorText('unknown'), record.request_id);
        if (result.secret_delivery === 'unavailable') {
            await this.inspect(record.request_id);
            throw recoveryError(operatorText('unavailable'), record.request_id);
        }
        this.received.set(result, {scope, request_id: record.request_id, generation});
        return result;
    }

    async retryOriginal(requestId) {
        const scope = this.scope();
        const key = `${scope}:${requestId}`;
        const intent = this.retryIntents.get(key);
        const inspected = this.inspected.get(key);
        if (!intent || (!inspected?.not_found && inspected?.state !== 'unresolved')) throw recoveryError(operatorText('retry_reenter'), requestId);
        this.assertCurrent(scope, intent.generation);
        if (!window.confirm(operatorText('retry_confirm'))) return;
        // Consume the transient closure before the sole explicit attempt. Any
        // next attempt requires re-entering and inspecting the original intent.
        this.retryIntents.delete(key);
        this.render();
        const result = await this.sendRecord(intent.record, intent.send, intent.generation, true);
        if (intent.record.action.startsWith('credential.') && result.api_key) {
            const keys = window.vnbui?.keyManagement;
            if (!keys?.showKeyModal) throw recoveryError(operatorText('unknown'), requestId);
            keys.showKeyModal(operatorText('retry_received'), result);
        } else {
            await this.inspect(requestId);
        }
        return result;
    }

    acknowledge(result) {
        const record = result && this.received.get(result);
        if (!record || this.scope() !== record.scope || this.generation !== record.generation) return;
        this.save(this.records(record.scope).filter(item => item.request_id !== record.request_id), record.scope);
        this.received.delete(result);
    }

    async inspect(requestId) {
        const scope = this.scope();
        const generation = this.generation;
        const record = this.records(scope).find(item => item.request_id === requestId);
        if (!record) throw new Error(operatorText('scope_error'));
        const capabilities = await this.capability();
        this.assertCurrent(scope, generation);
        if (!capabilities?.actions.includes(record.action)) throw new Error(operatorText('capability_error'));
        try {
            const outcome = await this.read(`/api/v1/operator/requests/${encodeURIComponent(requestId)}`);
            this.assertCurrent(scope, generation);
            if (outcome.request_id !== requestId || outcome.action !== record.action ||
                outcome.contract_version !== 1 || !['admitted', 'unresolved'].includes(outcome.state)) throw new Error(operatorText('unknown'));
            // Explicit whitelist. Neither raw receipts nor secret response fields are retained.
            const receipt = outcome.receipt || {};
            const summary = {state: outcome.state, response_status: outcome.response_status,
                secret_delivery: outcome.secret_delivery, id: receipt.id || receipt.backup_id || receipt.queue_id,
                status: receipt.status, rotation_id: receipt.rotation_id,
                current_resource: outcome.current_resource && Object.fromEntries([
                    'id', 'rotation_id', 'agent_id', 'state', 'key_prefix', 'status', 'enabled', 'is_valid',
                    'expires_at', 'activated_at', 'resource_present', 'hold_reason', 'started_backup_id', 'replaced_by_id',
                ].filter(key => outcome.current_resource[key] !== undefined).map(key => [key, outcome.current_resource[key]])),
                summary: receipt.summary && {total: receipt.summary.total, created: receipt.summary.created,
                    skipped: receipt.summary.skipped, failed: receipt.summary.failed},
                details: receipt.details && Object.fromEntries(['created', 'skipped', 'failed'].map(category => [category,
                    (receipt.details[category] || []).map(item => ({vm_id: item.vm_id, backup_id: item.backup_id, reason: item.reason}))])),
                dispatches: (outcome.dispatches || []).map(work => ({kind: work.kind, resource_id: work.resource_id,
                    state: work.state, reason: work.reason, resource_status: work.resource_status,
                    resource_present: work.resource_present}))};
            this.inspected.set(`${scope}:${requestId}`, summary);
            this.render();
            return summary;
        } catch (error) {
            this.assertCurrent(scope, generation);
            this.inspected.set(`${scope}:${requestId}`, {not_found: error.status === 404, message: operatorText(error.status === 404 ? 'no_record' : 'denied')});
            this.render();
            throw recoveryError(operatorText(error.status === 404 ? 'no_record' : 'denied'), requestId);
        }
    }

    acknowledgeReviewed(requestId) {
        const scope = this.scope();
        if (this.inspected.get(`${scope}:${requestId}`)?.state !== 'admitted') return;
        this.save(this.records(scope).filter(record => record.request_id !== requestId), scope);
        this.inspected.delete(`${scope}:${requestId}`);
    }

    render() {
        const container = typeof document !== 'undefined' ? document.getElementById('operator-recovery') : null;
        if (!container) return;
        let records;
        try { records = this.records(); }
        catch { container.replaceChildren(); return; }
        if (!records.length) {container.replaceChildren(); return;}
        container.innerHTML = `<div class="alert alert-warning m-3" role="status"><strong>${escapeHtml(operatorText('title'))}</strong><p>${escapeHtml(operatorText('unknown'))}</p>${records.map(record => {
            const outcome = this.inspected.get(`${record.scope}:${record.request_id}`);
            return `<div class="border-top pt-2 mt-2"><div><code dir="ltr">${escapeHtml(record.request_id)}</code> ${escapeHtml(operatorText(record.summary.replace(/\./g, '_')))}</div>
                <button class="btn btn-sm btn-outline-primary mt-1" data-inspect="${escapeHtml(record.request_id)}">${escapeHtml(operatorText('inspect'))}</button>
                ${outcome ? `<pre class="small text-break mt-2">${escapeHtml(JSON.stringify(outcome, null, 2))}</pre>` : ''}
                ${this.retryIntents.has(`${record.scope}:${record.request_id}`) && (outcome?.not_found || outcome?.state === 'unresolved') ? `<button class="btn btn-sm btn-outline-warning" data-retry="${escapeHtml(record.request_id)}">${escapeHtml(operatorText('retry'))}</button>` : ''}
                ${(outcome?.not_found || outcome?.state === 'unresolved') ? `<p class="small">${escapeHtml(operatorText('retry_reenter'))}</p>` : ''}
                ${outcome?.secret_delivery === 'unavailable' ? `<p>${escapeHtml(operatorText('unavailable'))}</p>` : ''}
                ${outcome?.state === 'admitted' ? `<button class="btn btn-sm" data-ack="${escapeHtml(record.request_id)}">${escapeHtml(operatorText('acknowledge'))}</button>` : ''}</div>`;
        }).join('')}</div>`;
        container.querySelectorAll('[data-inspect]').forEach(button => button.addEventListener('click', () => {
            button.disabled = true;
            this.inspect(button.dataset.inspect).catch(() => {}).finally(() => {button.disabled = false;});
        }));
        container.querySelectorAll('[data-retry]').forEach(button => button.addEventListener('click', () => {
            button.disabled = true;
            this.retryOriginal(button.dataset.retry).catch(error => window.vnbui?.showToast?.(error.message, 'error'));
        }));
        container.querySelectorAll('[data-ack]').forEach(button => button.addEventListener('click', () => this.acknowledgeReviewed(button.dataset.ack)));
    }
}

export const operatorRequests = new OperatorRequests();
