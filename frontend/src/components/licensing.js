import { escapeHtml } from '../utils/security.js';
import { licensingService, MAX_LICENSE_BYTES } from '../services/licensing.service.js';

const DETAILS_TIMEOUT_MS = 5000;

const LICENSE_ERRORS = {
    unknown_key: 'error_unknown_key', invalid_trust_store: 'error_unknown_key',
    invalid_signature: 'error_signature', expired: 'error_expired', not_yet_valid: 'error_not_yet_valid', wrong_installation: 'error_wrong_installation',
    document_too_large: 'file_large', request_too_large: 'file_large',
    unsupported_schema: 'error_schema', unsupported_policy: 'error_schema', wrong_product: 'error_wrong_product',
    challenge_expired: 'error_challenge_expired', challenge_scope_changed: 'error_challenge_scope', invalid_challenge: 'error_challenge_expired', no_active_notice: 'error_challenge_scope',
    first_confirmation_required: 'ack_required', second_confirmation_required: 'phrase_required', invalid_registration_url: 'error_url',
};
for (const code of ['invalid_request', 'invalid_json', 'duplicate_field', 'invalid_envelope', 'invalid_payload', 'invalid_key_id', 'invalid_base64', 'invalid_date', 'invalid_date_range', 'invalid_identity', 'invalid_class', 'invalid_coverage', 'invalid_policy_version', 'invalid_installation_id']) LICENSE_ERRORS[code] = 'error_malformed';
export function licenseErrorKey(error) {
    const code = error?.data?.detail?.code;
    if (Object.hasOwn(LICENSE_ERRORS, code)) return LICENSE_ERRORS[code];
    return ['ack_required', 'phrase_required', 'file_required', 'paste_required', 'file_large'].includes(error?.message) ? error.message : 'operation_failed';
}

export function licenseStatusLabel(status, t = window.t) {
    const key = `licensing.states.${status}`;
    const label = t(key);
    return label && label !== key ? label : t('licensing.states.unknown');
}

function statusText(summary, t) {
    if (summary.status === 'required' && summary.reason_code === 'community_usage_threshold_reached') {
        return t('licensing.local_threshold_reached');
    }
    if (summary.status === 'not_required' && summary.reason_code === 'community_usage_below_threshold') {
        return t('licensing.local_threshold_below');
    }
    return licenseStatusLabel(summary.status, t);
}

function renderCommunityUsage(usage, t) {
    if (!usage) return '';
    const text = key => escapeHtml(t('licensing.' + key));
    const rows = [
        ['usage_backups', usage.successful_backups],
        ['usage_vms', usage.inventoried_vms],
        ['usage_agents', usage.registered_agents],
        ['usage_schedule', usage.schedule_version],
    ];
    return `<div class="mb-4"><h4>${text('usage_title')}</h4><p class="text-secondary">${text('usage_scope')}</p><dl class="row">${rows.map(([label, value]) => `<dt class="col-sm-4">${text(label)}</dt><dd class="col-sm-8"><bdi>${escapeHtml(String(value))}</bdi></dd>`).join('')}</dl></div>`;
}

export function licenseBanner(status, t = window.t) {
    if (!status || !status.notice_required || status.acknowledged) return '';
    return `<div class="alert alert-warning mb-0 rounded-0" role="status"><div class="container-xl d-flex flex-wrap align-items-center gap-2"><span><strong>${escapeHtml(t('licensing.warning'))}</strong> ${escapeHtml(statusText(status, t))}. ${escapeHtml(t('licensing.advisory'))}</span>${status.registration_url ? `<span class="text-break"><bdi>${escapeHtml(status.registration_url)}</bdi></span><button type="button" class="btn btn-sm position-relative z-2" data-license-copy-banner>${escapeHtml(t('licensing.copy'))}</button><span data-license-copy-feedback aria-live="polite"></span>` : ''}<a href="#licensing" class="alert-link stretched-link">${escapeHtml(t(status.can_manage ? 'licensing.open_settings' : 'licensing.view_status'))}</a>${status.can_manage ? '' : `<span>${escapeHtml(t('licensing.contact_admin'))}</span>`}</div></div>`;
}

export function renderLicenseSummary(status, t = window.t) {
    return `<section class="card" id="licensing-summary"><div class="card-body">
        <h2 class="card-title">${escapeHtml(t('licensing.status'))}</h2>
        <p>${escapeHtml(statusText(status, t))}</p>
        <p>${escapeHtml(t('licensing.advisory'))}</p>
        <p class="text-secondary mb-0">${escapeHtml(t('licensing.contact_admin'))}</p>
    </div></section>`;
}

export async function refreshLicenseBanner() {
    const target = document.getElementById('licensing-banner');
    if (!target) return;
    const revision = (target.licensingRevision || 0) + 1; target.licensingRevision = revision;
    try {
        const status = await licensingService.summary();
        if (target.isConnected !== false && target.licensingRevision === revision) {
            target.innerHTML = licenseBanner(status);
            target.querySelector('[data-license-copy-banner]')?.addEventListener('click', async () => {
                const feedback = target.querySelector('[data-license-copy-feedback]');
                try {await navigator.clipboard.writeText(status.registration_url); feedback.textContent = window.t('licensing.copied');}
                catch {feedback.textContent = window.t('licensing.copy_failed');}
            });
        }
    } catch {if (target.isConnected !== false && target.licensingRevision === revision) target.innerHTML = '';}

}

export function renderCertificate(certificate, t = window.t) {
    const text = key => escapeHtml(t('licensing.' + key));
    if (!certificate) return `<p class="text-secondary">${text('no_certificate')}</p>`;
    const recorded = value => escapeHtml(value || t('licensing.not_recorded'));
    const modules = Array.isArray(certificate.coverage?.modules) ? certificate.coverage.modules : [];
    const moduleNames = modules.map(module => {
        const key = `licensing.module_labels.${module}`;
        const label = t(key); return label === key ? t('licensing.other_module') : label;
    });
    const rows = [
        ['license_id', `<bdi>${recorded(certificate.license_id)}</bdi> <button type="button" class="btn btn-sm" data-license-action="copy-license-id">${text('copy_license_id')}</button>`],
        ['customer_id', `<bdi>${recorded(certificate.customer_id)}</bdi>`],
        ['license_class', text(certificate.class === 'free' ? 'class_free' : certificate.class === 'paid' ? 'class_paid' : 'not_recorded')],
        ['issued_at', `<bdi>${recorded(certificate.issued_at)}</bdi>`],
        ['valid_from', `<bdi>${recorded(certificate.not_before || certificate.issued_at)}</bdi>`],
        ['expires_at', certificate.expires_at ? `<bdi>${recorded(certificate.expires_at)}</bdi>` : text('no_expiry')],
        ['coverage', moduleNames.length ? escapeHtml(moduleNames.join(', ')) : text('no_additional_modules')],
    ];
    return `<dl class="row">${rows.map(([label, value]) => `<dt class="col-sm-4">${text(label)}</dt><dd class="col-sm-8" style="overflow-wrap:anywhere">${value}</dd>`).join('')}</dl><details><summary>${text('advanced_details')}</summary><pre class="border rounded p-2 mt-2" dir="ltr" style="white-space:pre-wrap;overflow-wrap:anywhere">${escapeHtml(JSON.stringify(certificate, null, 2))}</pre></details>`;
}

export class LicensingPanel {
    constructor(service = licensingService) {
        this.service = service;
        this.detail = null;
        this.error = null;
        this.message = null;
        this.challenge = null;
        this.loading = true;
        this.detailsRequest = null;
        this.destroyed = false;
    }

    async load() {
        if (this.destroyed) return false;
        this.detailsRequest?.abort();
        const controller = new AbortController();
        this.detailsRequest = controller;
        this.loading = true;
        const {signal} = controller;
        const cancelled = new Promise(resolve => signal.addEventListener('abort', () => resolve(null), {once: true}));
        const timeout = setTimeout(() => controller.abort(), DETAILS_TIMEOUT_MS);
        try {
            const detail = await Promise.race([this.service.details(signal), cancelled]);
            if (this.detailsRequest !== controller) return false;
            this.detail = signal.aborted ? null : detail;
            this.error = signal.aborted ? 'unavailable' : null;
        } catch {
            if (this.detailsRequest !== controller) return false;
            this.detail = null;
            this.error = 'unavailable';
        } finally {
            clearTimeout(timeout);
            if (this.detailsRequest === controller) {
                this.detailsRequest = null;
                this.loading = false;
            }
        }
        return true;
    }

    destroy() {
        this.destroyed = true;
        this.detailsRequest?.abort();
        this.detailsRequest = null;
    }

    feedback(t = window.t) {
        if (this.error) return `<div class="alert alert-danger">${escapeHtml(t('licensing.' + this.error))}</div>`;
        if (this.message) return `<div class="alert alert-success">${escapeHtml(t('licensing.' + this.message))}</div>`;
        return '';
    }

    afterRender() { return this.mount(); }

    render(t = window.t) {
        const text = key => escapeHtml(t('licensing.' + key));
        const action = (name, label, style = 'btn') => `<button type="button" class="${style}" data-license-action="${name}">${text(label)}</button>`;
        const heading = `<h3 class="card-title">${text('title')}</h3><p class="text-secondary">${text('advisory')}</p>`;
        if (!this.detail) {
            const status = this.loading
                ? `<p class="text-secondary" role="status">${escapeHtml(t('common.loading'))}</p>`
                : `<div class="alert alert-warning" role="status" tabindex="-1" data-license-feedback>${text('unavailable')}</div>${action('retry', 'retry')}`;
            return `<div id="licensing-panel" class="card"><div class="card-body">${heading}${status}</div></div>`;
        }
        const s = this.detail.status;
        const ack = this.detail.acknowledgement;
        return `<div id="licensing-panel" class="card"><div class="card-body">${heading}
            <div role="status" aria-live="polite" tabindex="-1" data-license-feedback>${this.feedback(t)}</div>
            <dl class="row mt-3"><dt class="col-sm-4">${text('status')}</dt><dd class="col-sm-8">${escapeHtml(statusText(s, t))}</dd><dt class="col-sm-4">${text('trust_store')}</dt><dd class="col-sm-8">${text('trust_' + (['configured', 'unprovisioned', 'invalid'].includes(this.detail.trust_store?.state) ? this.detail.trust_store.state : 'invalid'))}</dd></dl>
            <section class="mb-4"><h4>${text('details')}</h4><dl class="row"><dt class="col-sm-4">${text('installation_id')}</dt><dd class="col-sm-8 text-break"><bdi>${escapeHtml(this.detail.installation_id || t('licensing.not_recorded'))}</bdi> ${this.detail.installation_id ? action('copy-installation-id', 'copy_installation_id', 'btn btn-sm') : ''}</dd></dl>${renderCertificate(this.detail.certificate, t)}</section>
            <section class="mb-4"><h4>${text('import_title')}</h4><p id="license-import-hint" class="form-hint">${text('import_hint')}</p>
                <label for="license-file" class="form-label">${text('select_file')}</label><input id="license-file" class="form-control mb-2" type="file" accept="application/json,.json" aria-describedby="license-import-hint">${action('import', 'import_file')}
                <label for="license-paste" class="form-label mt-3">${text('paste_label')}</label><textarea id="license-paste" class="form-control mb-2" rows="4" dir="ltr" spellcheck="false" autocomplete="off" aria-describedby="license-import-hint"></textarea>${action('import-pasted', 'import_pasted')}
            </section>
            ${action('retry', 'retry')}
            ${renderCommunityUsage(this.detail.community_usage, t)}
            ${s.registration_url ? `<div class="mb-4"><label for="license-registration-display" class="form-label">${text('registration_url')}</label><div class="d-flex flex-wrap gap-2"><input id="license-registration-display" class="form-control flex-fill" style="min-width:0;flex-basis:15rem" type="text" dir="ltr" readonly value="${escapeHtml(s.registration_url)}">${action('copy', 'copy')}</div><p class="form-hint">${text('registration_hint')}</p></div>` : ''}
            <div class="mb-4"><label for="license-registration-url" class="form-label">${text('registration_edit')}</label><input id="license-registration-url" type="text" dir="ltr" class="form-control" maxlength="2048" value="${escapeHtml(s.registration_url)}" aria-describedby="license-registration-default"><p id="license-registration-default" class="form-hint">${text('registration_default')}</p>${action('save-url', 'save_url')}</div>
            ${s.acknowledged ? `<div class="alert alert-info"><strong>${text('notice_hidden')}</strong><dl class="row mb-0"><dt class="col-sm-4">${text('hidden_by')}</dt><dd class="col-sm-8" style="overflow-wrap:anywhere">${escapeHtml(ack?.actor?.label || ack?.actor?.user_id || t('licensing.not_recorded'))}</dd><dt class="col-sm-4">${text('hidden_at')}</dt><dd class="col-sm-8"><bdi>${escapeHtml(ack?.acknowledged_at || t('licensing.not_recorded'))}</bdi></dd></dl></div>${action('restore', 'restore_notice')}` : s.notice_required ? `<div class="border rounded p-3"><h4>${text('hide_notice')}</h4><p id="license-ack-explanation">${text('ack_explanation')}</p>${this.challenge ? `<h5>${text('ack_step_two')}</h5><p><bdi>${escapeHtml(this.challenge.expected_phrase)}</bdi></p><label class="form-label" for="license-phrase">${text('ack_phrase')}</label><input class="form-control mb-3" type="text" dir="ltr" autocomplete="off" id="license-phrase" aria-describedby="license-ack-explanation">${action('confirm', 'ack_confirm', 'btn btn-warning')} ${action('cancel', 'cancel')}` : `<label class="form-check mb-3"><input id="license-ack-checkbox" class="form-check-input" type="checkbox" aria-describedby="license-ack-explanation"><span class="form-check-label">${text('ack_checkbox')}</span></label>${action('prepare', 'ack_continue')}`}</div>` : ''}
        </div></div>`;
    }
    async mount() {
        const root = document.getElementById('licensing-panel');
        if (!root || this.destroyed) return;
        if (this.loading) {
            if (!this.detailsRequest && await this.load()) this.repaint(root, false);
            return;
        }
        root.querySelectorAll('[data-license-action]').forEach(button => button.addEventListener('click', () => this.act(button.dataset.licenseAction, root)));
    }

    repaint(expectedRoot, focus = true) {
        const root = document.getElementById('licensing-panel');
        if (this.destroyed || !root || root !== expectedRoot) return;
        root.outerHTML = this.render();
        this.mount();
        if (focus) document.querySelector(this.challenge ? '#license-phrase' : '#licensing-panel [data-license-feedback]')?.focus?.();
    }

    async act(action, root) {
        if (this.destroyed) return;
        const buttons = [...root.querySelectorAll('button')]; buttons.forEach(button => {button.disabled = true;});
        this.error = null; this.message = null;
        const copyValues = {
            copy: this.detail?.status.registration_url,
            'copy-installation-id': this.detail?.installation_id,
            'copy-license-id': this.detail?.certificate?.license_id,
        };
        try {
            if (Object.hasOwn(copyValues, action)) {
                try {
                    await navigator.clipboard.writeText(copyValues[action]);
                    this.message = action === 'copy' ? 'copied' : 'id_copied';
                } catch {
                    this.error = action === 'copy' ? 'copy_failed' : 'id_copy_failed';
                }
            } else if (action === 'cancel') this.challenge = null;
            else if (action === 'retry') {this.challenge = null; await this.load(); void refreshLicenseBanner();}
            else if (action === 'prepare') {
                if (!root.querySelector('#license-ack-checkbox').checked) throw new Error('ack_required');
                const challenge = await this.service.prepare(true);
                if (typeof challenge.challenge !== 'string' || typeof challenge.expected_phrase !== 'string' || challenge.notice_scope !== this.detail.status.notice_scope) throw new Error('operation_failed');
                this.challenge = challenge;
            } else if (action === 'confirm') {
                const phrase = root.querySelector('#license-phrase').value;
                if (!this.challenge || phrase !== this.challenge.expected_phrase) throw new Error('phrase_required');
                await this.service.confirm(this.challenge.challenge, phrase);
                this.challenge = null; await this.load(); void refreshLicenseBanner();
            } else if (action === 'restore') {
                await this.service.restore(); this.challenge = null; await this.load(); void refreshLicenseBanner();
            } else if (action === 'save-url') {
                await this.service.registrationUrl(root.querySelector('#license-registration-url').value.trim());
                this.challenge = null; await this.load(); this.message = 'saved'; void refreshLicenseBanner();
            } else if (action === 'import' || action === 'import-pasted') {
                let envelope;
                if (action === 'import') {
                    const file = root.querySelector('#license-file').files?.[0];
                    if (!file) throw new Error('file_required');
                    if (file.size > MAX_LICENSE_BYTES) throw new Error('file_large');
                    envelope = await file.text();
                } else {
                    envelope = root.querySelector('#license-paste').value;
                    if (!envelope.trim()) throw new Error('paste_required');
                }
                this.detail = await this.service.importLicense(envelope);
                this.challenge = null; this.message = 'imported'; void refreshLicenseBanner();
            }
        } catch (error) {if (error.status === 401 || error.status === 403) this.detail = null; this.error = licenseErrorKey(error);}
        finally {
            buttons.forEach(button => {button.disabled = false;});
            // Leave a rejected file or draft available for correction. A successful import clears both.
            if (root.isConnected && this.detail && (this.error || Object.hasOwn(copyValues, action))) {
                const feedback = root.querySelector('[data-license-feedback]');
                feedback.innerHTML = this.feedback();
                feedback.focus();
            } else this.repaint(root);
        }
    }
}
