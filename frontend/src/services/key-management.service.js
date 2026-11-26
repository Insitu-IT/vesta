/**
 * API Key Management Service
 * Handles orchestrator keys, registration keys, and agent key operations
 */
import { operatorText } from './operator-requests.service.js';
import { apiClient } from '../api/client.js';
import { escapeHtml } from '../utils/security.js';

class KeyManagementService {
    constructor() {
        this.currentModal = null;
        this.currentKeyData = null;
    }

    /**
     * Save current tab and reload preserving state
     */
    reloadPreservingTab() {
        const currentTab = document.querySelector('.nav-link.active[data-bs-toggle="pill"]');
        if (currentTab) {
            const tabId = currentTab.getAttribute('href');
            sessionStorage.setItem('activeSettingsTab', tabId);
        }
        window.location.reload();
    }

    /**
     * Show toast notification
     */
    showToast(message, type = 'success') {
        const bgClass = type === 'success' ? 'bg-success' : type === 'error' ? 'bg-danger' : 'bg-info';
        const toastHtml = `
            <div class="toast align-items-center text-white ${bgClass} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">${escapeHtml(message)}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;

        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
            document.body.appendChild(container);
        }

        container.insertAdjacentHTML('beforeend', toastHtml);
        const toastEl = container.lastElementChild;
        const toast = new bootstrap.Toast(toastEl);
        toast.show();
    }

    /**
     * Show modal with API key (only shown once!)
     */
    showKeyModal(title, keyData) {
        if (!keyData.api_key || keyData.secret_delivery === 'unavailable') {
            this.showToast(operatorText('unavailable'), 'error');
            apiClient.renderRequestRecovery();
            return;
        }
        const modalHtml = `
            <div class="modal fade" id="api-key-modal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${escapeHtml(title)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="alert alert-warning">
                                <svg xmlns="http://www.w3.org/2000/svg" class="icon alert-icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 9v2m0 4v.01"/><path d="M5 19h14a2 2 0 0 0 1.84 -2.75l-7.1 -12.25a2 2 0 0 0 -3.5 0l-7.1 12.25a2 2 0 0 0 1.75 2.75" /></svg>
                                <strong>Important!</strong> This is the only time you'll see this API key. Save it now!
                            </div>

                            ${keyData.rotation_id ? `<div class="alert alert-info">${escapeHtml(operatorText('stage'))}</div><p>${escapeHtml(operatorText('activation_steps'))}</p><pre dir="ltr" class="text-break">${escapeHtml(`python3 scripts/activate-agent-key.py --activate --api-url https://API_ORIGIN --agent-id ${keyData.agent_id} --rotation-id ${keyData.rotation_id} --candidate-file /private/saved-rotation.json`)}</pre><p class="small">${escapeHtml(operatorText('activation_tls'))}</p>` : ''}
                            <div class="mb-3">
                                <label class="form-label">API Key</label>
                                <div class="input-group">
                                    <input type="text" class="form-control font-monospace" id="generated-api-key" value="${escapeHtml(keyData.api_key)}" readonly>
                                    <button class="btn btn-primary" type="button" onclick="window.vnbui.keyManagement.copyToClipboard('generated-api-key')">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2" /></svg>
                                        Copy
                                    </button>
                                </div>
                            </div>

                            ${keyData.usage_snippet ? `
                            <div class="mb-3">
                                <label class="form-label">Usage in agent.env</label>
                                <div class="input-group">
                                    <textarea class="form-control font-monospace" id="usage-snippet" rows="2" readonly>${escapeHtml(keyData.usage_snippet)}</textarea>
                                    <button class="btn btn-primary align-self-start" type="button" onclick="window.vnbui.keyManagement.copyToClipboard('usage-snippet')">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2" /></svg>
                                        Copy
                                    </button>
                                </div>
                                <div class="form-hint">Add this line to /etc/vesta/agent.env on all agent hosts</div>
                            </div>
                            ` : ''}

                            ${keyData.env_snippet ? `
                            <div class="mb-3">
                                <label class="form-label">Complete Agent Configuration (agent.env)</label>
                                <div class="input-group">
                                    <textarea class="form-control font-monospace" id="agent-env-snippet" rows="10" readonly>${escapeHtml(keyData.env_snippet)}</textarea>
                                    <button class="btn btn-primary align-self-start" type="button" onclick="window.vnbui.keyManagement.copyToClipboard('agent-env-snippet')">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="icon" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2" /></svg>
                                        Copy
                                    </button>
                                </div>
                                <div class="form-hint">Copy this entire snippet to /etc/vesta/agent.env on your agent host</div>
                            </div>
                            ` : ''}

                            <div class="row">
                                <div class="col-md-6">
                                    <strong>Name:</strong> ${escapeHtml(keyData.name)}
                                </div>
                                <div class="col-md-6">
                                    <strong>Key Prefix:</strong> <code>${escapeHtml(keyData.key_prefix)}...</code>
                                </div>
                                ${keyData.expires_at ? `
                                <div class="col-md-6 mt-2">
                                    <strong>Expires:</strong> ${new Date(keyData.expires_at).toLocaleDateString()}
                                </div>
                                ` : ''}
                                ${keyData.max_uses ? `
                                <div class="col-md-6 mt-2">
                                    <strong>Max Uses:</strong> ${keyData.max_uses}
                                </div>
                                ` : ''}
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-primary" id="acknowledge-generated-key" data-bs-dismiss="modal">I've Saved the Key</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Remove existing modal if present
        const existing = document.getElementById('api-key-modal');
        if (existing) existing.remove();

        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('api-key-modal'));
        modal.show();

        // Explicit saved acknowledgment is separate from dismissal or copying.
        document.getElementById('acknowledge-generated-key').addEventListener('click', () => apiClient.acknowledge(keyData));
        const self = this;
        document.getElementById('api-key-modal').addEventListener('hidden.bs.modal', function () {
            this.remove();
            self.reloadPreservingTab();
        });
    }

    /**
     * Copy text to clipboard
     */
    copyToClipboard(elementId) {
        const element = document.getElementById(elementId);
        element.select();
        document.execCommand('copy');
        this.showToast('Copied to clipboard!', 'success');
    }

    /**
     * Show form modal for creating/editing keys
     */
    showFormModal(title, fields, onSubmit) {
        const modalHtml = `
            <div class="modal fade" id="key-form-modal" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${escapeHtml(title)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <form id="key-form">
                            <div class="modal-body">
                                ${fields.map(field => this.renderFormField(field)).join('')}
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                <button type="submit" class="btn btn-primary">Save</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        `;

        // Remove existing modal if present
        const existing = document.getElementById('key-form-modal');
        if (existing) existing.remove();

        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modalEl = document.getElementById('key-form-modal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();

        // Handle form submission
        document.getElementById('key-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = e.target.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Saving...';

            try {
                const formData = new FormData(e.target);
                const data = Object.fromEntries(formData.entries());

                // Convert date strings to ISO format (or null if empty)
                if (data.expires_at && data.expires_at.trim() !== '') {
                    data.expires_at = new Date(data.expires_at).toISOString();
                } else {
                    data.expires_at = null;
                }

                // Convert string numbers (or null if empty)
                if (data.max_uses && data.max_uses.trim() !== '') {
                    data.max_uses = parseInt(data.max_uses) || null;
                } else {
                    data.max_uses = null;
                }

                // Convert checkbox values
                if (data.enabled !== undefined) {
                    data.enabled = data.enabled === 'on';
                }

                await onSubmit(data);
                modal.hide();
            } catch (error) {
                console.error('Form submission error:', error);
                this.showToast(error.message || 'Failed to save', 'error');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Save';
            }
        });

        // Cleanup on close
        modalEl.addEventListener('hidden.bs.modal', function () {
            this.remove();
        });
    }

    /**
     * Render form field
     */
    renderFormField(field) {
        switch (field.type) {
            case 'text':
                return `
                    <div class="mb-3">
                        <label class="form-label">${escapeHtml(field.label)}${field.required ? ' <span class="text-danger">*</span>' : ''}</label>
                        <input type="text" class="form-control" name="${field.name}" value="${escapeHtml(field.value || '')}" ${field.required ? 'required' : ''} ${field.placeholder ? `placeholder="${escapeHtml(field.placeholder)}"` : ''}>
                        ${field.hint ? `<div class="form-hint">${escapeHtml(field.hint)}</div>` : ''}
                    </div>
                `;
            case 'number':
                return `
                    <div class="mb-3">
                        <label class="form-label">${escapeHtml(field.label)}</label>
                        <input type="number" class="form-control" name="${field.name}" value="${field.value || ''}" min="${field.min || 1}" ${field.placeholder ? `placeholder="${escapeHtml(field.placeholder)}"` : ''}>
                        ${field.hint ? `<div class="form-hint">${escapeHtml(field.hint)}</div>` : ''}
                    </div>
                `;
            case 'date':
                return `
                    <div class="mb-3">
                        <label class="form-label">${escapeHtml(field.label)}</label>
                        <input type="date" class="form-control" name="${field.name}" value="${field.value || ''}">
                        ${field.hint ? `<div class="form-hint">${escapeHtml(field.hint)}</div>` : ''}
                    </div>
                `;
            case 'checkbox':
                return `
                    <div class="mb-3">
                        <label class="form-check">
                            <input type="checkbox" class="form-check-input" name="${field.name}" ${field.value ? 'checked' : ''}>
                            <span class="form-check-label">${escapeHtml(field.label)}</span>
                        </label>
                        ${field.hint ? `<div class="form-hint">${escapeHtml(field.hint)}</div>` : ''}
                    </div>
                `;
            default:
                return '';
        }
    }

    // ========================================================================
    // Orchestrator API Keys
    // ========================================================================

    async createOrchestratorKey() {
        this.showFormModal('Create Orchestrator API Key', [
            { type: 'text', name: 'name', label: 'Key Name', required: true, placeholder: 'Production Agents', hint: 'Descriptive name for this key' },
            { type: 'date', name: 'expires_at', label: 'Expiration Date (optional)', hint: 'Leave blank for no expiration' }
        ], async (data) => {
            const result = await apiClient.post('/api/v1/orchestrator-keys', data);
            this.showKeyModal('Orchestrator API Key Created', result);
            // Page will reload when modal closes
        });
    }

    async editOrchestratorKey(keyId) {
        // Fetch current key data
        const keys = await apiClient.get('/api/v1/orchestrator-keys');
        const key = keys.items.find(k => k.id === keyId);

        if (!key) {
            this.showToast('Key not found', 'error');
            return;
        }

        this.showFormModal('Edit Orchestrator API Key', [
            { type: 'text', name: 'name', label: 'Key Name', required: true, value: key.name },
            { type: 'date', name: 'expires_at', label: 'Expiration Date', value: key.expires_at ? key.expires_at.split('T')[0] : '' },
            { type: 'checkbox', name: 'enabled', label: 'Enabled', value: key.enabled }
        ], async (data) => {
            await apiClient.patch(`/api/v1/orchestrator-keys/${keyId}`, data);
            this.showToast('Key updated successfully', 'success');
            setTimeout(() => this.reloadPreservingTab(), 2000);  // Give time to see toast
        });
    }

    async deleteOrchestratorKey(keyId, keyName) {
        if (!confirm(`Delete orchestrator API key "${keyName}"?\n\nAll agents using this key will be unable to authenticate.`)) {
            return;
        }

        try {
            await apiClient.delete(`/api/v1/orchestrator-keys/${keyId}`);
            this.showToast('Key deleted successfully', 'success');
            setTimeout(() => this.reloadPreservingTab(), 2000);  // Give time to see toast
        } catch (error) {
            this.showToast(error.message || 'Failed to delete key', 'error');
        }
    }

    // ========================================================================
    // Agent Registration Keys
    // ========================================================================

    async createRegistrationKey() {
        this.showFormModal('Create Agent Registration Key', [
            { type: 'text', name: 'name', label: 'Key Name', required: true, placeholder: 'KVM Production Hosts', hint: 'Descriptive name for this registration key' },
            { type: 'text', name: 'agent_hostname', label: 'Agent Hostname', required: true, placeholder: 'hypervisor-01', hint: 'This key can enroll only this exact agent identity.' },
            { type: 'number', name: 'max_uses', label: 'Max Uses (optional)', placeholder: '10', hint: 'Maximum number of times this key can be used. Leave blank for unlimited.' },
            { type: 'date', name: 'expires_at', label: 'Expiration Date (optional)', hint: 'Leave blank for no expiration' }
        ], async (data) => {
            const result = await apiClient.post('/api/v1/registration-keys', data);
            this.showKeyModal('Agent Registration Key Created', result);
            // Page will reload when modal closes
        });
    }

    async editRegistrationKey(keyId) {
        // Fetch current key data
        const keys = await apiClient.get('/api/v1/registration-keys');
        const key = keys.items.find(k => k.id === keyId);

        if (!key) {
            this.showToast('Key not found', 'error');
            return;
        }

        this.showFormModal('Edit Agent Registration Key', [
            { type: 'text', name: 'name', label: 'Key Name', required: true, value: key.name },
            { type: 'number', name: 'max_uses', label: 'Max Uses', value: key.max_uses || '' },
            { type: 'date', name: 'expires_at', label: 'Expiration Date', value: key.expires_at ? key.expires_at.split('T')[0] : '' },
            { type: 'checkbox', name: 'enabled', label: 'Enabled', value: key.enabled }
        ], async (data) => {
            await apiClient.patch(`/api/v1/registration-keys/${keyId}`, data);
            this.showToast('Key updated successfully', 'success');
            setTimeout(() => this.reloadPreservingTab(), 2000);
        });
    }

    async deleteRegistrationKey(keyId, keyName) {
        if (!confirm(`Delete registration key "${keyName}"?\n\nNo new agents will be able to register with this key.`)) {
            return;
        }

        try {
            await apiClient.delete(`/api/v1/registration-keys/${keyId}`);
            this.showToast('Key deleted successfully', 'success');
            setTimeout(() => this.reloadPreservingTab(), 2000);
        } catch (error) {
            this.showToast(error.message || 'Failed to delete key', 'error');
        }
    }

    // ========================================================================
    // Agent Management
    // ========================================================================

    async editAgentDisplayName(agentId, currentName) {
        this.showFormModal(window.t('agents.edit_display_name'), [
            { type: 'text', name: 'display_name', label: window.t('agents.display_name'), value: currentName || '', placeholder: '', hint: window.t('agents.display_name_hint') }
        ], async (data) => {
            await apiClient.patch(`/api/v1/agents/${agentId}`, data);
            this.showToast(window.t('agents.display_name_saved'), 'success');
            setTimeout(() => this.reloadPreservingTab(), 2000);
        });
    }

    async rotateAgentKey(agentId, agentName) {
      try {
        const capability = await apiClient.operatorCapabilities();
        if (capability?.agent_key_rotation !== 'staged-candidate-activation') {
            this.showToast(operatorText('rotation_unavailable'), 'error');
            return;
        }
        if (!confirm(operatorText('stage'))) {
            return;
        }

            const result = await apiClient.post(`/api/v1/agents/${agentId}/rotate-key`, {});
            this.showKeyModal(`${agentName}: ${operatorText('rotation_status')}`, result);
            // Page will reload when modal closes
        } catch (error) {
            this.showToast(error.message || 'Failed to rotate key', 'error');
        }
    }
    rotationMetadata(value) {
        return {rotation_id: value.rotation_id, agent_id: value.agent_id, state: value.state,
            key_prefix: value.key_prefix, created_at: value.created_at,
            expires_at: value.expires_at, activated_at: value.activated_at};
    }

    async inspectAgentRotations(agentId) {
        try {
            const data = await apiClient.get(`/api/v1/agents/${encodeURIComponent(agentId)}/key-rotations`);
            if (!Array.isArray(data.items)) throw new Error(operatorText('denied'));
            document.getElementById('agent-rotation-modal')?.remove();
            document.body.insertAdjacentHTML('beforeend', `<div class="modal fade" id="agent-rotation-modal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">${escapeHtml(operatorText('rotation_status'))}</h5><button class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body"><p>${escapeHtml(operatorText('stage'))}</p>${data.items.map(value => {
                    const rotation = this.rotationMetadata(value);
                    return `<div class="border-top py-2"><pre dir="ltr" class="small text-break" data-status="${escapeHtml(rotation.rotation_id)}">${escapeHtml(JSON.stringify(rotation, null, 2))}</pre>
                        <button class="btn btn-sm btn-outline-primary" data-refresh="${escapeHtml(rotation.rotation_id)}">${escapeHtml(operatorText('inspect'))}</button>
                        ${rotation.state === 'pending' ? `<button class="btn btn-sm btn-outline-danger" data-cancel="${escapeHtml(rotation.rotation_id)}">${escapeHtml(operatorText('cancel_candidate'))}</button>` : ''}</div>`;
                }).join('')}</div></div></div></div>`);
            const element = document.getElementById('agent-rotation-modal');
            element.querySelectorAll('[data-refresh]').forEach(button => button.addEventListener('click', async () => {
                button.disabled = true;
                try {
                    const value = await apiClient.get(`/api/v1/agents/${encodeURIComponent(agentId)}/key-rotations/${encodeURIComponent(button.dataset.refresh)}`);
                    element.querySelector(`[data-status="${CSS.escape(button.dataset.refresh)}"]`).textContent = JSON.stringify(this.rotationMetadata(value), null, 2);
                } catch (error) {this.showToast(error.message || operatorText('denied'), 'error');}
                finally {button.disabled = false;}
            }));
            element.querySelectorAll('[data-cancel]').forEach(button => button.addEventListener('click', async () => {
                if (!confirm(operatorText('cancel_confirm'))) return;
                button.disabled = true;
                try {
                    const value = await apiClient.delete(`/api/v1/agents/${encodeURIComponent(agentId)}/key-rotations/${encodeURIComponent(button.dataset.cancel)}`);
                    element.querySelector(`[data-status="${CSS.escape(button.dataset.cancel)}"]`).textContent = JSON.stringify(this.rotationMetadata(value), null, 2);
                    button.remove();
                } catch {
                    // Cancellation also has an uncertain transport boundary. Inspect;
                    // never automatically repeat DELETE or prepare a replacement.
                    this.showToast(operatorText('unknown'), 'error');
                }
            }));
            new bootstrap.Modal(element).show();
            element.addEventListener('hidden.bs.modal', () => element.remove());
        } catch (error) {
            this.showToast(error.message || operatorText('denied'), 'error');
        }
    }

}

// Export singleton instance
export const keyManagementService = new KeyManagementService();
