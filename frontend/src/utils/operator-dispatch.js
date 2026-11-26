import { escapeHtml } from './security.js';

const messages = {
    pending: 'Waiting for dispatch to the original agent.',
    dispatching: 'Agent handoff is in progress or its outcome is unknown. Inspect the original attempt.',
    held: 'Dispatch is held. Reconcile the original attempt before taking further action.',
    delivered: 'Dispatch processing finished. Check the job status for the result.',
    unknown: 'Dispatch status is unavailable. Inspect the original attempt.',
};

export function operatorDispatchMessage(dispatch) {
    if (!dispatch) return '';
    const state = Object.hasOwn(messages, dispatch.state) ? dispatch.state : 'unknown';
    const key = `operator_recovery.dispatch_${state}`;
    const translated = window.t?.(key);
    return translated && translated !== key ? translated : messages[state];
}

export function renderOperatorDispatch(dispatch) {
    if (!dispatch) return '';
    return `<div class="small mt-1 ${dispatch.state === 'held' ? 'text-warning' : 'text-secondary'}" role="status">${escapeHtml(operatorDispatchMessage(dispatch))}
        ${dispatch.reason || dispatch.request_id ? `<div class="small text-break" dir="ltr"><code>${escapeHtml(dispatch.reason || '')}</code> <code>${escapeHtml(dispatch.request_id || '')}</code></div>` : ''}</div>`;
}
