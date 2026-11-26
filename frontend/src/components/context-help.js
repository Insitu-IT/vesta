import { escapeHtml } from '../utils/security.js';
let nextId = 0;

export function contextHelp(key, t = window.t) {
    const id = `context-help-${++nextId}`;
    return `<details class="context-help"><summary aria-label="${escapeHtml(t('help.label'))}" aria-describedby="${id}"><i class="ti ti-help-circle icon" aria-hidden="true"></i></summary><span id="${id}" role="note" class="context-help-copy">${escapeHtml(t('help.' + key))}</span></details>`;
}

// Native details content stays hidden while closed, even if a child has display:block.
// Keep its actual open state aligned with hover/focus, and pin explicit activation.
export function installContextHelp() {
    const dismiss = help => {help.open = false; delete help.dataset.helpPinned; help.classList.add('context-help-dismissed');};
    document.addEventListener('keydown', event => {
        if (event.key !== 'Escape') return;
        const focused = document.activeElement;
        document.querySelectorAll('.context-help[open], .context-help:focus-within, .context-help:hover').forEach(help => {
            if (help.contains(focused)) help.querySelector('summary')?.focus();
            dismiss(help);
        });
    });
    document.addEventListener('pointerover', event => {
        const help = event.target.closest('.context-help');
        if (help && !help.contains(event.relatedTarget)) {help.classList.remove('context-help-dismissed'); help.open = true;}
    });
    document.addEventListener('pointerout', event => {
        const help = event.target.closest('.context-help');
        if (help && !help.contains(event.relatedTarget) && !help.contains(document.activeElement) && !help.dataset.helpPinned) help.open = false;
    });
    document.addEventListener('focusin', event => {
        const help = event.target.closest('.context-help');
        if (help) {help.classList.remove('context-help-dismissed'); help.open = true;}
    });
    document.addEventListener('focusout', event => {
        const help = event.target.closest('.context-help');
        if (help && !help.contains(event.relatedTarget) && !help.matches(':hover') && !help.dataset.helpPinned) help.open = false;
    });
    document.addEventListener('click', event => {
        const help = event.target.closest('.context-help');
        if (help && event.target.closest('summary') === help.querySelector('summary')) {
            event.preventDefault();
            if (help.dataset.helpPinned) dismiss(help);
            else {help.classList.remove('context-help-dismissed'); help.dataset.helpPinned = 'true'; help.open = true;}
        }
        document.querySelectorAll('.context-help[open]').forEach(other => {if (!other.contains(event.target)) dismiss(other);});
    });
}
