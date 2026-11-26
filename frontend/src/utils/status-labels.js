/** Display enums without changing the values sent to the API. */
export function enumLabel(value, domain = 'status', translate = globalThis.window?.t) {
    const key = `enums.${domain}.${String(value || 'unknown').toLowerCase()}`;
    if (typeof translate !== 'function') return '—';
    const label = translate(key);
    return label && label !== key ? label : translate('enums.status.unknown');
}

export function storageCapacity(free, total) {
    if (!Number.isFinite(free) || !Number.isFinite(total) || total <= 0 || free < 0 || free > total) return null;
    return Math.round(free / total * 100);
}
