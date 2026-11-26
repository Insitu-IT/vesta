/** Provider identity comes from reported capabilities, never host naming. */
export function agentProvider(agent) {
    const provider = agent.capabilities?.provider || agent.metrics?.provider;
    if (['kubevirt', 'libvirt'].includes(provider)) return provider;
    return {kubevirt_pull_transaction: 'kubevirt', native_push: 'libvirt'}[agent.capabilities?.backup_method] || 'unknown';
}
export function selectedNamespaces(value, installed) {
    const selected = value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (selected.some(s => !/^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(s) || s.length > 63) || new Set(selected).size !== selected.length) throw new Error('agents.scope_invalid');
    if (!Array.isArray(installed) || selected.some(s => !installed.includes(s))) throw new Error('agents.scope_outside');
    return selected;
}
