import { apiClient } from '../api/client.js';

/** Read a paginated snapshot or fail explicitly rather than truncate it. */
export async function loadSnapshot(path, {pageSize = 100, maxPages = 1000} = {}) {
    const result = new Map();
    for (let page = 0; page < maxPages; page++) {
        const separator = path.includes('?') ? '&' : '?';
        const data = await apiClient.get(`${path}${separator}limit=${pageSize}&skip=${page * pageSize}`);
        const items = data.items || data.backups || data.restores;
        if (!Array.isArray(items)) throw new Error('Invalid snapshot list');
        items.forEach(item => result.set(item.id, item));
        if (data.has_more === false || (data.has_more === undefined && items.length < pageSize)) return [...result.values()];
        if (!items.length) throw new Error('Snapshot pagination made no progress');
    }
    throw new Error('Snapshot exceeds the supported page limit; refresh with a narrower filter');
}
