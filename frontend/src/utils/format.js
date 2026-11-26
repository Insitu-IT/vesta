/**
 * Shared formatting utilities for vnbui frontend.
 * Single source of truth — all pages import from here instead of defining their own.
 */

const ACRONYMS = new Set(['oidc', 'vm', 'api', 's3', 'mtls', 'pki', 'kms', 'ip', 'sso', 'ca', 'csr', 'dek', 'kek', 'uuid']);

/**
 * Format a date as a human-readable relative time string (i18n-aware).
 * Examples: "just now", "3 minutes ago", "1 day ago", "14 days ago"
 */
export function formatRelativeTime(date) {
    if (!date) return '';
    const t = window.t;
    const now = new Date();
    const then = new Date(date);
    const diffMs = now - then;

    // Future dates (e.g. "next run" in schedules)
    if (diffMs < 0) {
        const futureMins = Math.floor(-diffMs / 60000);
        const futureHours = Math.floor(-diffMs / 3600000);
        const futureDays = Math.floor(-diffMs / 86400000);
        if (futureMins < 1) return t('time.just_now');
        if (futureMins < 60) return t('time.in_minutes', { count: futureMins });
        if (futureHours < 24) return t('time.in_hours', { count: futureHours });
        return t('time.in_days', { count: futureDays });
    }

    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return t('time.just_now');
    if (diffMins < 60) return t('time.minutes_ago', { count: diffMins });
    if (diffHours < 24) return t('time.hours_ago', { count: diffHours });
    return t('time.days_ago', { count: diffDays });
}

/**
 * Format a date as a compact relative time string (i18n-aware).
 * Used by activity and notifications pages for dense lists.
 * Examples: "now", "3m", "2h", "5d", "2w"
 */
export function formatRelativeTimeCompact(date) {
    if (!date) return '';
    const t = window.t;
    const now = new Date();
    const then = new Date(date);
    const diffMs = now - then;
    if (diffMs < 0) return t('time.compact_now');

    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    const diffWeeks = Math.floor(diffDays / 7);

    if (diffMins < 1) return t('time.compact_now');
    if (diffMins < 60) return t('time.compact_minutes', { count: diffMins });
    if (diffHours < 24) return t('time.compact_hours', { count: diffHours });
    if (diffDays < 14) return t('time.compact_days', { count: diffDays });
    return t('time.compact_weeks', { count: diffWeeks });
}

/**
 * Format a date as an absolute time string.
 * Today shows time only; older dates show "dd Mon HH:mm:ss".
 */
export function formatAbsoluteTime(date) {
    if (!date) return '';
    const d = new Date(date);
    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();
    const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    if (isToday) return time;
    const dateStr = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
    return `${dateStr} ${time}`;
}

/**
 * Format a date using the browser's locale.
 * Returns "N/A" (translated) for null/undefined dates.
 */
export function formatDate(date) {
    if (!date) return window.t('common.na');
    return new Date(date).toLocaleString();
}

/**
 * Format byte count as human-readable file size.
 * Returns "N/A" (translated) for null/zero/undefined values.
 */
export function formatSize(bytes) {
    if (!bytes) return window.t('common.na');
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Convert snake_case event type to display string with acronym handling.
 * Examples: "oidc_login" → "OIDC Login", "backup_created" → "Backup Created"
 */
export function formatEventType(eventType) {
    if (!eventType) return 'Activity';
    return eventType
        .split('_')
        .map(word => ACRONYMS.has(word.toLowerCase()) ? word.toUpperCase() : word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

/**
 * Strip ANSI escape codes from a string.
 * virtnbdbackup output contains terminal color codes that shouldn't be displayed in the UI.
 */
export function stripAnsi(text) {
    if (!text) return '';
    return text.replace(/\u001b\[[0-9;]*m/g, '');
}
