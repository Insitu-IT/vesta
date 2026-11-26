/**
 * Centralized version management for vnbui frontend
 * Version is imported from package.json at build time
 */

// Vite automatically replaces import.meta.env variables at build time
const version = import.meta.env.VITE_VERSION || '2.4.0';
const buildDate = import.meta.env.VITE_BUILD_DATE || new Date().toISOString().split('T')[0];

export function getVersion() {
    return version;
}

export function getBuildDate() {
    return buildDate;
}

export function getVersionInfo() {
    return {
        version: version,
        service: 'vesta-frontend',
        build_date: buildDate,
        framework: 'Vite + Tabler UI'
    };
}
