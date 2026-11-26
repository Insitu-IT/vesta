#!/usr/bin/env node
/**
 * Extract all frontend API calls and write them to api-calls.json.
 *
 * Scans all .js files under frontend/src/ for:
 * - apiClient.(get|post|put|patch|delete|upload|postForBlob) calls
 * - fetch() calls with /api/ paths
 *
 * Template literals like `${id}` are normalized to `:param`.
 * Output: frontend/api-calls.json
 */
const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname, '..', 'src');
const OUT_FILE = path.join(__dirname, '..', 'api-calls.json');

// Match literal API routes in apiClient methods and injected this.read() callbacks.
const API_CLIENT_RE = /(?:apiClient|this)\.(get|post|put|patch|delete|upload|postForBlob|read)\(\s*[`'"](\/api\/[^`'"]*)[`'"]/g;

// Match fetch(`/api/...`) or fetch('/api/...')
const FETCH_RE = /fetch\(\s*[`'"](\/api\/[^`'"]*)[`'"]/g;

// Normalize template literals: ${anything} → :param
function normalizePath(raw) {
    return raw
        .replace(/\$\{[^}]+\}/g, ':param')
        .replace(/\?.*$/, '');  // Strip query strings
}

// Map apiClient methods to HTTP methods
const METHOD_MAP = {
    get: 'GET',
    read: 'GET',      // Injected read-only operator recovery transport
    post: 'POST',
    put: 'PUT',
    patch: 'PATCH',
    delete: 'DELETE',
    upload: 'POST',      // upload() sends POST with FormData
    postForBlob: 'POST', // postForBlob() sends POST
};

function findJsFiles(dir) {
    const results = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...findJsFiles(fullPath));
        } else if (entry.name.endsWith('.js')) {
            results.push(fullPath);
        }
    }
    return results;
}

const calls = [];
const files = findJsFiles(SRC_DIR);

for (const filePath of files) {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const relPath = path.relative(path.join(__dirname, '..'), filePath);

    // Search line by line for accurate line numbers
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let match;

        // apiClient.method() calls
        const apiRe = new RegExp(API_CLIENT_RE.source, 'g');
        while ((match = apiRe.exec(line)) !== null) {
            const method = METHOD_MAP[match[1]] || match[1].toUpperCase();
            const rawPath = match[2];
            calls.push({
                method,
                path: normalizePath(rawPath),
                file: relPath,
                line: i + 1,
            });
        }

        // fetch() calls — look ahead for method: in nearby lines
        const fetchRe = new RegExp(FETCH_RE.source, 'g');
        while ((match = fetchRe.exec(line)) !== null) {
            // Check next 3 lines for method: 'POST' etc
            let fetchMethod = 'GET';
            const lookAhead = lines.slice(i, Math.min(i + 4, lines.length)).join('\n');
            const methodMatch = lookAhead.match(/method:\s*['"](\w+)['"]/);
            if (methodMatch) {
                fetchMethod = methodMatch[1].toUpperCase();
            }
            calls.push({
                method: fetchMethod,
                path: normalizePath(match[1]),
                file: relPath,
                line: i + 1,
            });
        }
    }
}

// Deduplicate by method+path (keep first occurrence)
const seen = new Set();
const unique = [];
for (const call of calls) {
    const key = `${call.method} ${call.path}`;
    if (!seen.has(key)) {
        seen.add(key);
        unique.push(call);
    }
}

fs.writeFileSync(OUT_FILE, JSON.stringify(unique, null, 2) + '\n');
console.log(`Extracted ${calls.length} API calls (${unique.length} unique) from ${files.length} files`);
console.log(`Written to ${OUT_FILE}`);
