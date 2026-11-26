/**
 * Security utilities for XSS prevention and input sanitization
 */

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} unsafe - Unsafe string that may contain HTML
 * @returns {string} - Escaped safe string
 */
export function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';

    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .replace(/\//g, "&#x2F;");
}

/**
 * Escape HTML attributes
 * @param {string} unsafe - Unsafe attribute value
 * @returns {string} - Escaped attribute value
 */
export function escapeAttr(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';

    return String(unsafe).replace(/["'<>&]/g, function(match) {
        return '&#' + match.charCodeAt(0) + ';';
    });
}

/**
 * Sanitize URL to prevent javascript: and data: schemes
 * @param {string} url - URL to sanitize
 * @returns {string} - Safe URL or empty string
 */
export function sanitizeUrl(url) {
    if (!url) return '';

    const trimmed = url.trim().toLowerCase();

    // Block dangerous protocols
    const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
    for (const protocol of dangerousProtocols) {
        if (trimmed.startsWith(protocol)) {
            console.warn('Blocked dangerous URL protocol:', protocol);
            return '';
        }
    }

    return url;
}

/**
 * Strip HTML tags from string
 * @param {string} html - HTML string
 * @returns {string} - Plain text without HTML tags
 */
export function stripHtml(html) {
    if (!html) return '';

    // Create a temporary div element
    const tmp = document.createElement('div');
    tmp.textContent = html;

    return tmp.textContent || tmp.innerText || '';
}

/**
 * Safely set innerHTML with sanitization
 * WARNING: Use sparingly, prefer textContent or escapeHtml
 * @param {HTMLElement} element - Target element
 * @param {string} html - HTML to set
 */
export function safeSetInnerHTML(element, html) {
    // Basic sanitization - remove script tags and event handlers
    const sanitized = html
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
        .replace(/on\w+\s*=\s*[^\s>]*/gi, '');

    element.innerHTML = sanitized;
}

/**
 * Validate and sanitize user input
 * @param {string} input - User input
 * @param {object} options - Validation options
 * @returns {string} - Sanitized input
 */
export function sanitizeInput(input, options = {}) {
    if (!input) return '';

    const {
        maxLength = 1000,
        allowNewlines = false,
        allowHtml = false
    } = options;

    let sanitized = String(input);

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Remove control characters except newlines/tabs
    if (!allowNewlines) {
        sanitized = sanitized.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
    } else {
        sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
    }

    // Escape HTML if not allowed
    if (!allowHtml) {
        sanitized = escapeHtml(sanitized);
    }

    // Truncate to max length
    if (sanitized.length > maxLength) {
        sanitized = sanitized.substring(0, maxLength);
    }

    return sanitized;
}

/**
 * Create a safe text node (preferred over innerHTML)
 * @param {string} text - Text content
 * @returns {Text} - Text node
 */
export function createSafeTextNode(text) {
    return document.createTextNode(text || '');
}

/**
 * Safely append text to element
 * @param {HTMLElement} element - Target element
 * @param {string} text - Text to append
 */
export function safeAppendText(element, text) {
    element.appendChild(createSafeTextNode(text));
}

/**
 * Validate JSON to prevent injection
 * @param {string} jsonString - JSON string
 * @returns {object|null} - Parsed object or null if invalid
 */
export function safeJsonParse(jsonString) {
    try {
        return JSON.parse(jsonString);
    } catch (e) {
        console.error('Invalid JSON:', e);
        return null;
    }
}

/**
 * Content Security Policy helper
 * @returns {boolean} - Whether CSP is supported
 */
export function isCspSupported() {
    return 'SecurityPolicyViolationEvent' in window;
}

/**
 * Report CSP violations
 */
export function setupCspReporting() {
    if (isCspSupported()) {
        document.addEventListener('securitypolicyviolation', (e) => {
            console.error('CSP Violation:', {
                violatedDirective: e.violatedDirective,
                blockedURI: e.blockedURI,
                sourceFile: e.sourceFile,
                lineNumber: e.lineNumber
            });
        });
    }
}
