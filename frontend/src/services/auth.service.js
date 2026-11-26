/**
 * Secure authentication service
 */

class AuthService {
    constructor() {
        this.tokenKey = 'auth_token';
        this.userKey = 'current_user';
        this.accessToken = null;  // In-memory storage
        this.verifiedUser = null; // Never restored from browser storage.
    }

    /**
     * Set authentication tokens
     * Uses sessionStorage instead of localStorage for better XSS protection
     * In production, should use httpOnly cookies
     */
    setToken(token) {
        if (typeof window !== 'undefined') window.vnbui?.requestRecovery?.clearSession();
        this.verifiedUser = null;
        this.accessToken = token;

        // Store in sessionStorage (cleared on tab close)
        if (token) {
            sessionStorage.setItem(this.tokenKey, token);
        } else {
            sessionStorage.removeItem(this.tokenKey);
        }
    }

    /**
     * Get current access token
     */
    getToken() {
        return this.accessToken || sessionStorage.getItem(this.tokenKey);
    }

    /**
     * Clear all authentication data
     */
    clearToken() {
        if (typeof window !== 'undefined') window.vnbui?.requestRecovery?.clearSession();
        if (typeof window !== 'undefined') window.vnbui?.updates?.destroy();
        this.accessToken = null;
        this.verifiedUser = null;
        sessionStorage.removeItem(this.tokenKey);
        sessionStorage.removeItem(this.userKey);
        if (typeof localStorage !== 'undefined') localStorage.removeItem(this.userKey);
    }

    /**
     * Set current user data
     */
    setUser(user) {
        this.verifiedUser = null;
        if (typeof localStorage !== 'undefined') localStorage.removeItem(this.userKey);
        if (user) {
            sessionStorage.setItem(this.userKey, JSON.stringify(user));
        } else {
            sessionStorage.removeItem(this.userKey);
        }
    }

    /**
     * Get current user data
     */
    getUser() {
        const userJson = sessionStorage.getItem(this.userKey);
        if (!userJson) return null;

        try {
            return JSON.parse(userJson);
        } catch (e) {
            this.clearToken();
            return null;
        }
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.getToken();
    }

    /**
     * Check if user has specific role
     */
    hasRole(role) {
        const user = this.getUser();
        return user && user.role === role;
    }

    /**
     * Check if user has any of the specified roles
     */
    hasAnyRole(...roles) {
        const user = this.getUser();
        return user && roles.includes(user.role);
    }

    /**
     * Login with username and password
     */
    async login(username, password, organizationId = '') {
        try {
            // This selects the credential namespace, never user authority.
            // Omit it for OSS; the server resolves the persisted default.
            const body = new URLSearchParams({ username, password });
            if (organizationId.trim()) body.set('org_id', organizationId.trim());
            const response = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body
            });

            if (!response.ok) {
                throw new Error('Login failed');
            }

            const data = await response.json();

            // Store token
            this.setToken(data.access_token);

            // Fetch and store user data
            if (!await this.fetchUserData()) {
                throw new Error('Unable to verify signed-in identity');
            }

            return data;
        } catch (error) {
            this.clearToken();
            throw error;
        }
    }

    /**
     * Fetch current user data from API
     */
    async fetchUserData(signal) {
        signal?.throwIfAborted();
        try {
            const response = await fetch('/api/v1/auth/me', {
                signal,
                headers: {
                    'Authorization': `Bearer ${this.getToken()}`
                }
            });

            if (response.ok) {
                const user = await response.json();
                signal?.throwIfAborted();
                this.setUser(user);
                this.verifiedUser = Object.freeze({...user});
                return user;
            }
        } catch (error) { /* Identity could not be verified. */ }
        signal?.throwIfAborted();
        this.clearToken();
        return null;
    }

    canManageInstallation() {
        return this.verifiedUser?.can_manage_installation === true;
    }

    async requireInstallationAccess(signal) {
        // Re-read persisted authority before navigation or an installation call.
        // The backend rechecks independently at the actual operation.
        await this.fetchUserData(signal);
        if (!this.canManageInstallation()) {
            const error = new Error('Installation authority required');
            error.status = 403;
            throw error;
        }
    }

    consumeCallbackFragment() {
        const fragment = new URLSearchParams(window.location.hash.substring(1));
        if (fragment.has('access_token')) {
            // Replace, never append a history entry containing credentials.
            window.history.replaceState(null, '', window.location.pathname + window.location.search);
            this.clearToken();
            const tokens = fragment.getAll('access_token');
            if (tokens.length === 1) this.setToken(tokens[0]);
        }
    }

    async restoreSession() {
        this.consumeCallbackFragment();
        if (!this.getToken() || this.isTokenExpired()) {
            this.clearToken();
            return false;
        }
        return !!await this.fetchUserData();
    }

    /**
     * Refresh access token using current (still-valid) JWT
     */
    async refreshAccessToken() {
        const token = this.getToken();
        if (!token || this.isTokenExpired()) {
            this.clearToken();
            window.location.href = '/login';
            return false;
        }

        try {
            const response = await fetch('/api/v1/auth/refresh', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.setToken(data.access_token);
                if (await this.fetchUserData()) return true;
            }
        } catch (error) {
            // Do not log transport errors that can contain bearer credentials.
        }

        // Refresh failed, clear tokens and redirect to login
        this.clearToken();
        window.location.href = '/login';
        return false;
    }

    /**
     * Logout
     */
    async logout() {
        const token = this.getToken();
        // Stateless JWTs remain valid until expiry; logout removes local custody.
        this.clearToken();
        window.location.replace('/login');
        try {
            // Best-effort acknowledgement only, never server-side revocation.
            await fetch('/api/v1/auth/logout', {
                method: 'POST',
                keepalive: true,
                signal: AbortSignal.timeout(3000),
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        } catch (error) { /* Local logout is independent of the acknowledgement. */ }
    }

    /**
     * Decode JWT token (client-side only for display, never trust!)
     */
    decodeToken(token = null) {
        token = token || this.getToken();
        if (!token) return null;

        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;

            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            return payload;
        } catch (e) {
            return null;
        }
    }

    /**
     * Check if token is expired (client-side check only!)
     */
    isTokenExpired() {
        const payload = this.decodeToken();
        if (!payload || !Number.isFinite(payload.exp)) return true;

        const now = Date.now() / 1000;
        return payload.exp <= now;
    }
}

// Singleton instance
export const authService = new AuthService();
