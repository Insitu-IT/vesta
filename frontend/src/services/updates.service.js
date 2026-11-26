/**
 * Real-time updates service with WebSocket + polling fallback
 * Handles enterprise environments where WebSocket may be blocked
 *
 * Implements architecture from REALTIME_UPDATES_IMPLEMENTATION.md
 */
import { apiClient } from '../api/client.js';
import { authService } from './auth.service.js';

class UpdateService {
    constructor() {
        this.ws = null;
        this.pollingInterval = null;
        this.connectionMode = 'initializing'; // initializing, websocket, polling, disconnected
        this.subscribers = new Map(); // event -> Set of callbacks
        this.config = {
            wsReconnectDelay: 5000,
            wsMaxReconnectAttempts: 3,
            pollingInterval: 5000, // 5 seconds default
            enableWebSocket: true,
            enablePolling: true,
        };
        this.cursor = null;
        this.pollInFlight = null;
        this.pollRequested = false;
        this.resyncSubscribers = new Set();
        this.reconnectAttempts = 0;
        this.active = false;
        this.generation = 0;
        this.initialization = null;
        this.sessionToken = null;
        this.reconnectTimer = null;
        this.healthInterval = null;
        this.cancelConnectionWait = null;
    }

    /**
     * Initialize real-time updates
     */
    initialize() {
        const token = authService.getToken();
        if (!token) return Promise.resolve();
        if (this.active && this.sessionToken === token) return this.initialization;
        if (this.active || this.initialization) this.destroy();
        this.active = true;
        this.sessionToken = token;
        const generation = this.generation;
        this.initialization = this.initializeSession(generation);
        return this.initialization;
    }

    async initializeSession(generation) {
        await this.loadConfig(generation);
        if (!this.active || generation !== this.generation) return;
        if (this.config.enableWebSocket) await this.connectWebSocket();
        if (!this.active || generation !== this.generation) return;
        if (this.config.enablePolling) {
            if (this.connectionMode !== 'websocket') this.connectionMode = 'polling';
            this.startPolling();
        }
        this.startHealthCheck();
    }

    /**
     * Connect to WebSocket with automatic fallback
     */
    async connectWebSocket() {
        if (!this.active || this.ws) return;
        const generation = this.generation;
        const token = authService.getToken();
        if (!token) return;
        let socket;
        try {
            socket = new WebSocket(this.getWebSocketUrl(), ['vnbui', `bearer.${token}`]);
        } catch {
            this.handleConnectionFailure();
            return;
        }
        this.ws = socket;
        await new Promise(resolve => {
            let settled = false, failed = false;
            const finish = () => {
                clearTimeout(timer);
                if (this.cancelConnectionWait === cancel) this.cancelConnectionWait = null;
                if (!settled) { settled = true; resolve(); }
            };
            const cancel = () => finish();
            const fail = () => {
                if (failed || !this.active || generation !== this.generation || this.ws !== socket) return;
                failed = true;
                socket.onopen = socket.onclose = socket.onerror = socket.onmessage = null;
                this.ws = null;
                socket.close();
                this.connectionMode = 'disconnected';
                finish();
                this.handleConnectionFailure();
            };
            const timer = setTimeout(fail, 5000);
            this.cancelConnectionWait = cancel;
            socket.onopen = () => {
                if (!this.active || generation !== this.generation || this.ws !== socket) return;
                finish();
                this.connectionMode = 'websocket';
                this.reconnectAttempts = 0;
                if (this.config.enablePolling) this.startPolling();
                this.notifySubscribers('connection', { mode: 'websocket', status: 'connected' });
            };
            socket.onmessage = event => {
                if (!this.active || generation !== this.generation || this.ws !== socket) return;
                // Socket delivery is a best-effort hint, never a cursor source.
                // Plain pong/ack messages need no event parsing.
                if (event.data !== 'pong') this.poll();
            };
            socket.onerror = fail;
            socket.onclose = fail;
        });
    }

    /**
     * Handle WebSocket connection failure
     */
    handleConnectionFailure() {
        if (!this.active || this.reconnectTimer) return;
        this.reconnectAttempts++;
        // Keep reads live during retries after an established socket is lost.
        if (this.config.enablePolling) {
            this.connectionMode = 'polling';
            this.startPolling();
        }

        if (this.reconnectAttempts < this.config.wsMaxReconnectAttempts) {
            // Try reconnecting
            console.log(`WebSocket reconnect attempt ${this.reconnectAttempts}/${this.config.wsMaxReconnectAttempts}`);
            this.reconnectTimer = setTimeout(() => {
                this.reconnectTimer = null;
                this.connectWebSocket();
            }, this.config.wsReconnectDelay);
        } else {
            // Give up and fall back to polling
            console.log('⚠️  WebSocket failed, falling back to polling');
            this.connectionMode = this.config.enablePolling ? 'polling' : 'disconnected';
            if (this.config.enablePolling) this.startPolling();
            this.notifySubscribers('connection', { mode: this.connectionMode, status: 'fallback' });
        }
    }

    /**
     * Start polling fallback
     */
    startPolling() {
        if (!this.active || !this.config.enablePolling || this.pollingInterval) {
            return; // Already polling
        }

        console.log(`Starting polling (interval: ${this.config.pollingInterval}ms)`);

        // Initial poll
        this.poll();

        // Set up interval
        this.pollingInterval = setInterval(() => {
            this.poll();
        }, this.config.pollingInterval);
    }

    /**
     * Perform single poll request
     */
    poll() {
        if (!this.active) return Promise.resolve();
        if (this.pollInFlight) {
            this.pollRequested = true;
            return this.pollInFlight;
        }
        const generation = this.generation;
        const pending = this.pollPages(generation).catch(error => {
            console.error('Polling failed:', error);
        }).finally(() => {
            // An older session must never clear a new session's in-flight read.
            if (this.pollInFlight !== pending) return;
            this.pollInFlight = null;
            if (this.pollRequested && this.active && generation === this.generation) {
                this.pollRequested = false;
                this.poll();
            }
        });
        this.pollInFlight = pending;
        return pending;
    }

    async pollPages(generation) {
        // Bound each drain so an endlessly busy feed cannot monopolize the UI.
        for (let page = 0; page < 20; page++) {
            const params = {contract: '2', limit: '100'};
            if (this.cursor) params.cursor = this.cursor;
            const updates = await apiClient.get(`/api/v1/updates?${new URLSearchParams(params)}`);
            if (!this.active || generation !== this.generation) return;
            if (!updates || !Array.isArray(updates.items) || typeof updates.next_cursor !== 'string' ||
                !updates.next_cursor || typeof updates.has_more !== 'boolean' ||
                typeof updates.reset_required !== 'boolean' || updates.delivery !== 'best_effort' ||
                updates.retention_seconds !== 300 ||
                (updates.reset_required && (updates.items.length || updates.has_more || typeof updates.reset_reason !== 'string')) ||
                (!updates.reset_required && updates.reset_reason !== null)) {
                throw new Error('Unsupported realtime cursor contract');
            }
            if (updates.reset_required) {
                this.notifySubscribers('resync_required', {reason: updates.reset_reason});
                // Keep the old cursor until every authoritative read succeeds.
                await Promise.all([...this.resyncSubscribers].map(callback => callback(updates.reset_reason)));
                if (!this.active || generation !== this.generation) return;
                this.cursor = updates.next_cursor;
                // Catch events emitted during the full-state reads.
                continue;
            }
            let prior = -1;
            for (const update of updates.items) {
                if (!update || typeof update.type !== 'string' || !Number.isSafeInteger(update.sequence) || update.sequence <= prior) {
                    throw new Error('Invalid realtime event ordering');
                }
                prior = update.sequence;
            }
            updates.items.forEach(update => this.handleUpdate(update));
            this.cursor = updates.next_cursor;
            if (!updates.has_more) return;
        }
        // A bounded drain leaves the original continuation for the next timer/hint.
    }

    /** Full snapshot callbacks are awaited before accepting a reset boundary. */
    subscribeResync(callback) {
        this.resyncSubscribers.add(callback);
        return () => this.resyncSubscribers.delete(callback);
    }

    handleUpdate(data) {
        const { type, payload } = data;
        this.notifySubscribers(type, payload);
        this.notifySubscribers('*', { type, payload });
    }

    /**
     * Subscribe to updates
     */
    subscribe(eventType, callback) {
        if (!this.subscribers.has(eventType)) {
            this.subscribers.set(eventType, new Set());
        }
        this.subscribers.get(eventType).add(callback);

        // Return unsubscribe function
        return () => {
            const callbacks = this.subscribers.get(eventType);
            if (callbacks) {
                callbacks.delete(callback);
            }
        };
    }

    /**
     * Notify all subscribers for an event
     */
    notifySubscribers(eventType, data) {
        const callbacks = this.subscribers.get(eventType) || new Set();
        callbacks.forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error(`Subscriber error for ${eventType}:`, error);
            }
        });
    }

    /**
     * Stop polling
     */
    stopPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
            console.log('Polling stopped');
        }
    }

    /**
     * Clean up resources
     */
    destroy() {
        this.active = false;
        this.generation++;
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
        if (this.healthInterval) clearInterval(this.healthInterval);
        this.reconnectTimer = this.healthInterval = null;
        if (this.cancelConnectionWait) this.cancelConnectionWait();
        if (this.ws) {
            const socket = this.ws;
            this.ws = null;
            socket.onopen = socket.onclose = socket.onerror = socket.onmessage = null;
            socket.close(1000, 'Service destroyed');
        }
        this.stopPolling();
        this.subscribers.clear();
        this.connectionMode = 'disconnected';
        this.reconnectAttempts = 0;
        this.cursor = null;
        this.pollInFlight = null;
        this.pollRequested = false;
        this.resyncSubscribers.clear();
        this.sessionToken = this.initialization = null;
    }

    /**
     * Get WebSocket URL based on current location
     */
    getWebSocketUrl() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        return `${protocol}//${host}/ws`;
    }

    /**
     * Load configuration from backend
     */
    async loadConfig(generation) {
        try {
            const serverConfig = await apiClient.get('/api/v1/config/realtime');
            if (!this.active || generation !== this.generation) return;

            // Merge with defaults
            this.config = {
                ...this.config,
                ...serverConfig,
            };

            console.log('Loaded real-time config:', this.config);
        } catch (error) {
            console.warn('Failed to load realtime config, using defaults:', error);
        }
    }

    /**
     * Health check for connection
     */
    startHealthCheck() {
        if (!this.active || this.healthInterval) return;
        this.healthInterval = setInterval(() => {
            if (this.connectionMode === 'websocket' && this.ws) {
                // Send ping to keep connection alive
                if (this.ws.readyState === WebSocket.OPEN) {
                    try {
                        this.ws.send('ping');
                    } catch (error) {
                        console.error('Failed to send ping:', error);
                    }
                }
            }
        }, 30000); // Every 30 seconds
    }

    /**
     * Get connection status
     */
    getStatus() {
        return {
            mode: this.connectionMode,
            connected: this.connectionMode === 'websocket' || this.connectionMode === 'polling',
            config: this.config
        };
    }
}

// Export singleton instance
export const updateService = new UpdateService();
