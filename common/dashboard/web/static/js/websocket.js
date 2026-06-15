/**
 * Forge Suite v5 APEX — WebSocket Client
 * Handles connection, reconnection, authentication, and message dispatch.
 */
const ForgeWS = (() => {
    let ws = null;
    let reconnectAttempts = 0;
    const MAX_RECONNECT = 20;
    const RECONNECT_BASE_MS = 1000;
    const subscribers = {};
    let authToken = null;
    let onConnected = null;
    let onDisconnected = null;

    function getWsUrl() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${proto}//${location.host}/ws/dashboard`;
    }

    function connect(token) {
        authToken = token || localStorage.getItem('forge_token');
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            return;
        }
        try {
            ws = new WebSocket(getWsUrl());
        } catch (e) {
            console.error('[WS] Connection failed:', e);
            scheduleReconnect();
            return;
        }

        ws.onopen = () => {
            console.log('[WS] Connected');
            reconnectAttempts = 0;
            updateStatusDot('connected');
            // Send auth token
            if (authToken) {
                ws.send(JSON.stringify({ token: authToken }));
            }
            if (onConnected) onConnected();
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                dispatch(msg);
            } catch (e) {
                console.warn('[WS] Bad message:', e);
            }
        };

        ws.onclose = (event) => {
            console.log('[WS] Disconnected (code:', event.code, ')');
            updateStatusDot('disconnected');
            if (onDisconnected) onDisconnected();
            if (event.code !== 4001) { // 4001 = auth failure, don't reconnect
                scheduleReconnect();
            }
        };

        ws.onerror = (error) => {
            console.error('[WS] Error:', error);
        };
    }

    function disconnect() {
        if (ws) {
            ws.close(1000, 'Client disconnect');
            ws = null;
        }
    }

    function send(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(typeof data === 'string' ? data : JSON.stringify(data));
        }
    }

    function ping() {
        send({ action: 'ping' });
    }

    function requestState() {
        send({ action: 'get_state' });
    }

    function scheduleReconnect() {
        if (reconnectAttempts >= MAX_RECONNECT) {
            console.error('[WS] Max reconnect attempts reached');
            return;
        }
        const delay = Math.min(RECONNECT_BASE_MS * Math.pow(1.5, reconnectAttempts), 30000);
        reconnectAttempts++;
        console.log(`[WS] Reconnecting in ${(delay / 1000).toFixed(1)}s (attempt ${reconnectAttempts})`);
        setTimeout(() => connect(authToken), delay);
    }

    function subscribe(eventType, callback) {
        if (!subscribers[eventType]) subscribers[eventType] = [];
        subscribers[eventType].push(callback);
    }

    function unsubscribe(eventType, callback) {
        if (subscribers[eventType]) {
            subscribers[eventType] = subscribers[eventType].filter(cb => cb !== callback);
        }
    }

    function dispatch(msg) {
        const type = msg.type || msg.event_type;
        // Dispatch to specific type subscribers
        if (subscribers[type]) {
            subscribers[type].forEach(cb => {
                try { cb(msg); } catch (e) { console.error('[WS] Subscriber error:', e); }
            });
        }
        // Dispatch to wildcard subscribers
        if (subscribers['*']) {
            subscribers['*'].forEach(cb => {
                try { cb(msg); } catch (e) { console.error('[WS] Wildcard subscriber error:', e); }
            });
        }
    }

    function updateStatusDot(status) {
        const dot = document.getElementById('ws-status');
        if (dot) {
            dot.className = 'status-dot status-dot--' + status;
            dot.title = 'WebSocket: ' + status;
        }
    }

    function isConnected() {
        return ws && ws.readyState === WebSocket.OPEN;
    }

    // Heartbeat to keep connection alive
    setInterval(() => {
        if (isConnected()) ping();
    }, 30000);

    return {
        connect,
        disconnect,
        send,
        ping,
        requestState,
        subscribe,
        unsubscribe,
        isConnected,
        set onConnected(fn) { onConnected = fn; },
        set onDisconnected(fn) { onDisconnected = fn; },
    };
})();
