/**
 * Forge Suite v5 APEX — Main Application
 * Wires all dashboard panels to the WebSocket event stream.
 */
const ForgeApp = (() => {
    let startTime = null;
    let elapsedTimer = null;
    let rpsChart = null;
    let lastRequestCount = 0;
    let currentState = {};

    function init() {
        console.log('[Forge] War Room initializing...');
        setupTabs();
        setupThemeSwitcher();
        setupWebSocket();
        rpsChart = ForgeCharts.createRpsChart();

        // Start elapsed time ticker
        elapsedTimer = setInterval(updateElapsedTime, 1000);
        // RPS chart ticker
        setInterval(updateRpsChart, 1000);
        // Auto-refresh state every 4s to catch events missed at connect time
        setInterval(() => { if (ForgeWS.isConnected()) ForgeWS.requestState(); }, 4000);
    }

    function setupWebSocket() {
        // Subscribe to events
        ForgeWS.subscribe('state_snapshot', handleStateSnapshot);
        ForgeWS.subscribe('event', handleEvent);
        ForgeWS.subscribe('pong', () => {});

        ForgeWS.onConnected = () => {
            ForgeNotify.show({ title: 'Connected', message: 'Dashboard live', type: 'success', duration: 3000 });
        };
        ForgeWS.onDisconnected = () => {
            ForgeNotify.show({ title: 'Disconnected', message: 'Reconnecting...', type: 'critical', duration: 4000 });
        };

        // Connect (no auth for now if auth is disabled on server)
        ForgeWS.connect();
    }

    function handleStateSnapshot(msg) {
        const state = msg.data || msg;
        currentState = state;

        // Engagement info
        setText('engagement-name', state.engagement || 'Engagement');
        setText('engagement-target', state.target || '—');
        setText('engagement-framework', state.framework || '—');

        // Scan status
        ForgeControls.updateScanStatus(state.scan_status || 'initializing', (state.scan_status || 'INIT').toUpperCase());

        // OpSec level
        const opsecLevel = state.scan_mode || 'normal';
        const opsecText = document.getElementById('opsec-level');
        const opsecDot = document.querySelector('.opsec-indicator__dot');
        if (opsecText) opsecText.textContent = opsecLevel.toUpperCase();
        if (opsecDot) {
            opsecDot.className = 'opsec-indicator__dot opsec--' + opsecLevel;
        }

        // Findings
        if (state.findings) {
            ForgeFindings.updateRecentList(state.findings);
            ForgeFindings.updateTable(state.findings);
            ForgeFindings.updateSeverityCounts();
        }

        // Modules
        if (state.modules) ForgeModules.update(state.modules);

        // Targets
        if (state.targets) ForgeTargets.update(state.targets);

        // Credentials
        if (state.credentials) ForgeCredentials.update(state.credentials);

        // Sessions
        if (state.sessions) ForgeSessions.update(state.sessions);

        // Kill chain
        if (state.kill_chain) ForgeKillChain.update(state.kill_chain);

        // Timeline
        if (state.timeline) ForgeTimeline.update(state.timeline);

        // Metrics
        if (state.metrics) updateMetrics(state.metrics);

        // Track start time for elapsed
        if (state.scan_status === 'running' && !startTime) {
            startTime = Date.now();
        }

        console.log('[Forge] State snapshot applied');
    }

    function handleEvent(msg) {
        const eventType = msg.event_type;
        const data = msg.data || {};

        switch (eventType) {
            case 'finding_new':
                ForgeFindings.addFinding(data);
                break;
            case 'credential_found':
                ForgeCredentials.addCredential(data);
                break;
            case 'shell_session':
                ForgeSessions.addSession(data);
                break;
            case 'target_discovered':
            case 'target_pwned':
                ForgeTargets.addTarget(data);
                break;
            case 'module_start':
            case 'module_progress':
            case 'module_complete':
            case 'module_fail':
            case 'module_skip':
                // Request fresh state for module updates
                ForgeWS.requestState();
                break;
            case 'scan_start':
                startTime = Date.now();
                ForgeControls.updateScanStatus('running', 'RUNNING');
                ForgeNotify.show({ title: 'Scan Started', type: 'success', icon: '🚀' });
                break;
            case 'scan_complete':
                ForgeControls.updateScanStatus('completed', 'COMPLETED');
                ForgeNotify.show({ title: 'Scan Complete', type: 'success', icon: '🏁', duration: 0 });
                break;
            case 'scan_paused':
                ForgeControls.updateScanStatus('paused', 'PAUSED');
                break;
            case 'scan_resumed':
                ForgeControls.updateScanStatus('running', 'RUNNING');
                break;
            case 'scan_aborted':
                ForgeControls.updateScanStatus('failed', 'ABORTED');
                break;
            case 'beacon_new':
                ForgeNotify.show({ title: 'New Beacon!', message: `${data.hostname || data.target}`, type: 'critical', icon: '💀', duration: 10000 });
                break;
            case 'request_sent':
                lastRequestCount++;
                break;
        }

        // Add to timeline
        if (['finding_new', 'scan_start', 'scan_complete', 'credential_found',
             'target_pwned', 'shell_session', 'module_fail', 'beacon_new'].includes(eventType)) {
            ForgeTimeline.addEvent({
                time: msg.timestamp || new Date().toISOString(),
                type: eventType,
                message: data.title || data.message || eventType,
                source: msg.source || '',
            });
        }
    }

    function updateMetrics(metrics) {
        setText('metric-requests', metrics.total_requests || 0);
        setText('metric-rps', (metrics.requests_per_second || 0).toFixed(1));
        setText('metric-errors', metrics.total_errors || 0);
        setText('metric-waf', metrics.waf_blocks || 0);
        setText('metric-bandwidth', formatBytes(metrics.bytes_in || 0));
    }

    function updateRpsChart() {
        if (!rpsChart) return;
        // Calculate RPS from request count delta
        const rps = lastRequestCount;
        lastRequestCount = 0;
        rpsChart.push(rps);
        setText('metric-rps', rps.toFixed(1));
    }

    function updateElapsedTime() {
        if (!startTime) return;
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const h = Math.floor(elapsed / 3600).toString().padStart(2, '0');
        const m = Math.floor((elapsed % 3600) / 60).toString().padStart(2, '0');
        const s = (elapsed % 60).toString().padStart(2, '0');
        setText('elapsed-time-value', `${h}:${m}:${s}`);
    }

    function setupTabs() {
        const tabBtns = document.querySelectorAll('.tab-nav__btn');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tabName = btn.dataset.tab;
                // Deactivate all
                tabBtns.forEach(b => b.classList.remove('tab-nav__btn--active'));
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('tab-panel--active'));
                // Activate selected
                btn.classList.add('tab-nav__btn--active');
                const panel = document.getElementById('tab-' + tabName);
                if (panel) panel.classList.add('tab-panel--active');

                // Re-render on tab switch for table
                if (tabName === 'findings') ForgeFindings.renderFilteredTable();
            });
        });
    }

    function setupThemeSwitcher() {
        const themes = ['hacker-dark', 'professional-dark', 'light'];
        let themeIdx = 0;
        const btn = document.getElementById('btn-theme');
        if (btn) {
            btn.addEventListener('click', () => {
                themeIdx = (themeIdx + 1) % themes.length;
                document.documentElement.setAttribute('data-theme', themes[themeIdx]);
                localStorage.setItem('forge_theme', themes[themeIdx]);
                // Update chart colors after theme change
                if (rpsChart) {
                    rpsChart.lineColor = getComputedStyle(document.documentElement).getPropertyValue('--chart-line').trim();
                    rpsChart.fillColor = getComputedStyle(document.documentElement).getPropertyValue('--chart-fill').trim();
                    rpsChart.gridColor = getComputedStyle(document.documentElement).getPropertyValue('--chart-grid').trim();
                    rpsChart.textColor = getComputedStyle(document.documentElement).getPropertyValue('--text-tertiary').trim();
                    rpsChart.render();
                }
            });
        }
        // Restore saved theme
        const saved = localStorage.getItem('forge_theme');
        if (saved && themes.includes(saved)) {
            document.documentElement.setAttribute('data-theme', saved);
            themeIdx = themes.indexOf(saved);
        }
    }

    function setText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    }

    document.addEventListener('DOMContentLoaded', init);

    return { init, handleStateSnapshot, handleEvent };
})();



// === CYBER RAIN & LIGHTNING EFFECT ===
function initCyberRain() {
    const canvas = document.getElementById('rainCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let width, height;
    let particles = [];
    
    function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }
    
    window.addEventListener('resize', resize);
    resize();
    
    for(let i = 0; i < 150; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            length: Math.random() * 20 + 10,
            speed: Math.random() * 10 + 15,
            opacity: Math.random() * 0.5 + 0.1
        });
    }
    
    let lightningTimer = 0;
    
    function draw() {
        ctx.clearRect(0, 0, width, height);
        
        // Draw Rain
        ctx.lineWidth = 1;
        ctx.lineCap = 'round';
        for(let i = 0; i < particles.length; i++) {
            let p = particles[i];
            ctx.strokeStyle = 
gba(255, 149, 0, ); // Neon orange rain
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p.x + p.speed * 0.2, p.y + p.length);
            ctx.stroke();
            
            p.y += p.speed;
            p.x += p.speed * 0.2; // Slight angle
            
            if (p.y > height) {
                p.y = -p.length;
                p.x = Math.random() * width;
            }
        }
        
        // Lightning Effect
        if (Math.random() < 0.005) { // 0.5% chance per frame
            lightningTimer = 10;
        }
        
        if (lightningTimer > 0) {
            ctx.fillStyle = 
gba(255, 255, 255, );
            ctx.fillRect(0, 0, width, height);
            lightningTimer--;
        }
        
        requestAnimationFrame(draw);
    }
    
    draw();
}

document.addEventListener('DOMContentLoaded', initCyberRain);
