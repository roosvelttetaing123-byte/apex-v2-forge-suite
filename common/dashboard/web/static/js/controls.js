/**
 * Forge Suite v5 APEX — Scan Controls (Pause/Resume/Abort)
 */
const ForgeControls = (() => {
    let isPaused = false;
    const API_BASE = '';

    function init() {
        const pauseBtn = document.getElementById('btn-pause');
        const resumeBtn = document.getElementById('btn-resume');
        const abortBtn = document.getElementById('btn-abort');

        if (pauseBtn) pauseBtn.addEventListener('click', pause);
        if (resumeBtn) resumeBtn.addEventListener('click', resume);
        if (abortBtn) abortBtn.addEventListener('click', abort);
    }

    async function apiPost(endpoint) {
        const token = localStorage.getItem('forge_token');
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        try {
            const res = await fetch(`${API_BASE}/api/v1/control/${endpoint}`, {
                method: 'POST', headers,
            });
            return await res.json();
        } catch (e) {
            console.error(`Control ${endpoint} failed:`, e);
            return null;
        }
    }

    async function pause() {
        const result = await apiPost('pause');
        if (result) {
            isPaused = true;
            updateButtons();
            updateScanStatus('paused', 'PAUSED');
            ForgeNotify.show({ title: 'Scan Paused', type: 'info', icon: '⏸' });
        }
    }

    async function resume() {
        const result = await apiPost('resume');
        if (result) {
            isPaused = false;
            updateButtons();
            updateScanStatus('running', 'RUNNING');
            ForgeNotify.show({ title: 'Scan Resumed', type: 'success', icon: '▶' });
        }
    }

    async function abort() {
        if (!confirm('Are you sure you want to abort the scan? This cannot be undone.')) return;
        const result = await apiPost('abort');
        if (result) {
            updateScanStatus('failed', 'ABORTED');
            ForgeNotify.show({ title: 'Scan Aborted', type: 'critical', icon: '⏹' });
        }
    }

    function updateButtons() {
        const pauseBtn = document.getElementById('btn-pause');
        const resumeBtn = document.getElementById('btn-resume');
        if (pauseBtn) pauseBtn.style.display = isPaused ? 'none' : 'flex';
        if (resumeBtn) resumeBtn.style.display = isPaused ? 'flex' : 'none';
    }

    function updateScanStatus(status, text) {
        const indicator = document.getElementById('scan-status-indicator');
        const textEl = document.getElementById('scan-status-text');
        if (indicator) {
            indicator.className = 'status-dot';
            const classMap = {
                running: 'status-dot--running', paused: 'status-dot--paused',
                completed: 'status-dot--complete', failed: 'status-dot--failed',
                initializing: 'status-dot--initializing',
            };
            indicator.classList.add(classMap[status] || 'status-dot--queued');
        }
        if (textEl) textEl.textContent = text || status.toUpperCase();
    }

    document.addEventListener('DOMContentLoaded', init);

    return { pause, resume, abort, updateScanStatus, updateButtons };
})();
