/**
 * Forge Suite v5 APEX — C2 Sessions Panel
 */
const ForgeSessions = (() => {
    let sessions = [];

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function update(sessionData) {
        sessions = sessionData || [];
        render();
    }

    function addSession(session) {
        sessions.push(session);
        render();
        ForgeNotify.shell(session.target, session.access_level);
        const badge = document.getElementById('tab-sessions-count');
        if (badge) badge.textContent = sessions.length;
    }

    function render() {
        const container = document.getElementById('c2-beacons');
        if (!container) return;

        if (sessions.length === 0) {
            container.innerHTML = '<div class="empty-state">No active beacons. Start a C2 listener to receive callbacks.</div>';
            return;
        }

        container.innerHTML = sessions.map(s => `
            <div class="target-card target-card--shell" style="margin-bottom:8px;cursor:pointer;" onclick="ForgeSessions.interact(${s.session_id})">
                <div class="target-card__header">
                    <span class="target-card__status">💀</span>
                    <span class="target-card__ip">${escapeHtml(s.target)}</span>
                    <span class="badge badge--critical">${escapeHtml(s.access_level)}</span>
                </div>
                <div class="target-card__details">
                    <span class="target-card__tag">Session #${s.session_id}</span>
                    <span class="target-card__tag">${escapeHtml(s.shell_type)}</span>
                    <span class="target-card__tag">${escapeHtml(s.module)}</span>
                    <span class="target-card__tag">${s.established ? new Date(s.established).toLocaleTimeString() : ''}</span>
                </div>
            </div>
        `).join('');

        const badge = document.getElementById('tab-sessions-count');
        if (badge) badge.textContent = sessions.length;
    }

    function interact(sessionId) {
        const consoleEl = document.getElementById('c2-console');
        const header = document.getElementById('console-header');
        const prompt = document.getElementById('console-prompt');
        if (!consoleEl) return;

        const session = sessions.find(s => s.session_id === sessionId);
        if (!session) return;

        consoleEl.style.display = 'flex';
        if (header) header.textContent = `Beacon #${sessionId} — ${session.target} (${session.access_level})`;
        if (prompt) prompt.textContent = `[${sessionId}/${session.target}]>`;

        // Focus input
        const input = document.getElementById('console-input');
        if (input) input.focus();
    }

    return { update, addSession, interact };
})();
