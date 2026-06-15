/**
 * Forge Suite v5 APEX — Credentials Vault
 */
const ForgeCredentials = (() => {
    let credentials = [];

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function update(creds) {
        credentials = creds || [];
        render();
    }

    function addCredential(cred) {
        credentials.push(cred);
        render();
        ForgeNotify.credential(cred.account, cred.cred_type);
        const badge = document.getElementById('tab-creds-count');
        if (badge) badge.textContent = credentials.length;
    }

    function render() {
        const tbody = document.getElementById('creds-tbody');
        if (!tbody) return;

        if (credentials.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No credentials discovered</td></tr>';
            return;
        }

        tbody.innerHTML = credentials.map(c => `
            <tr>
                <td><span class="badge badge--framework">${escapeHtml(c.cred_type)}</span></td>
                <td><code>${escapeHtml(c.account)}</code></td>
                <td><code style="color:var(--severity-high)">${escapeHtml(c.secret)}</code></td>
                <td><code>${escapeHtml(c.target)}</code></td>
                <td>${escapeHtml(c.discovered_by)}</td>
                <td>${c.timestamp ? new Date(c.timestamp).toLocaleTimeString() : '—'}</td>
            </tr>
        `).join('');

        const badge = document.getElementById('tab-creds-count');
        if (badge) badge.textContent = credentials.length;
    }

    return { update, addCredential };
})();
