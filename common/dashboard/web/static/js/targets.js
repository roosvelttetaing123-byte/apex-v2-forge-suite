/**
 * Forge Suite v5 APEX — Targets Panel
 */
const ForgeTargets = (() => {
    let targets = {};

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function update(targetData) {
        targets = targetData || {};
        render();
    }

    function addTarget(target) {
        targets[target.target] = target;
        render();
        // Update tab badge
        const badge = document.getElementById('tab-targets-count');
        if (badge) badge.textContent = Object.keys(targets).length;
    }

    function render() {
        const container = document.getElementById('targets-grid');
        if (!container) return;

        const entries = Object.values(targets);
        if (entries.length === 0) {
            container.innerHTML = '<div class="empty-state">No targets discovered yet...</div>';
            return;
        }

        container.innerHTML = entries.map(t => {
            const statusIcon = t.shell ? '🔴' : t.pwned ? '🟠' : '🟢';
            const cardClass = t.shell ? 'target-card--shell' : t.pwned ? 'target-card--pwned' : '';
            const accessLabel = t.access_level ? ` (${escapeHtml(t.access_level)})` : '';

            return `
                <div class="target-card ${cardClass}">
                    <div class="target-card__header">
                        <span class="target-card__status">${statusIcon}</span>
                        <span class="target-card__ip">${escapeHtml(t.target)}</span>
                        ${t.shell ? '<span class="badge badge--critical">SHELL</span>' : ''}
                        ${t.pwned && !t.shell ? '<span class="badge badge--high">PWNED</span>' : ''}
                    </div>
                    <div class="target-card__details">
                        ${t.services && t.services.length ? t.services.map(s =>
                            `<span class="target-card__tag">${escapeHtml(s)}</span>`
                        ).join('') : ''}
                        ${t.creds_count ? `<span class="target-card__tag">🔑 ${t.creds_count} creds</span>` : ''}
                        ${t.findings ? `<span class="target-card__tag">📋 ${t.findings} findings</span>` : ''}
                        ${accessLabel ? `<span class="target-card__tag">${escapeHtml(accessLabel)}</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');

        // Update tab badge
        const badge = document.getElementById('tab-targets-count');
        if (badge) badge.textContent = entries.length;
    }

    return { update, addTarget };
})();
