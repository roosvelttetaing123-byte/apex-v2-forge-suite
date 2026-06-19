/**
 * Forge Suite v5 APEX — Module Progress Panel
 */
const ForgeModules = (() => {
    let modules = {};

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function update(moduleData) {
        modules = moduleData || {};
        render();
    }

    function render() {
        const container = document.getElementById('modules-list');
        const summary = document.getElementById('modules-summary');
        if (!container) return;

        const entries = Object.values(modules);
        if (entries.length === 0) {
            container.innerHTML = '<div class="empty-state">Waiting for scan to start...</div>';
            if (summary) summary.textContent = '0/0 complete';
            return;
        }

        // Sort by phase, then status (running first)
        const statusOrder = { running: 0, queued: 1, complete: 2, failed: 3, skipped: 4 };
        entries.sort((a, b) => {
            if (a.phase !== b.phase) return (a.phase || 0) - (b.phase || 0);
            return (statusOrder[a.status] || 5) - (statusOrder[b.status] || 5);
        });

        const statusIcons = {
            queued: '⏳', running: '🔄', complete: '✅', failed: '❌', skipped: '⏭',
        };

        container.innerHTML = entries.map(m => {
            const icon = statusIcons[m.status] || '⏳';
            const pct = m.progress_pct || (m.status === 'complete' ? 100 : 0);
            const dur = m.duration ? m.duration.toFixed(1) + 's' : '—';
            const findings = m.findings_count || 0;

            return `
                <div class="module-item">
                    <span class="module-item__status" title="${m.status}">${icon}</span>
                    <span class="module-item__name">${escapeHtml(m.name)}</span>
                    <div class="module-item__progress">
                        <div class="progress-bar">
                            <div class="progress-bar__fill" style="width:${pct}%"></div>
                        </div>
                    </div>
                    <span class="module-item__duration">${dur}</span>
                    <span class="module-item__findings">${findings > 0 ? findings : ''}</span>
                </div>
            `;
        }).join('');

        // Summary
        const complete = entries.filter(m => m.status === 'complete').length;
        const total = entries.length;
        if (summary) summary.textContent = `${complete}/${total} complete`;

        // Metrics panel
        const metricModules = document.getElementById('metric-modules');
        if (metricModules) metricModules.textContent = `${complete}/${total}`;
    }

    return { update, render };
})();
