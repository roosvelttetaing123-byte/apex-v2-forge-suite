/**
 * Forge Suite v5 APEX — Findings Panel
 */
const ForgeFindings = (() => {
    let allFindings = [];

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function updateRecentList(findings) {
        allFindings = findings || [];
        const container = document.getElementById('recent-findings-list');
        if (!container) return;

        const recent = allFindings.slice(-10).reverse();
        if (recent.length === 0) {
            container.innerHTML = '<div class="empty-state">No findings yet...</div>';
            return;
        }

        container.innerHTML = recent.map(f => `
            <div class="finding-item" onclick="ForgeFindings.showDetail(${JSON.stringify(f).replace(/"/g, '&quot;')})">
                <div class="finding-item__severity finding-item__severity--${f.severity}"></div>
                <div class="finding-item__content">
                    <div class="finding-item__title">${escapeHtml(f.title)}</div>
                    <div class="finding-item__meta">${escapeHtml(f.module)} · ${escapeHtml(f.target)}</div>
                </div>
            </div>
        `).join('');
    }

    function updateTable(findings) {
        allFindings = findings || [];
        renderFilteredTable();
    }

    function renderFilteredTable() {
        const severity = document.getElementById('filter-severity')?.value || '';
        const search = (document.getElementById('filter-search')?.value || '').toLowerCase();

        let filtered = allFindings;
        if (severity) filtered = filtered.filter(f => f.severity === severity);
        if (search) filtered = filtered.filter(f =>
            (f.title || '').toLowerCase().includes(search) ||
            (f.module || '').toLowerCase().includes(search) ||
            (f.target || '').toLowerCase().includes(search)
        );

        const tbody = document.getElementById('findings-tbody');
        if (!tbody) return;

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No findings match filters</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.reverse().map(f => `
            <tr class="finding-row" onclick="ForgeFindings.showDetail(${JSON.stringify(f).replace(/"/g, '&quot;')})">
                <td><span class="badge badge--${(f.severity || 'info').toLowerCase()}">${escapeHtml(f.severity)}</span></td>
                <td>${escapeHtml(f.title)}</td>
                <td><code>${escapeHtml(f.module)}</code></td>
                <td><code>${escapeHtml(f.target)}</code></td>
                <td>${f.cvss_score ? f.cvss_score.toFixed(1) : '—'}</td>
                <td>${f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : '—'}</td>
            </tr>
        `).join('');
    }

    function addFinding(finding) {
        allFindings.push(finding);
        updateRecentList(allFindings);
        updateSeverityCounts();
        // Show toast for high+ severity
        if (['Critical', 'High'].includes(finding.severity)) {
            ForgeNotify.finding(finding.title, finding.severity);
        }
    }

    function updateSeverityCounts() {
        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
        allFindings.forEach(f => {
            if (counts[f.severity] !== undefined) counts[f.severity]++;
        });

        const setCount = (id, val) => {
            const el = document.querySelector(`#${id} .stat-card__value`);
            if (el) el.textContent = val;
        };

        setCount('stat-critical', counts.Critical);
        setCount('stat-high', counts.High);
        setCount('stat-medium', counts.Medium);
        setCount('stat-low', counts.Low);
        setCount('stat-info', counts.Informational);
        setCount('stat-total', allFindings.length);

        // Tab badge
        const badge = document.getElementById('tab-findings-count');
        if (badge) badge.textContent = allFindings.length;
    }

    function showDetail(finding) {
        const modal = document.getElementById('finding-modal');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        if (!modal || !body) return;

        title.textContent = finding.title || 'Finding Details';
        body.innerHTML = `
            <div style="display:grid;gap:12px;">
                <div><span class="badge badge--${(finding.severity||'').toLowerCase()}">${escapeHtml(finding.severity)}</span>
                ${finding.cvss_score ? `<span style="margin-left:8px;font-family:monospace;">CVSS: ${finding.cvss_score}</span>` : ''}</div>
                <div><strong>Module:</strong> <code>${escapeHtml(finding.module)}</code></div>
                <div><strong>Target:</strong> <code>${escapeHtml(finding.target)}</code></div>
                ${finding.port ? `<div><strong>Port:</strong> ${finding.port}</div>` : ''}
                ${finding.service ? `<div><strong>Service:</strong> ${escapeHtml(finding.service)}</div>` : ''}
                ${finding.url ? `<div><strong>URL:</strong> <code>${escapeHtml(finding.url)}</code></div>` : ''}
                ${finding.description ? `<div><strong>Description:</strong><br>${escapeHtml(finding.description)}</div>` : ''}
                ${finding.mitre && finding.mitre.length ? `<div><strong>MITRE ATT&CK:</strong> ${finding.mitre.map(m => `<span class="badge badge--framework">${escapeHtml(m)}</span>`).join(' ')}</div>` : ''}
            </div>
        `;
        modal.style.display = 'flex';
    }

    // Wire up filter events
    document.addEventListener('DOMContentLoaded', () => {
        const sevFilter = document.getElementById('filter-severity');
        const searchFilter = document.getElementById('filter-search');
        if (sevFilter) sevFilter.addEventListener('change', renderFilteredTable);
        if (searchFilter) searchFilter.addEventListener('input', renderFilteredTable);

        // Modal close
        const closeBtn = document.getElementById('modal-close');
        const backdrop = document.querySelector('.modal__backdrop');
        if (closeBtn) closeBtn.addEventListener('click', () => {
            document.getElementById('finding-modal').style.display = 'none';
        });
        if (backdrop) backdrop.addEventListener('click', () => {
            document.getElementById('finding-modal').style.display = 'none';
        });
    });

    return { updateRecentList, updateTable, addFinding, updateSeverityCounts, showDetail, renderFilteredTable };
})();
