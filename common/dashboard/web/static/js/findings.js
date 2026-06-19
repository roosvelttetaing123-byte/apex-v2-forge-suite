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
        const detailsContainer = document.getElementById('modal-details');
        const pocContainer = document.getElementById('modal-poc');
        const pocImage = document.getElementById('poc-image');
        
        if (!modal || !detailsContainer) return;

        title.textContent = finding.title || 'Finding Details';
        detailsContainer.innerHTML = `
            <div style="display:grid;gap:12px;">
                <div><span class="badge badge--${(finding.severity||'').toLowerCase()}">${escapeHtml(finding.severity)}</span>
                ${finding.cvss_score ? `<span style="margin-left:8px;font-family:monospace;color:var(--text-secondary);">CVSS: <strong style="color:var(--text-primary);">${finding.cvss_score}</strong></span>` : ''}</div>
                <div><strong style="color:var(--text-secondary);">Module:</strong> <code>${escapeHtml(finding.module)}</code></div>
                <div><strong style="color:var(--text-secondary);">Target:</strong> <code>${escapeHtml(finding.target)}</code></div>
                ${finding.port ? `<div><strong style="color:var(--text-secondary);">Port:</strong> ${finding.port}</div>` : ''}
                ${finding.service ? `<div><strong style="color:var(--text-secondary);">Service:</strong> ${escapeHtml(finding.service)}</div>` : ''}
                ${finding.url ? `<div><strong style="color:var(--text-secondary);">URL:</strong> <code>${escapeHtml(finding.url)}</code></div>` : ''}
                ${finding.description ? `<div style="margin-top:12px;"><strong style="color:var(--text-secondary);">Description:</strong><br><div style="background:var(--bg-primary);padding:12px;border-radius:var(--radius-md);border:1px solid var(--border-subtle);margin-top:6px;line-height:1.6;">${escapeHtml(finding.description).replace(/\n/g, '<br>')}</div></div>` : ''}
                ${finding.poc_text ? `<div style="margin-top:12px;"><strong style="color:var(--text-secondary);">Proof of Concept Details:</strong><br><pre style="background:var(--bg-primary);padding:12px;border-radius:var(--radius-md);border:1px solid var(--border-subtle);margin-top:6px;overflow-x:auto;font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--accent-secondary);">${escapeHtml(finding.poc_text)}</pre></div>` : ''}
                ${finding.mitre && finding.mitre.length ? `<div style="margin-top:12px;"><strong style="color:var(--text-secondary);">MITRE ATT&CK:</strong><br><div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;">${finding.mitre.map(m => `<span class="badge badge--framework">${escapeHtml(m)}</span>`).join('')}</div></div>` : ''}
            </div>
        `;

        if (pocContainer && pocImage) {
            if (finding.poc_image) {
                pocImage.src = finding.poc_image;
                pocContainer.style.display = 'flex';
            } else {
                pocImage.src = '';
                pocContainer.style.display = 'none';
            }
        }

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

    // --- Table Sorting & PoC Zoom Logic ---
    let currentSort = { column: null, asc: true };

    document.addEventListener('DOMContentLoaded', () => {
        // Table Sorting
        const headers = document.querySelectorAll('.sortable');
        headers.forEach(header => {
            header.addEventListener('click', () => {
                const column = header.dataset.sort;
                if (currentSort.column === column) {
                    currentSort.asc = !currentSort.asc;
                } else {
                    currentSort.column = column;
                    currentSort.asc = true;
                }

                // Update classes
                headers.forEach(h => h.classList.remove('asc', 'desc'));
                header.classList.add(currentSort.asc ? 'asc' : 'desc');

                // Sort data
                allFindings.sort((a, b) => {
                    let valA = a[column] || '';
                    let valB = b[column] || '';
                    
                    if (column === 'cvss') {
                        valA = a.cvss_score || 0;
                        valB = b.cvss_score || 0;
                    }
                    if (column === 'time') {
                        valA = a.timestamp || 0;
                        valB = b.timestamp || 0;
                    }
                    if (column === 'severity') {
                        const sevMap = { 'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Informational': 1 };
                        valA = sevMap[a.severity] || 0;
                        valB = sevMap[b.severity] || 0;
                    }

                    if (valA < valB) return currentSort.asc ? -1 : 1;
                    if (valA > valB) return currentSort.asc ? 1 : -1;
                    return 0;
                });
                renderFilteredTable();
            });
        });

        // PoC Zooming
        let currentZoom = 1;
        const pocImg = document.getElementById('poc-image');
        const btnZoomIn = document.getElementById('poc-zoom-in');
        const btnZoomOut = document.getElementById('poc-zoom-out');
        const btnReset = document.getElementById('poc-reset');

        if (btnZoomIn) btnZoomIn.addEventListener('click', () => { currentZoom += 0.2; updateZoom(); });
        if (btnZoomOut) btnZoomOut.addEventListener('click', () => { currentZoom = Math.max(0.2, currentZoom - 0.2); updateZoom(); });
        if (btnReset) btnReset.addEventListener('click', () => { currentZoom = 1; updateZoom(); });

        function updateZoom() {
            if (pocImg) pocImg.style.transform = \scale(\)\;
        }

        // Reset zoom on close
        const closeBtn = document.getElementById('modal-close');
        if (closeBtn) closeBtn.addEventListener('click', () => { currentZoom = 1; updateZoom(); });
    });
