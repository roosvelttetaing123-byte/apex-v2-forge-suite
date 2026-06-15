/**
 * Forge Suite v5 APEX — Threat Timeline
 */
const ForgeTimeline = (() => {
    let timelineEvents = [];

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function update(events) {
        timelineEvents = events || [];
        render();
    }

    function addEvent(event) {
        timelineEvents.push(event);
        if (timelineEvents.length > 500) timelineEvents = timelineEvents.slice(-500);
        render();
    }

    function render() {
        const container = document.getElementById('timeline-container');
        if (!container) return;

        if (timelineEvents.length === 0) {
            container.innerHTML = '<div class="empty-state">Timeline will populate as events occur...</div>';
            return;
        }

        const iconMap = {
            scan_start: '🚀', scan_complete: '🏁', scan_interrupted: '⚠️',
            phase_start: '📋', module_fail: '❌', credential: '🔑',
            target_pwned: '💀', finding_critical: '🔴', finding_high: '🟠',
            finding_medium: '🟡', finding_low: '🔵', finding_informational: '⚪',
            finding_info: '⚪',
        };

        const recent = timelineEvents.slice(-100).reverse();
        container.innerHTML = recent.map(e => {
            const icon = iconMap[e.type] || '📌';
            const time = e.time ? new Date(e.time).toLocaleTimeString() : '';

            return `
                <div class="timeline-item">
                    <span class="timeline-item__time">${time}</span>
                    <span class="timeline-item__icon">${icon}</span>
                    <span class="timeline-item__message">${escapeHtml(e.message)}</span>
                    <span class="timeline-item__source">${escapeHtml(e.source)}</span>
                </div>
            `;
        }).join('');
    }

    return { update, addEvent };
})();
