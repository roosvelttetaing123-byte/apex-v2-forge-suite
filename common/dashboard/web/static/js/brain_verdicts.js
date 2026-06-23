/**
 * Forge Suite v5 APEX — ForgeBrain Analysis Panel
 *
 * Subscribes to brain_verdict WebSocket events and renders a
 * "ForgeBrain Analysis" card per finding with verdict, confidence %,
 * severity adjustment, and reasoning.
 *
 * Event payload (brain_verdict):
 *   {
 *     finding_id:         string,
 *     verdict:            "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "EXPLOITABLE" | "UNEXPLOITABLE",
 *     confidence:         "HIGH" | "MEDIUM" | "LOW" | "UNVERIFIED",
 *     reasoning:          string,
 *     severity_adjustment: "ESCALATE" | "DOWNGRADE" | "MAINTAIN" | null
 *   }
 */
const ForgeBrainVerdicts = (() => {

    // Store verdicts keyed by finding_id for dedup and later lookup
    const _verdicts = {};
    const _MAX_CARDS = 100;

    // Verdict badge styling
    const _VERDICT_STYLES = {
        CONFIRMED:     { bg: '#27ae60', fg: '#ffffff', icon: '[+]' },
        FALSE_POSITIVE:{ bg: '#e74c3c', fg: '#ffffff', icon: '[!]' },
        NEEDS_REVIEW:  { bg: '#f39c12', fg: '#000000', icon: '[?]' },
        EXPLOITABLE:   { bg: '#8e44ad', fg: '#ffffff', icon: '[X]' },
        UNEXPLOITABLE: { bg: '#7f8c8d', fg: '#ffffff', icon: '[-]' },
    };

    // Confidence badge styling
    const _CONFIDENCE_STYLES = {
        HIGH:       { bg: '#2ecc71', fg: '#000000' },
        MEDIUM:     { bg: '#f39c12', fg: '#000000' },
        LOW:        { bg: '#e67e22', fg: '#ffffff' },
        UNVERIFIED: { bg: '#95a5a6', fg: '#ffffff' },
    };

    const _ADJUSTMENT_LABELS = {
        ESCALATE:  'Severity ESCALATED by AI analysis',
        DOWNGRADE: 'Severity DOWNGRADED by AI analysis',
        MAINTAIN:  'Severity unchanged',
    };

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = String(str || '');
        return div.innerHTML;
    }

    /**
     * Handle a single brain_verdict event from the WebSocket.
     * Called by app.js: ForgeBrainVerdicts.handleVerdict(data)
     */
    function handleVerdict(data) {
        if (!data || !data.finding_id) return;

        // Overwrite if we already have a verdict for this finding_id
        _verdicts[data.finding_id] = data;

        _renderCard(data);
        _updateBadgeCount();
        _pruneOldCards();
    }

    /**
     * Load a batch of brain_verdict objects from the state snapshot.
     * Called during state_snapshot hydration in app.js.
     */
    function hydrate(verdicts) {
        if (!Array.isArray(verdicts)) return;
        verdicts.forEach(v => handleVerdict(v));
    }

    /**
     * Render a verdict card into the #brain-verdicts-list container.
     */
    function _renderCard(data) {
        const container = document.getElementById('brain-verdicts-list');
        if (!container) return;

        const verdict    = data.verdict    || 'NEEDS_REVIEW';
        const confidence = data.confidence || 'UNVERIFIED';
        const reasoning  = data.reasoning  || '';
        const adjustment = data.severity_adjustment || null;
        const findingId  = data.finding_id;

        const vs = _VERDICT_STYLES[verdict]    || { bg: '#7f8c8d', fg: '#ffffff', icon: '[?]' };
        const cs = _CONFIDENCE_STYLES[confidence] || { bg: '#95a5a6', fg: '#ffffff' };

        // Remove existing card for this finding_id (update-in-place)
        const existing = document.getElementById(`brain-card-${CSS.escape(findingId)}`);
        if (existing) existing.remove();

        // Build confidence percentage display (HIGH=95, MEDIUM=70, LOW=40, UNVERIFIED=10)
        const confPct = { HIGH: 95, MEDIUM: 70, LOW: 40, UNVERIFIED: 10 }[confidence] || 10;

        const adjustmentHtml = adjustment && adjustment !== 'MAINTAIN' ? `
            <div style="margin-top:6px;font-size:0.75rem;color:${adjustment === 'ESCALATE' ? '#e74c3c' : '#27ae60'}">
                ${escapeHtml(_ADJUSTMENT_LABELS[adjustment] || adjustment)}
            </div>` : '';

        const card = document.createElement('div');
        card.id = `brain-card-${findingId}`;
        card.className = 'brain-verdict-card';
        card.style.cssText = `
            background: var(--bg-secondary, #1a1a2e);
            border: 1px solid var(--border-subtle, #2a2a4e);
            border-left: 4px solid ${vs.bg};
            border-radius: 6px;
            padding: 12px 14px;
            margin-bottom: 10px;
            font-size: 0.83rem;
            transition: box-shadow 0.2s;
        `;
        card.innerHTML = `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
                <!-- Verdict badge -->
                <span style="background:${vs.bg};color:${vs.fg};padding:3px 10px;border-radius:4px;
                             font-weight:700;font-size:0.75rem;letter-spacing:0.5px;font-family:monospace">
                    ${vs.icon} ${escapeHtml(verdict)}
                </span>
                <!-- Confidence badge -->
                <span style="background:${cs.bg};color:${cs.fg};padding:3px 8px;border-radius:4px;
                             font-size:0.72rem;font-weight:600">
                    ${escapeHtml(confidence)} ${confPct}%
                </span>
                <!-- Confidence bar -->
                <div style="flex:1;min-width:80px;background:rgba(255,255,255,0.1);
                            border-radius:10px;height:6px;overflow:hidden">
                    <div style="width:${confPct}%;background:${cs.bg};height:100%;
                                border-radius:10px;transition:width 0.4s"></div>
                </div>
            </div>

            <!-- Finding ID reference -->
            <div style="color:var(--text-secondary,#6c757d);font-family:monospace;
                        font-size:0.7rem;margin-bottom:6px">
                Finding: ${escapeHtml(findingId.slice(0, 16))}...
            </div>

            <!-- Reasoning -->
            ${reasoning ? `
            <div style="color:var(--text-primary,#e0e0e0);line-height:1.5;
                        font-size:0.82rem;margin-top:4px">
                ${escapeHtml(reasoning)}
            </div>` : ''}

            ${adjustmentHtml}
        `;

        // Insert newest at top
        container.insertBefore(card, container.firstChild);

        // Pulse animation for new card
        card.animate(
            [{ opacity: 0, transform: 'translateY(-6px)' },
             { opacity: 1, transform: 'translateY(0)' }],
            { duration: 300, easing: 'ease-out' }
        );
    }

    function _updateBadgeCount() {
        const count = Object.keys(_verdicts).length;
        const badge = document.getElementById('brain-verdict-count');
        if (badge) badge.textContent = count;

        const tabBadge = document.getElementById('tab-brain-count');
        if (tabBadge) tabBadge.textContent = count;
    }

    function _pruneOldCards() {
        const container = document.getElementById('brain-verdicts-list');
        if (!container) return;
        // Keep only the latest MAX_CARDS cards in DOM
        const cards = container.querySelectorAll('.brain-verdict-card');
        if (cards.length > _MAX_CARDS) {
            for (let i = _MAX_CARDS; i < cards.length; i++) {
                cards[i].remove();
            }
        }
    }

    /** Clear all verdicts and reset the panel. */
    function clear() {
        Object.keys(_verdicts).forEach(k => delete _verdicts[k]);
        const container = document.getElementById('brain-verdicts-list');
        if (container) {
            container.innerHTML = '<div class="empty-state" style="color:var(--text-secondary,#666);padding:16px;text-align:center">No AI verdicts yet — run a scan to activate ForgeBrain analysis.</div>';
        }
        _updateBadgeCount();
    }

    /** Return all stored verdicts (for export/debug). */
    function getAll() {
        return Object.values(_verdicts);
    }

    /** Return verdict for a specific finding_id. */
    function getByFindingId(findingId) {
        return _verdicts[findingId] || null;
    }

    /**
     * Inject a summary verdict row into the findings modal detail view.
     * Called by ForgeFindings.showDetail() to enrich the modal with AI verdict.
     */
    function enrichModal(finding) {
        const findingId = finding.id || finding.finding_id;
        if (!findingId) return;
        const verdict = _verdicts[findingId];
        if (!verdict) return;

        const container = document.getElementById('modal-brain-verdict');
        if (!container) return;

        const vs = _VERDICT_STYLES[verdict.verdict] || { bg: '#7f8c8d', fg: '#fff', icon: '[?]' };
        const cs = _CONFIDENCE_STYLES[verdict.confidence] || { bg: '#95a5a6', fg: '#fff' };

        container.innerHTML = `
            <div style="border:1px solid ${vs.bg};border-radius:6px;padding:12px;
                        background:rgba(${_hexToRgb(vs.bg)},0.08);margin-top:12px">
                <div style="font-weight:700;font-size:0.78rem;color:var(--text-secondary,#6c757d);
                             text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">
                    ForgeBrain AI Analysis
                </div>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
                    <span style="background:${vs.bg};color:${vs.fg};padding:3px 10px;
                                 border-radius:4px;font-weight:700;font-size:0.75rem">
                        ${vs.icon} ${escapeHtml(verdict.verdict)}
                    </span>
                    <span style="background:${cs.bg};color:${cs.fg};padding:3px 8px;
                                 border-radius:4px;font-size:0.72rem;font-weight:600">
                        ${escapeHtml(verdict.confidence)}
                    </span>
                </div>
                ${verdict.reasoning ? `
                <div style="font-size:0.82rem;color:var(--text-primary,#e0e0e0);line-height:1.5">
                    ${escapeHtml(verdict.reasoning)}
                </div>` : ''}
            </div>
        `;
        container.style.display = 'block';
    }

    /** Hex colour to RGB components string for rgba() usage. */
    function _hexToRgb(hex) {
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        return `${r},${g},${b}`;
    }

    // Expose public API
    return {
        handleVerdict,
        hydrate,
        clear,
        getAll,
        getByFindingId,
        enrichModal,
    };
})();
