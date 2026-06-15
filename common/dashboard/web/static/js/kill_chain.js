/**
 * Forge Suite v5 APEX — Kill Chain Visualization
 */
const ForgeKillChain = (() => {
    const phaseIds = ['kc-recon', 'kc-weaponize', 'kc-deliver', 'kc-exploit', 'kc-install', 'kc-c2', 'kc-actions'];

    function update(killChainData) {
        if (!killChainData || !killChainData.phases) return;
        const phases = killChainData.phases;

        phases.forEach((phase, i) => {
            const el = document.getElementById(phaseIds[i]);
            if (!el) return;

            // Update count
            const countEl = el.querySelector('.kc-phase__count');
            if (countEl) countEl.textContent = phase.findings || 0;

            // Update progress fill
            const fillEl = el.querySelector('.kc-phase__fill');
            if (fillEl) fillEl.style.width = (phase.completion_pct || 0) + '%';

            // Update class states
            el.classList.remove('kc-phase--active', 'kc-phase--reached', 'kc-phase--unreached');
            if (phase.is_active) {
                el.classList.add('kc-phase--active');
            } else if (phase.is_reached) {
                el.classList.add('kc-phase--reached');
            } else {
                el.classList.add('kc-phase--unreached');
            }
        });

        // Update summary
        const progressText = document.getElementById('kc-progress-text');
        const statusText = document.getElementById('kc-status-text');
        if (progressText) progressText.textContent = (killChainData.overall_completion || 0).toFixed(0) + '% Complete';
        if (statusText) {
            statusText.textContent = killChainData.compromise_achieved
                ? '🏴 COMPROMISED' : '⏳ In Progress';
        }
    }

    return { update };
})();
