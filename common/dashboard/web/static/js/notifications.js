/**
 * Forge Suite v5 APEX — Toast Notification System
 */
const ForgeNotify = (() => {
    const container = () => document.getElementById('toast-container');
    let toastId = 0;

    function show(options = {}) {
        const {
            title = '',
            message = '',
            type = 'info', // critical, high, medium, success, info
            duration = 5000,
            icon = null,
        } = options;

        const icons = {
            critical: '🔴', high: '🟠', medium: '🟡',
            success: '✅', info: 'ℹ️',
        };

        const id = 'toast-' + (++toastId);
        const toast = document.createElement('div');
        toast.id = id;
        toast.className = `toast toast--${type}`;
        toast.innerHTML = `
            <span class="toast__icon">${icon || icons[type] || 'ℹ️'}</span>
            <div class="toast__content">
                <div class="toast__title">${escapeHtml(title)}</div>
                ${message ? `<div class="toast__message">${escapeHtml(message)}</div>` : ''}
            </div>
            <button class="toast__close" onclick="ForgeNotify.dismiss('${id}')">✕</button>
        `;

        const c = container();
        if (c) {
            c.appendChild(toast);
            if (duration > 0) {
                setTimeout(() => dismiss(id), duration);
            }
        }
        return id;
    }

    function dismiss(id) {
        const toast = document.getElementById(id);
        if (toast) {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(24px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }
    }

    function finding(title, severity) {
        const typeMap = {
            Critical: 'critical', High: 'high',
            Medium: 'medium', Low: 'info', Informational: 'info',
        };
        show({
            title: `[${severity}] Finding`,
            message: title,
            type: typeMap[severity] || 'info',
            duration: 6000,
        });
    }

    function credential(account, credType) {
        show({
            title: '🔑 Credential Found',
            message: `${credType}: ${account}`,
            type: 'success',
            duration: 8000,
            icon: '🔑',
        });
    }

    function shell(target, accessLevel) {
        show({
            title: '💀 Shell Session',
            message: `${target} — ${accessLevel}`,
            type: 'critical',
            duration: 10000,
            icon: '💀',
        });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    return { show, dismiss, finding, credential, shell };
})();
