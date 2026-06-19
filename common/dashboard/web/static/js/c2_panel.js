/**
 * Forge Suite v5 APEX — C2 Beacon Console
 */
const ForgeC2 = (() => {
    let activeBeaconId = null;
    const commandHistory = [];
    let historyIndex = -1;

    function init() {
        const input = document.getElementById('console-input');
        if (!input) return;

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const cmd = input.value.trim();
                if (cmd) {
                    executeCommand(cmd);
                    commandHistory.push(cmd);
                    historyIndex = commandHistory.length;
                }
                input.value = '';
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    input.value = commandHistory[historyIndex] || '';
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    input.value = commandHistory[historyIndex] || '';
                } else {
                    historyIndex = commandHistory.length;
                    input.value = '';
                }
            }
        });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function executeCommand(cmd) {
        appendOutput(`> ${cmd}`, 'command');

        // Built-in client commands
        if (cmd === 'help') {
            appendOutput(
                'Available commands:\n' +
                '  shell <cmd>     Execute shell command\n' +
                '  download <path> Download file from target\n' +
                '  upload <path>   Upload file to target\n' +
                '  screenshot      Capture desktop screenshot\n' +
                '  hashdump        Dump password hashes\n' +
                '  socks <port>    Start SOCKS proxy\n' +
                '  sleep <sec>     Set beacon sleep interval\n' +
                '  clear           Clear console\n' +
                '  help            Show this help',
                'info'
            );
            return;
        }

        if (cmd === 'clear') {
            const output = document.getElementById('console-output');
            if (output) output.innerHTML = '';
            return;
        }

        // Send command to server via WebSocket
        ForgeWS.send({
            action: 'beacon_command',
            beacon_id: activeBeaconId,
            command: cmd,
        });
        appendOutput('Tasked beacon...', 'info');
    }

    function appendOutput(text, type = 'output') {
        const output = document.getElementById('console-output');
        if (!output) return;

        const line = document.createElement('div');
        line.style.fontFamily = "'JetBrains Mono', monospace";
        line.style.fontSize = '0.75rem';
        line.style.padding = '1px 0';

        if (type === 'command') {
            line.style.color = 'var(--accent-primary)';
        } else if (type === 'error') {
            line.style.color = 'var(--severity-critical)';
        } else if (type === 'info') {
            line.style.color = 'var(--text-tertiary)';
        }

        line.textContent = text;
        output.appendChild(line);
        output.scrollTop = output.scrollHeight;
    }

    function setActiveBeacon(id) {
        activeBeaconId = id;
    }

    document.addEventListener('DOMContentLoaded', init);

    return { executeCommand, appendOutput, setActiveBeacon };
})();
