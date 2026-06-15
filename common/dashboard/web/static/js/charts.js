/**
 * Forge Suite v5 APEX — Chart Rendering
 * Canvas-based charts for metrics visualization.
 */
const ForgeCharts = (() => {
    const charts = {};

    class RollingLineChart {
        constructor(canvasId, options = {}) {
            this.canvas = document.getElementById(canvasId);
            if (!this.canvas) return;
            this.ctx = this.canvas.getContext('2d');
            this.maxPoints = options.maxPoints || 60;
            this.data = new Array(this.maxPoints).fill(0);
            this.label = options.label || '';
            this.lineColor = options.lineColor || getComputedStyle(document.documentElement).getPropertyValue('--chart-line').trim() || '#00ff88';
            this.fillColor = options.fillColor || getComputedStyle(document.documentElement).getPropertyValue('--chart-fill').trim() || 'rgba(0,255,136,0.1)';
            this.gridColor = options.gridColor || getComputedStyle(document.documentElement).getPropertyValue('--chart-grid').trim() || 'rgba(148,163,184,0.08)';
            this.textColor = getComputedStyle(document.documentElement).getPropertyValue('--text-tertiary').trim() || '#64748b';
            this.maxValue = 1;
            this._resizeObserver = null;
            this._setupResize();
            this.render();
        }

        _setupResize() {
            if (!this.canvas) return;
            this._resizeObserver = new ResizeObserver(() => this.render());
            this._resizeObserver.observe(this.canvas.parentElement);
        }

        push(value) {
            this.data.push(value);
            if (this.data.length > this.maxPoints) {
                this.data.shift();
            }
            this.maxValue = Math.max(1, ...this.data) * 1.2;
            this.render();
        }

        render() {
            if (!this.canvas || !this.ctx) return;
            const rect = this.canvas.parentElement.getBoundingClientRect();
            const dpr = window.devicePixelRatio || 1;
            this.canvas.width = rect.width * dpr;
            this.canvas.height = rect.height * dpr;
            this.canvas.style.width = rect.width + 'px';
            this.canvas.style.height = rect.height + 'px';
            this.ctx.scale(dpr, dpr);

            const w = rect.width;
            const h = rect.height;
            const pad = { top: 8, right: 8, bottom: 20, left: 40 };
            const chartW = w - pad.left - pad.right;
            const chartH = h - pad.top - pad.bottom;

            // Clear
            this.ctx.clearRect(0, 0, w, h);

            // Grid lines
            this.ctx.strokeStyle = this.gridColor;
            this.ctx.lineWidth = 0.5;
            for (let i = 0; i <= 4; i++) {
                const y = pad.top + (chartH / 4) * i;
                this.ctx.beginPath();
                this.ctx.moveTo(pad.left, y);
                this.ctx.lineTo(w - pad.right, y);
                this.ctx.stroke();
            }

            // Y-axis labels
            this.ctx.fillStyle = this.textColor;
            this.ctx.font = '10px JetBrains Mono, monospace';
            this.ctx.textAlign = 'right';
            for (let i = 0; i <= 4; i++) {
                const y = pad.top + (chartH / 4) * i;
                const val = this.maxValue * (1 - i / 4);
                this.ctx.fillText(val.toFixed(0), pad.left - 6, y + 3);
            }

            // Data line
            if (this.data.length < 2) return;
            const stepX = chartW / (this.maxPoints - 1);

            // Fill area
            this.ctx.beginPath();
            this.ctx.moveTo(pad.left, pad.top + chartH);
            for (let i = 0; i < this.data.length; i++) {
                const x = pad.left + i * stepX;
                const y = pad.top + chartH - (this.data[i] / this.maxValue) * chartH;
                if (i === 0) this.ctx.lineTo(x, y);
                else this.ctx.lineTo(x, y);
            }
            this.ctx.lineTo(pad.left + (this.data.length - 1) * stepX, pad.top + chartH);
            this.ctx.closePath();
            this.ctx.fillStyle = this.fillColor;
            this.ctx.fill();

            // Line
            this.ctx.beginPath();
            for (let i = 0; i < this.data.length; i++) {
                const x = pad.left + i * stepX;
                const y = pad.top + chartH - (this.data[i] / this.maxValue) * chartH;
                if (i === 0) this.ctx.moveTo(x, y);
                else this.ctx.lineTo(x, y);
            }
            this.ctx.strokeStyle = this.lineColor;
            this.ctx.lineWidth = 2;
            this.ctx.lineJoin = 'round';
            this.ctx.stroke();

            // Current value dot
            const lastIdx = this.data.length - 1;
            const lastX = pad.left + lastIdx * stepX;
            const lastY = pad.top + chartH - (this.data[lastIdx] / this.maxValue) * chartH;
            this.ctx.beginPath();
            this.ctx.arc(lastX, lastY, 3, 0, Math.PI * 2);
            this.ctx.fillStyle = this.lineColor;
            this.ctx.fill();
            this.ctx.beginPath();
            this.ctx.arc(lastX, lastY, 6, 0, Math.PI * 2);
            this.ctx.strokeStyle = this.lineColor;
            this.ctx.lineWidth = 1;
            this.ctx.globalAlpha = 0.3;
            this.ctx.stroke();
            this.ctx.globalAlpha = 1;

            // Label
            this.ctx.fillStyle = this.textColor;
            this.ctx.font = '10px Inter, sans-serif';
            this.ctx.textAlign = 'center';
            this.ctx.fillText(this.label, w / 2, h - 4);
        }

        destroy() {
            if (this._resizeObserver) this._resizeObserver.disconnect();
        }
    }

    function createRpsChart() {
        charts.rps = new RollingLineChart('rps-chart', {
            label: 'Requests/sec (60s rolling)',
            maxPoints: 60,
        });
        return charts.rps;
    }

    function getChart(name) {
        return charts[name];
    }

    return {
        RollingLineChart,
        createRpsChart,
        getChart,
    };
})();
