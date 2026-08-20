/**
 * Lightweight Canvas Chart Renderer for Anomaly Scores & Metric Time-Series.
 */

class MetricsChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.data = [];
        this.resize();
        window.addEventListener('resize', () => this.resize());
    }

    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = 180;
        this.draw();
    }

    setData(dataPoints) {
        this.data = dataPoints || [];
        this.draw();
    }

    draw() {
        if (!this.ctx || !this.canvas) return;
        const w = this.canvas.width;
        const h = this.canvas.height;
        const ctx = this.ctx;

        ctx.clearRect(0, 0, w, h);

        const padLeft = 40;
        const padRight = 20;
        const padTop = 20;
        const padBottom = 30;
        const plotW = w - padLeft - padRight;
        const plotH = h - padTop - padBottom;

        // Draw grid lines
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.lineWidth = 1;

        for (let yVal = 0.0; yVal <= 1.0; yVal += 0.25) {
            const y = padTop + plotH * (1.0 - yVal);
            ctx.beginPath();
            ctx.moveTo(padLeft, y);
            ctx.lineTo(w - padRight, y);
            ctx.stroke();

            ctx.fillStyle = '#64748b';
            ctx.font = '10px JetBrains Mono, monospace';
            ctx.textAlign = 'right';
            ctx.fillText(yVal.toFixed(2), padLeft - 8, y + 3);
        }

        // Draw 0.70 Threshold line
        const thresholdY = padTop + plotH * (1.0 - 0.70);
        ctx.strokeStyle = 'rgba(255, 179, 0, 0.7)';
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(padLeft, thresholdY);
        ctx.lineTo(w - padRight, thresholdY);
        ctx.stroke();
        ctx.setLineDash([]);

        if (this.data.length < 2) {
            ctx.fillStyle = '#64748b';
            ctx.font = '12px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('Awaiting metric stream...', w / 2, h / 2);
            return;
        }

        // Plot Anomaly Score curve
        const stepX = plotW / (this.data.length - 1);
        ctx.strokeStyle = '#00e5ff';
        ctx.lineWidth = 2;
        ctx.beginPath();

        this.data.forEach((d, i) => {
            const score = Math.max(0.0, Math.min(1.0, d.anomaly_score || 0.0));
            const x = padLeft + i * stepX;
            const y = padTop + plotH * (1.0 - score);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Draw gradient area under curve
        const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
        grad.addColorStop(0, 'rgba(0, 229, 255, 0.25)');
        grad.addColorStop(1, 'rgba(0, 229, 255, 0.0)');
        ctx.fillStyle = grad;
        ctx.lineTo(padLeft + (this.data.length - 1) * stepX, padTop + plotH);
        ctx.lineTo(padLeft, padTop + plotH);
        ctx.closePath();
        ctx.fill();

        // Plot latest point dot
        const lastIdx = this.data.length - 1;
        const lastScore = Math.max(0.0, Math.min(1.0, this.data[lastIdx].anomaly_score || 0.0));
        const lastX = padLeft + lastIdx * stepX;
        const lastY = padTop + plotH * (1.0 - lastScore);

        ctx.fillStyle = lastScore >= 0.70 ? '#ff3366' : '#00e5ff';
        ctx.beginPath();
        ctx.arc(lastX, lastY, 5, 0, Math.PI * 2);
        ctx.fill();
    }
}

window.MetricsChart = MetricsChart;
