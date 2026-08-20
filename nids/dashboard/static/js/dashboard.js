/**
 * Home-Gateway NIDS Dashboard Controller
 * Real-time polling, alert filtering, and 10x60s sequence inspector.
 */

document.addEventListener('DOMContentLoaded', () => {
    let currentFilter = 'ALL';
    let allAlerts = [];
    let chartInstance = null;
    let selectedHostIp = '';
    let countdownSec = 5;

    // Initialize Chart
    chartInstance = new window.MetricsChart('metricsChart');

    // Filter Buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentFilter = e.target.dataset.filter;
            renderAlertsTable();
        });
    });

    // Select Host Dropdown
    const selectHost = document.getElementById('selectHost');
    selectHost.addEventListener('change', (e) => {
        selectedHostIp = e.target.value;
        loadSequenceInspection(selectedHostIp);
    });

    // Fetch Stats & Health
    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            if (!res.ok) return;
            const data = await res.json();

            document.getElementById('valTotalAlerts').textContent = data.total_alerts || 0;
            document.getElementById('valTotalDevices').textContent = data.total_devices || 0;
            document.getElementById('valHighRisk').textContent = data.high_risk_devices || 0;

            const mlBadge = document.getElementById('mlStatusBadge');
            if (data.ml_status === 'ACTIVE') {
                mlBadge.textContent = 'ML: ACTIVE';
                mlBadge.className = 'pill pill-status';
            } else {
                mlBadge.textContent = 'ML: UNAVAILABLE';
                mlBadge.className = 'pill pill-status status-error';
            }

            const envBadge = document.getElementById('envBadge');
            envBadge.textContent = `ENV: ${(data.environment || 'DEV').toUpperCase()}`;
        } catch (err) {
            console.error('Error fetching stats:', err);
        }
    }

    // Fetch Alerts
    async function fetchAlerts() {
        try {
            const res = await fetch('/api/alerts?limit=50');
            if (!res.ok) return;
            const data = await res.json();
            allAlerts = data.alerts || [];
            renderAlertsTable();
        } catch (err) {
            console.error('Error fetching alerts:', err);
        }
    }

    // Render Alerts Table
    function renderAlertsTable() {
        const tbody = document.getElementById('alertsTableBody');
        const filtered = allAlerts.filter(a => {
            if (currentFilter === 'ALL') return true;
            return a.detection_method === currentFilter;
        });

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No alerts recorded in this category.</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.map(a => {
            const tsStr = a.iso_timestamp ? a.iso_timestamp.replace('T', ' ').substring(0, 19) : new Date(a.timestamp * 1000).toISOString().replace('T', ' ').substring(0, 19);
            const methodClass = a.detection_method === 'HYBRID' ? 'method-hybrid' : (a.detection_method === 'SURICATA' ? 'method-suricata' : 'method-transformer');
            const scoreDisplay = a.confidence_score ? a.confidence_score.toFixed(2) : '1.00';

            return `
                <tr>
                    <td class="cell-mono">${tsStr}</td>
                    <td><strong class="cell-mono">${a.src_ip}</strong></td>
                    <td>${a.attack_family}</td>
                    <td><span class="badge-method ${methodClass}">${a.detection_method}</span></td>
                    <td class="cell-mono"><strong>${scoreDisplay}</strong></td>
                    <td style="font-size: 0.75rem; color: var(--text-secondary);">${a.details || 'N/A'}</td>
                </tr>
            `;
        }).join('');
    }

    // Fetch Devices
    async function fetchDevices() {
        try {
            const res = await fetch('/api/devices');
            if (!res.ok) return;
            const data = await res.json();
            const devices = data.devices || [];

            // Update dropdown options
            const currentSelected = selectHost.value;
            selectHost.innerHTML = '<option value="">Select Host IP...</option>' +
                devices.map(d => `<option value="${d.ip}" ${d.ip === currentSelected ? 'selected' : ''}>${d.ip} (${d.risk_level})</option>`).join('');

            const tbody = document.getElementById('devicesTableBody');
            if (devices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">No devices currently detected.</td></tr>';
                return;
            }

            tbody.innerHTML = devices.map(d => {
                const riskClass = d.risk_level === 'CRITICAL' || d.risk_level === 'HIGH' ? 'risk-high' : (d.risk_level === 'MEDIUM' ? 'risk-medium' : 'risk-low');
                const lastSeenStr = new Date(d.last_seen * 1000).toLocaleTimeString();

                return `
                    <tr>
                        <td class="cell-mono"><strong>${d.ip}</strong></td>
                        <td class="cell-mono">${d.total_packets || 0}</td>
                        <td><span class="risk-pill ${riskClass}">${d.risk_level}</span></td>
                        <td class="cell-mono">${lastSeenStr}</td>
                        <td>
                            <button class="btn btn-secondary btn-sm" onclick="window.inspectHost('${d.ip}')">
                                Inspect 10x60s
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        } catch (err) {
            console.error('Error fetching devices:', err);
        }
    }

    // Inspect Host 10x60s sequence
    window.inspectHost = function(ip) {
        selectHost.value = ip;
        selectedHostIp = ip;
        loadSequenceInspection(ip);
    };

    async function loadSequenceInspection(ip) {
        const container = document.getElementById('sequenceView');
        if (!ip) {
            container.innerHTML = '<div class="empty-state">Select a device from the table or dropdown to view its 10-window progression.</div>';
            return;
        }

        try {
            const res = await fetch(`/api/sequence/${ip}`);
            if (!res.ok) {
                container.innerHTML = `<div class="empty-state">Failed to load sequence for ${ip}.</div>`;
                return;
            }
            const data = await res.json();
            const seq = data.sequence || [];

            const stepCards = seq.map(s => {
                const isValid = s.is_valid;
                const ports = s.features.dst_port_count || 0;
                const synRatio = s.features.syn_ratio ? (s.features.syn_ratio * 100).toFixed(0) : '0';
                const isHigh = ports >= 10 || (ports >= 2 && s.features.syn_ratio >= 0.7);

                return `
                    <div class="sequence-step ${isValid ? 'valid' : ''} ${isHigh ? 'anomaly-high' : ''}">
                        <div class="step-label">W-${10 - s.step + 1}</div>
                        <div class="step-ports">${isValid ? ports : '-'}</div>
                        <div style="font-size: 0.6rem; color: var(--text-muted);">${isValid ? `SYN ${synRatio}%` : 'pad'}</div>
                    </div>
                `;
            }).join('');

            container.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div>
                        <strong class="cell-mono">${data.src_ip}</strong>
                        <span style="font-size: 0.75rem; color: var(--text-muted); margin-left: 8px;">(Temporal Sequence t-9 to t)</span>
                    </div>
                    <div class="cell-mono" style="font-size: 0.85rem;">
                        ML Anomaly Score: <strong style="color: ${data.anomaly_score >= 0.7 ? 'var(--accent-threat)' : 'var(--accent-cyan)'}">${data.anomaly_score.toFixed(4)}</strong>
                    </div>
                </div>
                <div class="sequence-grid">
                    ${stepCards}
                </div>
            `;
        } catch (err) {
            console.error('Error loading sequence inspection:', err);
        }
    }

    // Fetch Flow Metrics for Chart
    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics?limit=30');
            if (!res.ok) return;
            const data = await res.json();
            if (chartInstance) {
                chartInstance.setData(data.metrics || []);
            }
        } catch (err) {
            console.error('Error fetching metrics:', err);
        }
    }

    // Polling Loop
    async function pollAll() {
        await Promise.all([
            fetchStats(),
            fetchAlerts(),
            fetchDevices(),
            fetchMetrics()
        ]);
        if (selectedHostIp) {
            loadSequenceInspection(selectedHostIp);
        }
    }

    // Countdown Timer
    setInterval(() => {
        countdownSec -= 1;
        if (countdownSec <= 0) {
            countdownSec = 5;
            pollAll();
        }
        document.getElementById('refreshTimer').textContent = `Next refresh in ${countdownSec}s`;
    }, 1000);

    // Initial Load
    pollAll();
});
