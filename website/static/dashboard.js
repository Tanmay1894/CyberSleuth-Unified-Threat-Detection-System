// 🚀 BULLETPROOF EVENT-DRIVEN DASHBOARD

let networkChart = null;
let threatChart = null;
let ws = null;

document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

function initializeDashboard() {
    createNetworkChart();
    createThreatChart();

    // Initial data load
    fetchFullState();

    // Connect to WebSocket for instant live updates
    connectWebSocket();

    // Keep polling secondary non-socket stats
    setInterval(updateDashboardStats, 5000);
    setInterval(updateActiveSchedules, 3000);
    setInterval(checkSystemHealth, 5000);
}

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close();
    }

    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    const wsStatus = document.getElementById('wsHealthStatus');

    ws.onopen = () => {
        if (wsStatus) wsStatus.innerHTML = '<span style="color: #10b981;">● Connected</span>';
    };

    ws.onmessage = async (event) => {
        try {
            const msg = JSON.parse(event.data);

            switch (msg.type) {
                case 'phishing':
                case 'vulnerability':
                    await updateRecentAlerts();
                    await updateCharts();
                    break;
                case 'packet':
                    await updateActivityTimeline();
                    if (msg.data && msg.data.anomalyScore > 0.5) {
                        await updateRecentAlerts();
                        await updateCharts();
                    }
                    break;
                case 'stats':
                    // BUG FIX: Align WebSocket stats handler with the same
                    // stat card IDs used by updateDashboardStats().
                    // packetsCount  → flows (network flows / active alerts)
                    // alertsCount   → flows  (same field, different card label)
                    // urlsCount     → phishing_scans
                    // vulnCount     → vulnerability_scans
                    if (msg.data) {
                        const packetsCountEl = document.getElementById('packetsCount');
                        const alertsCountEl  = document.getElementById('alertsCount');
                        const urlsCountEl    = document.getElementById('urlsCount');
                        const vulnCountEl    = document.getElementById('vulnCount');

                        if (packetsCountEl && Number.isFinite(msg.data.sessions)) {
                            packetsCountEl.textContent = msg.data.sessions.toLocaleString();
                        }
                        if (alertsCountEl && Number.isFinite(msg.data.flows)) {
                            alertsCountEl.textContent = msg.data.flows.toLocaleString();
                        }
                        if (urlsCountEl && Number.isFinite(msg.data.phishing_scans)) {
                            urlsCountEl.textContent = msg.data.phishing_scans.toLocaleString();
                        }
                        if (vulnCountEl && Number.isFinite(msg.data.vulnerability_scans)) {
                            vulnCountEl.textContent = msg.data.vulnerability_scans.toLocaleString();
                        }
                    }
                    break;
                default:
                    break;
            }
        } catch (e) {
            console.warn('WebSocket event parse failed:', e);
        }
    };

    ws.onerror = (event) => {
        console.warn('WebSocket error:', event);
    };

    ws.onclose = () => {
        if (wsStatus) wsStatus.innerHTML = '<span style="color: #ef4444;">● Disconnected</span>';
        setTimeout(connectWebSocket, 3000);
    };
}

async function fetchFullState() {
    // BUG FIX: fetchFullState was synchronous but called async functions.
    // Now awaited in sequence so errors don't silently swallow each other.
    await updateDashboardStats();
    await updateCharts();
    await updateRecentAlerts();
    await updateActivityTimeline();
    await updateActiveSchedules();
    await checkSystemHealth();
}

async function updateDashboardStats() {
    try {
        const response = await fetch('/api/statistics');
        if (!response.ok) return;
        const stats = await response.json();

        const packetsCount = document.getElementById('packetsCount');
        const alertsCount  = document.getElementById('alertsCount');
        const urlsCount    = document.getElementById('urlsCount');
        const vulnCount    = document.getElementById('vulnCount');

        // BUG FIX: stat IDs are now consistent between this function
        // and the WebSocket 'stats' handler above.
        // packetsCount = sessions (number of capture sessions)
        // alertsCount  = flows    (total network flows / active alerts)
        // urlsCount    = phishing_scans
        // vulnCount    = vulnerability_scans
        if (packetsCount) packetsCount.textContent = (stats.sessions || 0).toLocaleString();
        if (alertsCount)  alertsCount.textContent  = (stats.flows || 0).toLocaleString();
        if (urlsCount)    urlsCount.textContent    = (stats.phishing_scans || 0).toLocaleString();
        if (vulnCount)    vulnCount.textContent    = (stats.vulnerability_scans || 0).toLocaleString();
    } catch (error) {
        console.warn("Stats fetch failed:", error);
    }
}

async function updateActiveSchedules() {
    const schedulesList = document.getElementById('dashboardSchedulesList');
    if (!schedulesList) return;

    try {
        const response = await fetch('/api/dashboard/schedules');
        if (!response.ok) return;
        const schedules = await response.json();

        if (!schedules || schedules.length === 0) {
            schedulesList.innerHTML = '<div class="no-alerts">No scheduled scans active.</div>';
            return;
        }

        schedulesList.innerHTML = schedules.map(job => {
            const nextRunDate = new Date(job.next_run);
            const timeStr = isNaN(nextRunDate) ? "Running Now" : nextRunDate.toLocaleString();
            return `
                <div class="schedule-item">
                    <span class="schedule-target">${job.target}</span>
                    <span class="schedule-time">Next: ${timeStr}</span>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.warn("Schedules fetch failed:", error);
    }
}

async function updateRecentAlerts() {
    const alertsList = document.getElementById('alertsList');
    if (!alertsList) return;

    try {
        const response = await fetch('/api/dashboard/alerts');
        if (!response.ok) return;
        const alerts = await response.json();

        if (!alerts || alerts.length === 0) {
            alertsList.innerHTML = '<div class="no-alerts">No recent security threats detected.</div>';
            return;
        }

        alertsList.innerHTML = alerts.map(alert => `
            <div class="alert-item severity-${alert.severity || 'low'}">
                <div class="alert-icon">${getModuleIcon(alert.module)}</div>
                <div class="alert-content">
                    <div class="alert-header">
                        <span class="alert-module">${alert.module}</span>
                        <span class="alert-time">${formatRelativeTime(alert.time)}</span>
                    </div>
                    <div class="alert-message">${alert.message}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.warn("Alerts fetch failed:", error);
    }
}

async function updateActivityTimeline() {
    const timeline = document.getElementById('timeline');
    if (!timeline) return;
    try {
        const response = await fetch('/api/flows?limit=5');
        if (!response.ok) return;
        const data = await response.json();

        if (!data.flows || data.flows.length === 0) return;

        timeline.innerHTML = data.flows.map(flow => `
            <div class="timeline-item">
                <div class="timeline-marker">
                    <div class="timeline-dot"></div>
                    <div class="timeline-line"></div>
                </div>
                <div class="timeline-content">
                    <div class="timeline-time">${new Date(flow.created_at).toLocaleTimeString()}</div>
                    <div class="timeline-event">
                        Detected <span style="color:#3b82f6">${flow.protocol}</span> flow from ${flow.src_ip}
                        ${flow.is_anomalous ? '<span style="color:#ef4444; font-weight:bold;"> (Anomalous)</span>' : ''}
                    </div>
                </div>
            </div>
        `).join('');
    } catch (e) {
        console.warn("Timeline fetch failed:", e);
    }
}

async function checkSystemHealth() {
    try {
        const response = await fetch('/api/sessions/latest');
        if (!response.ok) return;
        const data = await response.json();
        const sessionId = data.sessionId;

        const snifferStatus = document.getElementById('snifferHealthStatus');
        if (sessionId && snifferStatus) {
            const statusRes = await fetch(`/api/sessions/${sessionId}/status`);
            if (!statusRes.ok) return;
            const status = await statusRes.json();

            if (status.isActive) {
                snifferStatus.innerHTML = '<span style="color: #10b981;">● Active</span>';
            } else {
                snifferStatus.innerHTML = '<span style="color: #6b7280;">● Idle</span>';
            }
        }
    } catch (error) {
        console.warn('Health check failed:', error);
    }
}

// BUG FIX #1 (PRIMARY / FATAL): updateCharts() was declared as a plain
// function() but used `await` inside, making it an illegal syntax in
// non-module scripts. This caused the ENTIRE dashboard.js to throw a
// SyntaxError/TypeError on load, preventing ALL other functions from
// running — the root cause of the completely black dashboard.
// Fix: declare it as `async function`.
async function updateCharts() {
    try {
        const response = await fetch('/api/threat-breakdown');
        if (!response.ok) return;
        const threatData = await response.json();
        if (threatChart && threatData.labels && threatData.data) {
            threatChart.data.labels = threatData.labels;
            threatChart.data.datasets[0].data = threatData.data;
            threatChart.update();
        }

        // Also refresh the network line chart with live flow counts.
        // Shift old data left and append the latest flows-per-second.
        if (networkChart) {
            const statsRes = await fetch('/api/statistics');
            if (statsRes.ok) {
                const stats = await statsRes.json();
                const liveValue = stats.flows || 0;
                networkChart.data.datasets[0].data.shift();
                networkChart.data.datasets[0].data.push(liveValue);
                networkChart.data.labels.shift();
                networkChart.data.labels.push('Now');
                networkChart.update('none'); // 'none' = no animation for live feel
            }
        }
    } catch (error) {
        console.warn("Chart update failed:", error);
    }
}

function getModuleIcon(module) {
    switch(module) {
        case 'Network': return '📡';
        case 'Phishing': return '🎣';
        case 'Vulnerability': return '🛡️';
        default: return '⚠️';
    }
}

function formatRelativeTime(timestamp) {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function createNetworkChart() {
    const canvas = document.getElementById('networkChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    networkChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['10m ago', '8m ago', '6m ago', '4m ago', '2m ago', 'Now'],
            datasets: [{
                label: 'Traffic',
                data: [0, 0, 0, 0, 0, 0],
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                borderWidth: 2,
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { grid: { color: '#374151' }, ticks: { color: '#9ca3af' } },
                x: { grid: { color: '#374151' }, ticks: { color: '#9ca3af' } }
            }
        }
    });
}

function createThreatChart() {
    const canvas = document.getElementById('threatChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Network Anomalies', 'Phishing Links', 'Web Vulnerabilities'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ef4444', '#f97316', '#eab308'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } }
        }
    });
}