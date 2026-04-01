// Dashboard Page JavaScript

let networkChart = null;
let threatChart = null;

document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

function initializeDashboard() {
    updateRecentAlerts();
    renderTimeline();
    createNetworkChart();
    createThreatChart();
    startDashboardUpdates();
}

async function updateDashboardStats() {
    try {
        const response = await fetch('/api/statistics');
        const stats = await response.json();

        // Update the Counter Cards
        document.getElementById('packetsCount').textContent = stats.sessions.toLocaleString();
        document.getElementById('alertsCount').textContent = stats.flows;
        document.getElementById('urlsCount').textContent = stats.phishing_scans;
        document.getElementById('vulnCount').textContent = stats.vulnerability_scans;

        // Update Alert Badge (difference from last check or total)
        const alertBadge = document.getElementById('alertBadge');
        alertBadge.textContent = `+${stats.flows}`;
        
    } catch (error) {
        console.error("Failed to fetch dashboard stats:", error);
    }
}

async function updateCharts() {
    const response = await fetch('/api/threat-breakdown');
    const threatData = await response.json();

    // Assuming threatChart is your Chart.js instance
    threatChart.data.labels = threatData.labels;
    threatChart.data.datasets[0].data = threatData.data;
    threatChart.update();
}

async function updateActivityTimeline() {
    const timeline = document.getElementById('timeline');
    try {
        const response = await fetch('/api/flows?limit=5');
        const data = await response.json();
        
        timeline.innerHTML = ''; // Clear old items
        
        data.flows.forEach(flow => {
            const item = document.createElement('div');
            item.className = 'timeline-item';
            item.innerHTML = `
                <div class="timeline-time">${new Date(flow.created_at).toLocaleTimeString()}</div>
                <div class="timeline-desc">
                    Detected ${flow.protocol} flow from ${flow.src_ip} 
                    ${flow.is_anomalous ? '<span class="text-danger">(Anomalous)</span>' : ''}
                </div>
            `;
            timeline.appendChild(item);
        });
    } catch (e) {
        console.error(e);
    }
}

async function checkSystemHealth() {
    try {
        const response = await fetch('/api/sessions/latest');
        const { sessionId } = await response.json();
        
        if (sessionId) {
            const statusRes = await fetch(`/api/sessions/${sessionId}/status`);
            const status = await statusRes.json();
            
            // Find the Packet Sniffer health item
            const healthItems = document.querySelectorAll('.health-item');
            healthItems.forEach(item => {
                const label = item.querySelector('span:first-child');
                if (label && label.textContent === 'Packet Sniffer') {
                    const statusSpan = item.querySelector('.health-status span:last-child');
                    if (statusSpan) {
                        if (status.isActive) {
                            statusSpan.textContent = 'Running';
                            statusSpan.className = 'status-running';
                        } else {
                            statusSpan.textContent = 'Idle';
                            statusSpan.className = 'status-stopped';
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Failed to check system health:', error);
    }
}

async function updateRecentAlerts() {
    const alertsList = document.getElementById('alertsList');
    if (!alertsList) return;

    try {
        const response = await fetch('/api/dashboard/alerts');
        const alerts = await response.json();

        if (alerts.length === 0) {
            alertsList.innerHTML = '<div class="no-alerts">No recent security threats detected.</div>';
            return;
        }

        alertsList.innerHTML = ''; // Clear placeholders

        alerts.forEach(alert => {
            const alertItem = document.createElement('div');
            // Use your existing CSS classes for alert items
            alertItem.className = `alert-item severity-${alert.severity}`;
            
            alertItem.innerHTML = `
                <div class="alert-icon">
                    ${getModuleIcon(alert.module)}
                </div>
                <div class="alert-content">
                    <div class="alert-header">
                        <span class="alert-module">${alert.module}</span>
                        <span class="alert-time">${formatRelativeTime(alert.time)}</span>
                    </div>
                    <div class="alert-message">${alert.message}</div>
                </div>
                <div class="alert-badge">${alert.severity.toUpperCase()}</div>
            `;
            alertsList.appendChild(alertItem);
        });
    } catch (error) {
        console.error("Error updating alerts:", error);
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
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function renderTimeline() {
    // Initial static timeline - will be replaced by updateActivityTimeline
    const activities = [
        { time: '14:25', event: 'Network scan completed - 245 hosts discovered' },
        { time: '14:20', event: 'Phishing detector updated threat database' },
        { time: '14:15', event: 'Vulnerability scan started for example.com' },
        { time: '14:10', event: 'Packet capture started on interface eth0' }
    ];

    const timeline = document.getElementById('timeline');
    timeline.innerHTML = activities.map((activity, index) => `
        <div class="timeline-item">
            <div class="timeline-marker">
                <div class="timeline-dot"></div>
                ${index < activities.length - 1 ? '<div class="timeline-line"></div>' : ''}
            </div>
            <div class="timeline-content">
                <div class="timeline-time">${activity.time}</div>
                <div class="timeline-event">${activity.event}</div>
            </div>
        </div>
    `).join('');
}

function createNetworkChart() {
    const ctx = document.getElementById('networkChart').getContext('2d');
    networkChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['14:00', '14:05', '14:10', '14:15', '14:20', '14:25'],
            datasets: [{
                label: 'Traffic',
                data: [450, 520, 380, 680, 590, 720],
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
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    grid: {
                        color: '#374151'
                    },
                    ticks: {
                        color: '#9ca3af'
                    }
                },
                x: {
                    grid: {
                        color: '#374151'
                    },
                    ticks: {
                        color: '#9ca3af'
                    }
                }
            },
            animation: {
                duration: 750,
                easing: 'easeInOutQuart'
            }
        }
    });
}

function createThreatChart() {
    const ctx = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Network Anomalies', 'Phishing Links', 'Web Vulnerabilities'],
            datasets: [{
                data: [35, 28, 15],
                backgroundColor: ['#ef4444', '#f97316', '#eab308'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1000
            }
        }
    });

    const legend = document.getElementById('threatLegend');
    legend.innerHTML = [
        { name: 'Network Anomalies', value: 35, color: '#ef4444' },
        { name: 'Phishing Links', value: 28, color: '#f97316' },
        { name: 'Web Vulnerabilities', value: 15, color: '#eab308' }
    ].map(item => `
        <div class="legend-item">
            <div class="legend-label">
                <span class="legend-color" style="background-color: ${item.color}"></span>
                <span>${item.name}</span>
            </div>
            <span class="legend-value">${item.value}%</span>
        </div>
    `).join('');
}

function startDashboardUpdates() {
    // Initialize and Set Interval
    updateDashboardStats();
    updateCharts();
    updateActivityTimeline();
    updateRecentAlerts();
    checkSystemHealth();
    
    // Poll every 5 seconds for "Live" feel
    setInterval(updateDashboardStats, 5000);
    setInterval(updateCharts, 10000); // Update charts less frequently
    setInterval(updateActivityTimeline, 15000); // Update timeline even less frequently
    setInterval(updateRecentAlerts, 10000); // Update alerts every 10 seconds
    setInterval(checkSystemHealth, 10000); // Check system health periodically
}
