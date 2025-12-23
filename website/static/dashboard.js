// Dashboard Page JavaScript

let networkChart = null;
let threatChart = null;

const dashboardState = {
    stats: {
        packetsCaptures: 45231,
        alerts: 12,
        suspiciousUrls: 8,
        vulnerableSites: 3
    },
    networkData: [
        { time: '14:00', traffic: 450 },
        { time: '14:05', traffic: 520 },
        { time: '14:10', traffic: 380 },
        { time: '14:15', traffic: 680 },
        { time: '14:20', traffic: 590 },
        { time: '14:25', traffic: 720 }
    ]
};

document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

function initializeDashboard() {
    renderAlerts();
    renderTimeline();
    createNetworkChart();
    createThreatChart();
    startDashboardUpdates();
}

function renderAlerts() {
    const alerts = [
        { id: 1, time: '14:23:15', severity: 'critical', message: 'SQL Injection attempt detected on target.example.com' },
        { id: 2, time: '14:20:42', severity: 'high', message: 'Phishing URL detected: malicious-site.com/login' },
        { id: 3, time: '14:18:30', severity: 'medium', message: 'Unusual traffic pattern from IP 192.168.1.45' },
        { id: 4, time: '14:15:12', severity: 'low', message: 'Port scan detected from external source' },
        { id: 5, time: '14:10:05', severity: 'high', message: 'XSS vulnerability found in web application' }
    ];

    const alertsList = document.getElementById('alertsList');
    alertsList.innerHTML = alerts.map(alert => `
        <div class="alert-item">
            <span class="alert-severity ${alert.severity}">${alert.severity}</span>
            <div class="alert-content">
                <div class="alert-message">${alert.message}</div>
                <div class="alert-time">${alert.time}</div>
            </div>
        </div>
    `).join('');
}

function renderTimeline() {
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
            labels: dashboardState.networkData.map(d => d.time),
            datasets: [{
                label: 'Traffic',
                data: dashboardState.networkData.map(d => d.traffic),
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
    const threatData = [
        { name: 'Malware', value: 35, color: '#ef4444' },
        { name: 'Phishing', value: 28, color: '#f97316' },
        { name: 'DDoS', value: 15, color: '#eab308' },
        { name: 'SQL Injection', value: 12, color: '#06b6d4' },
        { name: 'Other', value: 10, color: '#8b5cf6' }
    ];

    const ctx = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: threatData.map(d => d.name),
            datasets: [{
                data: threatData.map(d => d.value),
                backgroundColor: threatData.map(d => d.color),
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
    legend.innerHTML = threatData.map(item => `
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
    setInterval(() => {
        // Update stats with animation
        dashboardState.stats.packetsCaptures += Math.floor(Math.random() * 100);
        
        if (Math.random() > 0.8) {
            dashboardState.stats.alerts++;
            // Update badge with animation
            const badge = document.getElementById('alertBadge');
            badge.textContent = '+' + dashboardState.stats.alerts;
            badge.style.animation = 'none';
            setTimeout(() => {
                badge.style.animation = 'pulse 0.5s ease-out';
            }, 10);
        }
        
        if (Math.random() > 0.9) dashboardState.stats.suspiciousUrls++;
        if (Math.random() > 0.95) dashboardState.stats.vulnerableSites++;

        // Animate counter updates
        animateValue('packetsCount', dashboardState.stats.packetsCaptures);
        document.getElementById('alertsCount').textContent = dashboardState.stats.alerts;
        document.getElementById('urlsCount').textContent = dashboardState.stats.suspiciousUrls;
        document.getElementById('vulnCount').textContent = dashboardState.stats.vulnerableSites;

        // Update network chart
        dashboardState.networkData.shift();
        const lastTime = dashboardState.networkData[dashboardState.networkData.length - 1].time;
        const [hours, minutes] = lastTime.split(':').map(Number);
        const newMinutes = (minutes + 5) % 60;
        const newTime = hours + ':' + String(newMinutes).padStart(2, '0');
        
        dashboardState.networkData.push({
            time: newTime,
            traffic: Math.floor(Math.random() * 400) + 300
        });

        if (networkChart) {
            networkChart.data.labels = dashboardState.networkData.map(d => d.time);
            networkChart.data.datasets[0].data = dashboardState.networkData.map(d => d.traffic);
            networkChart.update('none');
        }
    }, 3000);
}

function animateValue(id, value) {
    const element = document.getElementById(id);
    element.textContent = value.toLocaleString();
    element.style.animation = 'none';
    setTimeout(() => {
        element.style.animation = 'fadeIn 0.5s ease-out';
    }, 10);
}
