// Phishing Detector Page JavaScript

const phishingState = {
    history: []
};

document.addEventListener('DOMContentLoaded', function() {
    initializePhishingDetector();
    loadHistory();
});

function initializePhishingDetector() {
    const scanBtn = document.getElementById('phishingScanBtn');
    const urlInput = document.getElementById('phishingUrlInput');

    scanBtn.addEventListener('click', () => scanPhishingUrl());
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') scanPhishingUrl();
    });
}

async function scanPhishingUrl() {
    const urlInput = document.getElementById('phishingUrlInput');
    const url = urlInput.value.trim();

    if (!url) return;

    const scanBtn = document.getElementById('phishingScanBtn');
    scanBtn.disabled = true;
    scanBtn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spinning">
            <circle cx="12" cy="12" r="10"></circle>
        </svg>
        Scanning...
    `;

    // Add spinning animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .spinning { animation: spin 1s linear infinite; }
    `;
    document.head.appendChild(style);

    // Simulate scanning
    await new Promise(resolve => setTimeout(resolve, 2000));

    const riskScore = Math.floor(Math.random() * 100);
    const status = riskScore < 30 ? 'safe' : riskScore < 70 ? 'suspicious' : 'malicious';

    const reasons = status === 'malicious' 
        ? [
            'Domain registered less than 30 days ago',
            'Uses HTTPS but certificate is self-signed',
            'Contains suspicious keywords in URL',
            'Similar to known phishing domains'
        ]
        : status === 'suspicious'
        ? [
            'Domain age is relatively new (3 months)',
            'No WHOIS protection information',
            'Unusual TLD usage'
        ]
        : [
            'Well-established domain (10+ years)',
            'Valid SSL certificate',
            'No suspicious patterns detected'
        ];

    const features = [
        { name: 'URL Length', value: url.length + ' characters', risk: url.length > 75 ? 'high' : url.length > 50 ? 'medium' : 'low' },
        { name: 'Has HTTPS', value: url.startsWith('https') ? 'Yes' : 'No', risk: url.startsWith('https') ? 'low' : 'high' },
        { name: 'Domain Age', value: status === 'malicious' ? '< 30 days' : status === 'suspicious' ? '3 months' : '10+ years', risk: status === 'malicious' ? 'high' : status === 'suspicious' ? 'medium' : 'low' },
        { name: 'Special Characters', value: (url.match(/[^a-zA-Z0-9:/.?=&-]/g) || []).length.toString(), risk: (url.match(/[^a-zA-Z0-9:/.?=&-]/g) || []).length > 5 ? 'high' : 'low' },
        { name: 'Suspicious Keywords', value: /(login|secure|bank|verify|account)/i.test(url) ? 'Found' : 'None', risk: /(login|secure|bank|verify|account)/i.test(url) ? 'medium' : 'low' }
    ];

    displayPhishingResults(url, riskScore, status, reasons, features);

    // Add to history
    phishingState.history.unshift({
        url,
        riskScore,
        status,
        timestamp: formatDateTime()
    });
    saveHistory();
    renderPhishingHistory();

    scanBtn.disabled = false;
    scanBtn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"></circle>
            <path d="m21 21-4.35-4.35"></path>
        </svg>
        Scan
    `;
}

function displayPhishingResults(url, riskScore, status, reasons, features) {
    document.getElementById('phishingEmptyState').classList.add('hidden');
    document.getElementById('phishingResults').classList.remove('hidden');

    // Status badge
    const statusBadge = document.getElementById('phishingStatus');
    statusBadge.className = 'status-badge ' + status;
    statusBadge.innerHTML = `
        ${getStatusIcon(status)}
        <span>${status}</span>
    `;

    // URL
    document.getElementById('scannedUrl').textContent = url;

    // Risk score with animation
    const riskValue = document.getElementById('riskScoreValue');
    riskValue.textContent = riskScore + '/100';
    riskValue.className = 'risk-value ' + status;

    const riskBarFill = document.getElementById('riskBarFill');
    riskBarFill.className = 'risk-bar-fill ' + status;
    // Animate from 0 to actual value
    setTimeout(() => {
        riskBarFill.style.width = riskScore + '%';
    }, 100);

    // Reasons with staggered animation
    const reasonsList = document.getElementById('reasonsList');
    reasonsList.innerHTML = reasons.map((reason, index) => `
        <div class="reason-item" style="animation-delay: ${index * 0.1}s">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
            <span>${reason}</span>
        </div>
    `).join('');

    // Features with staggered animation
    const featuresList = document.getElementById('featuresList');
    featuresList.innerHTML = features.map((feature, index) => `
        <div class="feature-item" style="animation-delay: ${index * 0.1}s">
            <div class="feature-header">
                <span class="feature-name">${feature.name}</span>
                <span class="feature-risk ${feature.risk}">${feature.risk}</span>
            </div>
            <div class="feature-value">${feature.value}</div>
        </div>
    `).join('');
}

function renderPhishingHistory() {
    const history = document.getElementById('phishingHistory');
    history.innerHTML = phishingState.history.slice(0, 5).map((item, index) => `
        <div class="history-item" style="animation-delay: ${index * 0.05}s">
            <div class="status-badge ${item.status}">
                ${getStatusIcon(item.status)}
                <span>${item.status}</span>
            </div>
            <div class="history-url">${item.url}</div>
            <div class="history-meta">
                <span>Risk: ${item.riskScore}/100</span>
                <span>${item.timestamp.split(' ')[1]}</span>
            </div>
        </div>
    `).join('');
}

function getStatusIcon(status) {
    if (status === 'safe') {
        return '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
    } else if (status === 'suspicious') {
        return '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
    } else {
        return '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    }
}

function saveHistory() {
    try {
        localStorage.setItem('phishingHistory', JSON.stringify(phishingState.history.slice(0, 10)));
    } catch (e) {
        console.error('Failed to save history:', e);
    }
}

function loadHistory() {
    try {
        const saved = localStorage.getItem('phishingHistory');
        if (saved) {
            phishingState.history = JSON.parse(saved);
            if (phishingState.history.length > 0) {
                renderPhishingHistory();
            }
        }
    } catch (e) {
        console.error('Failed to load history:', e);
    }
}
