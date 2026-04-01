class PhishingDetector {
    constructor() {
        this.currentSessionId = localStorage.getItem('lastPhishingSessionId');
        this.isMonitoring = false;
        this.results = [];
        this.autoRefreshInterval = null;

        this.initializeElements();
        this.bindEvents();

        this.restoreState().then(() => {
            this.loadHistory();
            this.startAutoRefresh();
        });

        window.addEventListener('beforeunload', () => {
            this.saveState();
            this.stopAutoRefresh();
        });
    }

    initializeElements() {
        this.urlInput = document.getElementById('phishingUrlInput');
        this.scanBtn = document.getElementById('phishingScanBtn');

        this.monitoringToggleBtn = document.getElementById('monitoringToggleBtn');
        this.startBtn = document.getElementById('startBtn') || this.monitoringToggleBtn;
        this.stopBtn = document.getElementById('stopBtn') || null;

        this.monitoringStatus = document.getElementById('monitoringStatus');
        this.resultsContainer = document.getElementById('resultsContainer') || document.getElementById('phishingHistory');
        this.browserHistoryContainer = document.getElementById('browserHistory');
        this.browserHistoryCount = document.getElementById('browserHistoryCount');

        this.resultsPanel = document.getElementById('phishingResults');
        this.emptyPanel = document.getElementById('phishingEmptyState');
        this.statusBadge = document.getElementById('phishingStatus');
        this.scannedUrl = document.getElementById('scannedUrl');
        this.riskScoreValue = document.getElementById('riskScoreValue');
        this.riskBarFill = document.getElementById('riskBarFill');
        this.reasonsList = document.getElementById('reasonsList');
        this.featuresList = document.getElementById('featuresList');

        this.toastContainer = document.body;
    }

    bindEvents() {
        if (this.scanBtn) {
            this.scanBtn.addEventListener('click', () => this.scanUrl());
        }

        if (this.urlInput) {
            this.urlInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.scanUrl();
            });
        }

        if (this.startBtn && this.stopBtn && this.startBtn !== this.stopBtn) {
            this.startBtn.addEventListener('click', () => this.startMonitoring());
            this.stopBtn.addEventListener('click', () => this.stopMonitoring());
        } else if (this.monitoringToggleBtn) {
            this.monitoringToggleBtn.addEventListener('click', () => {
                if (this.isMonitoring) {
                    this.stopMonitoring();
                } else {
                    this.startMonitoring();
                }
            });
        }
    }

    async restoreState() {
        try {
            const appStartTime = sessionStorage.getItem('phishingAppStartTime');
            const now = Date.now();
            const isFreshStart = !appStartTime || (now - parseInt(appStartTime) > 300000);

            if (isFreshStart) {
                sessionStorage.removeItem('phishingDetectorState');
                sessionStorage.setItem('phishingAppStartTime', now.toString());
                console.log('🆕 Phishing: Fresh app start - cleared state');
                return false;
            }

            const savedState = sessionStorage.getItem('phishingDetectorState');
            if (!savedState) return false;

            const state = JSON.parse(savedState);
            if (state.lastSaveTime && (now - state.lastSaveTime) < 7200000) {
                this.results = state.results || [];
                this.currentSessionId = state.currentSessionId;
                this.isMonitoring = state.isMonitoring || false;

                this.setMonitoringUI(this.isMonitoring);
                this.renderResults(this.results);
                this.showToast('Session Restored', `${this.results.length} scan results loaded`, 'info');
                console.log(`✅ Phishing: Restored ${this.results.length} results`);
                return true;
            }
        } catch (error) {
            console.warn('Failed to restore phishing state:', error);
        }
        return false;
    }

    saveState() {
        const state = {
            results: this.results.slice(0, 100),
            currentSessionId: this.currentSessionId,
            isMonitoring: this.isMonitoring,
            lastSaveTime: Date.now()
        };

        try {
            sessionStorage.setItem('phishingDetectorState', JSON.stringify(state));
            if (this.currentSessionId) {
                localStorage.setItem('lastPhishingSessionId', this.currentSessionId);
            }
            console.log(`💾 Phishing: Saved ${state.results.length} results`);
        } catch (error) {
            console.warn('Failed to save phishing state:', error);
        }
    }

    startAutoRefresh() {
        if (this.autoRefreshInterval) return;

        this.autoRefreshInterval = setInterval(async () => {
            await this.loadHistory();
            await this.loadBrowserHistory();
        }, 3000);

        console.log('🔄 Phishing: Auto-refresh started');
    }

    stopAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
            this.autoRefreshInterval = null;
        }
    }

    async loadHistory() {
        try {
            const response = await fetch('/api/phishing/history');
            if (response.ok) {
                const data = await response.json();

                this.results = (data.results || []).map(result => this.normalizeResult(result));
                this.renderResults(this.results);
                this.updateStats(data.count || this.results.length);
                this.saveState();
            }
        } catch (error) {
            console.warn('Failed to load phishing history:', error);
        }
    }

    renderResults(results) {
        if (!this.resultsContainer) return;

        if (!results || results.length === 0) {
            this.resultsContainer.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <p>No scan results yet</p>
                    <p>Start monitoring or scan manually</p>
                </div>
            `;
            return;
        }

        this.resultsContainer.innerHTML = results.map(result => {
            const normalized = this.normalizeResult(result);
            const risk = Math.round(Number(normalized.risk_score ?? 0));
            const status = normalized.result || 'safe';
            const url = normalized.url || '-';
            return `
                <div class="result-row ${status === 'phishing' || status === 'malicious' ? 'danger' : ''}" title="${url}">
                    <div class="url" data-full-url="${url}">${this.truncateUrl(url)}</div>
                    <div class="risk">${risk}%</div>
                    <div class="status ${status}">${status.toUpperCase()}</div>
                    <div class="timestamp">${new Date(normalized.timestamp).toLocaleTimeString()}</div>
                    <div class="source">${normalized.source || 'manual'}</div>
                    <div class="detection-method">${normalized.detection_method || 'gsb'}</div>
                </div>
            `;
        }).join('');
    }

    truncateUrl(url, maxLength = 50) {
        if (!url || url.length <= maxLength) return url || '-';
        try {
            const base = new URL(url).hostname;
            return `${base}/...`;
        } catch (error) {
            return `${url.slice(0, maxLength - 3)}...`;
        }
    }

    async startMonitoring() {
        this.isMonitoring = true;
        this.setMonitoringUI(true);

        try {
            const response = await fetch('/api/phishing/monitor/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sessionId: this.currentSessionId })
            });

            if (!response.ok) throw new Error(`Start failed: ${response.status}`);

            this.showToast('Monitoring Started', 'Chrome history scanning active...', 'success');
            this.saveState();

            setTimeout(() => {
                fetch('/api/phishing-to-vuln', { method: 'POST' })
                    .then(() => {
                        this.showToast('Auto-Vuln Scan', 'Suspicious links queued for vuln scanning', 'info');
                    })
                    .catch(() => {});
            }, 10000);
        } catch (error) {
            console.error('Monitor start failed:', error);
            this.resetMonitoringUI();
        }
    }

    async stopMonitoring() {
        this.isMonitoring = false;
        this.setMonitoringUI(false);

        try {
            await fetch('/api/phishing/monitor/stop', { method: 'POST' });
            this.showToast('Monitoring Stopped', 'Chrome history scanning stopped', 'info');
        } catch (error) {
            console.error('Monitor stop failed:', error);
        }

        this.saveState();
    }

    async scanUrl() {
        const url = this.urlInput?.value?.trim();
        if (!url) return;

        this.setScanButtonLoading(true);
        try {
            const response = await fetch('/api/analyze/phishing', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url,
                    session_id: this.currentSessionId
                })
            });

            if (!response.ok) {
                throw new Error(`Phishing scan failed: ${response.status}`);
            }

            const result = await response.json();
            if (result.session_id) {
                this.currentSessionId = result.session_id;
                localStorage.setItem('lastPhishingSessionId', result.session_id);
            }

            this.displayLatestResult(result);
            await this.loadHistory();
        } catch (error) {
            console.error('Error making phishing scan API call:', error);
            this.showToast('Scan Failed', 'Check server logs and try again', 'error');
        } finally {
            this.setScanButtonLoading(false);
        }
    }

    displayLatestResult(result) {
        if (!this.resultsPanel || !this.emptyPanel) return;

        const normalized = this.normalizeResult(result);
        const status = normalized.result || 'safe';
        const riskScore = Math.round(Number(normalized.risk_score || 0));

        this.emptyPanel.classList.add('hidden');
        this.resultsPanel.classList.remove('hidden');

        if (this.statusBadge) {
            this.statusBadge.className = `status-badge ${status}`;
            this.statusBadge.innerHTML = `<span>${status.toUpperCase()}</span>`;
        }

        if (this.scannedUrl) this.scannedUrl.textContent = normalized.url || '-';
        if (this.riskScoreValue) {
            this.riskScoreValue.textContent = `${riskScore}/100`;
            this.riskScoreValue.className = `risk-value ${status}`;
        }
        if (this.riskBarFill) {
            this.riskBarFill.className = `risk-bar-fill ${status}`;
            this.riskBarFill.style.width = `${riskScore}%`;
        }

        const reasons = [
            `Google Safe Browsing: ${result.gsb_status || 'UNKNOWN'}`,
            `ML verdict: ${result.ml_verdict || 'Unknown'} (${Math.round((Number(result.ml_confidence || 0)) * 100)}%)`,
            `Final verdict: ${result.final_verdict || 'UNKNOWN'}`
        ];

        if (this.reasonsList) {
            this.reasonsList.innerHTML = reasons.map(reason => `<div class="reason-item"><span>${reason}</span></div>`).join('');
        }

        const features = [
            { name: 'GSB Status', value: result.gsb_status || 'UNKNOWN' },
            { name: 'ML Verdict', value: result.ml_verdict || 'Unknown' },
            { name: 'ML Confidence', value: `${Math.round((Number(result.ml_confidence || 0)) * 100)}%` },
            { name: 'Final Verdict', value: result.final_verdict || 'UNKNOWN' }
        ];

        if (this.featuresList) {
            this.featuresList.innerHTML = features.map(feature => `
                <div class="feature-item">
                    <div class="feature-header">
                        <span class="feature-name">${feature.name}</span>
                    </div>
                    <div class="feature-value">${feature.value}</div>
                </div>
            `).join('');
        }
    }

    async loadBrowserHistory() {
        if (!this.isMonitoring || !this.browserHistoryContainer) return;

        try {
            const response = await fetch('/api/phishing/browser-history?limit=50');
            if (response.ok) {
                const data = await response.json();
                if (this.browserHistoryCount) {
                    this.browserHistoryCount.textContent = `(${data.total || 0} URLs)`;
                }

                const urls = data.urls || [];
                if (urls.length === 0) {
                    this.browserHistoryContainer.innerHTML = '<p style="color: #999; text-align: center; padding: 20px;">No URLs captured yet</p>';
                    return;
                }

                this.browserHistoryContainer.innerHTML = urls.map(item => `
                    <div class="history-item">
                        <div class="history-url" title="${item.url}" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${item.url}</div>
                        <div class="history-meta"><span>${new Date(item.timestamp).toLocaleTimeString()}</span></div>
                    </div>
                `).join('');
            }
        } catch (error) {
            console.warn('Failed to load browser history:', error);
        }
    }

    setScanButtonLoading(isLoading) {
        if (!this.scanBtn) return;

        if (isLoading) {
            this.scanBtn.disabled = true;
            this.scanBtn.textContent = 'Scanning...';
            return;
        }

        this.scanBtn.disabled = false;
        this.scanBtn.textContent = 'Scan';
    }

    setMonitoringUI(isActive) {
        if (this.startBtn && this.stopBtn && this.startBtn !== this.stopBtn) {
            this.startBtn.disabled = isActive;
            this.stopBtn.disabled = !isActive;
        }

        if (this.monitoringToggleBtn) {
            this.monitoringToggleBtn.style.background = isActive ? '#f44336' : '#4CAF50';
            this.monitoringToggleBtn.innerHTML = isActive
                ? `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <rect x="9" y="9" width="6" height="6"></rect>
                    </svg>
                    Stop Monitoring
                `
                : `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <polyline points="12 6 12 12 16 14"></polyline>
                    </svg>
                    Start Monitoring
                `;
        }

        if (this.monitoringStatus) {
            this.monitoringStatus.textContent = isActive ? 'Monitoring...' : 'Idle';
            this.monitoringStatus.style.color = isActive ? '#4CAF50' : '#666';
            this.monitoringStatus.classList.toggle('active', isActive);
        }
    }

    updateStats(count) {
        if (this.browserHistoryCount) {
            this.browserHistoryCount.textContent = `(${count} results)`;
        }

        if (this.emptyPanel && this.resultsPanel) {
            if (count > 0) {
                this.emptyPanel.classList.add('hidden');
                this.resultsPanel.classList.remove('hidden');
            }
        }
    }

    normalizeResult(result) {
        const verdict = (result.result || result.final_verdict || '').toString().toUpperCase();
        const mapped = verdict === 'MALICIOUS' || verdict === 'PHISHING'
            ? 'malicious'
            : (verdict === 'SUSPICIOUS' || verdict === 'WARNING')
                ? 'suspicious'
                : 'safe';

        const risk = result.risk_score !== undefined
            ? Number(result.risk_score)
            : Math.max(0, Math.min(100, Math.round((Number(result.ml_confidence || 0)) * 100)));

        return {
            ...result,
            result: mapped,
            risk_score: risk,
            timestamp: result.timestamp || new Date().toISOString(),
            url: result.url || '-'
        };
    }

    resetMonitoringUI() {
        this.isMonitoring = false;
        this.setMonitoringUI(false);
    }

    showToast(title, description, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.style.position = 'fixed';
        toast.style.right = '1rem';
        toast.style.bottom = '1rem';
        toast.style.background = '#1f2937';
        toast.style.color = '#fff';
        toast.style.padding = '0.75rem 1rem';
        toast.style.borderRadius = '8px';
        toast.style.zIndex = '9999';
        toast.innerHTML = `<strong>${title}</strong><div style="font-size:12px;opacity:.9;">${description}</div>`;

        this.toastContainer.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
});
