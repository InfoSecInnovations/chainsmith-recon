/**
 * Chainsmith Recon - Shared JavaScript
 */

// ─── Session Management ────────────────────────────────────────
function getSessionId() {
    const params = new URLSearchParams(window.location.search);
    return params.get('session');
}

function setSessionId(sessionId) {
    const url = new URL(window.location);
    url.searchParams.set('session', sessionId);
    window.history.replaceState({}, '', url);
}

function navigateTo(page) {
    const sessionId = getSessionId();
    const url = sessionId ? `${page}?session=${sessionId}` : page;
    window.location.href = url;
}

// ─── API ───────────────────────────────────────────────────────
const api = {
    async reset() {
        const res = await fetch('/api/v1/reset', { method: 'POST' });
        const data = await res.json();
        if (data.session_id) setSessionId(data.session_id);
        return data;
    },

    async getSettings() { return (await fetch('/api/v1/settings')).json(); },

    async updateSettings(settings) {
        return (await fetch('/api/v1/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        })).json();
    },

    async getScope() { return (await fetch('/api/v1/scope')).json(); },

    async setScope(target, exclude, techniques, options = {}) {
        return (await fetch('/api/v1/scope', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target, exclude, techniques,
                scan_window: options.scan_window || null,
                proof_of_scope: options.proof_of_scope || null,
                outside_window_acknowledged: options.outside_window_acknowledged || false,
                scan_behavior: options.scan_behavior || null,
            })
        })).json();
    },

    async checkScanWindow() { return (await fetch('/api/v1/scope/window-check')).json(); },
    async getTrafficLog(limit = 100) { return (await fetch(`/api/v1/compliance/traffic?limit=${limit}`)).json(); },
    async getViolations() { return (await fetch('/api/v1/compliance/violations')).json(); },
    async generateComplianceReport() { return (await fetch('/api/v1/compliance/report', { method: 'POST' })).json(); },
    async getComplianceReport() { return (await fetch('/api/v1/compliance/report')).json(); },
    async startScan() { return (await fetch('/api/v1/scan', { method: 'POST' })).json(); },
    async pauseScan(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/scan/pause${qs}`, { method: 'POST' })).json();
    },
    async resumeScan(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/scan/resume${qs}`, { method: 'POST' })).json();
    },
    async stopScan(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/scan/stop${qs}`, { method: 'POST' })).json();
    },
    async getScanStatus(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/scan${qs}`)).json();
    },
    async getCheckStatuses(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/scan/checks${qs}`)).json();
    },
    async listLiveScans() { return (await fetch('/api/v1/scans/live')).json(); },
    async getObservations(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/observations${qs}`)).json();
    },
    async getObservationsByHost(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/observations/by-host${qs}`)).json();
    },
    async getChecks() { return (await fetch('/api/v1/checks')).json(); },
    async analyzeChains(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/chains/analyze${qs}`, { method: 'POST' })).json();
    },
    async retryChains(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/chains/retry${qs}`, { method: 'POST' })).json();
    },
    async getChains(scanId = null) {
        const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : '';
        return (await fetch(`/api/v1/chains${qs}`)).json();
    },
    async getChainDetail(chainId) { return (await fetch(`/api/v1/chains/${chainId}`)).json(); },
    async exportReport() { return (await fetch('/api/v1/export', { method: 'POST' })).json(); },
    async exportObservationsCsv(scanId) {
        const params = scanId ? `?scan_id=${scanId}` : '';
        return fetch(`/api/v1/observations/export/csv${params}`);
    },

    // ─── Scan History & Trends ────────────────────────────────
    async listScans(filters = {}, limit = null) {
        // Back-compat: allow listScans(targetString, limit) as well as
        // listScans({target, status, started_after, started_before, limit, offset}).
        if (typeof filters === 'string' || filters === null) {
            filters = filters ? { target: filters } : {};
        }
        if (limit != null && filters.limit == null) filters.limit = limit;
        const params = new URLSearchParams();
        if (filters.target) params.set('target', filters.target);
        if (filters.status) params.set('status', filters.status);
        if (filters.started_after) params.set('started_after', filters.started_after);
        if (filters.started_before) params.set('started_before', filters.started_before);
        if (filters.limit != null) params.set('limit', filters.limit);
        if (filters.offset != null) params.set('offset', filters.offset);
        return (await fetch(`/api/v1/scans?${params}`)).json();
    },
    async getScanDetail(scanId) {
        return (await fetch(`/api/v1/scans/${scanId}`)).json();
    },
    async getScanObservationsByHost(scanId) {
        return (await fetch(`/api/v1/scans/${scanId}/observations/by-host`)).json();
    },
    async getScanChains(scanId) {
        return (await fetch(`/api/v1/scans/${scanId}/chains`)).json();
    },
    async getScanLog(scanId) {
        return (await fetch(`/api/v1/scans/${scanId}/log`)).json();
    },
    async deleteScan(scanId) {
        return (await fetch(`/api/v1/scans/${scanId}`, { method: 'DELETE' })).json();
    },
    async getObservationHistory(fingerprint) {
        return (await fetch(`/api/v1/observations/${encodeURIComponent(fingerprint)}/history`)).json();
    },
    async compareScans(scanAId, scanBId) { return (await fetch(`/api/v1/scans/${scanAId}/compare/${scanBId}`)).json(); },
    async getTargetTrend(domain, filters = {}) {
        const params = new URLSearchParams();
        if (filters.since) params.set('since', filters.since);
        if (filters.until) params.set('until', filters.until);
        if (filters.last_n) params.set('last_n', filters.last_n);
        const qs = params.toString();
        return (await fetch(`/api/v1/targets/${encodeURIComponent(domain)}/trend${qs ? '?' + qs : ''}`)).json();
    },

    // ─── Capabilities ─────────────────────────────────────────
    async getCapabilities() { return (await fetch('/api/v1/capabilities')).json(); },

    // ─── Scan Observations (for targeted export) ──────────────────
    async getScanObservations(scanId, severityOrFilters = null, host = null) {
        // Back-compat: allow getScanObservations(scanId, "high") and
        // getScanObservations(scanId, { severity, host }).
        let filters = {};
        if (typeof severityOrFilters === 'string') {
            filters.severity = severityOrFilters;
            if (host) filters.host = host;
        } else if (severityOrFilters && typeof severityOrFilters === 'object') {
            filters = severityOrFilters;
        }
        const params = new URLSearchParams();
        if (filters.severity) params.set('severity', filters.severity);
        if (filters.host) params.set('host', filters.host);
        const qs = params.toString();
        return (await fetch(`/api/v1/scans/${scanId}/observations${qs ? '?' + qs : ''}`)).json();
    },

    // ─── Report Generation ─────────────────────────────────────
    async generateTechnicalReport(scanId, format = 'md') {
        const res = await fetch('/api/v1/reports/technical', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: scanId, format })
        });
        if (format === 'pdf') return res;
        return res.json();
    },
    async generateDeltaReport(scanAId, scanBId, format = 'md') {
        const res = await fetch('/api/v1/reports/delta', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_a_id: scanAId, scan_b_id: scanBId, format })
        });
        if (format === 'pdf') return res;
        return res.json();
    },
    async generateExecutiveReport(scanId, format = 'md') {
        const body = { scan_id: scanId, format };
        const res = await fetch('/api/v1/reports/executive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (format === 'pdf') return res;
        return res.json();
    },
    async generateComplianceReport(scanId, format = 'md') {
        const body = { scan_id: scanId, format };
        const res = await fetch('/api/v1/reports/compliance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (format === 'pdf') return res;
        return res.json();
    },
    async generateTrendReport(format = 'md', target = null) {
        const body = { format };
        if (target) body.target = target;
        const res = await fetch('/api/v1/reports/trend', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (format === 'pdf') return res;
        return res.json();
    },
    async generateTargetedExport(fingerprints, format = 'md', title = null) {
        const body = { fingerprints, format };
        if (title) body.title = title;
        const res = await fetch('/api/v1/reports/targeted', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (format === 'pdf') return res;
        return res.json();
    },

    // ─── Scenarios ─────────────────────────────────────────────
    async listScenarios() { return (await fetch('/api/v1/scenarios')).json(); },

    async loadScenario(name) {
        return (await fetch('/api/v1/scenarios/load', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        })).json();
    },

    async clearScenario() { return (await fetch('/api/v1/scenarios/clear', { method: 'POST' })).json(); },
    async getCurrentScenario() { return (await fetch('/api/v1/scenarios/current')).json(); },

    // ─── Profiles ────────────────────────────────────────────────
    async getProfiles() { return (await fetch('/api/v1/profiles')).json(); },
    async getProfile(name) { return (await fetch(`/api/v1/profiles/${name}`)).json(); },
    async getPreferences() { return (await fetch('/api/v1/preferences')).json(); },
    async updatePreferences(prefs) {
        return (await fetch('/api/v1/preferences', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(prefs)
        })).json();
    },
    async activateProfile(name) {
        return (await fetch(`/api/v1/profiles/${name}/activate`, { method: 'PUT' })).json();
    },
    async resolveProfile(name) { return (await fetch(`/api/v1/profiles/${name}/resolve`)).json(); }
};

// ─── Theme Management ──────────────────────────────────────────
function loadTheme() {
    if (localStorage.getItem('theme') === 'light')
        document.body.classList.add('theme-light');
}

function setTheme(theme) {
    document.body.classList.toggle('theme-light', theme === 'light');
    localStorage.setItem('theme', theme);
}

// ─── Accessibility Modes ───────────────────────────────────────
const A11Y_KEYS = {
    contrast: { storage: 'a11yContrast', className: 'a11y-contrast', media: '(prefers-contrast: more)' },
    'reduce-motion': { storage: 'a11yReduceMotion', className: 'a11y-reduce-motion', media: '(prefers-reduced-motion: reduce)' },
    'status-icons': { storage: 'a11yStatusIcons', className: 'a11y-status-icons', media: null }
};

function isA11yOn(key) {
    const cfg = A11Y_KEYS[key];
    if (!cfg) return false;
    const stored = localStorage.getItem(cfg.storage);
    if (stored !== null) return stored === 'true';
    return cfg.media ? window.matchMedia(cfg.media).matches : false;
}

function loadA11y() {
    Object.keys(A11Y_KEYS).forEach(key => {
        document.body.classList.toggle(A11Y_KEYS[key].className, isA11yOn(key));
    });
}

function setA11y(key, on) {
    const cfg = A11Y_KEYS[key];
    if (!cfg) return;
    document.body.classList.toggle(cfg.className, on);
    localStorage.setItem(cfg.storage, on ? 'true' : 'false');
}

// ─── Scenario Banner ───────────────────────────────────────────
async function updateScenarioBanner() {
    // Remove legacy full-width banner if present
    const legacyBanner = document.getElementById('scenario-banner');
    if (legacyBanner) {
        legacyBanner.style.display = 'none';
    }
    
    // Find or create inline badge in header
    let badge = document.getElementById('scenario-badge');
    
    try {
        const data = await api.getCurrentScenario();
        if (data.active) {
            if (!badge) {
                // Create badge after tagline in header
                const tagline = document.querySelector('.brand-tagline');
                if (tagline) {
                    badge = document.createElement('span');
                    badge.id = 'scenario-badge';
                    badge.className = 'scenario-badge';
                    tagline.insertAdjacentElement('afterend', badge);
                }
            }
            if (badge) {
                badge.innerHTML = `
                    <span class="scenario-label">Scenario</span>
                    <span class="scenario-name">${data.active.name}</span>
                `;
                badge.title = data.active.description || '';
                badge.style.display = 'inline-flex';
            }
        } else {
            if (badge) {
                badge.style.display = 'none';
            }
        }
    } catch (e) {
        if (badge) {
            badge.style.display = 'none';
        }
    }
}

// ─── Profile Selector ─────────────────────────────────────────────
async function loadProfileSelector() {
    const select = document.getElementById('setting-profile');
    if (!select) return;
    try {
        const data = await api.getProfiles();
        select.innerHTML = '';
        for (const p of (data.profiles || [])) {
            const opt = document.createElement('option');
            opt.value = p.name;
            opt.textContent = p.name + (p.built_in ? '' : ' (custom)');
            opt.title = p.description || '';
            if (p.active) opt.selected = true;
            select.appendChild(opt);
        }
        updateProfileDescription();
    } catch (e) {
        select.innerHTML = '<option value="">Error loading profiles</option>';
    }
}

async function updateProfileDescription() {
    const select = document.getElementById('setting-profile');
    const desc = document.getElementById('profile-description');
    if (!select || !desc) return;
    
    const name = select.value;
    if (!name) {
        desc.textContent = '';
        return;
    }
    
    try {
        const data = await api.getProfile(name);
        desc.textContent = data.profile?.description || '';
        
        // Update key settings display
        const prefs = data.resolved_preferences;
        const keySettings = document.getElementById('profile-key-settings');
        if (keySettings && prefs) {
            keySettings.innerHTML = `
                <div class="profile-setting">Timeout: ${prefs.network.timeout_seconds}s</div>
                <div class="profile-setting">Rate: ${prefs.rate_limiting.requests_per_second} req/s</div>
                <div class="profile-setting">Concurrent: ${prefs.network.max_concurrent_requests}</div>
                ${prefs.advanced.waf_evasion ? '<div class="profile-setting accent">WAF evasion: on</div>' : ''}
            `;
        }
    } catch (e) {
        desc.textContent = '';
    }
}

// ─── Scenario Selector (in settings drawer) ────────────────────
async function loadScenarioSelector() {
    const select = document.getElementById('setting-scenario');
    if (!select) return;
    try {
        const data = await api.listScenarios();
        const active = data.active ? data.active.name : '';
        select.innerHTML = '<option value="">— No scenario —</option>';
        for (const s of (data.scenarios || [])) {
            const opt = document.createElement('option');
            opt.value = s.name;
            opt.textContent = `${s.name} (${s.simulation_count} sims)`;
            opt.title = s.description || '';
            if (s.name === active) opt.selected = true;
            select.appendChild(opt);
        }
    } catch (e) {
        select.innerHTML = '<option value="">Error loading scenarios</option>';
    }
}

// ─── Settings Drawer ───────────────────────────────────────────
function initSettingsDrawer() {
    const overlay = document.getElementById('drawer-overlay');
    const drawer = document.getElementById('drawer-settings');
    const btnSettings = document.getElementById('btn-settings');
    const btnClose = document.getElementById('close-settings');

    if (!overlay || !drawer || !btnSettings) return;

    btnSettings.addEventListener('click', async () => {
        const settings = await api.getSettings();

        const parallel = document.getElementById('setting-parallel');
        const rate = document.getElementById('setting-rate');
        const verification = document.getElementById('setting-verification');
        const autoRedirect = document.getElementById('setting-auto-redirect');
        const autoChains = document.getElementById('setting-auto-chains');

        if (parallel) parallel.checked = settings.parallel;
        if (rate) rate.value = settings.rate_limit;
        if (verification) verification.value = settings.verification_level || 'none';
        if (autoRedirect) autoRedirect.checked = localStorage.getItem('autoRedirect') === 'true';
        if (autoChains) autoChains.checked = localStorage.getItem('autoChains') === 'true';

        document.querySelectorAll('.theme-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.theme === (localStorage.getItem('theme') || 'dark'));
        });

        Object.keys(A11Y_KEYS).forEach(key => {
            const cb = document.getElementById(`setting-a11y-${key}`);
            if (cb) cb.checked = isA11yOn(key);
        });

        await loadProfileSelector();
        await loadScenarioSelector();
        overlay.classList.add('open');
        drawer.classList.add('open');
    });

    btnClose?.addEventListener('click', () => {
        overlay.classList.remove('open');
        drawer.classList.remove('open');
    });

    overlay.addEventListener('click', () => {
        overlay.classList.remove('open');
        drawer.classList.remove('open');
    });

    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.theme-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            setTheme(btn.dataset.theme);
        });
    });

    document.getElementById('setting-parallel')?.addEventListener('change', saveSettings);
    document.getElementById('setting-rate')?.addEventListener('change', saveSettings);
    document.getElementById('setting-verification')?.addEventListener('change', saveSettings);
    document.getElementById('setting-auto-redirect')?.addEventListener('change', (e) => {
        localStorage.setItem('autoRedirect', e.target.checked);
    });
    document.getElementById('setting-auto-chains')?.addEventListener('change', (e) => {
        localStorage.setItem('autoChains', e.target.checked);
    });

    Object.keys(A11Y_KEYS).forEach(key => {
        document.getElementById(`setting-a11y-${key}`)?.addEventListener('change', (e) => {
            setA11y(key, e.target.checked);
        });
    });

    // Profile selector change handler
    document.getElementById('setting-profile')?.addEventListener('change', async (e) => {
        const name = e.target.value;
        if (name) {
            await api.activateProfile(name);
            await updateProfileDescription();
        }
    });

    // Scenario selector change handler
    document.getElementById('setting-scenario')?.addEventListener('change', async (e) => {
        const name = e.target.value;
        if (name) {
            await api.loadScenario(name);
        } else {
            await api.clearScenario();
        }
        await updateScenarioBanner();
    });

    document.getElementById('btn-export')?.addEventListener('click', async () => {
        const report = await api.exportReport();
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `recon-report-${report.session_id}.json`;
        a.click();
        URL.revokeObjectURL(url);
    });

    document.getElementById('btn-export-csv')?.addEventListener('click', async () => {
        const resp = await api.exportObservationsCsv();
        if (!resp.ok) { alert('CSV export failed'); return; }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'observations.csv';
        a.click();
        URL.revokeObjectURL(url);
    });

    document.getElementById('btn-reset')?.addEventListener('click', async () => {
        if (confirm('Reset all scan data and start fresh?')) {
            await api.reset();
            navigateTo('index.html');
        }
    });
}

async function saveSettings() {
    await api.updateSettings({
        parallel: document.getElementById('setting-parallel')?.checked || false,
        rate_limit: parseFloat(document.getElementById('setting-rate')?.value || '10'),
        verification_level: document.getElementById('setting-verification')?.value || 'none'
    });
}

// ─── Modal ─────────────────────────────────────────────────────
function initModal() {
    const overlay = document.getElementById('modal-overlay');
    document.getElementById('close-modal')?.addEventListener('click', closeModal);
    overlay?.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
}

function openModal(title, content) {
    const overlay = document.getElementById('modal-overlay');
    const titleEl = document.getElementById('modal-title');
    const bodyEl = document.getElementById('modal-body');
    if (titleEl) titleEl.textContent = title;
    if (bodyEl) bodyEl.innerHTML = content;
    overlay?.classList.add('open');
}

function closeModal() {
    document.getElementById('modal-overlay')?.classList.remove('open');
}

// ─── Header Status ─────────────────────────────────────────────
async function updateHeaderStatus() {
    const statusEl = document.getElementById('header-status');
    if (!statusEl) return;
    try {
        const scope = await api.getScope();
        const sid = (window.ScanSelector && ScanSelector.getSelectedScanId()) || null;
        const observations = await api.getObservations(sid);
        statusEl.innerHTML = scope.target
            ? `<strong>${scope.target}</strong> | ${observations.total || 0} observations`
            : '<em>No target set</em>';
    } catch (err) {
        statusEl.innerHTML = '<em>No target set</em>';
    }
}

// ─── Framework Badges ──────────────────────────────────────────
// Global check-name → frameworks[] lookup, populated once by loadFrameworkMap().
let _frameworkMap = {};

async function loadFrameworkMap() {
    try {
        const data = await api.getChecks();
        const checks = data.checks || [];
        _frameworkMap = {};
        for (const c of checks) {
            if (c.frameworks?.length > 0) {
                _frameworkMap[c.name] = c.frameworks;
            }
        }
    } catch (e) {
        console.warn('Could not load framework map:', e);
    }
}

function renderFrameworkBadges(frameworks, maxVisible = 5) {
    if (!frameworks || frameworks.length === 0) return '';
    const visible = frameworks.slice(0, maxVisible);
    const overflow = frameworks.length - maxVisible;
    const badges = visible.map(f =>
        `<a class="framework-badge" href="${f.url}" target="_blank" rel="noopener"` +
        ` style="background:${f.badge_color}"` +
        ` title="${f.framework} — ${f.tag_id}">${f.short_label} ${f.tag_id}</a>`
    ).join('');
    const more = overflow > 0
        ? `<span class="framework-badges-overflow">+${overflow} more</span>`
        : '';
    return `
        <div class="modal-section">
            <div class="modal-section-title">Compliance Frameworks</div>
            <div class="modal-section-content">
                <div class="framework-badges">${badges}${more}</div>
            </div>
        </div>`;
}

// ─── Check Modal Content ───────────────────────────────────────
function getCheckModalContent(check) {
    const simulatedBadge = check.simulated
        ? `<span class="simulated-badge" title="This check uses simulated data">simulated</span> `
        : '';
    return `
        <div class="modal-section">
            <div class="modal-section-title">${simulatedBadge}Description</div>
            <div class="modal-section-content">${check.description || 'No description'}</div>
        </div>
        ${check.reason ? `
        <div class="modal-section">
            <div class="modal-section-title">Why This Matters</div>
            <div class="modal-section-content">${check.reason}</div>
        </div>` : ''}
        ${check.techniques?.length > 0 ? `
        <div class="modal-section">
            <div class="modal-section-title">Techniques</div>
            <div class="modal-section-content">${check.techniques.join(', ')}</div>
        </div>` : ''}
        ${check.references?.length > 0 ? `
        <div class="modal-section">
            <div class="modal-section-title">References</div>
            <ul class="modal-list">
                ${check.references.map(ref => `<li>${ref}</li>`).join('')}
            </ul>
        </div>` : ''}
        ${renderFrameworkBadges(check.frameworks)}
    `;
}

// ─── Observation Modal Content ─────────────────────────────────────
function getObservationModalContent(observation, chains = []) {
    // Find chains that include this observation
    const relatedChains = chains.filter(c => c.observation_ids?.includes(observation.id));
    const chainLinks = relatedChains.length > 0 
        ? `<div class="modal-section">
            <div class="modal-section-title">Part of Attack Chain</div>
            <div class="modal-section-content">
                ${relatedChains.map(c => `<a href="#" class="chain-link" data-chain-id="${c.id}" style="color:var(--accent);text-decoration:underline;cursor:pointer">${c.title}</a>`).join(', ')}
            </div>
        </div>` 
        : '';
    
    return `
        <div class="modal-section">
            <div class="modal-section-title">Severity</div>
            <div class="modal-section-content">
                <span class="severity-badge severity-${observation.severity}">${observation.severity}</span>
            </div>
        </div>
        <div class="modal-section">
            <div class="modal-section-title">Description</div>
            <div class="modal-section-content">${observation.description || 'No description'}</div>
        </div>
        ${observation.target_url ? `
        <div class="modal-section">
            <div class="modal-section-title">Target URL</div>
            <div class="modal-section-content" style="word-break:break-all">${observation.target_url}</div>
        </div>` : ''}
        ${observation.evidence ? `
        <div class="modal-section">
            <div class="modal-section-title">Evidence</div>
            <div class="modal-section-content" style="font-family:monospace;background:var(--bg-tertiary);padding:8px;border-radius:4px;white-space:pre-wrap">${observation.evidence}</div>
        </div>` : ''}
        ${observation.check_name ? `
        <div class="modal-section">
            <div class="modal-section-title">Discovered By</div>
            <div class="modal-section-content">${observation.check_name}</div>
        </div>` : ''}
        ${renderFrameworkBadges(observation.check_name ? _frameworkMap[observation.check_name] : null)}
        ${chainLinks}
    `;
}

// ─── Chain Modal Content ───────────────────────────────────────
function getChainModalContent(chain, observations) {
    const stepsHtml = chain.exploitation_steps?.length > 0
        ? `<ol style="list-style:decimal;padding-left:20px;margin:0">
            ${chain.exploitation_steps.map(s => `<li style="margin-bottom:8px">${s}</li>`).join('')}
           </ol>`
        : '<p>No attack path defined</p>';
    return `
        <div class="modal-section">
            <div style="display:flex;gap:8px;align-items:center">
                <span class="severity-badge severity-${chain.severity}">${chain.severity}</span>
                <span class="chain-source-badge ${chain.source}">${chain.source}</span>
            </div>
        </div>
        <div class="modal-section">
            <div class="modal-section-title">Description</div>
            <div class="modal-section-content">${chain.description || 'No description'}</div>
        </div>
        <div class="modal-section">
            <div class="modal-section-title">Related Observations</div>
            <div class="modal-section-content">
                ${chain.observation_ids.map(id => {
                    const f = observations.find(f => f.id === id);
                    return `<a href="#" class="observation-link chain-observation-tag" data-observation-id="${id}" style="margin-right:4px;margin-bottom:4px;display:inline-block;cursor:pointer;text-decoration:none">${id}: ${f ? f.title : 'Unknown'}</a>`;
                }).join('')}
            </div>
        </div>
        <div class="modal-section">
            <div class="modal-section-title">Potential Attack Path</div>
            <div class="modal-section-content">${stepsHtml}</div>
        </div>
        ${chain.llm_reasoning ? `
        <div class="modal-section">
            <div class="modal-section-title">LLM Reasoning</div>
            <div class="modal-section-content" style="font-style:italic;color:var(--text-secondary)">${chain.llm_reasoning}</div>
        </div>` : ''}
        ${chain.pattern_name ? `
        <div class="modal-section">
            <div class="modal-section-title">Pattern</div>
            <div class="modal-section-content">${chain.pattern_name}</div>
        </div>` : ''}
    `;
}

// ─── Modal Cross-Link Handlers ────────────────────────────────
// Call this after opening a modal to enable observation<->chain links
function initModalCrossLinks(observations, chains, onOpenFinding, onOpenChain) {
    // Handle clicks on observation links (in chain modals)
    document.querySelectorAll('.observation-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const observationId = link.dataset.observationId;
            const observation = observations.find(f => f.id === observationId);
            if (observation && onOpenFinding) {
                onOpenFinding(observation);
            }
        });
    });
    
    // Handle clicks on chain links (in observation modals)
    document.querySelectorAll('.chain-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const chainId = link.dataset.chainId;
            const chain = chains.find(c => c.id === chainId);
            if (chain && onOpenChain) {
                onOpenChain(chain);
            }
        });
    });
}

// ─── Toast Notifications ──────────────────────────────────────
function showStatus(message, type) {
    const el = document.getElementById('status-message');
    if (!el) return;
    el.textContent = message;
    el.className = 'status-message ' + type;
    el.style.display = 'block';
    setTimeout(() => {
        el.style.display = 'none';
    }, 3000);
}

// ─── Initialize Common Elements ────────────────────────────────
function initCommon() {
    loadTheme();
    loadA11y();
    initSettingsDrawer();
    initModal();
    updateHeaderStatus();
    updateScenarioBanner();
}
