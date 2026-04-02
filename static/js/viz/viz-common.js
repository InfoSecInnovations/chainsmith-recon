/**
 * Chainsmith Viz — shared visualization infrastructure.
 *
 * Provides:
 *  - ChainsmithViz namespace
 *  - Severity color palette & ordering
 *  - Suite color palette & ordering
 *  - Tooltip factory (show / move / hide)
 *  - Resize debounce factory
 *  - CSS variable reader (theme helper)
 *  - inferSuite() — maps check names to suite categories
 *  - Host normalization helpers
 *
 * Load order: D3 → viz-common.js → individual viz modules.
 */

window.ChainsmithViz = window.ChainsmithViz || {};

(function (ns) {
    'use strict';

    // ─── Severity palette ──────────────────────────────────────────
    ns.SEV_COLORS = {
        critical: '#991b1b',
        high:     '#dc2626',
        medium:   '#f59e0b',
        low:      '#4a9eff',
        info:     '#6b7280',
        none:     '#1e293b',
    };

    ns.SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

    ns.SEV_WEIGHTS = {
        critical: 16,
        high:     8,
        medium:   4,
        low:      2,
        info:     1,
    };

    // Host-table severity gradient (distinct from viz palette)
    ns.HOST_SEV_COLORS = {
        critical: '#b91c1c',
        high:     '#dc2626',
        medium:   '#f87171',
        low:      '#fca5a5',
        info:     '#fecaca',
    };

    // Sankey-specific severity colors (brighter for dark background links)
    ns.SANKEY_SEV_COLORS = {
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#3b82f6',
        info:     '#64748b',
    };

    // ─── Coverage status colors ────────────────────────────────────
    ns.COVERAGE_STATUS_COLORS = {
        completed: '#4ade80',
        found:     '#f59e0b',
        skipped:   '#6b7280',
        error:     '#ef4444',
        'not-run': '#1e293b',
    };

    // ─── Suite palette ─────────────────────────────────────────────
    ns.SUITE_COLORS = {
        web:     '#4a9eff',
        network: '#8b5cf6',
        ai:      '#f59e0b',
        mcp:     '#ec4899',
        agent:   '#10b981',
        rag:     '#06b6d4',
        cag:     '#f97316',
        unknown: '#6b7280',
    };

    ns.KNOWN_SUITES = ['web', 'network', 'ai', 'mcp', 'agent', 'rag', 'cag'];

    // Chain source colors
    ns.SOURCE_COLORS = {
        'rule-based': '#4a9eff',
        'llm':        '#4ade80',
        'both':       '#fbbf24',
    };

    // Timeline dot radii
    ns.TIMELINE_SEV_RADII = {
        critical: 10,
        high:     8,
        medium:   6,
        low:      5,
        info:     4,
    };

    // ─── Suite inference ───────────────────────────────────────────
    const SUITE_PATTERNS = {
        network: ['dns', 'service_probe', 'port'],
        web:     ['header', 'robots', 'path', 'openapi', 'cors', 'content'],
        ai:      ['llm', 'embedding', 'model', 'fingerprint', 'error', 'tool', 'prompt', 'rate', 'filter', 'context'],
        mcp:     ['mcp'],
        agent:   ['agent', 'goal'],
        rag:     ['rag', 'indirect'],
        cag:     ['cag', 'cache'],
    };

    ns.inferSuite = function (checkName) {
        if (!checkName) return 'other';
        var lower = checkName.toLowerCase();
        for (var suite in SUITE_PATTERNS) {
            if (SUITE_PATTERNS[suite].some(function (p) { return lower.includes(p); })) return suite;
        }
        return 'other';
    };

    // Keep backward compat — some code references window.inferSuite
    window.inferSuite = ns.inferSuite;

    // ─── Host normalization ────────────────────────────────────────
    /**
     * Normalize host string: strip URL components & ports.
     * "http://api.example.com:8080/foo" → "api.example.com"
     * "example.com:443" → "example.com"
     */
    ns.normalizeHost = function (name) {
        try {
            if (/^https?:\/\//i.test(name)) {
                return new URL(name).hostname;
            }
        } catch (e) { /* fall through */ }
        return name.replace(/:\d+$/, '');
    };

    // ─── Severity helpers ──────────────────────────────────────────
    ns.worstSeverity = function (findings) {
        for (var i = 0; i < ns.SEV_ORDER.length; i++) {
            var sev = ns.SEV_ORDER[i];
            if (findings.some(function (f) { return f.severity === sev; })) return sev;
        }
        return 'info';
    };

    ns.severityBreakdown = function (findings) {
        var counts = {};
        findings.forEach(function (f) {
            var s = f.severity || 'info';
            counts[s] = (counts[s] || 0) + 1;
        });
        return ns.SEV_ORDER
            .filter(function (s) { return counts[s]; })
            .map(function (s) {
                return '<span style="color:' + ns.SEV_COLORS[s] + '">' + s + ': ' + counts[s] + '</span>';
            })
            .join(', ');
    };

    ns.countBySeverity = function (hostFindings) {
        var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        hostFindings.forEach(function (f) {
            if (counts.hasOwnProperty(f.severity)) {
                counts[f.severity]++;
            }
        });
        return counts;
    };

    // ─── Tooltip factory ───────────────────────────────────────────
    /**
     * Create tooltip helpers bound to a specific tooltip element.
     * Returns { show(html, event), move(event), hide() }.
     */
    ns.tooltip = function (tooltipEl) {
        return {
            show: function (html, event) {
                tooltipEl.innerHTML = html;
                tooltipEl.style.display = 'block';
                tooltipEl.style.left = (event.clientX + 12) + 'px';
                tooltipEl.style.top  = (event.clientY + 12) + 'px';
            },
            move: function (event) {
                tooltipEl.style.left = (event.clientX + 12) + 'px';
                tooltipEl.style.top  = (event.clientY + 12) + 'px';
            },
            hide: function () {
                tooltipEl.style.display = 'none';
            },
        };
    };

    // ─── Resize debounce factory ───────────────────────────────────
    /**
     * Returns a function that debounces calls to `fn` by `delay` ms.
     */
    ns.debounce = function (fn, delay) {
        var timer;
        return function () {
            var ctx = this, args = arguments;
            clearTimeout(timer);
            timer = setTimeout(function () { fn.apply(ctx, args); }, delay || 250);
        };
    };

    // ─── CSS variable reader ───────────────────────────────────────
    ns.cssVar = function (name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    };

})(window.ChainsmithViz);
