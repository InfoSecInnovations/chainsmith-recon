/**
 * Chainsmith Recon - Guided Mode (Phase 36)
 *
 * Injects the "Guided" pill badge into the page header,
 * manages guided mode state, and provides the proactive
 * message infrastructure for the chat panel.
 */

(function () {
    'use strict';

    // ─── State ──────────────────────────────────────────────────
    let guidedModeActive = false;
    // Dismiss-to-suppress: trigger -> count (session-scoped)
    const dismissalCounts = {};
    const suppressedTriggers = new Set();

    // ─── Init ───────────────────────────────────────────────────

    async function init() {
        await fetchGuidedModeState();
        injectBadge();
        hookSSEForProactiveMessages();
    }

    // ─── API ────────────────────────────────────────────────────

    async function fetchGuidedModeState() {
        try {
            const res = await fetch('/api/v1/guided-mode');
            if (res.ok) {
                const data = await res.json();
                guidedModeActive = data.enabled;
            }
        } catch {
            // Default to off on error
        }
    }

    async function toggleGuidedMode(enabled) {
        try {
            const res = await fetch('/api/v1/guided-mode', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled }),
            });
            if (res.ok) {
                guidedModeActive = enabled;
                updateBadgeVisibility();
                showToast(enabled ? 'Guided Mode on' : 'Guided Mode off');
                // Activate tooltips if turning on
                if (enabled) {
                    initGuidedTooltips();
                } else {
                    removeGuidedTooltips();
                }
            }
        } catch {
            // Silently fail
        }
    }

    // ─── Badge ──────────────────────────────────────────────────

    function injectBadge() {
        const headerRight = document.querySelector('.header-right');
        if (!headerRight) return;

        const badge = document.createElement('button');
        badge.className = 'guided-badge';
        badge.id = 'guided-badge';
        badge.textContent = 'Guided';
        badge.title = 'Guided Mode is active. Click to turn off.';
        badge.addEventListener('click', () => toggleGuidedMode(false));

        // Insert before the first child of header-right
        headerRight.insertBefore(badge, headerRight.firstChild);

        updateBadgeVisibility();
    }

    function updateBadgeVisibility() {
        const badge = document.getElementById('guided-badge');
        if (badge) {
            badge.style.display = guidedModeActive ? '' : 'none';
        }
        // Also toggle body class for CSS gating
        document.body.classList.toggle('guided-mode', guidedModeActive);
    }

    // ─── Toast ──────────────────────────────────────────────────

    function showToast(message) {
        // Remove existing toast
        const existing = document.getElementById('guided-toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = 'guided-toast';
        toast.id = 'guided-toast';
        toast.textContent = message;
        document.body.appendChild(toast);

        // Trigger animation
        requestAnimationFrame(() => toast.classList.add('show'));

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 2000);
    }

    // ─── Proactive Messages ─────────────────────────────────────

    function hookSSEForProactiveMessages() {
        // Listen for proactive_message events on any existing SSE connection.
        // The chat.js module opens the SSE; we add a listener on the same
        // EventSource by watching for it on the window.
        // We'll use a MutationObserver-free approach: poll for the connection
        // or hook into the EventSource constructor.

        // Simpler: listen on document for a custom event dispatched by
        // our patched SSE handler, or just add the listener after chat
        // opens. We'll do the latter by periodically checking.
        const interval = setInterval(() => {
            const sources = performance.getEntriesByType?.('resource') || [];
            // Instead, we'll patch EventSource to intercept
            clearInterval(interval);
        }, 5000);

        // Patch: intercept EventSource to add proactive_message listener
        const OriginalEventSource = window.EventSource;
        window.EventSource = function (url, config) {
            const source = new OriginalEventSource(url, config);

            if (url.includes('/api/v1/chat/stream')) {
                source.addEventListener('proactive_message', (e) => {
                    if (!guidedModeActive) return;
                    try {
                        const data = JSON.parse(e.data);
                        handleProactiveMessage(data);
                    } catch {
                        // Ignore malformed events
                    }
                });
            }

            return source;
        };
        // Preserve prototype chain
        window.EventSource.prototype = OriginalEventSource.prototype;
        window.EventSource.CONNECTING = OriginalEventSource.CONNECTING;
        window.EventSource.OPEN = OriginalEventSource.OPEN;
        window.EventSource.CLOSED = OriginalEventSource.CLOSED;
    }

    function handleProactiveMessage(data) {
        const trigger = data.trigger;

        // Check suppression
        if (suppressedTriggers.has(trigger)) return;

        // Render in chat panel
        renderProactiveMessage(data);

        // Show notification dot on chat toggle if panel is closed
        const panel = document.getElementById('chat-panel');
        if (panel && !panel.classList.contains('open')) {
            showNotificationDot();
        }
    }

    function renderProactiveMessage(data) {
        const container = document.getElementById('chat-messages');
        if (!container) return;

        // Hide empty state
        const empty = document.getElementById('chat-empty');
        if (empty) empty.style.display = 'none';

        const div = document.createElement('div');
        div.className = 'chat-msg proactive';
        div.dataset.trigger = data.trigger;

        // Agent badge
        const badge = document.createElement('div');
        badge.className = `agent-badge ${data.agent}`;
        badge.textContent = data.agent;
        div.appendChild(badge);

        // Message text
        const textEl = document.createElement('div');
        textEl.className = 'proactive-text';
        textEl.textContent = data.text;
        div.appendChild(textEl);

        // Action buttons
        if (data.actions && data.actions.length > 0) {
            const actions = document.createElement('div');
            actions.className = 'chat-actions';
            data.actions.forEach((action) => {
                const btn = document.createElement('button');
                btn.className = 'chat-action-btn';
                btn.textContent = action.label;
                btn.addEventListener('click', () => {
                    // Inject synthetic message into chat
                    injectSyntheticMessage(action.injected_message || action.label);
                    div.remove();
                });
                actions.appendChild(btn);
            });
            div.appendChild(actions);
        }

        // Dismiss button
        if (data.dismissable !== false) {
            const dismiss = document.createElement('button');
            dismiss.className = 'proactive-dismiss';
            dismiss.title = 'Dismiss';
            dismiss.innerHTML = '&times;';
            dismiss.addEventListener('click', () => {
                div.remove();
                onDismiss(data.trigger);
            });
            div.appendChild(dismiss);
        }

        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    }

    function injectSyntheticMessage(text) {
        // Set the chat input and trigger send
        const input = document.getElementById('chat-input');
        if (input) {
            input.value = text;
            const sendBtn = document.getElementById('chat-send');
            if (sendBtn) sendBtn.click();
        }
    }

    function onDismiss(trigger) {
        dismissalCounts[trigger] = (dismissalCounts[trigger] || 0) + 1;
        if (dismissalCounts[trigger] >= 3) {
            suppressedTriggers.add(trigger);
        }
    }

    function showNotificationDot() {
        const toggle = document.getElementById('chat-toggle');
        if (toggle) {
            toggle.classList.add('has-proactive');
        }
    }

    // ─── Tooltips ───────────────────────────────────────────────

    const TERMINOLOGY = {
        'adjudication': 'An agent re-evaluates whether the severity rating is accurate given the target context.',
        'attack-chain': 'A sequence of findings that, combined, create a more severe attack path than any single finding alone.',
        'observation': 'A single finding discovered during reconnaissance — may be verified, rejected, or flagged as a hallucination.',
        'triage': 'Prioritization of findings into an ordered remediation plan based on effort, impact, and context.',
        'hallucination': 'A finding the AI reported that doesn\'t hold up under verification — it\'s not real.',
        'severity-multiplier': 'A chain\'s combined severity can exceed its individual parts. The multiplier reflects this compounding risk.',
        'severity': 'The impact rating assigned to a finding: info, low, medium, high, or critical.',
        'chain': 'A sequence of findings that, combined, create a more severe attack path than any single finding alone.',
        'verification': 'The process of confirming whether a reported finding is genuine or a hallucination.',
        'evidence-quality': 'How strong the proof is for a finding: direct observation, inferred, or claimed without proof.',
        'remediation': 'The actions needed to fix or mitigate a finding.',
        'quick-win': 'A low-effort fix that resolves one or more findings.',
    };

    function initGuidedTooltips() {
        if (!guidedModeActive) return;

        document.querySelectorAll('[data-term]').forEach((el) => {
            const term = el.dataset.term;
            const definition = TERMINOLOGY[term];
            if (definition) {
                el.classList.add('has-tooltip');
                el.setAttribute('title', definition);
            }
        });
    }

    function removeGuidedTooltips() {
        document.querySelectorAll('.has-tooltip[data-term]').forEach((el) => {
            el.classList.remove('has-tooltip');
            el.removeAttribute('title');
        });
    }

    // ─── Settings page integration ──────────────────────────────

    function injectSettingsToggle() {
        // Only on settings page
        if (!window.location.pathname.includes('settings')) return;

        const settingsGrid = document.querySelector('.settings-grid');
        if (!settingsGrid) return;

        // Insert guided mode card after the profile card
        const profileCard = settingsGrid.querySelector('.full-width');
        if (!profileCard) return;

        const card = document.createElement('div');
        card.className = 'settings-card full-width';
        card.innerHTML = `
            <div class="card-header">
                <span class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    Guided Mode
                </span>
            </div>
            <div class="card-body">
                <div class="guided-mode-toggle">
                    <label class="toggle-row">
                        <input type="checkbox" id="guided-mode-checkbox"
                            ${guidedModeActive ? 'checked' : ''}>
                        <span class="toggle-label">
                            <strong>Enable Guided Mode</strong>
                            <span class="toggle-desc">
                                Agents offer proactive tips, explain terminology,
                                and suggest next steps as you work.
                            </span>
                        </span>
                    </label>
                    <a href="guided-quickstart.html" class="guided-quickstart-link">
                        Quick Start Guide →
                    </a>
                </div>
            </div>
        `;

        profileCard.insertAdjacentElement('afterend', card);

        // Bind toggle
        const checkbox = document.getElementById('guided-mode-checkbox');
        if (checkbox) {
            checkbox.addEventListener('change', () => {
                toggleGuidedMode(checkbox.checked);
            });
        }
    }

    // ─── Expose for external use ────────────────────────────────

    window.ChainsmithGuided = {
        isActive: () => guidedModeActive,
        toggle: toggleGuidedMode,
        initTooltips: initGuidedTooltips,
        TERMINOLOGY,
    };

    // ─── Boot ───────────────────────────────────────────────────

    function boot() {
        init().then(() => {
            injectSettingsToggle();
            initGuidedTooltips();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
