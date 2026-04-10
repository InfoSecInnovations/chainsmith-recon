/**
 * Chainsmith Recon - Chat Panel (Phase 35a)
 *
 * Slide-out chat panel with SSE streaming, agent attribution,
 * and prompt router integration.
 */

(function () {
    'use strict';

    // ─── State ──────────────────────────────────────────────────
    let sseConnection = null;
    let panelOpen = localStorage.getItem('chat_panel_state') === 'expanded';
    let unreadCount = 0;
    let typingAgent = null;

    // ─── DOM Setup ──────────────────────────────────────────────

    function injectChatDOM() {
        // Toggle button
        const toggle = document.createElement('button');
        toggle.className = 'chat-toggle';
        toggle.id = 'chat-toggle';
        toggle.title = 'Open chat';
        toggle.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
            <span class="unread-badge" id="chat-unread">0</span>
        `;
        document.body.appendChild(toggle);

        // Panel
        const panel = document.createElement('div');
        panel.className = 'chat-panel';
        panel.id = 'chat-panel';
        panel.innerHTML = `
            <div class="chat-header">
                <span class="chat-header-title">Agent Chat</span>
                <div class="chat-header-actions">
                    <button id="chat-clear" title="Clear chat">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                        </svg>
                    </button>
                    <button id="chat-close" title="Close chat">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
            </div>
            <div class="chat-messages" id="chat-messages">
                <div class="chat-empty" id="chat-empty">
                    Talk to any Chainsmith agent.<br>
                    Messages are routed automatically.
                </div>
            </div>
            <div class="chat-input-area">
                <div class="chat-input-row">
                    <textarea class="chat-input" id="chat-input"
                        placeholder="Type a message..." rows="1"></textarea>
                    <button class="chat-send-btn" id="chat-send" title="Send">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="22" y1="2" x2="11" y2="13"/>
                            <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                        </svg>
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(panel);

        // Bind events
        toggle.addEventListener('click', togglePanel);
        document.getElementById('chat-close').addEventListener('click', closePanel);
        document.getElementById('chat-clear').addEventListener('click', clearChat);
        document.getElementById('chat-send').addEventListener('click', sendMessage);
        document.getElementById('chat-input').addEventListener('keydown', onInputKeydown);
        document.getElementById('chat-input').addEventListener('input', autoResizeInput);

        // Restore panel state
        if (panelOpen) {
            panel.classList.add('open');
            toggle.style.display = 'none';
            loadHistory();
        }
    }

    // ─── Panel Controls ─────────────────────────────────────────

    function togglePanel() {
        const panel = document.getElementById('chat-panel');
        const toggle = document.getElementById('chat-toggle');
        panelOpen = !panelOpen;
        panel.classList.toggle('open', panelOpen);
        toggle.style.display = panelOpen ? 'none' : '';
        localStorage.setItem('chat_panel_state', panelOpen ? 'expanded' : 'collapsed');

        if (panelOpen) {
            unreadCount = 0;
            updateUnreadBadge();
            loadHistory();
            document.getElementById('chat-input').focus();
        }
    }

    function closePanel() {
        const panel = document.getElementById('chat-panel');
        const toggle = document.getElementById('chat-toggle');
        panelOpen = false;
        panel.classList.remove('open');
        toggle.style.display = '';
        localStorage.setItem('chat_panel_state', 'collapsed');
    }

    // ─── SSE Connection ─────────────────────────────────────────

    function connectSSE() {
        if (sseConnection) return;

        sseConnection = new EventSource('/api/v1/chat/stream');

        sseConnection.addEventListener('chat_response', (e) => {
            const data = JSON.parse(e.data);
            appendAgentMessage(data);
            clearTypingIndicator();
            if (!panelOpen) {
                unreadCount++;
                updateUnreadBadge();
            }
        });

        sseConnection.addEventListener('agent_event', (e) => {
            const data = JSON.parse(e.data);
            showAgentEvent(data);
        });

        sseConnection.addEventListener('typing', (e) => {
            const data = JSON.parse(e.data);
            showTypingIndicator(data.agent, data.status);
        });

        sseConnection.addEventListener('redirect', (e) => {
            const data = JSON.parse(e.data);
            showRedirect(data);
        });

        sseConnection.onerror = () => {
            // EventSource auto-reconnects; on reconnect we re-fetch history
            if (sseConnection.readyState === EventSource.CLOSED) {
                sseConnection = null;
            }
        };

        sseConnection.onopen = () => {
            // Re-fetch history on reconnect to backfill missed messages
            if (panelOpen) loadHistory();
        };
    }

    function disconnectSSE() {
        if (sseConnection) {
            sseConnection.close();
            sseConnection = null;
        }
    }

    // ─── Send Message ───────────────────────────────────────────

    async function sendMessage() {
        const input = document.getElementById('chat-input');
        const text = input.value.trim();
        if (!text) return;

        input.value = '';
        input.style.height = 'auto';
        document.getElementById('chat-send').disabled = true;

        // Show operator message immediately
        appendOperatorMessage(text);
        hideEmptyState();

        // Open SSE on first message
        connectSSE();

        try {
            const res = await fetch('/api/v1/chat/message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: text,
                    ui_context: getUIContext(),
                }),
            });

            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
                appendSystemMessage(err.detail || 'Failed to send message.');
            }
            // Response arrives via SSE, not from this fetch
        } catch (err) {
            appendSystemMessage('Network error. Check your connection.');
        } finally {
            document.getElementById('chat-send').disabled = false;
            document.getElementById('chat-input').focus();
        }
    }

    function onInputKeydown(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
        if (e.key === 'Escape') {
            closePanel();
        }
    }

    function autoResizeInput() {
        const el = this;
        el.style.height = 'auto';
        el.style.height = Math.min(el.scrollHeight, 100) + 'px';
    }

    // ─── UI Context ─────────────────────────────────────────────

    function getUIContext() {
        // Detect current page from URL
        const path = window.location.pathname;
        let page = 'unknown';
        if (path.includes('index') || path === '/') page = 'scope';
        else if (path.includes('scan')) page = 'scan';
        else if (path.includes('observations')) page = 'observations';
        else if (path.includes('reports')) page = 'reports';
        else if (path.includes('engagements')) page = 'engagements';
        else if (path.includes('trend')) page = 'trend';
        else if (path.includes('settings')) page = 'settings';
        else if (path.includes('profiles')) page = 'profiles';

        return { page: page };
    }

    // ─── Message Rendering ──────────────────────────────────────

    function appendOperatorMessage(text) {
        const container = document.getElementById('chat-messages');
        const div = document.createElement('div');
        div.className = 'chat-msg operator';
        div.textContent = text;
        container.appendChild(div);
        scrollToBottom();
    }

    function appendAgentMessage(data) {
        const container = document.getElementById('chat-messages');
        hideEmptyState();

        const div = document.createElement('div');
        div.className = 'chat-msg agent';
        div.dataset.msgId = data.id;

        // Agent badge
        if (data.agent) {
            const badge = document.createElement('div');
            badge.className = `agent-badge ${data.agent}`;
            badge.textContent = data.agent;
            div.appendChild(badge);
        }

        // Message text
        const textEl = document.createElement('div');
        textEl.textContent = data.text;
        div.appendChild(textEl);

        // References
        if (data.references && data.references.length > 0) {
            const refs = document.createElement('div');
            refs.style.marginTop = '4px';
            data.references.forEach((ref) => {
                const link = document.createElement('span');
                link.className = 'chat-ref';
                link.textContent = ref.label || ref.id;
                link.title = `${ref.type}: ${ref.id}`;
                link.addEventListener('click', () => navigateToRef(ref));
                refs.appendChild(link);
                refs.appendChild(document.createTextNode(' '));
            });
            div.appendChild(refs);
        }

        // Action buttons
        if (data.actions && data.actions.length > 0) {
            const actions = document.createElement('div');
            actions.className = 'chat-actions';
            data.actions.forEach((action) => {
                const btn = document.createElement('button');
                btn.className = 'chat-action-btn';
                btn.textContent = action.label;
                btn.addEventListener('click', () => handleAction(action));
                actions.appendChild(btn);
            });
            div.appendChild(actions);
        }

        container.appendChild(div);
        scrollToBottom();
    }

    function appendSystemMessage(text) {
        const container = document.getElementById('chat-messages');
        const div = document.createElement('div');
        div.className = 'chat-msg system';
        div.textContent = text;
        container.appendChild(div);
        scrollToBottom();
    }

    function showTypingIndicator(agent, status) {
        clearTypingIndicator();
        typingAgent = agent;
        const container = document.getElementById('chat-messages');
        const div = document.createElement('div');
        div.className = 'chat-typing';
        div.id = 'chat-typing-indicator';

        const label = status === 'queued' ? `${agent} queued` : `${agent} is thinking`;
        div.innerHTML = `<span class="agent-badge ${agent}" style="font-size:0.625rem">${agent}</span> ${label}<span class="dots"></span>`;
        container.appendChild(div);
        scrollToBottom();
    }

    function clearTypingIndicator() {
        const el = document.getElementById('chat-typing-indicator');
        if (el) el.remove();
        typingAgent = null;
    }

    function showRedirect(data) {
        const container = document.getElementById('chat-messages');
        const div = document.createElement('div');
        div.className = 'chat-redirect';
        div.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="15 10 20 15 15 20"/>
                <path d="M4 4v7a4 4 0 0 0 4 4h12"/>
            </svg>
            ${escapeHtml(data.reason)}
        `;
        container.appendChild(div);
        scrollToBottom();
    }

    function showAgentEvent(data) {
        // Show important agent events as muted inline messages
        if (data.importance === 'high' || data.event_type === 'error') {
            const container = document.getElementById('chat-messages');
            const div = document.createElement('div');
            div.className = 'chat-msg system';
            div.textContent = `[${data.agent}] ${data.message}`;
            container.appendChild(div);
            scrollToBottom();
        }
    }

    // ─── History ────────────────────────────────────────────────

    async function loadHistory() {
        try {
            const res = await fetch('/api/v1/chat/history?limit=50');
            if (!res.ok) return;
            const data = await res.json();
            const messages = data.messages || [];

            if (messages.length === 0) return;

            hideEmptyState();
            const container = document.getElementById('chat-messages');

            // Clear existing messages (except empty state)
            container.querySelectorAll('.chat-msg, .chat-redirect, .chat-typing').forEach(
                (el) => el.remove()
            );

            // Messages come newest-first; reverse for display
            messages.reverse().forEach((msg) => {
                if (msg.direction === 'operator') {
                    appendOperatorMessage(msg.text);
                } else {
                    appendAgentMessage(msg);
                }
            });

            scrollToBottom();
        } catch (err) {
            // Silently fail — chat history is non-critical
        }
    }

    // ─── Clear Chat ─────────────────────────────────────────────

    async function clearChat() {
        try {
            await fetch('/api/v1/chat/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });
        } catch (err) {
            // Continue with UI clear even if API fails
        }

        const container = document.getElementById('chat-messages');
        container.querySelectorAll('.chat-msg, .chat-redirect, .chat-typing').forEach(
            (el) => el.remove()
        );
        showEmptyState();
        disconnectSSE();
    }

    // ─── Helpers ────────────────────────────────────────────────

    function scrollToBottom() {
        const container = document.getElementById('chat-messages');
        container.scrollTop = container.scrollHeight;
    }

    function hideEmptyState() {
        const el = document.getElementById('chat-empty');
        if (el) el.style.display = 'none';
    }

    function showEmptyState() {
        const el = document.getElementById('chat-empty');
        if (el) el.style.display = '';
    }

    function updateUnreadBadge() {
        const badge = document.getElementById('chat-unread');
        if (!badge) return;
        badge.textContent = unreadCount;
        badge.classList.toggle('visible', unreadCount > 0);
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function navigateToRef(ref) {
        if (ref.type === 'observation') {
            navigateTo(`observations.html#obs-${ref.id}`);
        } else if (ref.type === 'chain') {
            navigateTo(`scan.html#chain-${ref.id}`);
        }
    }

    function handleAction(action) {
        // Send action as a chat message describing what the operator wants
        const input = document.getElementById('chat-input');
        input.value = action.label;
        sendMessage();
    }

    // ─── Keyboard shortcut ──────────────────────────────────────

    document.addEventListener('keydown', (e) => {
        // Ctrl+Shift+C toggles chat panel
        if (e.ctrlKey && e.shiftKey && e.key === 'C') {
            e.preventDefault();
            togglePanel();
        }
    });

    // ─── Init ───────────────────────────────────────────────────

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectChatDOM);
    } else {
        injectChatDOM();
    }
})();
