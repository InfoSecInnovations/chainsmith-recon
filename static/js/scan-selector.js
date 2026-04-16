/**
 * scan-selector.js — shared live-scan picker.
 *
 * Phase D of the concurrent-scans overhaul. One dropdown, one localStorage key
 * (`chainsmith.selectedScanId`), usable across any page that reports live scan
 * state (scan, chains, observations, adjudication, chainsmith, chat, compliance).
 *
 * Usage:
 *   <div id="scan-selector"></div>
 *   <script src="/static/js/api.js"></script>
 *   <script src="/static/js/scan-selector.js"></script>
 *   <script>
 *     ScanSelector.mount('#scan-selector', {
 *       onChange: (scanId) => { // refresh page data
 *     });
 *     const scanId = ScanSelector.getSelectedScanId();
 *   </script>
 *
 * Selection semantics:
 *   - If user hasn't picked, default to the server's "current" (most-recent
 *     non-terminal) session by leaving scanId null on requests.
 *   - If user has picked id X and X is still in the live list, honor it.
 *   - If X has been reaped (gone from live list), fall back to current and
 *     clear the sticky pick.
 */
(function (global) {
    const STORAGE_KEY = 'chainsmith.selectedScanId';
    const POLL_MS = 3000;

    const state = {
        scans: [],
        mounted: [],  // { el, onChange }
        pollTimer: null,
    };

    function getSelectedScanId() {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return null;
        // If selection has been reaped from the live list, fall back.
        if (state.scans.length > 0 && !state.scans.some(s => s.id === raw)) {
            localStorage.removeItem(STORAGE_KEY);
            return null;
        }
        return raw;
    }

    function setSelectedScanId(id) {
        if (id) localStorage.setItem(STORAGE_KEY, id);
        else localStorage.removeItem(STORAGE_KEY);
        const resolved = getSelectedScanId();
        state.mounted.forEach(m => {
            renderInto(m.el);
            if (m.onChange) m.onChange(resolved);
        });
        // Global change event so non-mounted consumers (chat pin, etc.) can react.
        try {
            window.dispatchEvent(new CustomEvent('chainsmith:selected-scan-changed', {
                detail: { scanId: resolved },
            }));
        } catch (_) { /* old browsers */ }
    }

    function shortId(id) {
        return id ? id.slice(0, 8) : '';
    }

    function labelFor(scan) {
        const pieces = [shortId(scan.id), scan.target || '(no target)'];
        if (scan.is_terminal) pieces.push(`(${scan.status})`);
        else if (scan.phase) pieces.push(scan.phase);
        if (scan.checks_total > 0 && !scan.is_terminal) {
            pieces.push(`${scan.checks_completed}/${scan.checks_total}`);
        }
        return pieces.join(' · ');
    }

    function renderInto(el) {
        const selected = getSelectedScanId();
        if (state.scans.length === 0) {
            el.innerHTML = '<span class="scan-selector-empty">No live scans</span>';
            return;
        }
        const opts = state.scans.map(s => {
            const sel = s.id === selected ? ' selected' : '';
            return `<option value="${s.id}"${sel}>${labelFor(s)}</option>`;
        }).join('');
        const defaultSel = selected ? '' : ' selected';
        el.innerHTML = `
            <label class="scan-selector-label">Scan:
                <select class="scan-selector-dropdown">
                    <option value=""${defaultSel}>Current (auto)</option>
                    ${opts}
                </select>
            </label>
        `;
        const select = el.querySelector('select');
        select.addEventListener('change', (e) => {
            setSelectedScanId(e.target.value || null);
        });
    }

    async function refresh() {
        try {
            const data = await api.listLiveScans();
            state.scans = data.scans || [];
            state.mounted.forEach(m => renderInto(m.el));
        } catch (err) {
            console.warn('scan-selector: refresh failed', err);
        }
    }

    function mount(selector, opts = {}) {
        const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
        if (!el) return;
        state.mounted.push({ el, onChange: opts.onChange || null });
        renderInto(el);
        refresh();
        if (state.pollTimer === null) {
            state.pollTimer = setInterval(refresh, POLL_MS);
        }
    }

    global.ScanSelector = {
        mount,
        refresh,
        getSelectedScanId,
        setSelectedScanId,
        STORAGE_KEY,
    };
})(window);
