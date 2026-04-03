/**
 * Chainsmith Viz — Fullscreen & Pop-Out Module
 *
 * Adds fullscreen (expand in-place) and pop-out (new window) controls
 * to every visualization panel on findings.html and trend.html.
 */
(function () {
    'use strict';

    var activeFullscreen = null;  // currently fullscreen panel element

    // ─── SVG Icons ────────────────────────────────────────────────
    var ICON_FULLSCREEN = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>';
    var ICON_EXIT_FULLSCREEN = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14h6v6m10-10h-6V4m0 6 7-7M3 21l7-7"/></svg>';
    var ICON_POPOUT = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';

    // ─── Helpers ──────────────────────────────────────────────────
    function createButton(className, title, icon, onClick) {
        var btn = document.createElement('button');
        btn.className = 'btn btn-icon viz-ctrl-btn ' + className;
        btn.title = title;
        btn.innerHTML = icon;
        btn.addEventListener('click', function (e) {
            e.stopPropagation();
            onClick(e);
        });
        return btn;
    }

    // ─── Fullscreen Toggle ───────────────────────────────────────
    function toggleFullscreen(panel, fsBtn) {
        if (activeFullscreen === panel) {
            exitFullscreen(panel, fsBtn);
        } else {
            enterFullscreen(panel, fsBtn);
        }
    }

    function enterFullscreen(panel, fsBtn) {
        if (activeFullscreen) return;
        activeFullscreen = panel;
        panel.classList.add('viz-fullscreen');
        fsBtn.innerHTML = ICON_EXIT_FULLSCREEN;
        fsBtn.title = 'Exit Fullscreen';

        // Force a resize so D3 re-renders at the new size
        window.dispatchEvent(new Event('resize'));
        // Also trigger after transition completes
        setTimeout(function () { window.dispatchEvent(new Event('resize')); }, 220);
    }

    function exitFullscreen(panel, fsBtn) {
        activeFullscreen = null;
        panel.classList.remove('viz-fullscreen');
        fsBtn.innerHTML = ICON_FULLSCREEN;
        fsBtn.title = 'Fullscreen';

        window.dispatchEvent(new Event('resize'));
        setTimeout(function () { window.dispatchEvent(new Event('resize')); }, 220);
    }

    // ─── Pop-Out Window ──────────────────────────────────────────
    function popOutPanel(panel, label) {
        var w = Math.min(screen.width * 0.8, 1200);
        var h = Math.min(screen.height * 0.8, 800);
        var left = (screen.width - w) / 2;
        var top = (screen.height - h) / 2;

        var popup = window.open('', '_blank',
            'width=' + w + ',height=' + h + ',left=' + left + ',top=' + top +
            ',menubar=no,toolbar=no,location=no,status=no,resizable=yes,scrollbars=yes');
        if (!popup) {
            alert('Pop-out blocked. Please allow pop-ups for this site.');
            return;
        }

        // Gather stylesheets from the parent document
        var styles = '';
        document.querySelectorAll('link[rel="stylesheet"]').forEach(function (link) {
            styles += '<link rel="stylesheet" href="' + link.href + '">';
        });
        // Also grab inline <style> blocks
        document.querySelectorAll('style').forEach(function (s) {
            styles += '<style>' + s.textContent + '</style>';
        });

        // Clone the panel content
        var clone = panel.cloneNode(true);
        clone.classList.remove('viz-fullscreen');
        // Remove the control buttons from the clone
        clone.querySelectorAll('.viz-ctrl-bar').forEach(function (bar) { bar.remove(); });
        // Ensure the panel fills the window
        clone.style.cssText = 'position:relative;width:100%;height:100vh;display:flex;flex-direction:column;';

        var theme = document.body.classList.contains('theme-light') ? 'theme-light' : '';

        popup.document.open();
        popup.document.write(
            '<!DOCTYPE html><html lang="en"><head>' +
            '<meta charset="UTF-8"><title>Chainsmith — ' + label + '</title>' +
            styles +
            '<style>' +
            'body{margin:0;background:var(--bg-primary);color:var(--text-primary);overflow:auto;}' +
            '</style>' +
            '</head><body class="' + theme + '">' +
            clone.outerHTML +
            '<script src="https://d3js.org/d3.v7.min.js"><\/script>' +
            '</body></html>'
        );
        popup.document.close();
    }

    // ─── Attach Controls to Panels ───────────────────────────────
    function attachControls(panel, label) {
        var bar = document.createElement('div');
        bar.className = 'viz-ctrl-bar';

        var fsBtn = createButton('viz-fs-btn', 'Fullscreen', ICON_FULLSCREEN, function () {
            toggleFullscreen(panel, fsBtn);
        });
        var poBtn = createButton('viz-po-btn', 'Pop Out', ICON_POPOUT, function () {
            popOutPanel(panel, label);
        });

        bar.appendChild(fsBtn);
        bar.appendChild(poBtn);
        panel.style.position = 'relative'; // ensure bar positions correctly
        panel.appendChild(bar);
    }

    // ─── Escape Key Handler ──────────────────────────────────────
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && activeFullscreen) {
            var fsBtn = activeFullscreen.querySelector('.viz-fs-btn');
            exitFullscreen(activeFullscreen, fsBtn);
        }
    });

    // ─── Initialize ──────────────────────────────────────────────
    function init() {
        // Findings page: .viz-panel elements
        document.querySelectorAll('.viz-panel').forEach(function (panel) {
            var id = panel.id || '';
            var label = id.replace('panel-', '').replace(/-/g, ' ');
            label = label.charAt(0).toUpperCase() + label.slice(1);
            attachControls(panel, label);
        });

        // Trend page: .chart-panel elements
        document.querySelectorAll('.chart-panel').forEach(function (panel) {
            var id = panel.id || '';
            var label = id.replace('panel-', '').replace(/-/g, ' ');
            label = label.charAt(0).toUpperCase() + label.slice(1);
            attachControls(panel, label);
        });
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
