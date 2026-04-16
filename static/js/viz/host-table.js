/**
 * Chainsmith Viz — Host Table (expandable host/observations rows).
 * Requires: viz-common.js
 */
(function (ns) {
    'use strict';

    var severityOrder    = ns.SEV_ORDER;
    var hostSeverityColors = ns.HOST_SEV_COLORS;

    /**
     * Render the host-table visualization.
     */
    ns.renderHostTable = async function (openModal) {
        var sid     = (window.ScanSelector && ScanSelector.getSelectedScanId()) || null;
        var data    = await api.getObservationsByHost(sid);
        var emptyEl   = document.getElementById('hosts-empty');
        var contentEl = document.getElementById('hosts-content');

        if (!data.hosts || data.hosts.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        emptyEl.style.display  = 'none';
        contentEl.style.display = 'block';

        function normalizeHost(name) {
            return name.replace(/:\d+$/, '');
        }

        var hostMap = new Map();
        data.hosts.forEach(function (host) {
            var hostName = normalizeHost(host.name);
            if (!hostMap.has(hostName)) hostMap.set(hostName, new Map());
            var observationsMap = hostMap.get(hostName);
            host.observations.forEach(function (f) {
                var key = f.id || (f.title + '-' + f.check_name);
                if (!observationsMap.has(key)) observationsMap.set(key, f);
            });
        });

        var hostData = Array.from(hostMap.entries()).map(function (entry) {
            return { name: entry[0], observations: Array.from(entry[1].values()) };
        });

        // Store on namespace for expand-all access
        ns._hostData = hostData;

        renderSummaryBar(hostData);
        renderHostsTable(hostData, openModal);
    };

    function getWorstSeverity(hostObservations) {
        for (var i = 0; i < severityOrder.length; i++) {
            if (hostObservations.some(function (f) { return f.severity === severityOrder[i]; })) return severityOrder[i];
        }
        return 'info';
    }

    function renderSummaryBar(hostData) {
        var allObservations = hostData.reduce(function (acc, h) { return acc.concat(h.observations); }, []);
        var counts = ns.countBySeverity(allObservations);

        document.getElementById('summary-bar').innerHTML =
            '<div class="summary-item">' +
            '<div class="summary-count" style="color: ' + hostSeverityColors.critical + '">' + counts.critical + '</div>' +
            '<div class="summary-label">Critical</div></div>' +
            '<div class="summary-item">' +
            '<div class="summary-count" style="color: ' + hostSeverityColors.high + '">' + counts.high + '</div>' +
            '<div class="summary-label">High</div></div>' +
            '<div class="summary-item">' +
            '<div class="summary-count" style="color: ' + hostSeverityColors.medium + '">' + counts.medium + '</div>' +
            '<div class="summary-label">Medium</div></div>' +
            '<div class="summary-item">' +
            '<div class="summary-count" style="color: ' + hostSeverityColors.low + '">' + counts.low + '</div>' +
            '<div class="summary-label">Low</div></div>' +
            '<div class="summary-item">' +
            '<div class="summary-count" style="color: ' + hostSeverityColors.info + '">' + counts.info + '</div>' +
            '<div class="summary-label">Info</div></div>' +
            '<div class="summary-item">' +
            '<div class="summary-count">' + allObservations.length + '</div>' +
            '<div class="summary-label">Total</div></div>';
    }

    function renderHostsTable(hostData, openModal) {
        var container = document.getElementById('hosts-table');

        var sortedHosts = hostData.slice().sort(function (a, b) {
            return severityOrder.indexOf(getWorstSeverity(a.observations)) -
                   severityOrder.indexOf(getWorstSeverity(b.observations));
        });

        container.innerHTML = sortedHosts.map(function (host) {
            var counts   = ns.countBySeverity(host.observations);
            var worstSev = getWorstSeverity(host.observations);

            var sortedObservations = host.observations.slice().sort(function (a, b) {
                return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
            });

            return '<div class="host-row" data-host="' + host.name + '">' +
                '<div class="host-header">' +
                '<div class="host-expand"><svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 2L8 6L4 10"/></svg></div>' +
                '<div class="host-risk-bar" style="background: ' + hostSeverityColors[worstSev] + '"></div>' +
                '<div class="host-name">' + host.name + '</div>' +
                '<div class="host-stats">' +
                (counts.critical ? '<div class="severity-dot sev-critical" style="background:' + hostSeverityColors.critical + '">' + counts.critical + '</div>' : '') +
                (counts.high ? '<div class="severity-dot sev-high" style="background:' + hostSeverityColors.high + '">' + counts.high + '</div>' : '') +
                (counts.medium ? '<div class="severity-dot sev-medium" style="background:' + hostSeverityColors.medium + '">' + counts.medium + '</div>' : '') +
                (counts.low ? '<div class="severity-dot sev-low" style="background:' + hostSeverityColors.low + '">' + counts.low + '</div>' : '') +
                (counts.info ? '<div class="severity-dot sev-info" style="background:' + hostSeverityColors.info + '">' + counts.info + '</div>' : '') +
                '</div>' +
                '<div class="host-observation-count">' + host.observations.length + ' observations</div>' +
                '</div>' +
                '<div class="observations-list-container">' +
                sortedObservations.map(function (f) {
                    return '<div class="observation-item" data-observation-id="' + (f.id || '') + '" data-observation=\'' + JSON.stringify(f).replace(/'/g, "&#39;") + '\'>' +
                        '<div class="observation-severity-dot" style="background: ' + hostSeverityColors[f.severity] + '"></div>' +
                        '<div class="observation-title">' + f.title + '</div>' +
                        '<div class="observation-badge sev-' + f.severity + '" style="background: ' + hostSeverityColors[f.severity] + '">' + f.severity + '</div>' +
                        '</div>';
                }).join('') +
                '</div></div>';
        }).join('');

        container.querySelectorAll('.host-header').forEach(function (header) {
            header.addEventListener('click', function () {
                header.parentElement.classList.toggle('expanded');
            });
        });

        container.querySelectorAll('.observation-item').forEach(function (item) {
            item.addEventListener('click', function (e) {
                e.stopPropagation();
                try {
                    var observation = JSON.parse(item.dataset.observation.replace(/&#39;/g, "'"));
                    openModal(observation.title, getObservationModalContent(observation));
                } catch (err) {
                    console.error('Failed to parse observation:', err);
                }
            });
        });
    }

})(window.ChainsmithViz);
