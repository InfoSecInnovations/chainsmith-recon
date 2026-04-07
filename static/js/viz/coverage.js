/**
 * Chainsmith Viz — Coverage Matrix (Check × Host status grid).
 * Requires: D3, viz-common.js
 */
(function (ns) {
    'use strict';

    var STATUS_COLORS = ns.COVERAGE_STATUS_COLORS;

    // Expose for backward compat
    window.COVERAGE_STATUS_COLORS = STATUS_COLORS;

    /**
     * Build coverage matrix data.
     */
    function buildCoverageData(observationsList, checkStatuses) {
        var checks = [];
        var checkStatusMap = {};

        (checkStatuses || []).forEach(function (cs) {
            var name = cs.name || cs.check_name;
            if (!name) return;
            if (!checkStatusMap[name]) {
                checkStatusMap[name] = cs.status || 'completed';
                checks.push(name);
            }
        });

        observationsList.forEach(function (f) {
            var name = f.check_name;
            if (name && !checkStatusMap[name]) {
                checkStatusMap[name] = 'completed';
                checks.push(name);
            }
        });

        if (checks.length === 0) return { matrix: {}, hosts: [], checks: [], isGlobal: true };

        var observationsByHost = {};
        observationsList.forEach(function (f) {
            var rawHost = f.host || f.target_url || 'global';
            var host = ns.normalizeHost(rawHost);
            if (!observationsByHost[host]) observationsByHost[host] = [];
            observationsByHost[host].push(f);
        });

        var hosts = Object.keys(observationsByHost).sort();
        var isGlobal = hosts.length <= 1;

        if (isGlobal) {
            var globalHost = hosts[0] || 'all';
            var matrix = {};
            matrix[globalHost] = {};

            var observationsByCheck = {};
            observationsList.forEach(function (f) {
                if (!f.check_name) return;
                if (!observationsByCheck[f.check_name]) observationsByCheck[f.check_name] = [];
                observationsByCheck[f.check_name].push(f);
            });

            checks.forEach(function (check) {
                var checkObservations = observationsByCheck[check] || [];
                var status = checkStatusMap[check] || 'not-run';
                if (checkObservations.length > 0 && status === 'completed') status = 'found';
                matrix[globalHost][check] = {
                    status: status,
                    observationCount: checkObservations.length,
                    observations: checkObservations,
                };
            });

            return { matrix: matrix, hosts: [globalHost], checks: checks, isGlobal: true };
        }

        // Multi-host view
        var matrix = {};
        hosts.forEach(function (host) {
            matrix[host] = {};
            var hostObservations = observationsByHost[host] || [];

            var hostObservationsByCheck = {};
            hostObservations.forEach(function (f) {
                if (!f.check_name) return;
                if (!hostObservationsByCheck[f.check_name]) hostObservationsByCheck[f.check_name] = [];
                hostObservationsByCheck[f.check_name].push(f);
            });

            checks.forEach(function (check) {
                var checkObservations = hostObservationsByCheck[check] || [];
                var status = checkStatusMap[check] || 'not-run';
                if (checkObservations.length > 0 && status === 'completed') status = 'found';
                matrix[host][check] = {
                    status: status,
                    observationCount: checkObservations.length,
                    observations: checkObservations,
                };
            });
        });

        return { matrix: matrix, hosts: hosts, checks: checks, isGlobal: false };
    }

    // Expose for tests
    window.buildCoverageData = buildCoverageData;
    ns.buildCoverageData = buildCoverageData;

    /**
     * Render the coverage matrix visualization.
     */
    ns.renderCoverage = async function (observations, openModal) {
        var emptyEl   = document.getElementById('coverage-empty');
        var contentEl = document.getElementById('coverage-content');
        var tooltipEl = document.getElementById('coverage-tooltip');
        var noteEl    = document.getElementById('coverage-note');
        var tip       = ns.tooltip(tooltipEl);

        var checkStatuses = [];
        try {
            var csData = await api.getCheckStatuses();
            checkStatuses = csData.checks || csData || [];
        } catch (e) { /* check statuses may not be available */ }

        if (observations.length === 0 && checkStatuses.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        emptyEl.style.display  = 'none';
        contentEl.style.display = 'block';

        var data   = buildCoverageData(observations, checkStatuses);
        var matrix = data.matrix;
        var hosts  = data.hosts;
        var checks = data.checks;

        if (checks.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        noteEl.textContent = data.isGlobal
            ? 'Showing global check status (checks ran against the target as a whole, not per-host).'
            : '';

        // Sizing
        var margin   = { top: 120, right: 20, bottom: 40, left: 180 };
        var cellSize = 32;
        var width    = margin.left + checks.length * cellSize + margin.right;
        var height   = margin.top + hosts.length * cellSize + margin.bottom;

        var svgEl = d3.select('#coverage-graph')
            .attr('width', width)
            .attr('height', height);

        svgEl.selectAll('*').remove();

        var g = svgEl.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var x = d3.scaleBand()
            .domain(checks)
            .range([0, checks.length * cellSize])
            .padding(0.08);

        var y = d3.scaleBand()
            .domain(hosts)
            .range([0, hosts.length * cellSize])
            .padding(0.08);

        // X-axis labels (checks) — rotated
        g.selectAll('.x-label')
            .data(checks)
            .join('text')
            .attr('class', 'x-label')
            .attr('x', function (d) { return x(d) + x.bandwidth() / 2; })
            .attr('y', -8)
            .attr('text-anchor', 'start')
            .attr('transform', function (d) { return 'rotate(-45, ' + (x(d) + x.bandwidth() / 2) + ', -8)'; })
            .attr('fill', 'var(--text-secondary)')
            .attr('font-size', '11px')
            .text(function (d) { return d.length > 20 ? d.slice(0, 18) + '..' : d; });

        // Y-axis labels (hosts)
        g.selectAll('.y-label')
            .data(hosts)
            .join('text')
            .attr('class', 'y-label')
            .attr('x', -8)
            .attr('y', function (d) { return y(d) + y.bandwidth() / 2; })
            .attr('text-anchor', 'end')
            .attr('dominant-baseline', 'middle')
            .attr('fill', 'var(--text-secondary)')
            .attr('font-size', '12px')
            .text(function (d) { return d.length > 24 ? d.slice(0, 22) + '..' : d; });

        // Build cell data
        var cells = [];
        hosts.forEach(function (host) {
            checks.forEach(function (check) {
                var cell = (matrix[host] && matrix[host][check]) || { status: 'not-run', observationCount: 0, observations: [] };
                cells.push({
                    host: host,
                    check: check,
                    status: cell.status,
                    observationCount: cell.observationCount,
                    observations: cell.observations,
                });
            });
        });

        // Draw cells
        g.selectAll('.coverage-cell')
            .data(cells)
            .join('rect')
            .attr('class', 'coverage-cell')
            .attr('x', function (d) { return x(d.check); })
            .attr('y', function (d) { return y(d.host); })
            .attr('width', x.bandwidth())
            .attr('height', y.bandwidth())
            .attr('rx', 3)
            .attr('fill', function (d) { return STATUS_COLORS[d.status] || STATUS_COLORS['not-run']; })
            .attr('stroke', 'var(--bg-primary)')
            .attr('stroke-width', 1.5)
            .style('cursor', function (d) { return d.observationCount > 0 ? 'pointer' : 'default'; })
            .on('mouseenter', function (event, d) {
                var statusLabel = d.status.charAt(0).toUpperCase() + d.status.slice(1).replace('-', ' ');
                tip.show(
                    '<strong>' + d.check + '</strong>' +
                    '<div class="coverage-tip-status">Host: ' + d.host + '</div>' +
                    '<div>Status: <span style="color:' + STATUS_COLORS[d.status] + '">' + statusLabel + '</span></div>' +
                    (d.observationCount > 0 ? '<div>' + d.observationCount + ' observation' + (d.observationCount !== 1 ? 's' : '') + '</div>' : ''),
                    event
                );
            })
            .on('mousemove', function (event) { tip.move(event); })
            .on('mouseleave', function () { tip.hide(); })
            .on('click', function (event, d) {
                if (d.observationCount === 0) return;
                var content =
                    '<div class="modal-section">' +
                    '<div class="modal-section-title">Check: ' + d.check + '</div>' +
                    '<div class="modal-section-content">Host: ' + d.host + '</div>' +
                    '</div>' +
                    '<div class="modal-section">' +
                    '<div class="modal-section-title">Observations (' + d.observationCount + ')</div>' +
                    '<div class="modal-section-content">' +
                    d.observations.map(function (f) {
                        return '<div style="padding:6px 0;border-bottom:1px solid var(--border)">' +
                            '<span class="severity-badge severity-' + f.severity + '">' + f.severity + '</span>' +
                            '<span style="margin-left:8px">' + f.title + '</span>' +
                            '</div>';
                    }).join('') +
                    '</div></div>';
                openModal(d.check + ' \u2014 ' + d.host, content);
            });

        // Observation count labels
        g.selectAll('.cell-observation-count')
            .data(cells.filter(function (d) { return d.observationCount > 0; }))
            .join('text')
            .attr('class', 'cell-observation-count')
            .attr('x', function (d) { return x(d.check) + x.bandwidth() / 2; })
            .attr('y', function (d) { return y(d.host) + y.bandwidth() / 2; })
            .attr('text-anchor', 'middle')
            .attr('dominant-baseline', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '11px')
            .attr('font-weight', '600')
            .attr('pointer-events', 'none')
            .text(function (d) { return d.observationCount; });

        // Summary row
        var summaryY = hosts.length * cellSize + 8;
        checks.forEach(function (check) {
            var ran = 0;
            hosts.forEach(function (host) {
                var status = matrix[host] && matrix[host][check] ? matrix[host][check].status : null;
                if (status === 'completed' || status === 'found') ran++;
            });
            var pct = hosts.length > 0 ? Math.round((ran / hosts.length) * 100) : 0;
            g.append('text')
                .attr('class', 'coverage-summary-row')
                .attr('x', x(check) + x.bandwidth() / 2)
                .attr('y', summaryY + 12)
                .attr('text-anchor', 'middle')
                .attr('fill', 'var(--text-muted)')
                .attr('font-size', '10px')
                .text(pct + '%');
        });
    };

})(window.ChainsmithViz);
