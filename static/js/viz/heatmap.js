/**
 * Chainsmith Viz — Heatmap (Host × Suite severity matrix).
 * Requires: D3, viz-common.js
 */
(function (ns) {
    'use strict';

    var SEV_COLORS = ns.SEV_COLORS;
    var SEV_ORDER  = ns.SEV_ORDER;

    /**
     * Build heatmap data: host × suite matrix with worst severity per cell.
     */
    function buildHeatmapData(observationsList) {
        var matrix = {};   // host -> suite -> { worst, count, observations }
        var hosts  = new Set();
        var suites = new Set();

        observationsList.forEach(function (f) {
            var rawHost = f.target_host || 'unknown';
            var host  = ns.normalizeHost(rawHost);
            var suite = f.suite || ns.inferSuite(f.check_name);
            hosts.add(host);
            suites.add(suite);

            if (!matrix[host]) matrix[host] = {};
            if (!matrix[host][suite]) matrix[host][suite] = { worst: null, count: 0, observations: [] };

            var cell = matrix[host][suite];
            cell.count++;
            cell.observations.push(f);

            var sevIdx   = SEV_ORDER.indexOf(f.severity);
            var worstIdx = cell.worst ? SEV_ORDER.indexOf(cell.worst) : SEV_ORDER.length;
            if (sevIdx >= 0 && sevIdx < worstIdx) {
                cell.worst = f.severity;
            }
        });

        // Merge known suites with discovered suites, preserve order
        var allSuites = ns.KNOWN_SUITES.filter(function (s) { return suites.has(s); });
        suites.forEach(function (s) {
            if (!allSuites.includes(s)) allSuites.push(s);
        });

        var sortedHosts = Array.from(hosts).sort();
        return { matrix: matrix, hosts: sortedHosts, suites: allSuites };
    }

    // Expose for tests
    window.buildHeatmapData = buildHeatmapData;
    ns.buildHeatmapData = buildHeatmapData;

    /**
     * Render the heatmap visualization.
     */
    ns.renderHeatmap = function (observations, openModal) {
        var container = document.getElementById('heatmap-container');
        var emptyEl   = document.getElementById('heatmap-empty');
        var contentEl = document.getElementById('heatmap-content');
        var tooltipEl = document.getElementById('heatmap-tooltip');
        var tip       = ns.tooltip(tooltipEl);

        if (observations.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        emptyEl.style.display  = 'none';
        contentEl.style.display = 'block';

        var data   = buildHeatmapData(observations);
        var matrix = data.matrix;
        var hosts  = data.hosts;
        var suites = data.suites;

        // Sizing
        var margin   = { top: 60, right: 20, bottom: 20, left: 180 };
        var cellSize = 48;
        var width    = margin.left + suites.length * cellSize + margin.right;
        var height   = margin.top + hosts.length * cellSize + margin.bottom;

        var svgEl = d3.select('#heatmap-graph')
            .attr('width', width)
            .attr('height', height);

        svgEl.selectAll('*').remove();

        var g = svgEl.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var x = d3.scaleBand()
            .domain(suites)
            .range([0, suites.length * cellSize])
            .padding(0.08);

        var y = d3.scaleBand()
            .domain(hosts)
            .range([0, hosts.length * cellSize])
            .padding(0.08);

        // X-axis labels (suites)
        g.selectAll('.x-label')
            .data(suites)
            .join('text')
            .attr('class', 'x-label')
            .attr('x', function (d) { return x(d) + x.bandwidth() / 2; })
            .attr('y', -8)
            .attr('text-anchor', 'middle')
            .attr('fill', 'var(--text-secondary)')
            .attr('font-size', '12px')
            .attr('font-weight', '500')
            .text(function (d) { return d.charAt(0).toUpperCase() + d.slice(1); });

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
            .text(function (d) { return d.length > 24 ? d.slice(0, 22) + '...' : d; });

        // Build cell data
        var cells = [];
        hosts.forEach(function (host) {
            suites.forEach(function (suite) {
                var cell = matrix[host] && matrix[host][suite];
                cells.push({
                    host: host,
                    suite: suite,
                    worst: cell ? cell.worst || 'none' : 'none',
                    count: cell ? cell.count : 0,
                    observations: cell ? cell.observations : [],
                });
            });
        });

        // Draw cells
        g.selectAll('.heatmap-cell')
            .data(cells)
            .join('rect')
            .attr('class', 'heatmap-cell')
            .attr('x', function (d) { return x(d.suite); })
            .attr('y', function (d) { return y(d.host); })
            .attr('width', x.bandwidth())
            .attr('height', y.bandwidth())
            .attr('rx', 4)
            .attr('fill', function (d) { return SEV_COLORS[d.worst] || SEV_COLORS.none; })
            .attr('stroke', 'var(--bg-primary)')
            .attr('stroke-width', 2)
            .style('cursor', function (d) { return d.count > 0 ? 'pointer' : 'default'; })
            .on('mouseenter', function (event, d) {
                if (d.count === 0) return;
                tip.show(
                    '<strong>' + d.host + ' / ' + d.suite + '</strong>' +
                    '<div class="heatmap-tip-count">' + d.count + ' observation' + (d.count !== 1 ? 's' : '') + '</div>' +
                    '<div>Worst: <span style="color:' + SEV_COLORS[d.worst] + '">' + d.worst + '</span></div>',
                    event
                );
            })
            .on('mousemove', function (event) { tip.move(event); })
            .on('mouseleave', function () { tip.hide(); })
            .on('click', function (event, d) {
                if (d.count === 0) return;
                var content =
                    '<div class="modal-section">' +
                    '<div class="modal-section-title">Host</div>' +
                    '<div class="modal-section-content">' + d.host + '</div>' +
                    '</div>' +
                    '<div class="modal-section">' +
                    '<div class="modal-section-title">Suite: ' + d.suite + '</div>' +
                    '<div class="modal-section-content">' +
                    d.observations.map(function (f) {
                        return '<div style="padding:6px 0;border-bottom:1px solid var(--border)">' +
                            '<span class="severity-badge severity-' + f.severity + '">' + f.severity + '</span>' +
                            '<span style="margin-left:8px">' + f.title + '</span>' +
                            '</div>';
                    }).join('') +
                    '</div></div>';
                openModal(d.host + ' \u2014 ' + d.suite, content);
            });

        // Cell count labels
        g.selectAll('.cell-count')
            .data(cells.filter(function (d) { return d.count > 0; }))
            .join('text')
            .attr('class', 'cell-count')
            .attr('x', function (d) { return x(d.suite) + x.bandwidth() / 2; })
            .attr('y', function (d) { return y(d.host) + y.bandwidth() / 2; })
            .attr('text-anchor', 'middle')
            .attr('dominant-baseline', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '13px')
            .attr('font-weight', '600')
            .attr('pointer-events', 'none')
            .text(function (d) { return d.count; });
    };

})(window.ChainsmithViz);
