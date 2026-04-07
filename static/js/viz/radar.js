/**
 * Chainsmith Viz — Radar (attack-surface risk chart).
 * Requires: D3, viz-common.js
 */
(function (ns) {
    'use strict';

    var SEV_COLORS   = ns.SEV_COLORS;
    var SEV_WEIGHTS  = ns.SEV_WEIGHTS;
    var KNOWN_SUITES = ns.KNOWN_SUITES;

    /**
     * Build radar data: risk score per suite.
     */
    function buildRadarData(observationsList) {
        var scores = {};

        observationsList.forEach(function (f) {
            var suite = f.suite || ns.inferSuite(f.check_name);
            if (!scores[suite]) scores[suite] = { score: 0, breakdown: {}, observations: [] };
            var entry  = scores[suite];
            var weight = SEV_WEIGHTS[f.severity] || 0;
            entry.score += weight;
            entry.breakdown[f.severity] = (entry.breakdown[f.severity] || 0) + 1;
            entry.observations.push(f);
        });

        var suites = KNOWN_SUITES.filter(function (s) { return scores[s]; });
        Object.keys(scores).forEach(function (s) {
            if (!suites.includes(s)) suites.push(s);
        });

        return { suites: suites, scores: scores };
    }

    // Expose for tests
    window.buildRadarData    = buildRadarData;
    window.RADAR_RISK_WEIGHTS = SEV_WEIGHTS;
    ns.buildRadarData        = buildRadarData;

    /**
     * Render the radar visualization.
     */
    ns.renderRadar = function (observations, openModal) {
        var emptyEl   = document.getElementById('radar-empty');
        var contentEl = document.getElementById('radar-content');
        var tooltipEl = document.getElementById('radar-tooltip');
        var legendEl  = document.getElementById('radar-legend');
        var tip       = ns.tooltip(tooltipEl);

        if (observations.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        emptyEl.style.display       = 'none';
        contentEl.style.display     = 'flex';
        contentEl.style.flexDirection = 'column';
        contentEl.style.alignItems   = 'center';

        var data   = buildRadarData(observations);
        var suites = data.suites;
        var scores = data.scores;

        if (suites.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        // Legend
        legendEl.innerHTML = Object.entries(SEV_WEIGHTS).map(function (entry) {
            return '<span class="radar-legend-item"><span class="radar-swatch" style="background:' + SEV_COLORS[entry[0]] + '"></span>' + entry[0] + ' (\u00d7' + entry[1] + ')</span>';
        }).join('');

        // Sizing
        var size   = 480;
        var margin = 60;
        var radius = (size / 2) - margin;
        var cx     = size / 2;
        var cy     = size / 2;

        var svgEl = d3.select('#radar-graph')
            .attr('width', size)
            .attr('height', size);

        svgEl.selectAll('*').remove();

        var g = svgEl.append('g')
            .attr('transform', 'translate(' + cx + ',' + cy + ')');

        var maxScore   = Math.max.apply(null, suites.map(function (s) { return scores[s].score; }).concat([1]));
        var angleSlice = (2 * Math.PI) / suites.length;

        // Grid circles
        [0.25, 0.5, 0.75, 1.0].forEach(function (level) {
            g.append('circle')
                .attr('cx', 0).attr('cy', 0)
                .attr('r', radius * level)
                .attr('fill', 'none')
                .attr('stroke', 'var(--border)')
                .attr('stroke-dasharray', '3,3')
                .attr('stroke-width', 1);

            g.append('text')
                .attr('x', 4)
                .attr('y', -radius * level - 2)
                .attr('fill', 'var(--text-muted)')
                .attr('font-size', '10px')
                .text(Math.round(maxScore * level));
        });

        // Axis lines and labels
        suites.forEach(function (suite, i) {
            var angle = angleSlice * i - Math.PI / 2;
            var xEnd  = radius * Math.cos(angle);
            var yEnd  = radius * Math.sin(angle);

            g.append('line')
                .attr('x1', 0).attr('y1', 0)
                .attr('x2', xEnd).attr('y2', yEnd)
                .attr('stroke', 'var(--border)')
                .attr('stroke-width', 1);

            var labelR = radius + 18;
            g.append('text')
                .attr('x', labelR * Math.cos(angle))
                .attr('y', labelR * Math.sin(angle))
                .attr('text-anchor', 'middle')
                .attr('dominant-baseline', 'middle')
                .attr('fill', 'var(--text-secondary)')
                .attr('font-size', '12px')
                .attr('font-weight', '500')
                .text(suite.charAt(0).toUpperCase() + suite.slice(1));
        });

        // Polygon points
        var points = suites.map(function (suite, i) {
            var angle = angleSlice * i - Math.PI / 2;
            var r     = (scores[suite].score / maxScore) * radius;
            return {
                x: r * Math.cos(angle),
                y: r * Math.sin(angle),
                suite: suite,
                score: scores[suite].score,
                breakdown: scores[suite].breakdown,
                observations: scores[suite].observations,
            };
        });

        var lineGenerator = d3.lineRadial()
            .radius(function (d, i) { return (scores[suites[i]].score / maxScore) * radius; })
            .angle(function (d, i) { return angleSlice * i; })
            .curve(d3.curveLinearClosed);

        // Filled polygon
        g.append('path')
            .attr('d', lineGenerator(suites))
            .attr('fill', 'rgba(74, 158, 255, 0.25)')
            .attr('stroke', '#4a9eff')
            .attr('stroke-width', 2);

        // Dots
        g.selectAll('.radar-dot')
            .data(points)
            .join('circle')
            .attr('class', 'radar-dot')
            .attr('cx', function (d) { return d.x; })
            .attr('cy', function (d) { return d.y; })
            .attr('r', 6)
            .attr('fill', '#4a9eff')
            .attr('stroke', 'var(--bg-primary)')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer')
            .on('mouseenter', function (event, d) {
                var breakdownHtml = Object.entries(d.breakdown)
                    .sort(function (a, b) { return (SEV_WEIGHTS[b[0]] || 0) - (SEV_WEIGHTS[a[0]] || 0); })
                    .map(function (e) { return '<div>' + e[0] + ': ' + e[1] + ' \u00d7 ' + (SEV_WEIGHTS[e[0]] || 0) + ' = ' + e[1] * (SEV_WEIGHTS[e[0]] || 0) + '</div>'; })
                    .join('');
                tip.show(
                    '<strong>' + d.suite.charAt(0).toUpperCase() + d.suite.slice(1) + '</strong>' +
                    '<div class="radar-tip-score">Risk score: ' + d.score + '</div>' +
                    '<div style="margin-top:4px;font-size:0.75rem">' + breakdownHtml + '</div>',
                    event
                );
            })
            .on('mousemove', function (event) { tip.move(event); })
            .on('mouseleave', function () { tip.hide(); })
            .on('click', function (event, d) {
                var content =
                    '<div class="modal-section">' +
                    '<div class="modal-section-title">' + d.suite.charAt(0).toUpperCase() + d.suite.slice(1) + ' \u2014 Risk Score: ' + d.score + '</div>' +
                    '<div class="modal-section-content">' +
                    d.observations.map(function (f) {
                        return '<div style="padding:6px 0;border-bottom:1px solid var(--border)">' +
                            '<span class="severity-badge severity-' + f.severity + '">' + f.severity + '</span>' +
                            '<span style="margin-left:8px">' + f.title + '</span>' +
                            '<span style="float:right;color:var(--text-muted)">+' + (SEV_WEIGHTS[f.severity] || 0) + '</span>' +
                            '</div>';
                    }).join('') +
                    '</div></div>';
                openModal(d.suite.charAt(0).toUpperCase() + d.suite.slice(1) + ' Observations', content);
            });
    };

})(window.ChainsmithViz);
