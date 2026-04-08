/**
 * Chainsmith Viz — Timeline (discovery-order scatter by swim lanes).
 * Requires: D3, viz-common.js
 */
(function (ns) {
    'use strict';

    var SEV_COLORS = ns.SEV_COLORS;
    var RADII      = ns.TIMELINE_SEV_RADII;

    /**
     * Build timeline data: points + swim lanes grouped by host or suite.
     */
    function buildTimelineData(observationsList, groupBy) {
        var mode  = groupBy || 'host';
        var lanes = {};
        var points = [];

        observationsList.forEach(function (f, index) {
            var rawHost = f.host || f.target_url || 'unknown';
            var host  = ns.normalizeHost(rawHost);
            var suite = f.suite || ns.inferSuite(f.check_name);
            var lane  = mode === 'host' ? host : suite;

            if (!lanes[lane]) lanes[lane] = [];

            var point = {
                index: index,
                observation: f,
                lane: lane,
                host: host,
                suite: suite,
                severity: f.severity || 'info',
                title: f.title || 'Untitled',
                checkName: f.check_name || '',
                createdAt: f.created_at || null,
            };
            points.push(point);
            lanes[lane].push(point);
        });

        // Sort lane keys
        var laneKeys;
        if (mode === 'suite') {
            var known = ns.KNOWN_SUITES.filter(function (s) { return s in lanes; });
            var extra = Object.keys(lanes).filter(function (k) { return !known.includes(k); }).sort();
            laneKeys = known.concat(extra);
        } else {
            laneKeys = Object.keys(lanes).sort();
        }

        return { points: points, lanes: lanes, laneKeys: laneKeys };
    }

    // Expose for tests
    window.buildTimelineData = buildTimelineData;
    ns.buildTimelineData = buildTimelineData;

    // Expose constants for backward compat
    window.TIMELINE_SEV_COLORS = SEV_COLORS;
    window.TIMELINE_SEV_RADII  = RADII;

    /**
     * Render the timeline visualization.
     */
    ns.renderTimeline = function (observations, openModal, timelineGroupBy) {
        var emptyEl   = document.getElementById('timeline-empty');
        var contentEl = document.getElementById('timeline-content');
        var tooltipEl = document.getElementById('timeline-tooltip');
        var tip       = ns.tooltip(tooltipEl);

        if (observations.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        emptyEl.style.display  = 'none';
        contentEl.style.display = 'block';

        var data     = buildTimelineData(observations, timelineGroupBy);
        var points   = data.points;
        var laneKeys = data.laneKeys;

        if (laneKeys.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        // Sizing — extra bottom margin when timestamps are available
        var hasAnyTimestamp = points.some(function (p) { return !!p.createdAt; });
        var laneHeight = 48;
        var margin     = { top: 40, right: 30, bottom: hasAnyTimestamp ? 48 : 30, left: 160 };
        var width      = Math.max(600, points.length * 24 + margin.left + margin.right);
        var height     = margin.top + laneKeys.length * laneHeight + margin.bottom;

        var svgEl = d3.select('#timeline-graph')
            .attr('width', width)
            .attr('height', height);

        svgEl.selectAll('*').remove();

        var g = svgEl.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var innerWidth  = width - margin.left - margin.right;
        var innerHeight = laneKeys.length * laneHeight;

        var x = d3.scaleLinear()
            .domain([0, Math.max(1, points.length - 1)])
            .range([0, innerWidth]);

        var y = d3.scaleBand()
            .domain(laneKeys)
            .range([0, innerHeight])
            .padding(0.2);

        // Swim lane backgrounds
        g.selectAll('.timeline-lane-bg')
            .data(laneKeys)
            .join('rect')
            .attr('class', 'timeline-lane-bg')
            .attr('x', 0)
            .attr('y', function (d) { return y(d); })
            .attr('width', innerWidth)
            .attr('height', y.bandwidth())
            .attr('fill', function (d, i) { return i % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'rgba(255,255,255,0.05)'; })
            .attr('rx', 3);

        // Y-axis lane labels
        g.selectAll('.timeline-lane-label')
            .data(laneKeys)
            .join('text')
            .attr('class', 'timeline-lane-label')
            .attr('x', -12)
            .attr('y', function (d) { return y(d) + y.bandwidth() / 2; })
            .attr('text-anchor', 'end')
            .attr('dominant-baseline', 'middle')
            .attr('fill', 'var(--text-secondary)')
            .attr('font-size', '12px')
            .text(function (d) { return d.length > 20 ? d.slice(0, 18) + '..' : d; });

        // X-axis
        var xAxis = d3.axisBottom(x)
            .ticks(Math.min(points.length, 10))
            .tickFormat(function (d) { return '#' + (Math.round(d) + 1); });

        g.append('g')
            .attr('transform', 'translate(0,' + innerHeight + ')')
            .call(xAxis)
            .selectAll('text')
            .attr('fill', 'var(--text-muted)')
            .attr('font-size', '10px');

        g.selectAll('.domain, .tick line')
            .attr('stroke', 'var(--border)');

        // Check if timestamps are available for time-based axis labels
        var hasTimestamps = points.some(function (p) { return !!p.createdAt; });

        if (hasTimestamps) {
            // Add short time labels below discovery-order ticks
            var tickIndices = x.ticks(Math.min(points.length, 10)).map(Math.round);
            g.selectAll('.timeline-time-label')
                .data(tickIndices.filter(function (i) { return i >= 0 && i < points.length; }))
                .join('text')
                .attr('class', 'timeline-time-label')
                .attr('x', function (i) { return x(i); })
                .attr('y', innerHeight + 26)
                .attr('text-anchor', 'middle')
                .attr('fill', 'var(--text-muted)')
                .attr('font-size', '9px')
                .attr('opacity', 0.7)
                .text(function (i) { return ns.formatTimeShort(points[i].createdAt); });
        }

        // X-axis label — show time range if timestamps available
        var axisLabel = 'Discovery order';
        if (hasTimestamps && points.length >= 2) {
            var firstTs = ns.formatTimeShort(points[0].createdAt);
            var lastTs = ns.formatTimeShort(points[points.length - 1].createdAt);
            if (firstTs && lastTs) {
                axisLabel = 'Discovery order (' + firstTs + ' \u2013 ' + lastTs + ')';
            }
        }

        g.append('text')
            .attr('x', innerWidth / 2)
            .attr('y', innerHeight + (hasTimestamps ? 40 : 28))
            .attr('text-anchor', 'middle')
            .attr('fill', 'var(--text-muted)')
            .attr('font-size', '11px')
            .text(axisLabel);

        // Observation dots
        g.selectAll('.timeline-dot')
            .data(points)
            .join('circle')
            .attr('class', 'timeline-dot')
            .attr('cx', function (d) { return x(d.index); })
            .attr('cy', function (d) { return y(d.lane) + y.bandwidth() / 2; })
            .attr('r', function (d) { return RADII[d.severity] || 4; })
            .attr('fill', function (d) { return SEV_COLORS[d.severity] || SEV_COLORS.info; })
            .attr('stroke', 'var(--bg-primary)')
            .attr('stroke-width', 1.5)
            .attr('opacity', 0.9)
            .style('cursor', 'pointer')
            .on('mouseenter', function (event, d) {
                var tsHtml = '';
                if (d.createdAt) {
                    var abs = ns.formatTimestamp(d.createdAt);
                    var rel = ns.relativeTime(d.createdAt);
                    tsHtml = '<div class="timeline-tip-detail">Time: ' + abs +
                        (rel ? ' <span style="opacity:0.7">(' + rel + ')</span>' : '') + '</div>';
                }
                tip.show(
                    '<strong>' + d.title + '</strong>' +
                    '<div class="timeline-tip-detail">Severity: <span style="color:' + SEV_COLORS[d.severity] + '">' + d.severity + '</span></div>' +
                    '<div class="timeline-tip-detail">Host: ' + d.host + '</div>' +
                    '<div class="timeline-tip-detail">Suite: ' + d.suite + '</div>' +
                    (d.checkName ? '<div class="timeline-tip-detail">Check: ' + d.checkName + '</div>' : '') +
                    '<div class="timeline-tip-detail">Order: #' + (d.index + 1) + '</div>' +
                    tsHtml,
                    event
                );
            })
            .on('mousemove', function (event) { tip.move(event); })
            .on('mouseleave', function () { tip.hide(); })
            .on('click', function (event, d) {
                openModal(d.observation.title, getObservationModalContent(d.observation));
            });
    };

})(window.ChainsmithViz);
