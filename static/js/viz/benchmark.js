/**
 * Chainsmith Viz — Benchmark Bar Chart.
 * Grouped bar chart comparing current scan findings per severity against a baseline.
 * Requires: D3, viz-common.js
 */
(function (ns) {
    'use strict';

    var SEV_COLORS = ns.SEV_COLORS;
    var SEV_ORDER  = ns.SEV_ORDER;

    /**
     * Build benchmark data: severity counts per host, with weighted baseline.
     * Returns { hosts, currentCounts, weightedBaseline }.
     */
    function buildBenchmarkData(observationsList) {
        // Group observations by normalized host
        var hostMap = {};  // host -> observations[]
        observationsList.forEach(function (f) {
            var rawHost = f.host || f.target_url || 'unknown';
            var host = ns.normalizeHost(rawHost);
            if (!hostMap[host]) hostMap[host] = [];
            hostMap[host].push(f);
        });

        var hosts = Object.keys(hostMap).sort();

        // Per-host severity counts and check counts (for weighting)
        var perHost = {};  // host -> { counts: {sev: n}, checkCount: n }
        hosts.forEach(function (host) {
            var obs = hostMap[host];
            var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            var checks = new Set();
            obs.forEach(function (f) {
                if (counts.hasOwnProperty(f.severity)) {
                    counts[f.severity]++;
                }
                if (f.check_name) checks.add(f.check_name);
            });
            perHost[host] = { counts: counts, checkCount: Math.max(checks.size, 1) };
        });

        // Weighted average baseline across all hosts (weighted by checks-per-host)
        var totalWeight = 0;
        var weightedSums = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        hosts.forEach(function (host) {
            var w = perHost[host].checkCount;
            totalWeight += w;
            SEV_ORDER.forEach(function (sev) {
                weightedSums[sev] += perHost[host].counts[sev] * w;
            });
        });

        var weightedBaseline = {};
        SEV_ORDER.forEach(function (sev) {
            weightedBaseline[sev] = totalWeight > 0
                ? Math.round((weightedSums[sev] / totalWeight) * 10) / 10
                : 0;
        });

        return {
            hosts: hosts,
            perHost: perHost,
            weightedBaseline: weightedBaseline,
        };
    }

    /**
     * Compute historical baseline from trend API response data_points.
     * Returns { critical: avg, high: avg, ... }
     */
    function computeHistoricalBaseline(dataPoints) {
        var baseline = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        if (!dataPoints || dataPoints.length === 0) return baseline;

        dataPoints.forEach(function (dp) {
            SEV_ORDER.forEach(function (sev) {
                baseline[sev] += (dp[sev] || 0);
            });
        });

        SEV_ORDER.forEach(function (sev) {
            baseline[sev] = Math.round((baseline[sev] / dataPoints.length) * 10) / 10;
        });

        return baseline;
    }

    // Expose for tests
    window.buildBenchmarkData = buildBenchmarkData;
    ns.buildBenchmarkData = buildBenchmarkData;
    window.computeHistoricalBaseline = computeHistoricalBaseline;
    ns.computeHistoricalBaseline = computeHistoricalBaseline;

    /**
     * Render the benchmark bar chart visualization.
     *
     * @param {Array}    observations  Current scan observations
     * @param {Function} openModal     Modal opener callback
     * @param {Object}   [options]     { targetDomain: string }
     */
    ns.renderBenchmark = function (observations, openModal, options) {
        options = options || {};

        var emptyEl     = document.getElementById('benchmark-empty');
        var contentEl   = document.getElementById('benchmark-content');
        var tooltipEl   = document.getElementById('benchmark-tooltip');
        var tip         = ns.tooltip(tooltipEl);

        if (observations.length === 0) {
            emptyEl.style.display  = 'flex';
            contentEl.style.display = 'none';
            return;
        }

        emptyEl.style.display  = 'none';
        contentEl.style.display = 'block';

        var data = buildBenchmarkData(observations);

        // --- Controls ---
        var hostSelect     = document.getElementById('benchmark-host-select');
        var baselineSelect = document.getElementById('benchmark-baseline-select');
        var depthSelect    = document.getElementById('benchmark-depth-select');
        var historyNote    = document.getElementById('benchmark-history-note');

        // Populate host dropdown
        hostSelect.innerHTML = '<option value="__all__">All Hosts</option>';
        data.hosts.forEach(function (h) {
            var opt = document.createElement('option');
            opt.value = h;
            opt.textContent = h;
            hostSelect.appendChild(opt);
        });

        // State
        var currentHost     = '__all__';
        var currentBaseline = 'all_hosts';
        var currentDepth    = 5;
        var trendCache      = null;

        function getSelectedCounts() {
            if (currentHost === '__all__') {
                // Sum across all hosts
                var totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                data.hosts.forEach(function (h) {
                    SEV_ORDER.forEach(function (sev) {
                        totals[sev] += data.perHost[h].counts[sev];
                    });
                });
                return totals;
            }
            return data.perHost[currentHost]
                ? data.perHost[currentHost].counts
                : { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        }

        function getBaselineLabel() {
            if (currentBaseline === 'all_hosts') return 'All Hosts Average (weighted)';
            return 'Target History (last ' + (currentDepth || 'all') + ' scans)';
        }

        function updateBaselineOptions() {
            if (currentHost === '__all__') {
                // Auto-switch: disable "all hosts" baseline, force "target history"
                baselineSelect.value = 'target_history';
                currentBaseline = 'target_history';
                Array.from(baselineSelect.options).forEach(function (opt) {
                    opt.disabled = opt.value === 'all_hosts';
                });
            } else {
                Array.from(baselineSelect.options).forEach(function (opt) {
                    opt.disabled = false;
                });
            }
        }

        async function getBaseline() {
            if (currentBaseline === 'all_hosts') {
                depthSelect.style.display = 'none';
                historyNote.textContent = '';
                return data.weightedBaseline;
            }

            // Target history
            depthSelect.style.display = 'inline-block';

            if (!options.targetDomain) {
                historyNote.textContent = 'No target domain available for history lookup';
                return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            }

            try {
                var filters = {};
                if (currentDepth) filters.last_n = currentDepth;
                var trendData = await api.getTargetTrend(options.targetDomain, filters);
                trendCache = trendData;

                if (!trendData.data_points || trendData.data_points.length === 0) {
                    historyNote.textContent = 'Run multiple scans to see historical baseline';
                    return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                }

                historyNote.textContent = 'Based on ' + trendData.data_points.length + ' historical scan(s)';
                return computeHistoricalBaseline(trendData.data_points);
            } catch (err) {
                console.error('Benchmark: failed to load target trend', err);
                historyNote.textContent = 'Failed to load historical data';
                return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            }
        }

        async function draw() {
            updateBaselineOptions();
            var counts   = getSelectedCounts();
            var baseline = await getBaseline();

            drawChart(counts, baseline, tip, openModal);
        }

        function drawChart(counts, baseline, tip, openModal) {
            var svgEl = d3.select('#benchmark-graph');
            svgEl.selectAll('*').remove();

            var margin = { top: 30, right: 30, bottom: 50, left: 50 };
            var containerEl = document.getElementById('benchmark-chart-area');
            var totalWidth  = containerEl.clientWidth || 600;
            var totalHeight = Math.min(400, Math.max(280, totalWidth * 0.5));
            var width  = totalWidth - margin.left - margin.right;
            var height = totalHeight - margin.top - margin.bottom;

            svgEl
                .attr('width', totalWidth)
                .attr('height', totalHeight);

            var g = svgEl.append('g')
                .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

            // X scale: severity categories
            var x0 = d3.scaleBand()
                .domain(SEV_ORDER)
                .range([0, width])
                .padding(0.3);

            var x1 = d3.scaleBand()
                .domain(['current', 'baseline'])
                .range([0, x0.bandwidth()])
                .padding(0.08);

            // Y scale: max of current or baseline
            var maxVal = 0;
            SEV_ORDER.forEach(function (sev) {
                maxVal = Math.max(maxVal, counts[sev], baseline[sev]);
            });
            maxVal = Math.max(maxVal, 1);  // avoid 0 domain

            var y = d3.scaleLinear()
                .domain([0, maxVal * 1.1])
                .range([height, 0])
                .nice();

            // X axis
            g.append('g')
                .attr('class', 'axis')
                .attr('transform', 'translate(0,' + height + ')')
                .call(d3.axisBottom(x0).tickSize(0))
                .selectAll('text')
                .attr('fill', 'var(--text-secondary)')
                .attr('font-size', '12px')
                .style('text-transform', 'capitalize');

            // Y axis
            g.append('g')
                .attr('class', 'axis')
                .call(d3.axisLeft(y).ticks(5))
                .selectAll('text')
                .attr('fill', 'var(--text-secondary)')
                .attr('font-size', '11px');

            // Y grid lines
            g.append('g')
                .attr('class', 'grid')
                .call(d3.axisLeft(y).ticks(5).tickSize(-width).tickFormat(''));

            // Build bar data
            var barData = [];
            SEV_ORDER.forEach(function (sev) {
                barData.push({ sev: sev, group: 'current',  value: counts[sev] });
                barData.push({ sev: sev, group: 'baseline', value: baseline[sev] });
            });

            // Draw bars
            g.selectAll('.benchmark-bar')
                .data(barData)
                .join('rect')
                .attr('class', 'benchmark-bar')
                .attr('x', function (d) { return x0(d.sev) + x1(d.group); })
                .attr('y', function (d) { return y(d.value); })
                .attr('width', x1.bandwidth())
                .attr('height', function (d) { return height - y(d.value); })
                .attr('rx', 3)
                .attr('fill', function (d) {
                    if (d.group === 'current') return SEV_COLORS[d.sev];
                    // Baseline: same color but with transparency
                    return SEV_COLORS[d.sev];
                })
                .attr('opacity', function (d) {
                    return d.group === 'current' ? 1.0 : 0.35;
                })
                .style('cursor', 'pointer')
                .on('mouseenter', function (event, d) {
                    var label = d.group === 'current' ? 'Current Scan' : getBaselineLabel();
                    tip.show(
                        '<strong>' + d.sev.charAt(0).toUpperCase() + d.sev.slice(1) + '</strong>' +
                        '<div>' + label + ': ' + d.value + '</div>',
                        event
                    );
                })
                .on('mousemove', function (event) { tip.move(event); })
                .on('mouseleave', function () { tip.hide(); });

            // Bar value labels
            g.selectAll('.bar-label')
                .data(barData.filter(function (d) { return d.value > 0; }))
                .join('text')
                .attr('class', 'bar-label')
                .attr('x', function (d) { return x0(d.sev) + x1(d.group) + x1.bandwidth() / 2; })
                .attr('y', function (d) { return y(d.value) - 5; })
                .attr('text-anchor', 'middle')
                .attr('fill', 'var(--text-secondary)')
                .attr('font-size', '11px')
                .attr('font-weight', '500')
                .text(function (d) { return d.value; });

            // Legend
            var legendEl = document.getElementById('benchmark-legend');
            legendEl.innerHTML =
                '<span class="benchmark-legend-item">' +
                    '<span class="benchmark-swatch" style="opacity:1;background:var(--accent)"></span>Current Scan' +
                '</span>' +
                '<span class="benchmark-legend-item">' +
                    '<span class="benchmark-swatch" style="opacity:0.35;background:var(--accent)"></span>' + getBaselineLabel() +
                '</span>';
        }

        // Event listeners
        hostSelect.onchange = function () {
            currentHost = hostSelect.value;
            draw();
        };

        baselineSelect.onchange = function () {
            currentBaseline = baselineSelect.value;
            draw();
        };

        depthSelect.onchange = function () {
            var v = depthSelect.value;
            currentDepth = v === 'all' ? null : parseInt(v, 10);
            draw();
        };

        // Initial draw
        updateBaselineOptions();
        draw();
    };

})(window.ChainsmithViz);
