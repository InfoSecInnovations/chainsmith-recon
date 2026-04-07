/**
 * Chainsmith Viz — Trend Charts (severity, risk, suite, new/resolved, delta).
 * Requires: D3, viz-common.js
 */
(function (ns) {
    'use strict';

    var SEV_COLORS  = ns.SEV_COLORS;
    var SEV_ORDER   = ns.SEV_ORDER;
    var SUITE_COLORS = ns.SUITE_COLORS;

    var STATUS_COLORS = {
        new: '#22c55e',
        resolved: '#6b7280',
        regressed: '#ef4444',
    };

    function getChartDimensions(containerId) {
        var container = document.getElementById(containerId);
        var rect   = container.getBoundingClientRect();
        var margin = { top: 40, right: 30, bottom: 50, left: 50 };
        return {
            container: container,
            width: Math.max(rect.width - margin.left - margin.right, 200),
            height: Math.max(rect.height - margin.top - margin.bottom, 200),
            margin: margin,
            fullWidth: rect.width,
            fullHeight: rect.height,
        };
    }

    function showTooltip(tooltip, html, event) {
        tooltip.innerHTML = html;
        tooltip.classList.add('visible');
        tooltip.style.left = (event.pageX + 12) + 'px';
        tooltip.style.top  = (event.pageY - 12) + 'px';
    }

    function hideTooltip(tooltip) {
        tooltip.classList.remove('visible');
    }

    // ─── Severity Trend (Line Chart) ──────────────────────────────
    ns.renderSeverityChart = function (dataPoints, tooltip, openExportPanel) {
        var dims = getChartDimensions('chart-severity');
        var container = dims.container;
        var width = dims.width, height = dims.height, margin = dims.margin;
        container.innerHTML = '';

        var svg = d3.select(container).append('svg')
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom);

        var g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var parseDate = function (d) { return new Date(d.date); };
        var x = d3.scaleTime()
            .domain(d3.extent(dataPoints, parseDate))
            .range([0, width]);

        var maxCount = d3.max(dataPoints, function (d) {
            return Math.max(d.critical, d.high, d.medium, d.low, d.info);
        }) || 1;

        var y = d3.scaleLinear()
            .domain([0, maxCount * 1.1])
            .range([height, 0]);

        g.append('g').attr('class', 'grid')
            .call(d3.axisLeft(y).ticks(5).tickSize(-width).tickFormat(''));

        g.append('g').attr('class', 'axis')
            .attr('transform', 'translate(0,' + height + ')')
            .call(d3.axisBottom(x).ticks(Math.min(dataPoints.length, 8)));

        g.append('g').attr('class', 'axis')
            .call(d3.axisLeft(y).ticks(5));

        var hidden = new Set();
        var lineGroup = g.append('g');

        function drawLines() {
            lineGroup.selectAll('*').remove();
            SEV_ORDER.forEach(function (sev) {
                if (hidden.has(sev)) return;
                var line = d3.line()
                    .x(function (d) { return x(parseDate(d)); })
                    .y(function (d) { return y(d[sev] || 0); })
                    .curve(d3.curveMonotoneX);

                lineGroup.append('path')
                    .datum(dataPoints)
                    .attr('fill', 'none')
                    .attr('stroke', SEV_COLORS[sev])
                    .attr('stroke-width', 2.5)
                    .attr('d', line);

                lineGroup.selectAll('.dot-' + sev)
                    .data(dataPoints)
                    .enter().append('circle')
                    .attr('cx', function (d) { return x(parseDate(d)); })
                    .attr('cy', function (d) { return y(d[sev] || 0); })
                    .attr('r', 4)
                    .attr('fill', SEV_COLORS[sev])
                    .attr('stroke', 'var(--bg-primary)')
                    .attr('stroke-width', 1.5)
                    .on('mouseover', function (event, d) {
                        showTooltip(tooltip,
                            '<div style="font-weight:600;margin-bottom:4px">' + (d.date ? d.date.substring(0, 10) : '') + '</div>' +
                            SEV_ORDER.map(function (s) { return '<div style="color:' + SEV_COLORS[s] + '">' + s + ': ' + d[s] + '</div>'; }).join('') +
                            '<div style="margin-top:4px;color:var(--text-secondary)">Total: ' + d.total + ' | Risk: ' + d.risk_score + '</div>' +
                            '<div style="margin-top:2px;color:var(--accent);font-size:0.6875rem">Click to view observations</div>',
                            event
                        );
                    })
                    .on('mouseout', function () { hideTooltip(tooltip); })
                    .on('click', function (event, d) {
                        hideTooltip(tooltip);
                        openExportPanel(d.scan_id, d.date ? d.date.substring(0, 10) : d.scan_id.substring(0, 8));
                    })
                    .style('cursor', 'pointer');
            });
        }

        drawLines();

        var legend = d3.select(container).insert('div', 'svg').attr('class', 'legend');
        SEV_ORDER.forEach(function (sev) {
            var item = legend.append('div').attr('class', 'legend-item')
                .on('click', function () {
                    if (hidden.has(sev)) hidden.delete(sev); else hidden.add(sev);
                    item.classed('muted', hidden.has(sev));
                    drawLines();
                });
            item.append('div').attr('class', 'legend-swatch').style('background', SEV_COLORS[sev]);
            item.append('span').text(sev);
        });
    };

    // ─── Risk Score (Bar + Line) ──────────────────────────────────
    ns.renderRiskChart = function (dataPoints, tooltip, openExportPanel) {
        var dims = getChartDimensions('chart-risk');
        var container = dims.container;
        var width = dims.width, height = dims.height, margin = dims.margin;
        margin.right = 60;
        var effectiveWidth = width - 30;
        container.innerHTML = '';

        var svg = d3.select(container).append('svg')
            .attr('width', effectiveWidth + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom);

        var g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var x = d3.scaleBand()
            .domain(dataPoints.map(function (d, i) { return i; }))
            .range([0, effectiveWidth])
            .padding(0.3);

        var maxStacked = d3.max(dataPoints, function (d) {
            return d.critical + d.high + d.medium + d.low + d.info;
        }) || 1;

        var y = d3.scaleLinear().domain([0, maxStacked * 1.1]).range([height, 0]);
        var maxRisk = d3.max(dataPoints, function (d) { return d.risk_score; }) || 1;
        var yRisk = d3.scaleLinear().domain([0, maxRisk * 1.2]).range([height, 0]);

        g.append('g').attr('class', 'grid')
            .call(d3.axisLeft(y).ticks(5).tickSize(-effectiveWidth).tickFormat(''));

        g.append('g').attr('class', 'axis')
            .attr('transform', 'translate(0,' + height + ')')
            .call(d3.axisBottom(x).tickFormat(function (i) {
                var dp = dataPoints[i];
                return dp && dp.date ? dp.date.substring(5, 10) : '';
            }));

        g.append('g').attr('class', 'axis').call(d3.axisLeft(y).ticks(5));

        g.append('g').attr('class', 'axis')
            .attr('transform', 'translate(' + effectiveWidth + ',0)')
            .call(d3.axisRight(yRisk).ticks(5))
            .selectAll('text').style('fill', '#4ade80');

        var stack = d3.stack().keys(SEV_ORDER).value(function (d, key) { return d[key] || 0; });
        var stacked = stack(dataPoints);

        g.selectAll('.layer')
            .data(stacked)
            .enter().append('g')
            .attr('fill', function (d) { return SEV_COLORS[d.key]; })
            .selectAll('rect')
            .data(function (d) { return d.map(function (v, i) { return Object.assign({}, v, { index: i }); }); })
            .enter().append('rect')
            .attr('x', function (d) { return x(d.index); })
            .attr('y', function (d) { return y(d[1]); })
            .attr('height', function (d) { return y(d[0]) - y(d[1]); })
            .attr('width', x.bandwidth())
            .attr('rx', 2)
            .on('mouseover', function (event, d) {
                var dp = dataPoints[d.index];
                showTooltip(tooltip,
                    '<div style="font-weight:600;margin-bottom:4px">' + (dp.date ? dp.date.substring(0, 10) : '') + '</div>' +
                    SEV_ORDER.map(function (s) { return '<div style="color:' + SEV_COLORS[s] + '">' + s + ': ' + dp[s] + '</div>'; }).join('') +
                    '<div style="margin-top:4px;color:#4ade80;font-weight:600">Risk Score: ' + dp.risk_score + '</div>' +
                    '<div style="margin-top:2px;color:var(--accent);font-size:0.6875rem">Click to view observations</div>',
                    event
                );
            })
            .on('mouseout', function () { hideTooltip(tooltip); })
            .on('click', function (event, d) {
                hideTooltip(tooltip);
                var dp = dataPoints[d.index];
                openExportPanel(dp.scan_id, dp.date ? dp.date.substring(0, 10) : dp.scan_id.substring(0, 8));
            })
            .style('cursor', 'pointer');

        var riskLine = d3.line()
            .x(function (d, i) { return x(i) + x.bandwidth() / 2; })
            .y(function (d) { return yRisk(d.risk_score); })
            .curve(d3.curveMonotoneX);

        g.append('path').datum(dataPoints)
            .attr('fill', 'none').attr('stroke', '#4ade80').attr('stroke-width', 2.5).attr('d', riskLine);

        g.selectAll('.risk-dot').data(dataPoints).enter().append('circle')
            .attr('cx', function (d, i) { return x(i) + x.bandwidth() / 2; })
            .attr('cy', function (d) { return yRisk(d.risk_score); })
            .attr('r', 4).attr('fill', '#4ade80').attr('stroke', 'var(--bg-primary)').attr('stroke-width', 1.5);

        var legend = d3.select(container).insert('div', 'svg').attr('class', 'legend');
        SEV_ORDER.forEach(function (sev) {
            var item = legend.append('div').attr('class', 'legend-item');
            item.append('div').attr('class', 'legend-swatch').style('background', SEV_COLORS[sev]);
            item.append('span').text(sev);
        });
        var riskItem = legend.append('div').attr('class', 'legend-item');
        riskItem.append('div').attr('class', 'legend-swatch').style('background', '#4ade80');
        riskItem.append('span').text('risk score');
    };

    // ─── Suite Breakdown (Stacked Bar) ────────────────────────────
    ns.renderSuiteChart = function (dataPoints, tooltip) {
        var dims = getChartDimensions('chart-suite');
        var container = dims.container;
        var width = dims.width, height = dims.height, margin = dims.margin;
        container.innerHTML = '';

        var allSuites = new Set();
        dataPoints.forEach(function (dp) {
            Object.keys(dp.by_suite || {}).forEach(function (s) { allSuites.add(s); });
        });
        var suiteKeys = Array.from(allSuites).sort();

        if (!suiteKeys.length) {
            container.innerHTML = '<div class="empty-state"><h3>No Suite Data</h3><p>Suite information not available for these scans</p></div>';
            return;
        }

        var svg = d3.select(container).append('svg')
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom);

        var g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var prepared = dataPoints.map(function (dp, i) {
            var row = { index: i, date: dp.date };
            suiteKeys.forEach(function (s) { row[s] = (dp.by_suite && dp.by_suite[s]) || 0; });
            return row;
        });

        var x = d3.scaleBand()
            .domain(prepared.map(function (d) { return d.index; }))
            .range([0, width]).padding(0.3);

        var maxStacked = d3.max(prepared, function (d) {
            return suiteKeys.reduce(function (sum, s) { return sum + (d[s] || 0); }, 0);
        }) || 1;

        var y = d3.scaleLinear().domain([0, maxStacked * 1.1]).range([height, 0]);

        g.append('g').attr('class', 'grid')
            .call(d3.axisLeft(y).ticks(5).tickSize(-width).tickFormat(''));

        g.append('g').attr('class', 'axis')
            .attr('transform', 'translate(0,' + height + ')')
            .call(d3.axisBottom(x).tickFormat(function (i) {
                var dp = dataPoints[i];
                return dp && dp.date ? dp.date.substring(5, 10) : '';
            }));

        g.append('g').attr('class', 'axis').call(d3.axisLeft(y).ticks(5));

        var stack = d3.stack().keys(suiteKeys).value(function (d, key) { return d[key] || 0; });
        var stacked = stack(prepared);

        g.selectAll('.layer')
            .data(stacked)
            .enter().append('g')
            .attr('fill', function (d) { return SUITE_COLORS[d.key] || '#6b7280'; })
            .selectAll('rect')
            .data(function (d) { return d.map(function (v, i) { return Object.assign({}, v, { index: i, key: d.key }); }); })
            .enter().append('rect')
            .attr('x', function (d) { return x(d.index); })
            .attr('y', function (d) { return y(d[1]); })
            .attr('height', function (d) { return y(d[0]) - y(d[1]); })
            .attr('width', x.bandwidth())
            .attr('rx', 2)
            .on('mouseover', function (event, d) {
                var dp = dataPoints[d.index];
                var suiteEntries = Object.entries(dp.by_suite || {}).sort(function (a, b) { return b[1] - a[1]; });
                showTooltip(tooltip,
                    '<div style="font-weight:600;margin-bottom:4px">' + (dp.date ? dp.date.substring(0, 10) : '') + '</div>' +
                    suiteEntries.map(function (e) {
                        return '<div style="color:' + (SUITE_COLORS[e[0]] || '#6b7280') + '">' + e[0] + ': ' + e[1] + '</div>';
                    }).join(''),
                    event
                );
            })
            .on('mouseout', function () { hideTooltip(tooltip); });

        var legend = d3.select(container).insert('div', 'svg').attr('class', 'legend');
        suiteKeys.forEach(function (suite) {
            var item = legend.append('div').attr('class', 'legend-item');
            item.append('div').attr('class', 'legend-swatch').style('background', SUITE_COLORS[suite] || '#6b7280');
            item.append('span').text(suite);
        });
    };

    // ─── New / Resolved (Grouped Bar) ─────────────────────────────
    ns.renderNewResolvedChart = function (dataPoints, tooltip, openExportPanel) {
        var dims = getChartDimensions('chart-newresolved');
        var container = dims.container;
        var width = dims.width, height = dims.height, margin = dims.margin;
        container.innerHTML = '';

        var svg = d3.select(container).append('svg')
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom);

        var g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var statusKeys = ['new', 'resolved', 'regressed'];

        var x0 = d3.scaleBand()
            .domain(dataPoints.map(function (d, i) { return i; }))
            .range([0, width]).padding(0.25);

        var x1 = d3.scaleBand()
            .domain(statusKeys).range([0, x0.bandwidth()]).padding(0.08);

        var maxCount = d3.max(dataPoints, function (d) {
            return Math.max(d.new || 0, d.resolved || 0, d.regressed || 0);
        }) || 1;

        var y = d3.scaleLinear().domain([0, maxCount * 1.15]).range([height, 0]);

        g.append('g').attr('class', 'grid')
            .call(d3.axisLeft(y).ticks(5).tickSize(-width).tickFormat(''));

        g.append('g').attr('class', 'axis')
            .attr('transform', 'translate(0,' + height + ')')
            .call(d3.axisBottom(x0).tickFormat(function (i) {
                var dp = dataPoints[i];
                return dp && dp.date ? dp.date.substring(5, 10) : '';
            }));

        g.append('g').attr('class', 'axis').call(d3.axisLeft(y).ticks(5));

        var scanGroups = g.selectAll('.scan-group')
            .data(dataPoints.map(function (d, i) { return Object.assign({}, d, { index: i }); }))
            .enter().append('g')
            .attr('transform', function (d) { return 'translate(' + x0(d.index) + ',0)'; });

        statusKeys.forEach(function (key) {
            scanGroups.append('rect')
                .attr('x', x1(key))
                .attr('y', function (d) { return y(d[key] || 0); })
                .attr('width', x1.bandwidth())
                .attr('height', function (d) { return height - y(d[key] || 0); })
                .attr('fill', STATUS_COLORS[key])
                .attr('rx', 2)
                .on('mouseover', function (event, d) {
                    showTooltip(tooltip,
                        '<div style="font-weight:600;margin-bottom:4px">' + (d.date ? d.date.substring(0, 10) : '') + '</div>' +
                        '<div style="color:' + STATUS_COLORS.new + '">New: ' + (d.new || 0) + '</div>' +
                        '<div style="color:' + STATUS_COLORS.resolved + '">Resolved: ' + (d.resolved || 0) + '</div>' +
                        '<div style="color:' + STATUS_COLORS.regressed + '">Regressed: ' + (d.regressed || 0) + '</div>' +
                        '<div style="margin-top:4px;color:var(--text-secondary)">Total: ' + d.total + '</div>' +
                        '<div style="margin-top:2px;color:var(--accent);font-size:0.6875rem">Click to view observations</div>',
                        event
                    );
                })
                .on('mouseout', function () { hideTooltip(tooltip); })
                .on('click', function (event, d) {
                    hideTooltip(tooltip);
                    openExportPanel(d.scan_id, d.date ? d.date.substring(0, 10) : d.scan_id.substring(0, 8));
                })
                .style('cursor', 'pointer');
        });

        var netLine = d3.line()
            .x(function (d, i) { return x0(i) + x0.bandwidth() / 2; })
            .y(function (d) {
                var net = (d.new || 0) + (d.regressed || 0) - (d.resolved || 0);
                return y(Math.max(0, net));
            })
            .curve(d3.curveMonotoneX);

        g.append('path').datum(dataPoints)
            .attr('fill', 'none').attr('stroke', '#facc15')
            .attr('stroke-width', 2).attr('stroke-dasharray', '6,3').attr('d', netLine);

        var legend = d3.select(container).insert('div', 'svg').attr('class', 'legend');
        statusKeys.forEach(function (key) {
            var item = legend.append('div').attr('class', 'legend-item');
            item.append('div').attr('class', 'legend-swatch').style('background', STATUS_COLORS[key]);
            item.append('span').text(key);
        });
        var netItem = legend.append('div').attr('class', 'legend-item');
        netItem.append('div').attr('class', 'legend-swatch').style('background', '#facc15').style('opacity', '0.7');
        netItem.append('span').text('net change');
    };

    // ─── Delta Compare (Bar) ──────────────────────────────────────
    ns.renderDeltaBarChart = function (container, comparison, dataPoints, tooltip) {
        container.innerHTML = '';

        var dims = getChartDimensions('chart-delta');
        var width = dims.width, height = dims.height, margin = dims.margin;

        var header = document.createElement('div');
        header.style.cssText = 'padding:0 0 12px;display:flex;gap:16px;font-size:0.8125rem;';
        var scanA = dataPoints.find(function (d) { return d.scan_id === comparison.scan_a_id; });
        var scanB = dataPoints.find(function (d) { return d.scan_id === comparison.scan_b_id; });
        header.innerHTML =
            '<span style="color:var(--text-secondary)">Comparing:</span>' +
            '<span style="color:var(--text-primary);font-weight:600">' + (scanA && scanA.date ? scanA.date.substring(0, 10) : comparison.scan_a_id.substring(0, 8)) + '</span>' +
            '<span style="color:var(--text-muted)">\u2192</span>' +
            '<span style="color:var(--text-primary);font-weight:600">' + (scanB && scanB.date ? scanB.date.substring(0, 10) : comparison.scan_b_id.substring(0, 8)) + '</span>' +
            (comparison.checks_compared !== undefined ? '<span style="color:var(--text-muted)">(' + comparison.checks_compared + ' common checks)</span>' : '');
        container.appendChild(header);

        var categories = [
            { key: 'new', label: 'New', count: comparison.new_count, color: '#22c55e' },
            { key: 'resolved', label: 'Resolved', count: comparison.resolved_count, color: '#6b7280' },
            { key: 'recurring', label: 'Recurring', count: comparison.recurring_count, color: '#4a9eff' },
        ];
        if (comparison.regressed !== undefined && comparison.regressed > 0) {
            categories.push({ key: 'regressed', label: 'Regressed', count: comparison.regressed, color: '#ef4444' });
        }

        var svg = d3.select(container).append('svg')
            .attr('width', width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom);

        var g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var x = d3.scaleBand()
            .domain(categories.map(function (c) { return c.label; }))
            .range([0, width]).padding(0.4);

        var maxCount = d3.max(categories, function (c) { return c.count; }) || 1;
        var y = d3.scaleLinear().domain([0, maxCount * 1.15]).range([height, 0]);

        g.append('g').attr('class', 'grid')
            .call(d3.axisLeft(y).ticks(5).tickSize(-width).tickFormat(''));

        g.append('g').attr('class', 'axis')
            .attr('transform', 'translate(0,' + height + ')')
            .call(d3.axisBottom(x));

        g.append('g').attr('class', 'axis').call(d3.axisLeft(y).ticks(5));

        g.selectAll('.delta-bar')
            .data(categories)
            .enter().append('rect')
            .attr('x', function (d) { return x(d.label); })
            .attr('y', function (d) { return y(d.count); })
            .attr('width', x.bandwidth())
            .attr('height', function (d) { return height - y(d.count); })
            .attr('fill', function (d) { return d.color; })
            .attr('rx', 4)
            .on('mouseover', function (event, d) {
                var details = '';
                var observations = d.key === 'new' ? comparison.new_observations :
                              d.key === 'resolved' ? comparison.resolved_observations : [];
                if (observations && observations.length) {
                    var shown = observations.slice(0, 5);
                    details = shown.map(function (f) {
                        return '<div style="font-size:0.6875rem;color:' + (SEV_COLORS[f.severity] || '#ccc') + '">\u2022 ' + f.title + '</div>';
                    }).join('');
                    if (observations.length > 5) details += '<div style="font-size:0.6875rem;color:var(--text-muted)">+' + (observations.length - 5) + ' more</div>';
                }
                showTooltip(tooltip,
                    '<div style="font-weight:600;margin-bottom:4px">' + d.label + ': ' + d.count + '</div>' + details,
                    event
                );
            })
            .on('mouseout', function () { hideTooltip(tooltip); });

        g.selectAll('.delta-label')
            .data(categories)
            .enter().append('text')
            .attr('x', function (d) { return x(d.label) + x.bandwidth() / 2; })
            .attr('y', function (d) { return y(d.count) - 6; })
            .attr('text-anchor', 'middle')
            .attr('fill', 'var(--text-primary)')
            .attr('font-size', '0.8125rem')
            .attr('font-weight', '600')
            .text(function (d) { return d.count; });

        if (comparison.checks_only_in_a || comparison.checks_only_in_b) {
            var info = d3.select(container).append('div')
                .style('font-size', '0.6875rem')
                .style('color', 'var(--text-muted)')
                .style('padding-top', '8px');
            var parts = [];
            if (comparison.checks_only_in_a) parts.push(comparison.checks_only_in_a + ' checks only in scan A');
            if (comparison.checks_only_in_b) parts.push(comparison.checks_only_in_b + ' checks only in scan B');
            info.text('Note: ' + parts.join(', ') + ' (excluded from comparison)');
        }
    };

})(window.ChainsmithViz);
