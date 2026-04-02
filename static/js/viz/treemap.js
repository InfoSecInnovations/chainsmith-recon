/**
 * Chainsmith Viz — Treemap (drill-down finding hierarchy).
 * Requires: D3, viz-common.js
 */
(function (ns) {
    'use strict';

    var SEV_COLORS  = ns.SEV_COLORS;
    var SEV_ORDER   = ns.SEV_ORDER;
    var SEV_WEIGHTS = ns.SEV_WEIGHTS;

    // Module state
    var treemapSizeMode  = 'count';
    var treemapCurrentRoot = null;
    var treemapFullRoot    = null;
    var treemapFindings    = null;

    function buildTreemapHierarchy(findingsArr) {
        var suiteMap = new Map();
        findingsArr.forEach(function (f) {
            var suite = f.suite || ns.inferSuite(f.check_name);
            var host  = f.host || 'unknown';
            if (!suiteMap.has(suite)) suiteMap.set(suite, new Map());
            var hostMap = suiteMap.get(suite);
            if (!hostMap.has(host)) hostMap.set(host, []);
            hostMap.get(host).push(f);
        });

        return {
            name: 'All Findings',
            children: Array.from(suiteMap.entries()).map(function (suiteEntry) {
                return {
                    name: suiteEntry[0],
                    children: Array.from(suiteEntry[1].entries()).map(function (hostEntry) {
                        return {
                            name: hostEntry[0],
                            children: hostEntry[1].map(function (f) {
                                return {
                                    name: f.title,
                                    data: f,
                                    value: treemapSizeMode === 'risk' ? (SEV_WEIGHTS[f.severity] || 1) : 1,
                                };
                            }),
                        };
                    }),
                };
            }),
        };
    }

    function updateBreadcrumb(node) {
        var bc   = document.getElementById('treemap-breadcrumb');
        var path = [];
        var n    = node;
        while (n) { path.unshift(n); n = n.parent; }

        bc.innerHTML = path.map(function (p, i) {
            if (i === path.length - 1) {
                return '<span class="treemap-breadcrumb-current">' + p.data.name + '</span>';
            }
            return '<span class="treemap-breadcrumb-item" data-depth="' + i + '">' + p.data.name + '</span>' +
                   '<span class="treemap-breadcrumb-sep">/</span>';
        }).join('');

        bc.querySelectorAll('.treemap-breadcrumb-item').forEach(function (el) {
            el.addEventListener('click', function () {
                var depth = parseInt(el.dataset.depth);
                drawTreemapLevel(path[depth]);
            });
        });
    }

    function drawTreemapLevel(node) {
        treemapCurrentRoot = node;
        updateBreadcrumb(node);

        var chartEl  = document.getElementById('treemap-chart');
        var tooltipEl = document.getElementById('treemap-tooltip');
        var tip      = ns.tooltip(tooltipEl);
        var width    = chartEl.clientWidth;
        var height   = chartEl.clientHeight;

        if (width <= 0 || height <= 0) return;

        var svgEl = d3.select('#treemap-graph')
            .attr('width', width)
            .attr('height', height);

        svgEl.selectAll('*').remove();

        var revalued = d3.hierarchy(node.data)
            .sum(function (d) {
                if (d.data) return treemapSizeMode === 'risk' ? (SEV_WEIGHTS[d.data.severity] || 1) : 1;
                return 0;
            })
            .sort(function (a, b) { return b.value - a.value; });

        d3.treemap()
            .size([width, height])
            .paddingInner(2)
            .paddingOuter(3)
            .round(true)
            (revalued);

        var displayNodes = revalued.children || [];

        function getNodeFindings(d) {
            return d.leaves().map(function (l) { return l.data.data; }).filter(Boolean);
        }

        function getNodeColor(d) {
            var nf = getNodeFindings(d);
            if (nf.length === 0) return '#1e293b';
            return SEV_COLORS[ns.worstSeverity(nf)] || '#6b7280';
        }

        function getTextColor(d) {
            var nf = getNodeFindings(d);
            if (nf.length === 0) return '#fff';
            var worst = ns.worstSeverity(nf);
            if (worst === 'critical' || worst === 'high') return '#fff';
            if (worst === 'medium') return '#450a0a';
            return '#fff';
        }

        function showTooltip(event, d) {
            var nf = getNodeFindings(d);
            var content = '<strong>' + d.data.name + '</strong>';
            if (d.data.data && d.data.data.severity) {
                content += '<span class="treemap-tooltip-severity" style="background:' + SEV_COLORS[d.data.data.severity] + ';color:#fff">' + d.data.data.severity + '</span>';
            } else {
                content += '<div class="treemap-tooltip-breakdown">' + nf.length + ' finding' + (nf.length !== 1 ? 's' : '') + ': ' + ns.severityBreakdown(nf) + '</div>';
            }
            tip.show(content, event);
        }

        var cell = svgEl.selectAll('g')
            .data(displayNodes)
            .join('g')
            .attr('transform', function (d) { return 'translate(' + d.x0 + ',' + d.y0 + ')'; });

        cell.append('rect')
            .attr('width', function (d) { return Math.max(0, d.x1 - d.x0); })
            .attr('height', function (d) { return Math.max(0, d.y1 - d.y0); })
            .attr('fill', getNodeColor)
            .attr('stroke', 'var(--bg-primary)')
            .attr('stroke-width', 1.5)
            .attr('rx', 3)
            .style('cursor', function (d) { return (d.children || d.data.data) ? 'pointer' : 'default'; })
            .on('mouseenter', function (event, d) { showTooltip(event, d); })
            .on('mousemove', function (event) { tip.move(event); })
            .on('mouseleave', function () { tip.hide(); })
            .on('click', function (event, d) {
                event.stopPropagation();
                tip.hide();
                if (d.data.data) {
                    openModal(d.data.data.title, getFindingModalContent(d.data.data));
                    return;
                }
                if (d.children) {
                    var target = findNodeInTree(treemapFullRoot, d.data.name, node);
                    if (target) drawTreemapLevel(target);
                }
            });

        // Labels
        cell.append('text')
            .attr('x', 6).attr('y', 16)
            .attr('fill', getTextColor)
            .attr('font-size', function (d) {
                var w = d.x1 - d.x0, h = d.y1 - d.y0;
                if (w < 60 || h < 28) return '10px';
                if (w < 120) return '11px';
                return '12px';
            })
            .attr('font-weight', '500')
            .attr('pointer-events', 'none')
            .text(function (d) {
                var w = d.x1 - d.x0, h = d.y1 - d.y0;
                if (w < 35 || h < 20) return '';
                var name = d.data.name || '';
                var fontSize = w < 60 ? 10 : w < 120 ? 11 : 12;
                var maxChars = Math.floor((w - 12) / (fontSize * 0.6));
                if (maxChars < 3) return '';
                return name.length > maxChars ? name.slice(0, maxChars - 1) + '\u2026' : name;
            });

        // Count label
        cell.append('text')
            .attr('x', 6).attr('y', 30)
            .attr('fill', function (d) {
                return getTextColor(d) === '#fff' ? 'rgba(255,255,255,0.7)' : 'rgba(69,10,10,0.6)';
            })
            .attr('font-size', '10px')
            .attr('pointer-events', 'none')
            .text(function (d) {
                var w = d.x1 - d.x0, h = d.y1 - d.y0;
                if (w < 50 || h < 36) return '';
                var nf = getNodeFindings(d);
                if (d.data.data) return '';
                return nf.length + ' finding' + (nf.length !== 1 ? 's' : '');
            });

        svgEl.on('click', function () {
            if (treemapCurrentRoot && treemapCurrentRoot.parent) {
                drawTreemapLevel(treemapCurrentRoot.parent);
            }
        });
    }

    function findNodeInTree(root, name, parent) {
        if (!parent.children) return null;
        for (var i = 0; i < parent.children.length; i++) {
            if (parent.children[i].data.name === name) return parent.children[i];
        }
        return null;
    }

    function renderTreemapLegend() {
        var legend = document.getElementById('treemap-legend');
        legend.innerHTML = SEV_ORDER.map(function (sev) {
            return '<div class="treemap-legend-item">' +
                '<div class="treemap-legend-swatch" style="background:' + SEV_COLORS[sev] + '"></div>' +
                sev + '</div>';
        }).join('');
    }

    /**
     * Render the treemap visualization.
     */
    ns.renderTreemap = async function () {
        var findingsData = await api.getFindings();
        treemapFindings = findingsData.findings;

        var empty    = document.getElementById('treemap-empty');
        var controls = document.getElementById('treemap-controls');
        var chartEl  = document.getElementById('treemap-chart');

        if (!treemapFindings || treemapFindings.length === 0) {
            empty.style.display    = 'flex';
            controls.style.display = 'none';
            chartEl.style.display  = 'none';
            return;
        }

        empty.style.display    = 'none';
        controls.style.display = 'flex';
        chartEl.style.display  = 'block';

        var hierarchyData = buildTreemapHierarchy(treemapFindings);
        treemapFullRoot    = d3.hierarchy(hierarchyData);
        treemapCurrentRoot = treemapFullRoot;

        renderTreemapLegend();
        drawTreemapLevel(treemapFullRoot);

        // Size toggle
        document.getElementById('treemap-size-toggle').addEventListener('click', function (e) {
            var btn = e.target.closest('button');
            if (!btn || btn.classList.contains('active')) return;
            document.querySelectorAll('#treemap-size-toggle button').forEach(function (b) { b.classList.remove('active'); });
            btn.classList.add('active');
            treemapSizeMode = btn.dataset.mode;
            var newData = buildTreemapHierarchy(treemapFindings);
            treemapFullRoot = d3.hierarchy(newData);
            var target = treemapFullRoot;
            if (treemapCurrentRoot && treemapCurrentRoot !== treemapFullRoot) {
                var path = [];
                var n = treemapCurrentRoot;
                while (n.parent) { path.unshift(n.data.name); n = n.parent; }
                var cur = treemapFullRoot;
                for (var i = 0; i < path.length; i++) {
                    var child = cur.children ? cur.children.find(function (c) { return c.data.name === path[i]; }) : null;
                    if (child) cur = child; else break;
                }
                target = cur;
            }
            treemapCurrentRoot = target;
            drawTreemapLevel(treemapCurrentRoot);
        });
    };

})(window.ChainsmithViz);
