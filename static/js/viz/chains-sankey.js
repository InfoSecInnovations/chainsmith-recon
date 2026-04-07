/**
 * Chainsmith Viz — Chains Sankey (observations → attack chains graph).
 * Requires: D3, d3-sankey, viz-common.js
 */
(function (ns) {
    'use strict';

    var severityColors = ns.SANKEY_SEV_COLORS;
    var sourceColors   = ns.SOURCE_COLORS;

    /**
     * Render the chains list view.
     */
    ns.renderChainsList = function (chains, observations, openModal) {
        var list = document.getElementById('chains-list');
        list.innerHTML = chains.map(function (chain) {
            return '<div class="chain-card source-' + chain.source + '" data-chain="' + chain.id + '">' +
                '<div class="chain-card-header">' +
                '<span class="chain-card-title">' + chain.title + '</span>' +
                '<div class="chain-card-meta">' +
                '<span class="severity-badge severity-' + chain.severity + '">' + chain.severity + '</span>' +
                '<span class="chain-source-badge ' + chain.source + '">' + chain.source + '</span>' +
                '</div></div>' +
                '<div class="chain-card-desc">' + (chain.description || '') + '</div>' +
                '<div class="chain-card-observations">' +
                chain.observation_ids.map(function (id) { return '<span class="chain-observation-tag">' + id + '</span>'; }).join('') +
                '</div></div>';
        }).join('');

        list.querySelectorAll('.chain-card').forEach(function (card) {
            card.addEventListener('click', function () {
                var chain = chains.find(function (c) { return c.id === card.dataset.chain; });
                if (chain) openModal(chain.title, getChainModalContent(chain, observations));
            });
        });
    };

    /**
     * Render the chains Sankey graph view.
     */
    ns.renderChainsGraph = function (chains, observations, openModal) {
        var container = document.getElementById('chains-content');
        var width  = container.clientWidth - 32;
        var height = Math.max(400, container.clientHeight - 32);

        var svg = d3.select('#chains-graph')
            .attr('width', width)
            .attr('height', height);

        svg.selectAll('*').remove();

        if (chains.length === 0) return;

        // Build Sankey data
        var nodes = [];
        var links = [];

        var usedObservations = new Set();
        chains.forEach(function (chain) {
            chain.observation_ids.forEach(function (fid) { usedObservations.add(fid); });
        });

        var observationIndices = new Map();
        usedObservations.forEach(function (fid) {
            var observation = observations.find(function (f) { return f.id === fid; });
            observationIndices.set(fid, nodes.length);
            nodes.push({
                name: observation ? fid + ': ' + observation.title : fid,
                type: 'observation',
                severity: observation ? observation.severity : 'info',
                data: observation,
            });
        });

        var chainIndices = new Map();
        chains.forEach(function (chain) {
            chainIndices.set(chain.id, nodes.length);
            nodes.push({
                name: chain.title,
                type: 'chain',
                chainSource: chain.source,
                severity: chain.severity,
                data: chain,
            });
        });

        chains.forEach(function (chain) {
            var targetIdx = chainIndices.get(chain.id);
            chain.observation_ids.forEach(function (fid) {
                var sourceIdx = observationIndices.get(fid);
                if (sourceIdx !== undefined && targetIdx !== undefined) {
                    links.push({ source: sourceIdx, target: targetIdx, value: 1 });
                }
            });
        });

        var sankey = d3.sankey()
            .nodeWidth(20)
            .nodePadding(12)
            .nodeAlign(d3.sankeyLeft)
            .extent([[20, 30], [width - 20, height - 20]]);

        var graph = sankey({
            nodes: nodes.map(function (d) { return Object.assign({}, d); }),
            links: links.map(function (d) { return Object.assign({}, d); }),
        });

        // Draw links
        var link = svg.append('g')
            .attr('fill', 'none')
            .selectAll('path')
            .data(graph.links)
            .join('path')
            .attr('class', 'sankey-link')
            .attr('d', d3.sankeyLinkHorizontal())
            .attr('stroke', function (d) { return sourceColors[d.target.chainSource] || '#666'; })
            .attr('stroke-opacity', 0.3)
            .attr('stroke-width', function (d) { return Math.max(2, d.width); })
            .style('cursor', 'pointer');

        function highlightConnectedPaths(observationNode, highlight) {
            var connectedChainIds   = new Set();
            var connectedObservationIds = new Set();

            graph.links.forEach(function (l) {
                if (l.source === observationNode) connectedChainIds.add(l.target.index);
            });
            graph.links.forEach(function (l) {
                if (connectedChainIds.has(l.target.index)) connectedObservationIds.add(l.source.index);
            });

            link.attr('stroke-opacity', function (d) {
                if (!highlight) return 0.3;
                return connectedChainIds.has(d.target.index) ? 0.85 : 0.08;
            }).attr('stroke-width', function (d) {
                if (!highlight) return Math.max(2, d.width);
                return connectedChainIds.has(d.target.index) ? Math.max(4, d.width * 1.5) : Math.max(2, d.width);
            });

            node.select('rect').attr('opacity', function (d) {
                if (!highlight) return 0.9;
                if (d === observationNode) return 1;
                if (connectedChainIds.has(d.index)) return 1;
                if (connectedObservationIds.has(d.index)) return 0.9;
                return 0.2;
            });
            node.select('text').attr('opacity', function (d) {
                if (!highlight) return 1;
                if (d === observationNode || connectedChainIds.has(d.index) || connectedObservationIds.has(d.index)) return 1;
                return 0.3;
            });
        }

        function highlightChainPaths(chainNode, highlight) {
            var connectedObservationIds = new Set();
            graph.links.forEach(function (l) {
                if (l.target === chainNode) connectedObservationIds.add(l.source.index);
            });

            link.attr('stroke-opacity', function (d) {
                if (!highlight) return 0.3;
                return d.target === chainNode ? 0.85 : 0.08;
            }).attr('stroke-width', function (d) {
                if (!highlight) return Math.max(2, d.width);
                return d.target === chainNode ? Math.max(4, d.width * 1.5) : Math.max(2, d.width);
            });

            node.select('rect').attr('opacity', function (d) {
                if (!highlight) return 0.9;
                if (d === chainNode || connectedObservationIds.has(d.index)) return 1;
                return 0.2;
            });
            node.select('text').attr('opacity', function (d) {
                if (!highlight) return 1;
                if (d === chainNode || connectedObservationIds.has(d.index)) return 1;
                return 0.3;
            });
        }

        // Draw nodes
        var node = svg.append('g')
            .selectAll('g')
            .data(graph.nodes)
            .join('g')
            .attr('transform', function (d) { return 'translate(' + d.x0 + ',' + d.y0 + ')'; })
            .style('cursor', 'pointer')
            .on('mouseenter', function (event, d) {
                if (d.type === 'observation') highlightConnectedPaths(d, true);
                else if (d.type === 'chain') highlightChainPaths(d, true);
            })
            .on('mouseleave', function (event, d) {
                if (d.type === 'observation') highlightConnectedPaths(d, false);
                else if (d.type === 'chain') highlightChainPaths(d, false);
            })
            .on('click', function (event, d) {
                if (d.type === 'chain') openModal(d.data.title, getChainModalContent(d.data, observations));
                else if (d.data) openModal(d.data.title, getObservationModalContent(d.data));
            });

        node.append('rect')
            .attr('width', function (d) { return d.x1 - d.x0; })
            .attr('height', function (d) { return d.y1 - d.y0; })
            .attr('fill', function (d) {
                if (d.type === 'chain') return sourceColors[d.chainSource] || '#666';
                return severityColors[d.severity] || '#64748b';
            })
            .attr('rx', 3)
            .attr('opacity', 0.9);

        node.append('text')
            .attr('x', function (d) { return d.type === 'observation' ? (d.x1 - d.x0) + 6 : -6; })
            .attr('y', function (d) { return (d.y1 - d.y0) / 2; })
            .attr('dy', '0.35em')
            .attr('text-anchor', function (d) { return d.type === 'observation' ? 'start' : 'end'; })
            .attr('fill', 'var(--text-primary)')
            .attr('font-size', '11px')
            .text(function (d) {
                var maxLen = d.type === 'observation' ? 35 : 30;
                var name = d.name || '';
                return name.length > maxLen ? name.slice(0, maxLen - 2) + '...' : name;
            });

        // Column labels
        svg.append('text')
            .attr('x', 20).attr('y', 16)
            .attr('fill', 'var(--text-muted)')
            .attr('font-size', '12px')
            .attr('font-weight', '500')
            .text('Observations');

        svg.append('text')
            .attr('x', width - 20).attr('y', 16)
            .attr('text-anchor', 'end')
            .attr('fill', 'var(--text-muted)')
            .attr('font-size', '12px')
            .attr('font-weight', '500')
            .text('Attack Chains');
    };

})(window.ChainsmithViz);
