# Benchmark Bar Chart (formerly Phase 5f)

Moved out of Phase 5 to be addressed later in the project.

## What

Bar chart comparing current scan findings per severity against a baseline average.

## Severity Categories

Standard: Critical, High, Medium, Low, Info

## Baselines (launch with 2)

- **"All hosts average"** — **weighted** mean findings per severity across all hosts in current scan (weighted by number of checks run per host)
- **"This target over time"** — average from scan history via `api.getTargetTrend(last_n)`, default `last_n=5`

## UX Decisions

- **History depth**: default to last 5 scans; user-selectable via dropdown (5, 10, 20, All)
- **Host selector + baseline interaction**: when host is "All", auto-switch baseline to "Target history" and disable "All hosts (this scan)" since it's redundant. When a specific host is selected, both baselines are available.
- **Incomplete scans**: excluded — only complete scan data used for baseline computation
- **Chart library**: D3, consistent with all other Phase 5 visualizations

## Implementation

1. Add `<div class="tab" data-viz="benchmark">Benchmark</div>` tab + panel to `findings.html`
2. Build `renderBenchmark()`:
   - Grouped bar chart (D3): severity categories on X, count on Y
   - Primary bars: current host (or full scan) findings
   - Overlay line or ghost bars: selected baseline average
   - Baseline selector dropdown: "All hosts (this scan)", "Target history"
     - Auto-switch when host is "All" (see UX Decisions)
   - For "Target history": call `api.getTargetTrend(domain, { last_n })`, compute averages
   - History depth selector: 5 (default), 10, 20, All
   - Empty state for first-scan: "Run multiple scans to see historical baseline"
3. Host selector dropdown to pick which host to compare (or "All")
4. Tests: verify weighted baseline computation, tab presence, empty state, auto-switch logic

## API

- `api.getTargetTrend(domain, { last_n })` already exists in `static/js/api.js:112` and supports `last_n` filter

## Notes

- Most complex findings visualization — requires scan history API integration
- All other Phase 5 visualizations (Heatmap, Radar, Coverage, Timeline, Treemap) are complete
