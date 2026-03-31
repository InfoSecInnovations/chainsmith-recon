# Benchmark Bar Chart (formerly Phase 5f)

Moved out of Phase 5 to be addressed later in the project.

## What

Bar chart comparing current scan findings per severity against a baseline average.

## Baselines (launch with 2)

- **"All hosts average"** — mean findings per severity across all hosts in current scan
- **"This target over time"** — average from scan history via `api.getTargetTrend()`

## Implementation

1. Add `<div class="tab" data-viz="benchmark">Benchmark</div>` tab + panel to `findings.html`
2. Build `renderBenchmark()`:
   - Grouped bar chart: severity categories on X, count on Y
   - Primary bars: current host (or full scan) findings
   - Overlay line or ghost bars: selected baseline average
   - Baseline selector dropdown: "All hosts (this scan)", "Target history"
   - For "Target history": call `api.getTargetTrend()`, compute averages
   - Empty state for first-scan: "Run multiple scans to see historical baseline"
3. Host selector dropdown to pick which host to compare (or "All")
4. Tests: verify baseline computation, tab presence, empty state

## Notes

- Most complex findings visualization — requires scan history API integration
- All other Phase 5 visualizations (Heatmap, Radar, Coverage, Timeline, Treemap) are complete
