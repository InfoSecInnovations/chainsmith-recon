# Phase 10: Extract D3 Visualization Modules

Break inline JavaScript and CSS out of findings.html and trend.html into
separate, cacheable files organized under `static/js/viz/` and `static/css/`.

Source: `docs/future-ideas/extract-d3-visualization-modules.txt`

---

## Current State

- findings.html: 3,205 lines / 129 KB — ~87% inline CSS and JS
- trend.html: 1,701 lines / 71 KB — ~88% inline CSS and JS
- 7 visualization modules inlined in findings.html
- 6 chart modules inlined in trend.html
- Severity color scales copy-pasted ~7 times
- Tooltip creation/styling duplicated per module
- Resize debounce handlers duplicated per module
- No shared visualization infrastructure exists

---

## Design Decisions

1. **Namespace pattern** — all modules attach to `window.ChainsmithViz`
   (e.g., `ChainsmithViz.renderHeatmap(container, data)`). One global
   instead of 15+, no ES module complexity, zero build steps preserved.

2. **CSS strategy: shared base + per-viz overrides** — common tooltip,
   legend, container patterns use shared classes (`.viz-tooltip`,
   `.viz-legend`, `.viz-swatch`). Modules with unique styling needs
   (host-table expandable rows, chains-sankey link hovers) layer
   per-viz classes on top.

3. **No build tools** — plain `.js` files loaded via `<script>` tags,
   plain `.css` loaded via `<link>`. No transpilation, bundling, or npm.

4. **Script load order** — D3 first, then viz-common.js, then individual
   modules. Enforced by `<script>` tag ordering in the HTML.

---

## Target Structure

```
static/
  css/
    common.css              (existing, unchanged)
    viz.css                 NEW — shared viz CSS + per-viz overrides
  js/
    api.js                  (existing, unchanged)
    viz/
      viz-common.js         NEW — namespace init, severity palette,
                            tooltip factory, resize debounce, theme colors
      treemap.js            NEW — ~230 lines from findings.html
      host-table.js         NEW — ~160 lines from findings.html
      chains-sankey.js      NEW — ~330 lines from findings.html
      heatmap.js            NEW — ~170 lines from findings.html
      radar.js              NEW — ~200 lines from findings.html
      coverage.js           NEW — ~220 lines from findings.html
      timeline.js           NEW — ~150 lines from findings.html
      trend-charts.js       NEW — ~560 lines from trend.html
```

---

## Build Waves

### Wave 1 — Foundation (Phase 10a)

Create shared infrastructure. No changes to page behavior yet.

| Deliverable | Description |
|---|---|
| `viz-common.js` | Namespace init (`window.ChainsmithViz = window.ChainsmithViz \|\| {}`), severity color palette, tooltip factory (create/show/hide/move), resize debounce factory, theme color reader (CSS variable helper) |
| `viz.css` | Shared base classes: `.viz-container`, `.viz-legend`, `.viz-legend-item`, `.viz-swatch`, `.viz-tooltip`. Per-viz override blocks for host-table and chains-sankey unique styles |
| Script/link tags | Add `<link>` for viz.css and `<script>` for viz-common.js to findings.html and trend.html (no functional change yet) |
| Tests | Automated tests confirming viz-common.js loads and namespace exists |

### Wave 2 — Extract findings.html visualizations (Phase 10b)

Extract one module at a time. After each extraction: run automated tests,
then manual browser verification before proceeding to the next.

**Extraction order** (simplest/most-typical pattern first):

| Step | Module | File | Lines | Notes |
|---|---|---|---|---|
| 1 | Heatmap | `heatmap.js` | ~170 | Most typical pattern — good template |
| 2 | Timeline | `timeline.js` | ~150 | Simple scatter, minimal unique CSS |
| 3 | Radar | `radar.js` | ~200 | Standalone polar chart |
| 4 | Coverage | `coverage.js` | ~220 | Matrix pattern, slightly more complex |
| 5 | Treemap | `treemap.js` | ~230 | Drill-down state management |
| 6 | Host Table | `host-table.js` | ~160 | Unique expandable row pattern, per-viz CSS overrides |
| 7 | Chains Sankey | `chains-sankey.js` | ~330 | Most complex — Sankey links, node hover, per-viz CSS overrides |

For each extraction:
- Move JS into `static/js/viz/{module}.js`
- Register render function on `ChainsmithViz` namespace
- Replace per-module tooltip/legend CSS with shared classes (+ overrides where needed)
- Remove inline `<script>` block from findings.html
- Add `<script src>` tag in correct load order
- Update/add automated tests
- Manual browser verification

### Wave 3 — Extract trend.html charts (Phase 10c)

| Deliverable | Description |
|---|---|
| `trend-charts.js` | All 6 chart render functions moved to single file, registered on `ChainsmithViz` namespace |
| trend.html cleanup | Remove inline `<script>` and `<style>` blocks, add `<script src>` and `<link>` tags |
| Tests | Automated tests for trend chart rendering |

### Wave 4 — Cleanup (Phase 10d)

| Deliverable | Description |
|---|---|
| Dead code removal | Remove any empty `<script>` / `<style>` blocks left in findings.html and trend.html |
| Consistency pass | Verify all modules follow the same namespace registration pattern |
| Final line counts | Confirm findings.html ~600 lines, trend.html ~500 lines |

---

## Expected Impact

| File | Before | After |
|---|---|---|
| findings.html | ~3,205 lines | ~600 lines |
| trend.html | ~1,701 lines | ~500 lines |
| New JS (static/js/viz/) | 0 | ~2,100 lines (browser-cacheable) |
| New CSS (viz.css) | 0 | ~300 lines (browser-cacheable) |

Net byte reduction on repeat page visits due to browser caching of
extracted JS/CSS files.

---

## Verification

Each extraction step requires:
1. **Automated tests** — module loads, namespace function exists, renders
   without JS errors against test data
2. **Manual browser test** — visual comparison of the affected tab/chart
   before and after extraction

---

## Risks / Considerations

- **Script load order** — viz modules depend on D3 and viz-common.js.
  Enforced by `<script>` tag ordering. No loader or bundler needed.
- **Zero build steps** — all files are plain JS/CSS. No transpilation,
  no bundling, no npm.
- **One module at a time** — never extract two modules simultaneously.
  Verify each before proceeding to isolate regressions.
- **CSS specificity** — shared base classes must not conflict with
  existing common.css styles. Use `.viz-` prefix consistently.
