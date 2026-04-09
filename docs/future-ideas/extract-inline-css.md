Extract Inline CSS from Static Pages
=====================================
Captured 2026-04-08.

Status: Done

Problem
-------
The static HTML report pages contain inline CSS. This makes styles
harder to maintain, increases page size when styles repeat across
elements, and prevents leveraging browser caching of external
stylesheets.

Proposed Change
---------------
Extract all inline CSS from the static report pages into one or more
external stylesheet files. Reference them via <link> tags so styles
are centralized and cacheable.

Considerations
--------------
- Audit all static pages for inline style="" attributes and <style>
  blocks.
- Decide on a single shared stylesheet vs. per-page stylesheets.
- Ensure extracted styles don't conflict with existing external CSS.
- Static report pages must remain self-contained if distributed as
  standalone files — may need an "embed" build step that re-inlines
  for the portable single-file export.
