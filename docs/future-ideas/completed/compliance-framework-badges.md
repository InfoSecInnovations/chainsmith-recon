OWASP / MITRE / NIST Badges on Check Modals
=============================================
Captured 2026-04-08.

Status: Ready to implement (co-implement with compliance-framework-selector.md)

Problem
-------
Check detail modals do not indicate which compliance frameworks or
threat taxonomies a check maps to. Users have no quick visual cue
linking a check to OWASP, MITRE ATT&CK, or NIST controls.

Proposed Change
---------------
Add small badges (e.g. "OWASP LLM01", "ATLAS AML.T0054", "CWE-200")
to each check's modal dialog. Badges should be clickable, linking to
the relevant framework reference page.

Architecture: Data-Driven Framework Plugin System
--------------------------------------------------
Framework definitions live in a plugin directory rather than a
monolithic module. Each framework is a YAML file declaring its
matching pattern, URL template, and display properties. A thin
runtime loader auto-discovers definitions at startup.

### Directory layout

    app/checks/frameworks/
        __init__.py              # registry: load all YAMLs, expose parse_all()
        base.py                  # FrameworkTag dataclass, loader logic
        definitions/
            owasp-llm.yaml       # OWASP LLM Top 10
            owasp-top10.yaml     # OWASP Top 10 (web)
            owasp-api.yaml       # OWASP API Security Top 10
            mitre-atlas.yaml     # MITRE ATLAS
            cwe.yaml             # Common Weakness Enumeration
            mitre-atlas-controls.yaml   # (optional) control catalog
            owasp-llm-controls.yaml     # (optional) control catalog

### YAML definition schema

    # Example: mitre-atlas.yaml
    name: MITRE ATLAS
    short_label: ATLAS
    pattern: "MITRE ATLAS - (AML\\.T\\d+)"
    url_template: "https://atlas.mitre.org/techniques/{id}"
    badge_color: "#8b5cf6"
    controls_file: mitre-atlas-controls.yaml

Fields:
- name:           Full framework name for tooltips / report headers.
- short_label:    Compact label for badge text (e.g. "ATLAS", "LLM").
- pattern:        Regex applied to each reference string. First capture
                  group becomes the tag ID (e.g. "AML.T0054").
- url_template:   Badge href. `{id}` is replaced with the captured ID.
- badge_color:    Hex color for the badge background.
- controls_file:  Optional. Relative path to a separate YAML listing
                  all controls in the framework (for gap analysis in
                  the compliance report selector). Frameworks without
                  this file skip gap analysis.

### Controls file schema

    # Example: mitre-atlas-controls.yaml
    - id: AML.T0054
      name: LLM Prompt Injection
    - id: AML.T0051
      name: LLM Plugin Compromise
    ...

### Runtime interface (base.py)

    @dataclass
    class FrameworkTag:
        framework: str       # e.g. "MITRE ATLAS"
        short_label: str     # e.g. "ATLAS"
        tag_id: str          # e.g. "AML.T0054"
        url: str             # full link to reference page
        badge_color: str     # hex

    def parse_all(references: list[str]) -> list[FrameworkTag]
        """Match reference strings against all loaded framework
        definitions. Returns one FrameworkTag per match."""

Data is derived at render time from check.references -- no new DB
columns or migrations needed.

### Adding a new framework

Drop a YAML file in definitions/. No Python changes required.
Optionally add a controls file for gap analysis support.

Day-One Frameworks
------------------
Audit of 114+ checks found these frameworks already in reference
strings (counts are approximate):

| Framework              | Pattern in references         | Checks |
|------------------------|-------------------------------|--------|
| OWASP LLM Top 10      | OWASP LLM Top 10 - LLMxx     | ~60    |
| MITRE ATLAS            | MITRE ATLAS - AML.Txxxx       | ~12    |
| CWE                    | CWE-xxx or CWE-xxx: Desc      | ~10    |
| OWASP Top 10 (web)     | OWASP Top 10 - Axx            | ~2     |
| OWASP API Security     | OWASP API Security Top 10     | ~3     |

Known gaps / backfill candidates:
- Web suite checks should map to OWASP Top 10 but most don't yet.
- ai/fingerprint.py references "ML Supply Chain Compromise" without
  a formal AML.T code.
- CWE format is inconsistent ("CWE-200" vs "CWE-502: Deserialization
  of Untrusted Data") -- the regex must handle both.

Future framework candidates (require new reference mappings):
- OWASP AI Security Verification Standard (LLMSVS)
- NIST 800-53 / AI RMF
- MITRE ATT&CK (traditional, for network/web checks)

UI Implementation
-----------------
- Add `.framework-badge` CSS class (similar to existing `.severity-badge`).
- One color variant per framework, driven by badge_color from YAML.
- Render badges in getObservationModalContent() (static/js/api.js)
  after the "Discovered By" section.
- Look up check's framework tags via a check-name-to-frameworks map
  fetched once on page load from GET /api/v1/checks.
- Badge tooltip shows full framework name + control description.

Files touched:
- app/checks/frameworks/ (new package)
- app/engine/scanner.py -- add "frameworks" key to get_check_info()
- static/js/api.js -- badge rendering in modal
- static/css/common.css -- .framework-badge styles
- static/observations.html -- fetch + wire framework data

Considerations
--------------
- Badge overflow: checks with many framework mappings could clutter
  the modal. Consider a "+N more" overflow after 4-5 badges.
- Tooltip delay and positioning for small badge targets.
- Color accessibility: ensure badge_color + white text meets WCAG AA.
