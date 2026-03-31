# Web Suite

HTTP service analysis checks.

## header_analysis

**Analyze HTTP security headers.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `header_findings` |

Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.).

### Findings

- **medium**: Missing Content-Security-Policy
- **low**: Missing X-Content-Type-Options

---

## robots_txt

**Parse robots.txt for sensitive paths.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `robots_paths` |

Extracts disallowed paths that may reveal admin panels, API endpoints, or sensitive directories.

### Findings

- **medium**: Sensitive paths in robots.txt
- **info**: robots.txt parsed

---

## path_probe

**Probe common paths for discovery.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `discovered_paths` |

Checks for common admin, API, and debug endpoints.

### Findings

- **medium**: Admin endpoint accessible
- **low**: Debug endpoint found

---

## openapi_discovery

**Discover OpenAPI/Swagger specifications.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `api_endpoints`, `openapi_specs` |

Finds and parses OpenAPI specs to enumerate API endpoints.

### Findings

- **medium**: OpenAPI spec exposed
- **info**: API endpoints discovered

---

## cors_check

**Analyze CORS configuration.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `cors_findings` |

Tests for overly permissive CORS (wildcard, origin reflection).

### Findings

- **high**: CORS reflects any origin with credentials
- **medium**: Wildcard CORS
