# Web Suite

HTTP analysis, technology fingerprinting, and web vulnerability detection.
23 checks organized in 4 phases by dependency order.

---

## Phase 1 — Passive Analysis (depends on services)

### header_analysis

**Analyze HTTP headers for technology disclosure and security misconfigurations.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `header_observations` |

Checks for missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), grades CSP and HSTS values, detects CORS wildcards and server version disclosure.

#### Observations

- **medium**: Weak CSP policy (unsafe-inline, unsafe-eval, wildcard sources)
- **medium**: CORS allows any origin
- **low**: Missing Content-Security-Policy
- **low**: Missing X-Content-Type-Options
- **low**: Server version disclosed
- **low**: Weak HSTS configuration
- **low**: Weak Referrer-Policy
- **low**: Permissive Permissions-Policy

---

### cookie_security

**Check cookies for missing Secure, HttpOnly, SameSite attributes.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `cookie_observations` |

Parses Set-Cookie headers and flags missing security attributes on session and authentication cookies. Detects broad domain scope and excessively long-lived sessions.

#### Observations

- **medium**: Session cookie missing Secure flag
- **medium**: Session cookie missing HttpOnly
- **medium**: Session cookie SameSite=None
- **low**: Non-session cookie missing Secure, HttpOnly, or SameSite
- **low**: Long-lived session cookie (>1 year)
- **low**: Cookie scoped to broad domain

---

### cors_check

**Test for overly permissive CORS configurations.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `cors_observations` |

Sends OPTIONS requests with attacker-controlled Origin headers (evil.attacker.com, null). Detects wildcard CORS, origin reflection, null origin acceptance, and credentials exposure.

#### Observations

- **high**: CORS reflects arbitrary origin with credentials
- **high**: CORS allows any origin with credentials
- **medium**: CORS wildcard origin (without credentials)
- **medium**: CORS reflects arbitrary origin (without credentials)
- **medium**: CORS allows null origin

---

### robots_txt

**Retrieve robots.txt and identify potentially sensitive paths.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `robots_paths` |

Fetches robots.txt and searches disallowed paths for sensitive patterns: admin, internal, api, debug, config, backup, model, ml, ai, git, env.

#### Observations

- **low**: Sensitive paths in robots.txt
- **info**: Sitemaps disclosed

---

### waf_detection

**Detect WAF/CDN from headers, cookies, and error page signatures.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `waf_detected` |

Multi-method detection via response headers, cookie signatures, server header patterns, and error page fingerprints. Distinguishes WAF products (Cloudflare, AWS WAF, Imperva, Sucuri, F5 BIG-IP, Barracuda, Citrix ADC) from generic CDNs.

#### Observations

- **info**: WAF/CDN product detected
- **low**: WAF may affect scan accuracy

---

### auth_detection

**Detect authentication mechanisms (Basic, Bearer, OAuth, login forms).**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `auth_mechanisms` |

Probes for WWW-Authenticate headers, OAuth/OIDC endpoints, login forms, and unauthenticated API access.

#### Observations

- **medium**: API endpoint requires no authentication
- **low**: Bearer auth required on HTTP (insecure)
- **info**: OAuth/OIDC provider detected
- **info**: Login page detected
- **info**: Auth type detected (Basic, Bearer, Digest)

---

### favicon

**Download favicon and fingerprint framework via MD5 hash comparison.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `favicon_info` |

Downloads /favicon.ico and extracts favicon URLs from HTML link tags. Matches MD5 hash against OWASP database to identify CI/CD systems, monitoring platforms, web servers, frameworks, databases, and AI/ML platforms.

#### Observations

- **info**: Framework identified via favicon

---

### http2_detection

**Check for HTTP/2 (ALPN) and HTTP/3 (Alt-Svc) protocol support.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `http_protocols` |

Detects HTTP/2 via TLS ALPN negotiation, HTTP/3 via Alt-Svc header, and HTTP/2c via Upgrade header.

#### Observations

- **info**: Protocol support detected (HTTP/2, HTTP/3, HTTP/1.1 only)

---

## Phase 2 — Active Probing (depends on Phase 1)

### path_probe

**Check for common admin panels, config files, and sensitive endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `discovered_paths` |

Probes 50+ common paths including admin endpoints, config files, VCS files, backups, API endpoints, AI/ML paths, and monitoring endpoints. Returns accessible (200), protected (403), and redirect (3xx) results.

#### Observations

- **high**: Accessible .env, .git, database backups
- **medium**: Admin, config, debug, model, inference endpoints
- **low**: Protected paths (403) for admin/config/internal
- **info**: Redirects and other accessible paths

---

### sitemap

**Parse sitemap.xml to discover paths missed by wordlist probing.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `sitemap_paths` |

Fetches and parses XML sitemaps, follows sitemap index files (up to 10 sub-sitemaps), processes up to 500 URLs per service. Classifies sensitive and API paths.

#### Observations

- **low**: Sitemap reveals sensitive paths (staging, debug, internal, model)
- **low**: API versioning detected
- **info**: Sitemap URL count

---

### error_page

**Trigger error responses and fingerprint framework from error pages.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `error_page_info` |

Triggers 404, 405, and 500 errors and matches against 20+ framework signatures: Django, Flask/Werkzeug, Spring Boot, Express.js, ASP.NET, Laravel, FastAPI, Rails, Tomcat, nginx, Apache.

#### Observations

- **high**: Werkzeug/Flask debugger exposed (RCE risk)
- **medium**: Django DEBUG=True
- **medium**: Framework debug mode enabled
- **low**: Framework identified from error page
- **low**: Stack trace in response

---

### openapi_discovery

**Find exposed API documentation and extract endpoint information.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `api_endpoints`, `openapi_specs` |

Searches 13+ common paths for OpenAPI/Swagger specs. Parses JSON specs to extract endpoints, methods, security schemes, and sensitive endpoints.

#### Observations

- **high**: OpenAPI spec exposed with sensitive endpoints
- **medium**: OpenAPI spec exposed (no sensitive endpoints)
- **low**: API documentation UI found (Swagger/ReDoc)

---

## Phase 3 — Critical Observations (depends on services, uses path_probe output)

### webdav_check

**Probe for WebDAV methods that allow file upload or directory listing.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `webdav_observations` |

Tests PROPFIND, MKCOL, and PUT methods. Creates test file on PUT success and cleans up. Intrusive check.

#### Observations

- **critical**: WebDAV write access (PUT/MKCOL succeeded)
- **high**: WebDAV PROPFIND enabled (directory listing)
- **medium**: WebDAV methods require authentication

---

### vcs_exposure

**Assess depth of exposed .git/.svn/.hg repositories.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `vcs_observations` |

Deep check for VCS metadata. Probes .git/config, .git/HEAD, .git/COMMIT_EDITMSG, .git/refs/heads/\*, .git/logs/HEAD, .gitignore, .svn/entries, .hg/store. Searches .git/config for embedded credentials.

#### Observations

- **critical**: Git config contains credentials
- **critical**: Full git repository exposed (3+ files, code recoverable)
- **high**: Partial git repository exposed
- **high**: SVN/Mercurial metadata exposed

---

### config_exposure

**Parse accessible config files (.env, config.json, etc.) for secrets.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `config_observations` |

Analyzes config files for 16+ secret patterns: LLM provider keys (OpenAI, Anthropic, HuggingFace), cloud credentials (AWS, Azure, GCP), database credentials, JWT/session secrets, and private keys. Secrets are never stored — only redacted evidence in observations.

#### Observations

- **critical**: Configuration file contains secrets
- **high**: Configuration file accessible (no secrets detected)

---

### directory_listing

**Check for enabled directory listing (autoindex) on discovered paths.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `directory_listing_observations` |

Detects Apache, nginx, IIS, and Python autoindex signatures. Checks root and common paths plus path_probe results. Identifies sensitive file extensions (.py, .env, .json, .key, .pem, .sql, .db, .pt, .onnx, .pkl).

#### Observations

- **high**: Directory listing at root or with sensitive files
- **medium**: Directory listing at other paths

---

### default_creds

**Test admin panels for default credentials and unauthenticated access.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `default_creds_observations` |

Tests discovered admin panels for unauthenticated access and 6 default credential pairs (admin/admin, admin/password, root/root, etc.). Intrusive check.

#### Observations

- **critical**: Default credentials accepted
- **critical**: Admin panel requires no authentication
- **high**: Login form detected (default credentials rejected)

---

### debug_endpoints

**Analyze exposed debug/actuator/status endpoints for sensitive data.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `debug_observations` |

Probes /debug, /\_\_debug\_\_/, /actuator and sub-endpoints, /server-status, /phpinfo.php, /\_profiler, /trace. Detects Werkzeug debugger, Django DEBUG, Spring Boot Actuator, environment variables, connection strings, and internal IPs.

#### Observations

- **critical**: Werkzeug debugger exposed (RCE risk)
- **high**: Django DEBUG=True, Spring Boot Actuator exposed, sensitive data leak
- **medium**: Verbose health endpoint
- **low**: Framework identified from debug page
- **info**: Basic health endpoint

---

## Phase 4 — Advanced Analysis (depends on Phase 2-3)

### redirect_chain

**Follow redirect chains and check for HTTP->HTTPS, open redirects, excessive hops.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `redirect_info` |

Follows up to 10 redirect hops. Tests 8 common redirect parameter paths for open redirects. Intrusive check.

#### Observations

- **medium**: Long redirect chain (>3 hops)
- **medium**: Open redirect detected
- **medium**: No HTTP to HTTPS redirect
- **info**: HTTP to HTTPS redirect present
- **info**: Cross-domain redirect

---

### ssrf_indicator

**Detect parameters that accept URLs — potential SSRF vectors.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `ssrf_candidates` |

Identifies URL-accepting parameters via OpenAPI spec analysis, discovered path query strings, and probing known SSRF-prone paths. Detects 25+ parameter names (url, uri, image_url, fetch, proxy, webhook, etc.). Does NOT attempt actual SSRF exploitation.

#### Observations

- **medium**: SSRF candidate with proxy/forward/fetch parameter
- **medium**: SSRF candidate from OpenAPI spec
- **low**: URL parameter detected (potential SSRF)

---

### mass_assignment

**Test REST APIs for mass assignment by sending extra fields in requests.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `mass_assignment_info` |

Tests up to 5 endpoints with 21 injection fields across privilege (is_admin, role), billing (balance, credits), identity (user_id, tenant_id), and internal categories. Intrusive check.

#### Observations

- **critical**: Privilege field accepted and reflected (is_admin, role)
- **high**: Billing/identity field accepted and reflected
- **medium**: Fields accepted without reflection (blind mass assignment)
- **low**: Schema leak via validation error

---

### hsts_preload

**Check if domain is on the HSTS preload list (Chromium).**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `hsts_preload_info` |

Verifies HSTS preload status via hstspreload.org API. Checks for preload directive, includeSubDomains, and max-age >= 1 year.

#### Observations

- **low**: HSTS present but not preloaded (first-visit vulnerability)
- **info**: Domain is HSTS preloaded
- **info**: No HSTS header

---

### sri_check

**Verify external resources use Subresource Integrity (SRI) hashes.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `sri_info` |

Parses HTML for external script and link tags, checks for integrity= attributes. External resources without SRI are vulnerable to CDN compromise or supply-chain attacks.

#### Observations

- **medium**: Multiple external resources (3+) without SRI
- **low**: External resources without SRI (1-2)
- **info**: All external resources use SRI
