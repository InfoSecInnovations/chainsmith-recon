# Network Suite

Service discovery and infrastructure reconnaissance.
13 checks organized in 5 phases by dependency order.

---

## Phase 1 — DNS Discovery (no dependencies)

### dns_enumeration

**Enumerate subdomains via DNS resolution.**

| Property | Value |
|----------|-------|
| Conditions | None (entry point) |
| Produces | `target_hosts`, `dns_records` |

Resolves common subdomains (www, api, chat, app, admin, portal, auth, login, docs, dev, staging, test, internal, backend, frontend, cdn, etc.) in batches of 10. Accepts optional custom wordlist.

#### Observations

- **info**: Host discovered

---

### wildcard_dns

**Detect wildcard DNS records that cause false subdomain discoveries.**

| Property | Value |
|----------|-------|
| Conditions | None (entry point) |
| Produces | `wildcard_dns` |

Generates 3 random non-existent subdomains and checks if they resolve. If all resolve to the same IP, a definite wildcard is present. Multiple IPs suggest round-robin or geo-DNS.

#### Observations

- **info**: Wildcard DNS detected

---

### dns_records

**Extract MX, NS, TXT, CNAME, SOA, AAAA records for infrastructure context.**

| Property | Value |
|----------|-------|
| Conditions | None (entry point) |
| Produces | `dns_extra_records`, `dns_extra_hosts` |

Queries six record types. Detects verification tokens from 42 cloud/SaaS providers and extracts SPF provider information to map email infrastructure.

#### Observations

- **info**: MX, NS, CNAME, SOA, AAAA records found
- **low**: Verification token detected (Google, Microsoft, Facebook, Apple, etc.)
- **low**: SPF reveals mail providers (Google Workspace, Microsoft 365, Amazon SES, SendGrid, etc.)

---

### whois_lookup

**WHOIS domain registration and ASN lookup for resolved IPs.**

| Property | Value |
|----------|-------|
| Conditions | `dns_records is truthy` |
| Produces | `whois_data` |

Queries WHOIS servers for domain registration details and performs RDAP lookups for ASN/network ownership. Supports 18 common TLDs with fallback to whois.iana.org.

#### Observations

- **info**: Domain registrar details
- **info**: IP ASN/network ownership
- **low**: Domain registered within last 90 days (potential phishing/shadow IT)
- **info**: WHOIS data redacted (privacy/GDPR)

---

## Phase 2 — IP Analysis (depends on dns_enumeration)

### geoip

**GeoIP and ASN lookup for resolved IP addresses.**

| Property | Value |
|----------|-------|
| Conditions | `dns_records is truthy` |
| Produces | `geoip_data` |

Classifies IPs as hosting (major cloud, CDN, VPS), residential (consumer ISP), or other. Tracks 40+ hosting ASNs and 15+ residential ASNs. Requires MaxMind GeoLite2 databases.

#### Observations

- **info**: Host geolocation and ASN info
- **medium**: Residential IP hosting service (indicates home machine, misconfigured tunnel, or compromised host)
- **low**: Non-standard hosting provider

---

### reverse_dns

**Reverse DNS (PTR) lookup for discovered IP addresses.**

| Property | Value |
|----------|-------|
| Conditions | `dns_records is truthy` |
| Produces | `reverse_dns`, `reverse_dns_hosts` |

Reveals internal hostnames, virtual hosting relationships, and cloud infrastructure patterns from PTR records. Uses dnspython with socket fallback.

#### Observations

- **info**: PTR record found
- **info**: Multiple PTR records (possible virtual hosting)
- **low**: Internal hostname in PTR (.internal, .local, .corp, .ec2.internal, etc.)
- **info**: PTR/forward mismatch

---

### ipv6_discovery

**IPv6 AAAA record resolution and dual-stack analysis.**

| Property | Value |
|----------|-------|
| Conditions | `target_hosts is truthy` |
| Produces | `ipv6_data` |

Identifies hosts with IPv6 endpoints that may have different security postures than IPv4. Detects ULA and link-local addresses.

#### Observations

- **info**: IPv6 address discovered
- **medium**: Service reachable on IPv6 but not IPv4 (potential firewall bypass)
- **low**: RFC 4193 unique local address exposed

---

### port_scan

**Scan TCP ports to discover services.**

| Property | Value |
|----------|-------|
| Conditions | `target_hosts is truthy` |
| Produces | `services` |

TCP connect scan (no root required). Port selection uses profile hierarchy: in_scope_ports → port_profile → scope default. Profiles: "web", "ai", "full", "lab".

#### Observations

- **info**: Open port discovered

---

## Phase 3 — Service Analysis (depends on services/port_scan)

### tls_analysis

**TLS certificate inspection and protocol version detection.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `tls_data`, `tls_hosts` |

Inspects certificates on HTTPS services and common TLS ports. Extracts SANs for additional hostname discovery. Probes for deprecated TLS versions (1.0, 1.1).

#### Observations

- **info**: TLS certificate summary (subject, issuer, SAN count)
- **info**: Certificate SANs discovered
- **medium**: Self-signed certificate
- **medium**: Expired certificate
- **low**: Certificate expires within 30 days
- **low**: Deprecated TLS version supported (TLS 1.0, 1.1)

---

### service_probe

**Probe services to determine type and gather initial fingerprints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `services` (enriched) |

Probes each service with HTTPS then HTTP. Classifies as "ai", "api", "html", "http", or "tcp". Detects AI services via headers (x-model, x-inference, x-llm), powered-by values (vllm, ollama, tgi, langchain), and API paths.

#### Observations

- **low**: Server version disclosed
- **medium**: AI/ML technology disclosed via X-Powered-By
- **low**: Technology disclosed via X-Powered-By
- **medium**: Sensitive custom header (model, token, key, secret, debug)
- **info**: Custom header detected

---

### banner_grab

**Banner grabbing and service identification on non-HTTP ports.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `banner_data` |

Identifies non-HTTP services (Redis, PostgreSQL, MongoDB, MySQL, SMTP, FTP, SSH, Memcached, Elasticsearch) via TCP banner analysis. Checks for unauthenticated access.

#### Observations

- **info**: Service detected via banner
- **critical**: Redis accepting commands without authentication
- **high**: Memcached/other service accepting commands without authentication
- **low**: Service version disclosed in banner
- **medium**: Unidentified service with banner

---

## Phase 4 — Deep Probing (depends on service_probe)

### http_method_enum

**HTTP method enumeration and dangerous method detection.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `http_methods` |

Sends OPTIONS request then individually probes TRACE, PUT, DELETE, PATCH, and WebDAV methods (PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK).

#### Observations

- **info**: Allowed methods summary
- **medium**: TRACE method enabled (cross-site tracing risk)
- **medium**: PUT method enabled (unauthorized upload/modification)
- **low**: DELETE method enabled
- **low**: PATCH method enabled
- **medium**: WebDAV methods enabled

---

### traceroute

**TCP-based network path tracing and CDN/WAF detection.**

| Property | Value |
|----------|-------|
| Conditions | `dns_records is truthy` |
| Produces | `traceroute_data` |

TCP traceroute using incrementing TTL (no root required). Traces up to 30 hops, max 5 target IPs. Detects CDN/WAF presence in path: Cloudflare, Akamai, AWS CloudFront, Fastly, Google Cloud, Azure, Incapsula, Sucuri, StackPath, Limelight.

#### Observations

- **info**: Route summary (hop count, average RTT)
- **info**: CDN/WAF detected in path
