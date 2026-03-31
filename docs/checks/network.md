# Network Suite

Entry point checks that discover services.

## dns_enumeration

**Discover hosts via DNS enumeration.**

| Property | Value |
|----------|-------|
| Conditions | None (entry point) |
| Produces | `services`, `target_hosts` |

Enumerates subdomains and resolves IP addresses. This is typically the first check to run.

### Findings

- **info**: Hosts discovered

---

## service_probe

**Probe discovered hosts to identify services.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `services` (enriched) |

Connects to discovered hosts, identifies service types (HTTP, API, AI), and extracts server headers.

### Findings

- **info**: Service fingerprinted
