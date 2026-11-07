"""
app/checks/web/redirect_chain.py - HTTP Redirect Chain Analysis

Follows redirect chains (up to 10 hops) and analyzes each step.
Checks for:
- Missing HTTP -> HTTPS upgrade
- Open redirects (arbitrary destination accepted)
- Excessive redirect chain length
- Cross-domain redirects

**Probe/grade.** `check_service()` follows the chain from the
root, then probes the eight redirect-parameter paths, records every hop and
judges nothing; `grade()` re-reads the recorded chain and places the severity.
`redirect_info` is an output, so both halves call `_reading()` over the same
exchanges (§6.2's two parses, with one parser).

`grade()` separates the open-redirect probes from the chain by their URL: a probe
URL carries `OPEN_REDIRECT_TARGET` in its query string and nothing else does.

**Two confidences are load-bearing here.**

- `open-redirect` fired whenever the target string appeared *anywhere* in the
  `Location` header — which a server that echoes it into its own error page
  (`Location: /error?bad=https://evil.example.com`) also satisfies, and that is
  not an open redirect at all. When the Location's own host is the attacker's,
  the verdict carries 0.97; when the string merely appears inside it, 0.5.
- `cross-domain` subtracts the service host from the chain's hosts, so a
  redirect from `example.com` to `www.example.com` reads as an external domain.
  A genuinely third-party host carries 0.9; a sibling or parent of the service
  host carries 0.6.

#### One incidental cleanup

For a plain-HTTP service the root was fetched twice: once by
`_check_https_redirect()` and again as the first hop of `_follow_chain()`, under
identical conditions. The chain is now followed first and the HTTP→HTTPS
judgement reads its first hop — same question, one request, and one row in the
record instead of two indistinguishable ones.
"""

import logging
from typing import Any
from urllib.parse import urljoin, urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

logger = logging.getLogger(__name__)

MAX_HOPS = 10

REDIRECT_CODES = (301, 302, 303, 307, 308)

# Paths commonly vulnerable to open redirect
REDIRECT_PARAM_PATHS = [
    "/redirect?url={target}",
    "/redirect?next={target}",
    "/login?next={target}",
    "/login?return_to={target}",
    "/logout?redirect={target}",
    "/auth/callback?redirect_uri={target}",
    "/go?to={target}",
    "/out?url={target}",
]

OPEN_REDIRECT_TARGET = "https://evil.example.com"
OPEN_REDIRECT_HOST = urlparse(OPEN_REDIRECT_TARGET).hostname or ""


class RedirectChainCheck(ServiceIteratingCheck):
    """Analyze HTTP redirect chains for security issues."""

    name = "web_redirect_chain"
    description = "Follow redirect chains and check for HTTP->HTTPS, open redirects, excessive hops"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["redirect_info"]
    service_types = ["http", "html", "api"]

    reason = (
        "Missing HTTPS redirects expose traffic to interception; open redirects enable phishing"
    )
    references = ["OWASP WSTG-CLNT-04", "CWE-601"]
    techniques = ["redirect chain analysis", "open redirect testing"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Follow, probe, record. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        # One candidate per service: the chain and the open-redirect probes are
        # independent judgements over the same subject, so the candidate stays
        # undiscriminated and `grade()` names each one.
        candidate = self.create_candidate(host=service.host, target=service)

        # Use follow_redirects=False so we can inspect each hop
        cfg = HttpConfig(
            verify_ssl=False,
            follow_redirects=False,
        )

        try:
            async with AsyncHttpClient(cfg) as client:

                def record(resp) -> Exchange:
                    exchange = exchange_from_response(
                        resp, check_name=self.name, scan_id=scan_id, host=service.host
                    )
                    candidate.attach(exchange)
                    return exchange

                # 1. Follow the chain from the root. Its first hop is also the
                #    HTTP -> HTTPS judgement's evidence, so it is fetched once.
                await self._rate_limit()
                await self._follow_chain(client, service.url, record)

                # 2. Test for open redirects
                for path_template in REDIRECT_PARAM_PATHS:
                    path = path_template.format(target=OPEN_REDIRECT_TARGET)
                    await self._rate_limit()
                    resp = await client.get(service.with_path(path))
                    if resp.error:
                        continue
                    record(resp)

        except Exception as e:
            result.errors.append(f"Redirect chain error: {e}")

        result.candidates.append(candidate)
        result.outputs["redirect_info"] = _reading(
            candidate.exchanges, service.scheme, service.host
        )["info"]
        return result

    async def _follow_chain(self, client: AsyncHttpClient, url: str, record) -> None:
        """Follow the redirect chain from `url`, recording each hop.

        The hops go onto the candidate in order; `_reading()` reads the chain
        back off them, so there is one representation of where the target sent
        us rather than a list built alongside it.
        """
        visited = set()
        current_url = url

        for _ in range(MAX_HOPS):
            if current_url in visited:
                break  # Loop detected
            visited.add(current_url)

            resp = await client.get(current_url)
            exchange = record(resp)

            if resp.error or resp.status_code not in REDIRECT_CODES:
                break

            location = extract_headers_dict(exchange.response_headers or {}).get("location", "")
            if not location:
                break

            # Resolve relative redirect
            current_url = urljoin(current_url, location)
            await self._rate_limit()

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded chain. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one service's redirect behaviour."""
        exchanges = list(evidence)
        scheme = ctx.target.scheme if ctx.target else "https"
        reading = _reading(exchanges, scheme, ctx.host)
        chain = reading["chain"]
        verdicts: list[Verdict] = []

        # ── HTTP -> HTTPS on the root ─────────────────────
        if scheme != "https" and chain:
            first = chain[0]
            status = first.response_status
            location = extract_headers_dict(first.response_headers or {}).get("location", "")

            if status in REDIRECT_CODES and location.startswith("https://"):
                verdicts.append(
                    Verdict(
                        severity="info",
                        # Status and Location read verbatim off the record.
                        confidence=0.99,
                        discriminator="https-redirect-ok",
                        title=f"HTTP to HTTPS redirect present: {ctx.host}",
                        description="HTTP requests are redirected to HTTPS (good)",
                        evidence=f"HTTP {status} -> {location}",
                        reasoning=f"the root answered {status} with an https:// Location",
                        signals={"status": status, "location": location},
                        evidence_ids=[first.id],
                    )
                )
            else:
                verdicts.append(
                    Verdict(
                        severity="medium",
                        # One request to one path. A site can redirect other
                        # paths, or rely on HSTS, and still answer the root in
                        # clear — so the absence is observed rather than total.
                        confidence=0.95,
                        discriminator="no-https-redirect",
                        title=f"No HTTP to HTTPS redirect: {ctx.host}",
                        description=(
                            "HTTP requests are not redirected to HTTPS, content is served "
                            "over plain HTTP"
                        ),
                        evidence=(
                            f"GET {first.request_url} -> HTTP {status} (no redirect to HTTPS)"
                        ),
                        reasoning=(
                            f"the root answered {status} with "
                            f"{'no Location' if not location else f'Location: {location}'}, "
                            "which does not upgrade the scheme"
                        ),
                        signals={"status": status, "location": location},
                        references=["CWE-319"],
                        evidence_ids=[first.id],
                    )
                )

        if len(chain) > 1:
            chain_urls = [e.request_url or "" for e in chain]
            chain_ids = [e.id for e in chain]

            if len(chain) > 3:
                verdicts.append(
                    Verdict(
                        severity="low",
                        # The hops were counted by making them. Short of certain
                        # only because the walk stops at MAX_HOPS or a loop, so
                        # the length is what was followed.
                        confidence=0.95,
                        discriminator="long-chain",
                        title=f"Long redirect chain: {len(chain)} hops",
                        description=(
                            f"Redirect chain from {chain_urls[0]} traverses {len(chain)} "
                            "hops before reaching final destination"
                        ),
                        evidence=(
                            f"Chain: {' -> '.join(chain_urls[:6])}{'...' if len(chain) > 6 else ''}"
                        ),
                        reasoning=(
                            f"{len(chain)} hops were followed before a non-redirect "
                            f"response (cap is {MAX_HOPS})"
                        ),
                        signals={"chain": chain_urls, "hops": len(chain)},
                        raw_data={"chain": chain_urls},
                        evidence_ids=chain_ids,
                    )
                )

            # Check for cross-domain redirects
            domains = {urlparse(u).hostname for u in chain_urls if urlparse(u).hostname}
            external = domains - {ctx.host}
            if external:
                related = {d for d in external if _same_site(d, ctx.host)}
                third_party = external - related
                verdicts.append(
                    Verdict(
                        severity="info",
                        # The hostnames are read off the chain. The word
                        # "external" is the soft part: this subtracts the service
                        # host as a string, so `www.example.com` counts as
                        # external to `example.com`.
                        confidence=0.9 if third_party else 0.6,
                        discriminator="cross-domain",
                        title=(f"Cross-domain redirect to: {', '.join(sorted(external))}"),
                        description="Redirect chain passes through external domain(s)",
                        evidence=f"Domains in chain: {', '.join(sorted(domains))}",
                        reasoning=(
                            f"{', '.join(sorted(third_party))} share no registrable "
                            "domain with the service host"
                            if third_party
                            else f"{', '.join(sorted(related))} differ from the service "
                            "host only by subdomain, so this is very likely the same site"
                        ),
                        signals={
                            "domains": sorted(domains),
                            "external": sorted(external),
                            "third_party": sorted(third_party),
                        },
                        evidence_ids=chain_ids,
                    )
                )

        # ── Open redirects ────────────────────────────────
        for exchange in reading["probes"]:
            location = extract_headers_dict(exchange.response_headers or {}).get("location", "")
            if exchange.response_status not in REDIRECT_CODES:
                continue
            if OPEN_REDIRECT_TARGET not in location:
                continue

            base_path = urlparse(exchange.request_url or "").path or "/"
            # Did the Location actually point *at* the attacker's host, or does
            # it merely quote it back inside a URL of the server's own?
            redirected = (urlparse(location).hostname or "").lower() == OPEN_REDIRECT_HOST
            verdicts.append(
                Verdict(
                    severity="medium",
                    confidence=0.97 if redirected else 0.5,
                    discriminator=(f"open-redirect-{base_path.replace('/', '-').strip('-')}"),
                    title=f"Open redirect: {ctx.host}{base_path}",
                    description=(
                        "Endpoint accepts arbitrary redirect destination via URL parameter"
                    ),
                    evidence=(
                        f"GET {exchange.request_url} -> HTTP {exchange.response_status} "
                        f"Location: {location}"
                    ),
                    reasoning=(
                        f"Location resolves to {OPEN_REDIRECT_HOST}, the host supplied in "
                        "the parameter"
                        if redirected
                        else "the supplied URL appears inside the Location header but is "
                        "not its host — an error page quoting the parameter looks the same"
                    ),
                    signals={
                        "path": base_path,
                        "location": location,
                        "redirects_to_target": redirected,
                    },
                    references=["CWE-601", "OWASP WSTG-CLNT-04"],
                    evidence_ids=[exchange.id],
                )
            )

        return verdicts


# ── The one parser, called by both halves ────────────────────────────


def _is_probe(exchange: Exchange) -> bool:
    """True for an open-redirect probe: only those carry the target in the URL."""
    return OPEN_REDIRECT_TARGET in (exchange.request_url or "")


def _same_site(domain: str, host: str) -> bool:
    """True when two hostnames differ only by subdomain.

    A crude registrable-domain test — the last two labels — which is enough to
    tell `www.example.com` from `cdn.thirdparty.net` and is used only to set a
    confidence, never to change what is reported.
    """
    a = domain.lower().split(".")
    b = host.lower().split(".")
    return len(a) >= 2 and len(b) >= 2 and a[-2:] == b[-2:]


def _reading(exchanges: list[Exchange], scheme: str, host: str) -> dict[str, Any]:
    """Read one service's redirect behaviour out of its recorded hops.

    `info` is `redirect_info` verbatim — same keys, set under the same
    conditions — so the output this check produces is unchanged.
    """
    chain = [e for e in exchanges if not _is_probe(e)]
    probes = [e for e in exchanges if _is_probe(e)]

    info: dict[str, Any] = {}

    if scheme != "https" and chain:
        first = chain[0]
        location = extract_headers_dict(first.response_headers or {}).get("location", "")
        info["https_redirect"] = bool(
            first.response_status in REDIRECT_CODES and location.startswith("https://")
        )

    if len(chain) > 1:
        info["chain"] = [e.request_url or "" for e in chain]
        info["chain_length"] = len(chain)

    open_redirects = []
    for exchange in probes:
        location = extract_headers_dict(exchange.response_headers or {}).get("location", "")
        if exchange.response_status in REDIRECT_CODES and OPEN_REDIRECT_TARGET in location:
            url = exchange.request_url or ""
            parsed = urlparse(url)
            open_redirects.append(f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path)
    if open_redirects:
        info["open_redirects"] = open_redirects

    return {"chain": chain, "probes": probes, "info": info}
