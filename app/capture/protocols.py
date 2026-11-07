"""
app/capture/protocols.py - The `protocol` discriminator.

An evidence row records one **exchange** — a request/response pair in whatever
protocol the check speaks. `protocol` says how to read the request/response
columns, and which fields vary per run without changing meaning.

Capture is application-layer, one row per exchange. There is no pcap and no
transcript below the protocol the check speaks; see the phase doc §3.
"""

from __future__ import annotations

from typing import Literal, get_args

Protocol = Literal[
    "http",  # the bulk — everything through app/lib/http.py
    "dns",  # resolver checks (network_dns_enumeration, network_wildcard_dns, ...)
    "tcp",  # raw socket reads (network_banner_grab)
    "tls",  # certificate + protocol probing (network_tls_analysis)
    "whois",  # network_whois_lookup
    "icmp",  # network_traceroute
    "llm",  # an agent's exchange with a model — fact, recorded below the line
    "local",  # a resource on the operator's own host: the GeoLite2 mmdb
    #          lookup in network_geoip, and commands in future local checks
]

PROTOCOLS: tuple[str, ...] = get_args(Protocol)

#: Protocols captured under the default observation-linked rule. Everything else
#: is opt-in, because a `dns` row on a wide enumeration is cheap to write and
#: rarely what a grader reads — see the phase doc §5.2.
DEFAULT_PROTOCOLS: frozenset[str] = frozenset({"http", "llm"})


# ── Per-protocol volatile fields ─────────────────────────────────
#
# Excluded before hashing: they change every run without changing what the
# exchange means, and leaving them in would make `content_hash` never repeat
# even against a fixed target.

#: Header names (lowercased) dropped from every protocol before hashing.
COMMON_VOLATILE_HEADERS: frozenset[str] = frozenset(
    {
        "date",
        "age",
        "expires",
        "last-modified",
        "set-cookie",
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
        "x-amzn-requestid",
        "x-amz-request-id",
        "cf-ray",
        "request-id",
        "traceparent",
    }
)

#: Additional volatile headers per protocol.
VOLATILE_HEADERS: dict[str, frozenset[str]] = {
    # The WebSocket handshake key is a random nonce by specification (RFC 6455
    # §4.1), and the accept value is derived from it.
    "http": frozenset({"sec-websocket-key", "sec-websocket-accept"}),
    "llm": frozenset(
        {
            # Model responses carry per-call bookkeeping that says nothing about
            # what the model was asked or what it said.
            "x-ratelimit-remaining-requests",
            "x-ratelimit-remaining-tokens",
            "x-ratelimit-reset-requests",
            "x-ratelimit-reset-tokens",
            "openai-processing-ms",
            "x-request-duration",
        }
    ),
    "dns": frozenset({"query-id", "ttl"}),
    "tcp": frozenset(),
    "tls": frozenset(),
    "whois": frozenset(),
    "icmp": frozenset(),
    "local": frozenset(),
}


def volatile_headers(protocol: str) -> frozenset[str]:
    """Header names to drop before hashing an exchange in this protocol."""
    return COMMON_VOLATILE_HEADERS | VOLATILE_HEADERS.get(protocol, frozenset())


def is_known(protocol: str) -> bool:
    return protocol in PROTOCOLS
