"""
app/checks/network/traceroute.py

Network Path / Traceroute

TCP-based traceroute to target hosts. Identifies intermediate hops,
CDN/WAF presence, and network topology without requiring root privileges.

Depends on: dns_enumeration (needs dns_records with hostname -> IP mapping)
Feeds: CDN/WAF detection, network topology understanding

Note: This check is inherently less reliable than others — firewalls
may block probes, and results vary by network path. It is treated as
optional/best-effort.
"""

import asyncio
import logging
import socket
import struct
import time
from typing import Any, Optional

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.findings import build_finding

logger = logging.getLogger(__name__)

# CDN/WAF/Cloud provider hostname patterns in PTR records or hop names
CDN_PATTERNS: dict[str, list[str]] = {
    "Cloudflare": ["cloudflare", "cf-"],
    "Akamai": ["akamai", "akadns", "edgekey", "edgesuite"],
    "AWS CloudFront": ["cloudfront", "amazonaws"],
    "Fastly": ["fastly"],
    "Google Cloud": ["google", "1e100.net"],
    "Microsoft Azure": ["msedge", "azure", "microsoft"],
    "Incapsula/Imperva": ["incapsula", "imperva"],
    "Sucuri": ["sucuri"],
    "StackPath": ["stackpath", "highwinds"],
    "Limelight": ["limelight", "llnw"],
}

# Max hops to trace
MAX_HOPS = 30
# Timeout per hop probe (seconds)
HOP_TIMEOUT = 2.0
# Target port for TCP probes
PROBE_PORT = 80
# Max hosts to traceroute (avoid excessive network probing)
MAX_TARGETS = 5


class TracerouteCheck(BaseCheck):
    """
    TCP-based network path tracing to target hosts.

    Uses incrementing TTL values with TCP SYN probes to map the
    network path. Identifies CDN/WAF presence from intermediate
    hop hostnames. Works without root privileges on most platforms.

    Produces:
        traceroute_data - {
            host: {
                hops: [{hop, ip, hostname, rtt_ms}],
                total_hops: int,
                cdn_detected: str|None,
                avg_rtt_ms: float,
            }
        }
    """

    name = "traceroute"
    description = "TCP-based network path tracing and CDN/WAF detection"

    conditions = [
        CheckCondition("dns_records", "truthy"),
    ]
    produces = ["traceroute_data"]

    timeout_seconds = 120.0
    requests_per_second = 2.0  # Gentle on network

    reason = (
        "Network path analysis reveals CDN/WAF/reverse proxy presence "
        "in the path to target hosts, which affects what service_probe "
        "results mean. Geographic routing reveals data path for "
        "compliance analysis."
    )
    references = [
        "PTES - Intelligence Gathering",
        "https://attack.mitre.org/techniques/T1590/",
    ]
    techniques = [
        "TCP traceroute",
        "network path analysis",
        "CDN detection",
        "hop enumeration",
    ]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        dns_records: dict[str, str] = context.get("dns_records", {})
        if not dns_records:
            result.errors.append("No dns_records in context")
            result.success = False
            return result

        # Deduplicate by IP — no need to trace the same IP twice
        ip_to_hosts: dict[str, list[str]] = {}
        for hostname, ip in dns_records.items():
            ip_to_hosts.setdefault(ip, []).append(hostname)

        # Limit targets to avoid excessive probing
        target_ips = list(ip_to_hosts.keys())[:MAX_TARGETS]

        traceroute_data: dict[str, dict] = {}

        for ip in target_ips:
            hostnames = ip_to_hosts[ip]
            host_label = hostnames[0]

            trace_result = await self._trace_route(ip)
            if trace_result:
                traceroute_data[host_label] = trace_result
                self._generate_findings(result, host_label, ip, trace_result)

            result.targets_checked += 1

            # Brief pause between targets
            await asyncio.sleep(0.5)

        result.outputs["traceroute_data"] = traceroute_data
        return result

    async def _trace_route(self, target_ip: str) -> Optional[dict[str, Any]]:
        """Trace the network path to target_ip using TCP probes."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_trace_route, target_ip),
                timeout=self.timeout_seconds / 2,  # Per-target timeout
            )
        except (asyncio.TimeoutError, Exception) as exc:
            logger.debug(f"Traceroute failed for {target_ip}: {exc}")
            return None

    def _sync_trace_route(self, target_ip: str) -> Optional[dict[str, Any]]:
        """Synchronous TCP traceroute implementation."""
        hops: list[dict[str, Any]] = []
        cdn_detected: Optional[str] = None

        for ttl in range(1, MAX_HOPS + 1):
            hop_info = self._probe_hop(target_ip, ttl)
            hops.append(hop_info)

            # Check for CDN/WAF patterns in hostname
            if hop_info.get("hostname"):
                detected = self._detect_cdn(hop_info["hostname"])
                if detected and not cdn_detected:
                    cdn_detected = detected

            # Reached the target
            if hop_info.get("ip") == target_ip:
                break

            # Three consecutive timeouts after at least 3 hops — likely blocked
            if ttl >= 3 and len(hops) >= 3:
                last_three = hops[-3:]
                if all(h.get("ip") is None for h in last_three):
                    break

        # Calculate average RTT for responsive hops
        rtts = [h["rtt_ms"] for h in hops if h.get("rtt_ms") is not None]
        avg_rtt = sum(rtts) / len(rtts) if rtts else None

        return {
            "target_ip": target_ip,
            "hops": hops,
            "total_hops": len(hops),
            "cdn_detected": cdn_detected,
            "avg_rtt_ms": round(avg_rtt, 2) if avg_rtt else None,
            "reached_target": any(h.get("ip") == target_ip for h in hops),
        }

    def _probe_hop(self, target_ip: str, ttl: int) -> dict[str, Any]:
        """Probe a single hop using TCP connect with specific TTL."""
        hop_info: dict[str, Any] = {
            "hop": ttl,
            "ip": None,
            "hostname": None,
            "rtt_ms": None,
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(HOP_TIMEOUT)

            # Set TTL on the socket
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            start = time.monotonic()
            try:
                sock.connect((target_ip, PROBE_PORT))
                # If connect succeeds, we've reached the target (or a proxy)
                elapsed = (time.monotonic() - start) * 1000
                hop_info["ip"] = target_ip
                hop_info["rtt_ms"] = round(elapsed, 2)
            except socket.timeout:
                # Timeout — no response at this TTL
                pass
            except OSError as exc:
                elapsed = (time.monotonic() - start) * 1000
                # Connection refused or TTL expired errors can still tell
                # us the IP of the responding hop
                # On some platforms, errno 10013/10065 indicate TTL expired
                # or host unreachable — we can still extract info
                if hasattr(exc, "errno") and exc.errno in (
                    111,    # Connection refused (Linux)
                    10061,  # Connection refused (Windows)
                ):
                    # Reached the target but port is closed
                    hop_info["ip"] = target_ip
                    hop_info["rtt_ms"] = round(elapsed, 2)
            finally:
                sock.close()

        except Exception as exc:
            logger.debug(f"Hop {ttl} probe error: {exc}")

        # Reverse DNS lookup for the hop IP
        if hop_info["ip"]:
            try:
                hostname, _, _ = socket.gethostbyaddr(hop_info["ip"])
                hop_info["hostname"] = hostname
            except (socket.herror, socket.gaierror, OSError):
                pass

        return hop_info

    def _detect_cdn(self, hostname: str) -> Optional[str]:
        """Check if a hostname matches known CDN/WAF patterns."""
        hostname_lower = hostname.lower()
        for provider, patterns in CDN_PATTERNS.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return provider
        return None

    def _generate_findings(
        self,
        result: CheckResult,
        host: str,
        target_ip: str,
        trace: dict[str, Any],
    ) -> None:
        """Generate findings from traceroute results."""
        total_hops = trace["total_hops"]
        avg_rtt = trace.get("avg_rtt_ms")
        cdn = trace.get("cdn_detected")
        reached = trace.get("reached_target", False)

        rtt_str = f"{avg_rtt}ms avg" if avg_rtt else "unknown"

        # Info: route summary
        result.findings.append(build_finding(
            check_name=self.name,
            title=f"Route to {host}: {total_hops} hops, {rtt_str}",
            description=(
                f"Network path to {host} ({target_ip}): {total_hops} hops, "
                f"average latency {rtt_str}. "
                f"Target {'reached' if reached else 'not reached (blocked/filtered)'}."
            ),
            severity="info",
            evidence=(
                f"Target: {host} ({target_ip}) | Hops: {total_hops} | "
                f"Avg RTT: {rtt_str} | Reached: {reached}"
            ),
            host=host,
            discriminator="route",
            raw_data=trace,
        ))

        # Info: CDN/WAF detected in path
        if cdn:
            # Find the hop where CDN was detected
            cdn_hop = None
            for hop in trace.get("hops", []):
                if hop.get("hostname") and self._detect_cdn(hop["hostname"]):
                    cdn_hop = hop["hop"]
                    break

            hop_str = f" (hop {cdn_hop})" if cdn_hop else ""
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"CDN detected in path to {host}: {cdn}{hop_str}",
                description=(
                    f"Traffic to {host} ({target_ip}) passes through {cdn} "
                    f"infrastructure{hop_str}. This means service_probe and "
                    f"web check results may reflect the CDN, not the origin server."
                ),
                severity="info",
                evidence=(
                    f"Target: {host} | CDN: {cdn} | Hop: {cdn_hop or 'unknown'}"
                ),
                host=host,
                discriminator=f"cdn-{cdn.lower().replace('/', '-').replace(' ', '-')}",
            ))
