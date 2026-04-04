"""
Port Scanning Tool

Real network port scanning using python-nmap.
"""

import asyncio
import socket
from datetime import datetime

from app.checks.network.port_profiles import resolve_ports
from app.models import RawEvidence


async def port_scan(
    host: str, ports: list[int] | None = None, profile: str | None = None, timeout: float = 5.0
) -> dict:
    """
    Scan ports on a target host.

    Uses socket connections for speed (nmap fallback if available).

    Args:
        host: Target hostname or IP
        ports: Explicit list of ports to scan (overrides profile)
        profile: Port profile name ("web", "ai", "full", "lab")
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with scan results
    """
    if ports is None:
        ports = resolve_ports(profile=profile)

    results = {
        "host": host,
        "scan_time": datetime.utcnow().isoformat(),
        "ports_scanned": len(ports),
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
    }

    async def check_port(port: int) -> tuple[int, str]:
        """Check if a single port is open."""
        try:
            # Resolve hostname
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                return port, "filtered"

            # Try to connect
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)

            try:
                await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=timeout)
                sock.close()
                return port, "open"
            except TimeoutError:
                sock.close()
                return port, "filtered"
            except ConnectionRefusedError:
                sock.close()
                return port, "closed"
            except OSError:
                sock.close()
                return port, "filtered"

        except Exception:
            return port, "error"

    # Scan all ports concurrently
    tasks = [check_port(port) for port in ports]
    port_results = await asyncio.gather(*tasks)

    for port, status in port_results:
        if status == "open":
            results["open_ports"].append(port)
        elif status == "closed":
            results["closed_ports"].append(port)
        else:
            results["filtered_ports"].append(port)

    results["open_ports"].sort()

    return results


def create_port_scan_evidence(host: str, results: dict) -> RawEvidence:
    """Create evidence record for a port scan."""
    return RawEvidence(
        tool_name="port_scan",
        timestamp=datetime.utcnow(),
        request={"host": host, "type": "TCP connect scan"},
        response=results,
    )
