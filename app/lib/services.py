"""
app/lib/services.py - Shared service merging utility.

Canonical implementation for merging discovered services into a context dict,
used by CheckRunner, ChainOrchestrator, and SwarmCoordinator.
"""

from __future__ import annotations

from app.checks.base import Service


def merge_services(
    existing: list,
    new_services: list,
    *,
    convert_dicts: bool = False,
) -> list:
    """
    Merge new services into an existing list, deduplicating by URL.

    When a duplicate URL is found and both items are Service objects,
    metadata is merged and service_type is updated if the new service
    provides one.

    Args:
        existing: Current service list (modified in-place and returned).
        new_services: Services to add/merge.
        convert_dicts: If True, convert incoming dicts to Service objects
            via Service.from_dict() (used by swarm coordinator).

    Returns:
        The updated existing list.
    """
    if not new_services:
        return existing

    existing_urls: set[str] = set()
    for svc in existing:
        url = svc.url if isinstance(svc, Service) else svc.get("url", "")
        existing_urls.add(url)

    for svc in new_services:
        if convert_dicts and isinstance(svc, dict):
            url = svc.get("url", "")
            if not url:
                continue
            svc = Service.from_dict(svc)
        else:
            url = svc.url if isinstance(svc, Service) else svc.get("url", "")

        if url not in existing_urls:
            existing.append(svc)
            existing_urls.add(url)
        else:
            # Update existing service with new metadata
            for item in existing:
                item_url = item.url if isinstance(item, Service) else item.get("url", "")
                if item_url == url:
                    if isinstance(svc, Service) and isinstance(item, Service):
                        item.metadata.update(svc.metadata)
                        item.service_type = svc.service_type or item.service_type
                    break

    return existing
