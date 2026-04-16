"""
app/engine/chainsmith.py - Chainsmith Orchestration

Coordinates check ecosystem management: validation, custom check
scaffolding, upstream diff detection, and disable-impact analysis.
Routes call engine functions; the engine manages agent lifecycle,
state guards, and persistence.
"""

import logging

from app.agents.chainsmith import ChainsmithAgent

logger = logging.getLogger(__name__)

# Module-level chainsmith status. Chainsmith operations are not tied to a scan;
# this is a simple concurrency guard for the single-process chainsmith agent.
_chainsmith_status: str = "idle"


def get_status() -> str:
    """Return current chainsmith status (idle | validating | complete | error)."""
    return _chainsmith_status


async def run_validation() -> dict:
    """
    Run full check ecosystem validation.

    Guards against concurrent runs via the module-level _chainsmith_status.
    Persists results to the database.
    """
    global _chainsmith_status
    _chainsmith_status = "validating"

    try:
        agent = ChainsmithAgent()
        result = await agent.validate()
        result_dict = result.to_dict()

        # Persist to DB
        try:
            from app.db.repositories import ChainsmithRepository

            await ChainsmithRepository().save_validation(
                scan_id=None,
                validation_type="full",
                status="complete",
                result=result_dict,
                issues_count=len(result.issues),
            )
        except Exception:
            logger.warning("Failed to persist validation to DB", exc_info=True)

        _chainsmith_status = "complete"
        return result_dict

    except Exception as e:
        logger.exception("Chainsmith validation failed: %s", e)
        _chainsmith_status = "error"
        raise


async def run_upstream_diff() -> dict:
    """Check for community check drift and persist the result."""
    try:
        agent = ChainsmithAgent()
        diff = await agent.diff_upstream()
        community_hash = agent._hash_community_checks()

        # Persist to DB (include community_hash so future diffs can compare)
        try:
            from app.db.repositories import ChainsmithRepository

            await ChainsmithRepository().save_validation(
                scan_id=None,
                validation_type="upstream_diff",
                status="complete",
                result={"diff": diff, "community_hash": community_hash},
            )
        except Exception:
            logger.warning("Failed to persist upstream diff to DB", exc_info=True)

        return {"diff": diff}

    except Exception as e:
        logger.exception("Upstream diff failed: %s", e)
        raise


async def scaffold_check(
    name: str,
    description: str,
    suite: str,
    conditions: list[dict] | None = None,
    produces: list[str] | None = None,
    service_types: list[str] | None = None,
    intrusive: bool = False,
) -> dict:
    """Preview a custom check scaffold (no disk write)."""
    agent = ChainsmithAgent()
    return await agent.scaffold_check(
        name=name,
        description=description,
        suite=suite,
        conditions=conditions,
        produces=produces,
        service_types=service_types,
        intrusive=intrusive,
    )


async def create_check(
    name: str,
    description: str,
    suite: str,
    conditions: list[dict] | None = None,
    produces: list[str] | None = None,
    service_types: list[str] | None = None,
    intrusive: bool = False,
) -> dict:
    """Scaffold, write, and register a custom check. Persists metadata to DB."""
    agent = ChainsmithAgent()
    result = await agent.write_and_register_check(
        name=name,
        description=description,
        suite=suite,
        conditions=conditions,
        produces=produces,
        service_types=service_types,
        intrusive=intrusive,
    )

    if not result.get("error"):
        try:
            from app.db.repositories import ChainsmithRepository

            await ChainsmithRepository().save_custom_check(
                {
                    "name": name,
                    "description": description,
                    "suite": suite,
                    "file_path": result.get("path"),
                }
            )
        except Exception:
            logger.warning("Failed to persist custom check to DB", exc_info=True)

    return result


async def get_disable_impact(check_names: list[str]) -> dict:
    """Analyze the impact of disabling specific checks."""
    agent = ChainsmithAgent()
    impact = await agent.suggest_disable_impact(check_names)
    return {"impact": impact}


async def get_health() -> dict:
    """Quick health check — returns last validation from DB."""
    try:
        from app.db.repositories import ChainsmithRepository

        repo = ChainsmithRepository()
        validation = await repo.get_validation()
        custom_checks = await repo.get_custom_checks()

        return {
            "last_validation": validation.get("created_at") if validation else None,
            "issues_count": validation.get("issues_count", 0) if validation else 0,
            "custom_checks_count": len(custom_checks),
        }
    except Exception:
        logger.warning("Failed to read health from DB", exc_info=True)
        return {
            "last_validation": None,
            "issues_count": 0,
            "custom_checks_count": 0,
        }


async def get_custom_checks() -> list[dict]:
    """List all registered custom checks from DB."""
    try:
        from app.db.repositories import ChainsmithRepository

        return await ChainsmithRepository().get_custom_checks()
    except Exception:
        logger.warning("Failed to read custom checks from DB", exc_info=True)
        return []
