"""
app/scenario_services - Reusable service templates for Chainsmith scenarios.

This package provides pre-built FastAPI service implementations that scenarios
can reference and configure. Services are organized by vertical/domain:

    common/     - Shared utilities (config, middleware, responses)
    banking/    - Financial services (www, api, chatbot)
    ai/         - AI infrastructure (mcp_server, agent, rag, vector_db)
    corporate/  - Enterprise apps (helpdesk, intranet)
    healthcare/ - Medical apps (patient_portal, triage_bot)
    education/  - EdTech (lms, tutor_bot)
    ...

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.banking.www:app
      --host 0.0.0.0 --port 8080

Configuration via environment variables:
    - SCENARIO_CONFIG_PATH: Path to scenario.json
    - SESSION_STATE_PATH: Path to session.json (shared state)
    - SERVICE_NAME: Identifier for this service
    - SERVICE_PORT: Port number
    - BRAND_NAME: Display name override
    - BRAND_DOMAIN: Domain override
    - VERBOSE_ERRORS: Enable stack traces (default: true)
    - RANDOMIZE_FINDINGS: Enable finding randomization (default: true)

See common/config.py for full configuration options.
"""

__version__ = "0.1.0"
