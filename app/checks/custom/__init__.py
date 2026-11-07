"""
app/checks/custom/ - Organization-Specific Custom Checks

This directory holds custom checks created by or for the organization.
Community upstream updates never touch this directory.

Each custom check is a self-contained component folder, discovered exactly
like a core check:

    app/checks/custom/custom_<name>/
        contract.yaml   # identity + I/O contract (name: custom_<name>, suite: custom)
        check.py        # the BaseCheck subclass (no-arg constructible)
        config.yaml     # enabled flag + runtime defaults
        __init__.py     # re-export of the entry class (§3.1)

There is no registry and no manual registration: dropping a well-formed folder
here is enough for ``component_loader.discover_components`` to pick it up, just
like any core suite. Chainsmith's ``scaffold_check`` / ``write_check`` generate
this shape, and ``verify_contracts`` validates it (the same gate the loader, CI,
and ``chainsmith dev verify-contracts`` apply to core checks).

(Superseded the legacy ``CUSTOM_CHECK_REGISTRY`` tuple list + ``_get_custom_checks``
string-editing path, removed in Phase 56.10d.)
"""
