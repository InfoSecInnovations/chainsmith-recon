"""
app/checks/custom/ - Organization-Specific Custom Checks

This directory holds custom checks created by or for the organization.
Community upstream updates never touch this directory.

The registry below is maintained by Chainsmith but can also be
edited manually. Chainsmith validates after the fact — it is not a gatekeeper.

To add a custom check:
1. Create a .py file in this directory with a class extending BaseCheck
2. Add the class to CUSTOM_CHECKS below
3. Run Chainsmith validation to verify the check integrates cleanly
"""

# Registry of custom check classes.
# Each entry: ("module_name", "ClassName")
# Example: ("my_auth_check", "MyAuthCheck")
CUSTOM_CHECK_REGISTRY: list[tuple[str, str]] = []
