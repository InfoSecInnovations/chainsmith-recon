"""
app/cli.py - Chainsmith Recon CLI

Thin HTTP client that talks to the Chainsmith API server.
All business logic lives in the API layer; this file handles only:
  - Click command definitions
  - Terminal formatting (via cli_formatters)
  - Server lifecycle (via cli_server)

Usage:
    chainsmith scan <target> [options]
    chainsmith list-checks [--suite SUITE]
    chainsmith scenarios list
    chainsmith scenarios info <name>
    chainsmith export [--format FORMAT] [--output FILE]
    chainsmith serve [--host HOST] [--port PORT]
"""

import contextlib
import json
import sys
from pathlib import Path

import click

from app.cli_client import ChainsmithAPIError, ChainsmithClient
from app.cli_formatters import (
    SUITE_COLORS,
    observations_to_json,
    observations_to_markdown,
    observations_to_sarif,
    output_observations,
    print_checks_list,
    print_execution_plan,
    print_preferences_dict,
)
from app.cli_server import ServerManager

# ═══════════════════════════════════════════════════════════════════════════════
# CLI Group
# ═══════════════════════════════════════════════════════════════════════════════


@click.group()
@click.version_option(version="1.3.0", prog_name="chainsmith")
@click.option("--server", default="127.0.0.1:8000", help="API server address (host:port)")
@click.option("--profile", help="Activate a scan behavior profile (e.g., aggressive, stealth)")
@click.pass_context
def cli(ctx, server: str, profile: str):
    """Chainsmith Recon - AI Reconnaissance Framework

    A reconnaissance tool for AI/ML systems, designed for penetration testers
    and security researchers.
    """
    ctx.ensure_object(dict)
    ctx.obj["server"] = server
    ctx.obj["profile"] = profile


def _get_client(ctx) -> ChainsmithClient:
    """Get or create a ChainsmithClient, auto-starting server if needed."""
    if "client" in ctx.obj:
        return ctx.obj["client"]

    server = ctx.obj["server"]
    host, _, port = server.partition(":")
    port = int(port) if port else 8000

    mgr = ServerManager()
    base_url = mgr.ensure_server(host, port)
    client = ChainsmithClient(base_url)

    ctx.obj["server_mgr"] = mgr
    ctx.obj["client"] = client
    return client


def _handle_api_error(e: ChainsmithAPIError):
    """Print an API error and exit."""
    click.echo(click.style(f"Error: {e.detail}", fg="red"), err=True)
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Scan Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("target")
@click.option("--exclude", "-e", multiple=True, help="Exclude domains from scope")
@click.option("--checks", "-c", multiple=True, help="Run specific checks (by name)")
@click.option(
    "--suite",
    "-s",
    multiple=True,
    help="Run checks from suite (network, web, ai, mcp, agent, rag, cag)",
)
@click.option("--scenario", help="Load a scenario instead of live scanning")
@click.option("--parallel", is_flag=True, help="Run checks in parallel within phases")
@click.option("--plan", is_flag=True, help="Show execution plan and exit (don't run)")
@click.option("--dry-run", is_flag=True, help="Validate configuration without running checks")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["json", "yaml", "md", "sarif", "text"]),
    default="text",
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode (only observations)")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--no-llm", is_flag=True, help="Disable LLM-based chain analysis")
@click.option(
    "--provider",
    type=click.Choice(["openai", "anthropic", "litellm", "none"]),
    help="LLM provider override",
)
@click.option(
    "--port-profile",
    type=click.Choice(["web", "ai", "full", "lab"]),
    help="Port scan profile (web, ai, full, lab)",
)
@click.option("--engagement", help="Link scan to an engagement ID")
@click.pass_context
def scan(
    ctx,
    target: str,
    exclude: tuple,
    checks: tuple,
    suite: tuple,
    scenario: str,
    parallel: bool,
    plan: bool,
    dry_run: bool,
    output: str,
    fmt: str,
    verbose: bool,
    quiet: bool,
    no_color: bool,
    no_llm: bool,
    provider: str,
    port_profile: str,
    engagement: str,
):
    """Run reconnaissance scan against a target.

    TARGET is the base domain to scan (e.g., example.com, *.example.com).

    Examples:

        chainsmith scan example.com

        chainsmith scan example.com --exclude admin.example.com

        chainsmith scan example.com --suite network --suite web

        chainsmith scan example.com -c dns_enumeration -c header_analysis

        chainsmith scan example.com --scenario fakobanko

        chainsmith scan example.com -o report.json -f json

        chainsmith scan example.com --plan

        chainsmith scan example.com --parallel
    """
    # Validate --profile if specified
    profile_name = ctx.obj.get("profile")
    if profile_name:
        from app.preferences import BUILTIN_PROFILES, load_profile_store

        store = load_profile_store()
        if not (store.profiles.get(profile_name) or BUILTIN_PROFILES.get(profile_name)):
            click.echo(click.style(f"Unknown profile: {profile_name}", fg="red"), err=True)
            click.echo("Available profiles: default, aggressive, stealth")
            sys.exit(1)

    # Configure LLM env before starting server
    if no_llm or provider == "none":
        import os

        os.environ["CHAINSMITH_LLM_PROVIDER"] = "none"
    elif provider:
        import os

        os.environ["CHAINSMITH_LLM_PROVIDER"] = provider

    def style(text, **kwargs):
        if no_color:
            return text
        return click.style(text, **kwargs)

    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    # Collect check/suite filters for start_scan
    scan_checks = list(checks) if checks else None
    scan_suites = list(suite) if suite else None

    try:
        # 0. Activate scan behavior profile if specified
        if profile_name:
            try:
                client.activate_profile(profile_name)
                if not quiet:
                    click.echo(f"Profile: {profile_name}")
            except ChainsmithAPIError:
                # Profile may not exist on server yet (e.g., first run)
                pass

        # 1. Set scope
        client.set_scope(target, list(exclude))

        # 2. Update settings
        client.update_settings(parallel=parallel)

        # 3. Load scenario if requested
        if scenario:
            if not quiet:
                click.echo(f"Loading scenario: {scenario}")
            try:
                resp = client.load_scenario(scenario)
                sim_count = resp.get("simulation_count", 0)
                if not quiet:
                    click.echo(f"  Loaded {sim_count} simulated checks")
                    click.echo()
            except ChainsmithAPIError as e:
                click.echo(style(f"Error loading scenario: {e.detail}", fg="red"), err=True)
                sys.exit(1)

        # Header
        if not quiet:
            click.echo(style("Chainsmith Recon v1.3.0", fg="cyan", bold=True))
            click.echo(f"Target: {target}")
            if exclude:
                click.echo(f"Excluding: {', '.join(exclude)}")
            if dry_run:
                click.echo(style("Mode: DRY RUN (no checks will execute)", fg="yellow"))
            click.echo()

        # 4. Show plan or dry-run and exit
        if plan:
            resp = client.get_scan_checks()
            print_execution_plan(resp.get("checks", []))
            return

        if dry_run:
            resp = client.get_scan_checks()
            check_list = resp.get("checks", [])
            suites_found = sorted({c.get("suite", "other") for c in check_list})
            click.echo(style("Configuration valid.", fg="green"))
            click.echo(f"  Target: {target}")
            click.echo(f"  Checks: {len(check_list)}")
            click.echo(f"  Suites: {', '.join(suites_found)}")
            if output:
                click.echo(f"  Output: {output} ({fmt})")
            return

        # 5. Start scan with optional check/suite filters
        client.start_scan(
            checks=scan_checks,
            suites=scan_suites,
            engagement_id=engagement if engagement else None,
            port_profile=port_profile if port_profile else None,
        )

        # 6. Poll until complete
        last_check = None

        def progress_callback(status: dict):
            nonlocal last_check
            if quiet:
                return
            current = status.get("current_check")
            if current and current != last_check:
                last_check = current
                if verbose:
                    click.echo(f"  Running: {current}")
            completed = status.get("checks_completed", 0)
            total = status.get("checks_total", 0)
            if total and verbose:
                click.echo(f"\r  Progress: {completed}/{total}", nl=False)

        result = client.poll_scan(interval=1.0, callback=progress_callback)

        if verbose and not quiet:
            click.echo()  # newline after progress

        if result.get("status") == "error":
            click.echo(style(f"Scan error: {result.get('error', 'unknown')}", fg="red"), err=True)
            sys.exit(1)

        # 7. Get observations
        observations_resp = client.get_observations()
        observations = observations_resp.get("observations", [])

        # Summary
        if not quiet:
            click.echo()
            click.echo(style(f"Scan complete: {len(observations)} observations", fg="green", bold=True))
            click.echo()

        # 8. Output
        output_observations(observations, target, fmt, output, verbose, quiet, no_color)

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# List Checks Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command("list-checks")
@click.option("--suite", "-s", help="Filter by suite (network, web, ai, mcp, agent, rag, cag)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed info")
@click.option("--deps", is_flag=True, help="Show dependencies")
@click.pass_context
def list_checks(ctx, suite: str | None, as_json: bool, verbose: bool, deps: bool):
    """List available checks.

    Examples:

        chainsmith list-checks

        chainsmith list-checks --suite ai

        chainsmith list-checks --suite mcp --verbose

        chainsmith list-checks --deps

        chainsmith list-checks --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.get_checks()
        all_checks = resp.get("checks", [])

        if suite:
            all_checks = [c for c in all_checks if c.get("suite") == suite]
            if not all_checks:
                # Check if suite name is valid by looking at what suites exist
                click.echo(click.style(f"Unknown suite: {suite}", fg="red"), err=True)
                all_suites = sorted({c.get("suite", "other") for c in resp.get("checks", [])})
                click.echo(f"Available suites: {', '.join(all_suites)}")
                sys.exit(1)
            suites_to_show = [suite]
        else:
            suites_to_show = []
            for c in all_checks:
                s = c.get("suite", "other")
                if s not in suites_to_show:
                    suites_to_show.append(s)

        if as_json:
            click.echo(json.dumps(all_checks, indent=2))
            return

        print_checks_list(all_checks, suites_to_show, verbose=verbose, deps=deps)

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Suites Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command("suites")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def list_suites(ctx, as_json: bool):
    """List available check suites.

    Examples:

        chainsmith suites

        chainsmith suites --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.get_checks()
        all_checks = resp.get("checks", [])

        # Group checks by suite
        suites_map: dict[str, list[str]] = {}
        suite_order = []
        for c in all_checks:
            s = c.get("suite", "other")
            if s not in suites_map:
                suites_map[s] = []
                suite_order.append(s)
            suites_map[s].append(c.get("name", ""))

        suite_data = []
        for s in suite_order:
            suite_data.append(
                {
                    "name": s,
                    "checks": len(suites_map[s]),
                    "check_names": suites_map[s],
                }
            )

        if as_json:
            click.echo(json.dumps(suite_data, indent=2))
            return

        click.echo(click.style("\nCheck Suites", fg="cyan", bold=True))
        click.echo(f"Execution order: {' → '.join(suite_order)}\n")

        for s in suite_data:
            color = SUITE_COLORS.get(s["name"], "white")
            click.echo(
                click.style(f"{s['name']}", fg=color, bold=True) + f" ({s['checks']} checks)"
            )

            if s["check_names"]:
                names = ", ".join(s["check_names"][:4])
                if len(s["check_names"]) > 4:
                    names += f", ... (+{len(s['check_names']) - 4} more)"
                click.echo(click.style(f"  Checks: {names}", fg="white"))

            click.echo()

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Scenarios Commands
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group()
def scenarios():
    """Manage scenarios for simulated scans."""
    pass


@scenarios.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def scenarios_list(ctx, as_json: bool):
    """List available scenarios.

    Examples:

        chainsmith scenarios list

        chainsmith scenarios list --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.list_scenarios()
        available = resp.get("scenarios", [])

        if as_json:
            click.echo(json.dumps(available, indent=2))
            return

        if not available:
            click.echo("No scenarios found.")
            click.echo()
            click.echo("Scenarios are loaded from:")
            click.echo("  - $CHAINSMITH_SCENARIOS_DIR")
            click.echo("  - ~/.chainsmith/scenarios/")
            click.echo("  - ./scenarios/")
            return

        click.echo(click.style("Available Scenarios", fg="cyan", bold=True))
        click.echo()

        for s in available:
            click.echo(f"  {click.style(s['name'], bold=True)}")
            if s.get("description"):
                click.echo(f"    {s['description']}")
            click.echo(
                f"    Version: {s.get('version', 'unknown')} | "
                f"Simulations: {s.get('simulation_count', 0)}"
            )
            click.echo()

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@scenarios.command("info")
@click.argument("name")
@click.pass_context
def scenarios_info(ctx, name: str):
    """Show details about a scenario.

    Examples:

        chainsmith scenarios info fakobanko
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        # Load to get full info, then clear
        resp = client.load_scenario(name)
        scenario = resp.get("scenario", {})

        click.echo(click.style(scenario.get("name", name), fg="cyan", bold=True))
        click.echo()

        if scenario.get("description"):
            click.echo(f"Description: {scenario['description']}")
        click.echo(f"Version: {scenario.get('version', 'unknown')}")

        target = scenario.get("target", {})
        if target:
            click.echo()
            click.echo("Target:")
            if target.get("pattern"):
                click.echo(f"  Pattern: {target['pattern']}")
            if target.get("known_hosts"):
                click.echo(f"  Known hosts: {', '.join(target['known_hosts'])}")
            if target.get("ports"):
                click.echo(f"  Ports: {', '.join(map(str, target['ports']))}")

        sim_count = resp.get("simulation_count", 0)
        click.echo()
        click.echo(f"Simulations: {sim_count}")

        simulations = scenario.get("simulations", [])
        for sim in simulations[:10]:
            label = sim if isinstance(sim, str) else str(sim)
            click.echo(f"  - {label}")
        if len(simulations) > 10:
            click.echo(f"  ... and {len(simulations) - 10} more")

        expected = scenario.get("expected_observations", [])
        if expected:
            click.echo()
            click.echo(f"Expected observations: {len(expected)}")

        # Clear the loaded scenario
        client.clear_scenario()

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Export Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["json", "md", "sarif"]),
    default="json",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--input", "-i", "input_file", type=click.Path(exists=True), help="Input JSON observations file"
)
def export(fmt: str, output: str | None, input_file: str | None):
    """Export observations to various formats.

    Reads observations from stdin (JSON) or a file, and exports to the specified format.

    Examples:

        chainsmith scan example.com -f json | chainsmith export -f md -o report.md

        chainsmith export -i observations.json -f sarif -o observations.sarif
    """
    # Read input
    if input_file:
        data = json.loads(Path(input_file).read_text())
    else:
        if sys.stdin.isatty():
            click.echo("Reading observations from stdin (paste JSON, then Ctrl+D)...")
        data = json.loads(sys.stdin.read())

    # data is already a list of dicts
    observations = data if isinstance(data, list) else data.get("observations", data)
    target = observations[0].get("target_url", "unknown") if observations else "unknown"

    # Format output
    if fmt == "json":
        result = observations_to_json(observations)
    elif fmt == "md":
        result = observations_to_markdown(observations, target)
    elif fmt == "sarif":
        result = observations_to_sarif(observations, target)

    # Write output
    if output:
        Path(output).write_text(result)
        click.echo(f"Written to {output}")
    else:
        click.echo(result)


# ═══════════════════════════════════════════════════════════════════════════════
# Preferences Commands
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group()
def prefs():
    """Manage user preferences.

    Examples:

        chainsmith prefs show

        chainsmith prefs show --advanced

        chainsmith prefs set network.timeout_seconds 60

        chainsmith prefs reset network.timeout_seconds

        chainsmith prefs reset --all
    """
    pass


@prefs.command("show")
@click.option("--advanced", is_flag=True, help="Show advanced preferences")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.argument("key", required=False)
@click.pass_context
def prefs_show(ctx, advanced: bool, as_json: bool, key: str | None):
    """Show current preferences.

    If KEY is provided, show only that preference.

    Examples:

        chainsmith prefs show

        chainsmith prefs show network.timeout_seconds

        chainsmith prefs show --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.get_preferences()
        prefs_data = resp.get("preferences", {})

        if key:
            # Navigate dotted key
            parts = key.split(".")
            value = prefs_data
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    click.echo(click.style(f"Unknown preference: {key}", fg="red"), err=True)
                    sys.exit(1)

            if as_json:
                click.echo(json.dumps({key: value}, indent=2))
            else:
                click.echo(f"{key} = {value}")
        else:
            if as_json:
                click.echo(json.dumps(prefs_data, indent=2))
            else:
                sections = prefs_data
                if not advanced and "advanced" in sections:
                    sections = {k: v for k, v in sections.items() if k != "advanced"}

                for section, values in sections.items():
                    click.echo(click.style(f"\n[{section}]", fg="cyan", bold=True))

                    if isinstance(values, dict):
                        for k, v in values.items():
                            if v is None:
                                val_str = click.style("null", fg="yellow")
                            elif isinstance(v, bool):
                                val_str = click.style(str(v).lower(), fg="green" if v else "red")
                            else:
                                val_str = str(v)
                            click.echo(f"  {k} = {val_str}")
                    else:
                        click.echo(f"  {values}")

                if not advanced:
                    click.echo(click.style("\n  (use --advanced to show more)", dim=True))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs.command("set")
@click.argument("key")
@click.argument("value")
@click.pass_context
def prefs_set(ctx, key: str, value: str):
    """Set a preference value.

    Examples:

        chainsmith prefs set network.timeout_seconds 60

        chainsmith prefs set network.verify_ssl true

        chainsmith prefs set network.proxy http://127.0.0.1:8080
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        # Parse key into nested dict for the API
        parts = key.split(".")
        if len(parts) < 2:
            click.echo(
                click.style(
                    "Key must be in section.name format (e.g. network.timeout_seconds)",
                    fg="red",
                ),
                err=True,
            )
            sys.exit(1)

        # Auto-convert value types
        parsed_value: object = value
        if value.lower() == "true":
            parsed_value = True
        elif value.lower() == "false":
            parsed_value = False
        elif value.lower() == "null" or value.lower() == "none":
            parsed_value = None
        else:
            try:
                parsed_value = int(value)
            except ValueError:
                with contextlib.suppress(ValueError):
                    parsed_value = float(value)

        # Build nested update dict
        section = parts[0]
        field = ".".join(parts[1:])
        updates = {section: {field: parsed_value}}

        client.update_preferences(updates)
        click.echo(f"Set {key} = {value}")

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs.command("reset")
@click.argument("key", required=False)
@click.option("--all", "reset_all", is_flag=True, help="Reset all preferences to defaults")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation for --all")
@click.pass_context
def prefs_reset(ctx, key: str | None, reset_all: bool, yes: bool):
    """Reset preference(s) to default value.

    Examples:

        chainsmith prefs reset network.timeout_seconds

        chainsmith prefs reset --all

        chainsmith prefs reset --all --yes
    """
    if not reset_all and not key:
        click.echo("Specify a KEY to reset, or use --all to reset everything.", err=True)
        sys.exit(1)

    if reset_all and not yes and not click.confirm("Reset all preferences to defaults?"):
        click.echo("Cancelled.")
        return

    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        if reset_all:
            # Reset by activating default profile and resetting it
            client.reset_profile("default")
            client.activate_profile("default")
            click.echo("All preferences reset to defaults.")
        else:
            # Reset individual key by setting to None (API interprets as default)
            parts = key.split(".")
            if len(parts) >= 2:
                updates = {parts[0]: {".".join(parts[1:]): None}}
                client.update_preferences(updates)
            click.echo(f"Reset {key} to default.")

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs.command("path")
def prefs_path():
    """Show path to preferences file."""
    from app.preferences import _default_preferences_path

    path = _default_preferences_path()
    click.echo(path)

    if path.exists():
        click.echo(click.style("  (file exists)", fg="green"))
    else:
        click.echo(click.style("  (file does not exist yet)", dim=True))


# ═══════════════════════════════════════════════════════════════════════════════
# Profile Subcommands
# ═══════════════════════════════════════════════════════════════════════════════


@prefs.group("profile")
def prefs_profile():
    """Manage scan profiles.

    Profiles are named sets of preferences that can be quickly switched.
    Built-in profiles: default, aggressive, stealth

    Examples:

        chainsmith prefs profile list

        chainsmith prefs profile show aggressive

        chainsmith prefs profile create my-profile --base aggressive

        chainsmith prefs profile activate stealth
    """
    pass


@prefs_profile.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def profile_list(ctx, as_json: bool):
    """List all available profiles.

    Examples:

        chainsmith prefs profile list

        chainsmith prefs profile list --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.list_profiles()
        profiles = resp.get("profiles", [])

        if as_json:
            click.echo(json.dumps(profiles, indent=2))
            return

        click.echo(click.style("Profiles:", fg="cyan", bold=True))
        click.echo()

        for p in profiles:
            indicators = []
            if p.get("active"):
                indicators.append(click.style("active", fg="green", bold=True))
            if p.get("built_in"):
                indicators.append(click.style("built-in", dim=True))

            status = f" ({', '.join(indicators)})" if indicators else ""
            name = click.style(p["name"], bold=bool(p.get("active")))

            click.echo(f"  {name}{status}")
            if p.get("description"):
                click.echo(click.style(f"    {p['description']}", dim=True))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs_profile.command("show")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--resolved", is_flag=True, help="Show fully resolved preferences")
@click.pass_context
def profile_show(ctx, name: str, as_json: bool, resolved: bool):
    """Show details of a specific profile.

    Examples:

        chainsmith prefs profile show aggressive

        chainsmith prefs profile show stealth --resolved

        chainsmith prefs profile show my-profile --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.get_profile(name)
        profile = resp.get("profile", {})
        resolved_prefs = resp.get("resolved_preferences", {})

        if as_json:
            data = profile.copy()
            if resolved:
                data["resolved_preferences"] = resolved_prefs
            click.echo(json.dumps(data, indent=2))
            return

        # Header
        status = []
        if profile.get("active"):
            status.append(click.style("active", fg="green", bold=True))
        if profile.get("built_in"):
            status.append(click.style("built-in", dim=True))

        status_str = f" ({', '.join(status)})" if status else ""
        click.echo(click.style(f"Profile: {name}", fg="cyan", bold=True) + status_str)

        if profile.get("description"):
            click.echo(f"  {profile['description']}")
        click.echo()

        if resolved:
            click.echo(click.style("Resolved Preferences:", bold=True))
            print_preferences_dict(resolved_prefs)
        else:
            overrides = profile.get("overrides", {})
            if overrides:
                click.echo(click.style("Overrides:", bold=True))
                print_preferences_dict(overrides)
            else:
                click.echo(click.style("  (no overrides - uses defaults)", dim=True))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs_profile.command("create")
@click.argument("name")
@click.option("--base", "-b", default="default", help="Base profile to inherit from")
@click.option("--description", "-d", default="", help="Profile description")
@click.pass_context
def profile_create(ctx, name: str, base: str, description: str):
    """Create a new profile.

    Examples:

        chainsmith prefs profile create my-profile

        chainsmith prefs profile create fast-scan --base aggressive

        chainsmith prefs profile create quiet --base stealth -d "Extra quiet scanning"
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        client.create_profile(name, description=description, base=base)
        click.echo(click.style(f"Created profile '{name}'", fg="green"))
        if base != "default":
            click.echo(f"  Based on: {base}")
        if description:
            click.echo(f"  Description: {description}")
        click.echo()
        click.echo(f"Activate with: chainsmith prefs profile activate {name}")

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs_profile.command("activate")
@click.argument("name")
@click.pass_context
def profile_activate(ctx, name: str):
    """Set a profile as active.

    Examples:

        chainsmith prefs profile activate aggressive

        chainsmith prefs profile activate my-custom-profile
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.activate_profile(name)
        click.echo(click.style(f"Activated profile '{name}'", fg="green"))

        prefs_data = resp.get("preferences", {})
        network = prefs_data.get("network", {})
        rate = prefs_data.get("rate_limiting", {})
        advanced = prefs_data.get("advanced", {})

        click.echo()
        click.echo("Key settings:")
        click.echo(f"  Timeout: {network.get('timeout_seconds', '?')}s")
        click.echo(f"  Rate limit: {rate.get('requests_per_second', '?')} req/s")
        click.echo(f"  Concurrent requests: {network.get('max_concurrent_requests', '?')}")
        if advanced.get("waf_evasion"):
            click.echo(click.style("  WAF evasion: enabled", fg="yellow"))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs_profile.command("delete")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def profile_delete(ctx, name: str, yes: bool):
    """Delete a profile.

    Built-in profiles are reset instead of deleted.
    The active profile cannot be deleted.

    Examples:

        chainsmith prefs profile delete my-profile

        chainsmith prefs profile delete old-profile --yes
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        # Check profile exists and get info first
        resp = client.get_profile(name)
        profile = resp.get("profile", {})

        # Check if active
        prefs_resp = client.get_preferences()
        active_name = prefs_resp.get("active_profile", "default")
        if name == active_name:
            click.echo(
                click.style(
                    "Cannot delete active profile. Switch to another profile first.",
                    fg="red",
                ),
                err=True,
            )
            sys.exit(1)

        # Confirm
        if profile.get("built_in"):
            msg = f"Reset built-in profile '{name}' to defaults?"
        else:
            msg = f"Delete profile '{name}'?"

        if not yes and not click.confirm(msg):
            click.echo("Cancelled.")
            return

        resp = client.delete_profile(name)

        if resp.get("reset"):
            click.echo(click.style(f"Reset profile '{name}' to defaults", fg="green"))
        else:
            click.echo(click.style(f"Deleted profile '{name}'", fg="green"))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs_profile.command("reset")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def profile_reset(ctx, name: str, yes: bool):
    """Reset a profile to its default state.

    Examples:

        chainsmith prefs profile reset aggressive

        chainsmith prefs profile reset my-profile --yes
    """
    if not yes and not click.confirm(f"Reset profile '{name}'?"):
        click.echo("Cancelled.")
        return

    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        client.reset_profile(name)
        click.echo(click.style(f"Reset profile '{name}'", fg="green"))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@prefs_profile.command("copy")
@click.argument("source")
@click.argument("dest")
@click.option("--description", "-d", default="", help="Description for new profile")
@click.pass_context
def profile_copy(ctx, source: str, dest: str, description: str):
    """Copy a profile to a new name.

    Examples:

        chainsmith prefs profile copy aggressive my-aggressive

        chainsmith prefs profile copy stealth extra-quiet -d "Very slow scanning"
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        # Verify source exists
        client.get_profile(source)

        desc = description or f"Copy of {source}"
        client.create_profile(dest, description=desc, base=source)
        click.echo(click.style(f"Created profile '{dest}' (copy of '{source}')", fg="green"))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Scan History Commands
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group("scans")
def scans_group():
    """Browse and manage scan history."""
    pass


@scans_group.command("list")
@click.option("--target", "-t", help="Filter by target domain")
@click.option("--limit", "-n", default=20, help="Max results")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def scans_list(ctx, target: str | None, limit: int, as_json: bool):
    """List historical scans.

    Examples:

        chainsmith scans list

        chainsmith scans list --target example.com

        chainsmith scans list --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.list_scans(target=target, limit=limit)
        scans = resp.get("scans", [])

        if as_json:
            click.echo(json.dumps(resp, indent=2))
            return

        if not scans:
            click.echo("No scans found.")
            return

        click.echo(
            click.style(f"Scan History ({resp.get('total', 0)} total)", fg="cyan", bold=True)
        )
        click.echo()

        for s in scans:
            status_color = {"complete": "green", "error": "red", "running": "yellow"}.get(
                s["status"], "white"
            )
            click.echo(
                f"  {click.style(s['id'], bold=True)}  "
                f"{s['target_domain']}  "
                f"{click.style(s['status'], fg=status_color)}  "
                f"observations: {s.get('observations_count', 0)}  "
                f"{s.get('started_at', '')[:19]}"
            )

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@scans_group.command("show")
@click.argument("scan_id")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def scans_show(ctx, scan_id: str, as_json: bool):
    """Show details of a historical scan.

    Examples:

        chainsmith scans show abc123
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        scan = client.get_scan_detail(scan_id)

        if as_json:
            click.echo(json.dumps(scan, indent=2))
            return

        click.echo(click.style(f"Scan {scan['id']}", fg="cyan", bold=True))
        click.echo(f"  Target:   {scan['target_domain']}")
        click.echo(f"  Status:   {scan['status']}")
        click.echo(f"  Started:  {scan.get('started_at', 'N/A')}")
        click.echo(f"  Duration: {scan.get('duration_ms', 'N/A')}ms")
        click.echo(f"  Observations: {scan.get('observations_count', 0)}")
        click.echo(f"  Checks:   {scan.get('checks_completed', 0)}/{scan.get('checks_total', 0)}")
        if scan.get("engagement_id"):
            click.echo(f"  Engagement: {scan['engagement_id']}")
        if scan.get("error_message"):
            click.echo(click.style(f"  Error: {scan['error_message']}", fg="red"))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@scans_group.command("compare")
@click.argument("scan_a")
@click.argument("scan_b")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def scans_compare(ctx, scan_a: str, scan_b: str, as_json: bool):
    """Compare two scans.

    Examples:

        chainsmith scans compare abc123 def456
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.compare_scans(scan_a, scan_b)

        if as_json:
            click.echo(json.dumps(result, indent=2))
            return

        click.echo(click.style("Scan Comparison", fg="cyan", bold=True))
        click.echo(f"  A: {scan_a}")
        click.echo(f"  B: {scan_b}")
        click.echo()
        click.echo(
            f"  {click.style(str(result.get('new_count', 0)), fg='green')} new observations in B"
        )
        click.echo(
            f"  {click.style(str(result.get('resolved_count', 0)), fg='blue')} resolved (in A, not B)"
        )
        click.echo(f"  {result.get('recurring_count', 0)} recurring")

        new_observations = result.get("new_observations", [])
        if new_observations:
            click.echo()
            click.echo(click.style("New observations:", bold=True))
            for f in new_observations[:10]:
                click.echo(f"    [{f.get('severity', '?')}] {f.get('title', 'Untitled')}")

        resolved = result.get("resolved_observations", [])
        if resolved:
            click.echo()
            click.echo(click.style("Resolved observations:", bold=True))
            for f in resolved[:10]:
                click.echo(f"    [{f.get('severity', '?')}] {f.get('title', 'Untitled')}")

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@scans_group.command("delete")
@click.argument("scan_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def scans_delete(ctx, scan_id: str, yes: bool):
    """Delete a historical scan and its data.

    Examples:

        chainsmith scans delete abc123 --yes
    """
    if not yes and not click.confirm(f"Delete scan '{scan_id}' and all its data?"):
        click.echo("Cancelled.")
        return

    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        client.delete_scan_by_id(scan_id)
        click.echo(click.style(f"Deleted scan '{scan_id}'", fg="green"))
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@scans_group.command("trend")
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def scans_trend(ctx, target: str, as_json: bool):
    """Show trend data for a target domain across all scans.

    Examples:

        chainsmith scans trend --target example.com

        chainsmith scans trend -t example.com --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.get_target_trend(target)

        if as_json:
            click.echo(json.dumps(resp, indent=2))
            return

        data_points = resp.get("data_points", [])
        if not data_points:
            click.echo(f"No completed scans found for {target}.")
            return

        click.echo(click.style(f"Trend: {target} ({len(data_points)} scans)", fg="cyan", bold=True))
        click.echo()

        for dp in data_points:
            risk_color = (
                "red"
                if dp.get("risk_score", 0) > 50
                else "yellow"
                if dp.get("risk_score", 0) > 20
                else "green"
            )
            click.echo(
                f"  {dp.get('date', '')[:10]}  "
                f"scan {dp['scan_id'][:8]}  "
                f"observations: {dp.get('total', 0)}  "
                f"risk: {click.style(str(dp.get('risk_score', 0)), fg=risk_color)}  "
                f"+{dp.get('new', 0)} new  "
                f"-{dp.get('resolved', 0)} resolved"
            )

        avgs = resp.get("averages", {}).get("this_target", {})
        if avgs:
            click.echo()
            click.echo(click.style("  Averages:", bold=True))
            click.echo(
                f"    observations: {avgs.get('total', 0)}  "
                f"risk: {avgs.get('risk_score', 0)}  "
                f"C:{avgs.get('critical', 0)} H:{avgs.get('high', 0)} "
                f"M:{avgs.get('medium', 0)} L:{avgs.get('low', 0)}"
            )

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Engagement Commands
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group("engagements")
def engagements_group():
    """Manage engagements (groups of related scans)."""
    pass


@engagements_group.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def engagements_list(ctx, as_json: bool):
    """List engagements.

    Examples:

        chainsmith engagements list
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.list_engagements()
        engagements = resp.get("engagements", [])

        if as_json:
            click.echo(json.dumps(resp, indent=2))
            return

        if not engagements:
            click.echo("No engagements found.")
            click.echo(
                "Create one with: chainsmith engagements create --name 'My Pentest' --target example.com"
            )
            return

        click.echo(click.style(f"Engagements ({resp.get('total', 0)})", fg="cyan", bold=True))
        click.echo()

        for e in engagements:
            status_color = {"active": "green", "completed": "blue", "archived": "white"}.get(
                e["status"], "white"
            )
            click.echo(
                f"  {click.style(e['id'], bold=True)}  "
                f"{e['name']}  "
                f"{e['target_domain']}  "
                f"{click.style(e['status'], fg=status_color)}"
            )
            if e.get("description"):
                click.echo(click.style(f"    {e['description']}", dim=True))

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@engagements_group.command("create")
@click.option("--name", "-n", required=True, help="Engagement name")
@click.option("--target", "-t", required=True, help="Target domain")
@click.option("--description", "-d", default=None, help="Description")
@click.option("--client", "-c", default=None, help="Client/organization name")
@click.pass_context
def engagements_create(ctx, name: str, target: str, description: str, client: str):
    """Create a new engagement.

    Examples:

        chainsmith engagements create --name "Q1 Pentest" --target example.com

        chainsmith engagements create -n "API Audit" -t api.example.com -d "Quarterly API review" -c "Acme Corp"
    """
    try:
        client_obj = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        eng = client_obj.create_engagement(
            name=name,
            target_domain=target,
            description=description,
            client_name=client,
        )
        click.echo(click.style(f"Created engagement: {eng['id']}", fg="green"))
        click.echo(f"  Name:   {eng['name']}")
        click.echo(f"  Target: {eng['target_domain']}")
        click.echo()
        click.echo("Run a scan in this engagement:")
        click.echo(f"  chainsmith scan {target} --engagement {eng['id']}")

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@engagements_group.command("show")
@click.argument("engagement_id")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def engagements_show(ctx, engagement_id: str, as_json: bool):
    """Show engagement details and its scans.

    Examples:

        chainsmith engagements show abc123
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        eng = client.get_engagement(engagement_id)
        scans_resp = client.get_engagement_scans(engagement_id)

        if as_json:
            eng["scans"] = scans_resp.get("scans", [])
            click.echo(json.dumps(eng, indent=2))
            return

        click.echo(click.style(f"Engagement: {eng['name']}", fg="cyan", bold=True))
        click.echo(f"  ID:     {eng['id']}")
        click.echo(f"  Target: {eng['target_domain']}")
        click.echo(f"  Status: {eng['status']}")
        if eng.get("client_name"):
            click.echo(f"  Client: {eng['client_name']}")
        if eng.get("description"):
            click.echo(f"  Description: {eng['description']}")

        scans = scans_resp.get("scans", [])
        click.echo()
        click.echo(f"  Scans: {len(scans)}")
        for s in scans[:10]:
            click.echo(
                f"    {s['id']}  {s['status']}  "
                f"observations: {s.get('observations_count', 0)}  "
                f"{s.get('started_at', '')[:19]}"
            )

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@engagements_group.command("delete")
@click.argument("engagement_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def engagements_delete(ctx, engagement_id: str, yes: bool):
    """Delete an engagement (scans are kept but unlinked).

    Examples:

        chainsmith engagements delete abc123 --yes
    """
    if not yes and not click.confirm(
        f"Delete engagement '{engagement_id}'? (Scans will be unlinked, not deleted)"
    ):
        click.echo("Cancelled.")
        return

    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        client.delete_engagement(engagement_id)
        click.echo(click.style(f"Deleted engagement '{engagement_id}'", fg="green"))
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@engagements_group.command("trend")
@click.argument("engagement_id")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def engagements_trend(ctx, engagement_id: str, as_json: bool):
    """Show trend data for an engagement.

    Examples:

        chainsmith engagements trend abc123

        chainsmith engagements trend abc123 --json
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.get_engagement_trend(engagement_id)

        if as_json:
            click.echo(json.dumps(resp, indent=2))
            return

        data_points = resp.get("data_points", [])
        if not data_points:
            click.echo(f"No completed scans found for engagement '{engagement_id}'.")
            return

        click.echo(
            click.style(f"Engagement Trend ({len(data_points)} scans)", fg="cyan", bold=True)
        )
        click.echo()

        for dp in data_points:
            risk_color = (
                "red"
                if dp.get("risk_score", 0) > 50
                else "yellow"
                if dp.get("risk_score", 0) > 20
                else "green"
            )
            click.echo(
                f"  {dp.get('date', '')[:10]}  "
                f"scan {dp['scan_id'][:8]}  "
                f"{dp.get('target_domain', '')}  "
                f"observations: {dp.get('total', 0)}  "
                f"risk: {click.style(str(dp.get('risk_score', 0)), fg=risk_color)}  "
                f"+{dp.get('new', 0)} new  "
                f"-{dp.get('resolved', 0)} resolved"
            )

        avgs = resp.get("averages", {}).get("this_target", {})
        if avgs:
            click.echo()
            click.echo(click.style("  Averages:", bold=True))
            click.echo(
                f"    observations: {avgs.get('total', 0)}  "
                f"risk: {avgs.get('risk_score', 0)}  "
                f"C:{avgs.get('critical', 0)} H:{avgs.get('high', 0)} "
                f"M:{avgs.get('medium', 0)} L:{avgs.get('low', 0)}"
            )

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Observation Override Commands
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group("observations")
def observations_group():
    """Manage observation overrides (accept, false-positive, reopen)."""
    pass


@observations_group.command("accept")
@click.argument("fingerprint")
@click.option("--reason", "-r", default=None, help="Reason for accepting the risk")
@click.pass_context
def observations_accept(ctx, fingerprint: str, reason: str):
    """Mark an observation as accepted risk.

    Examples:

        chainsmith observations accept abc123def456 --reason "Accepted per CISO"
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.set_observation_override(fingerprint, "accepted", reason=reason)
        click.echo(click.style(f"Observation {fingerprint} marked as accepted", fg="green"))
        if result.get("reason"):
            click.echo(f"  Reason: {result['reason']}")
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@observations_group.command("false-positive")
@click.argument("fingerprint")
@click.option("--reason", "-r", default=None, help="Reason for marking as false positive")
@click.pass_context
def observations_false_positive(ctx, fingerprint: str, reason: str):
    """Mark an observation as a false positive.

    Examples:

        chainsmith observations false-positive abc123def456 --reason "Test endpoint only"
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.set_observation_override(fingerprint, "false_positive", reason=reason)
        click.echo(click.style(f"Observation {fingerprint} marked as false positive", fg="green"))
        if result.get("reason"):
            click.echo(f"  Reason: {result['reason']}")
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@observations_group.command("reopen")
@click.argument("fingerprint")
@click.pass_context
def observations_reopen(ctx, fingerprint: str):
    """Reopen an observation by removing its override.

    Examples:

        chainsmith observations reopen abc123def456
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        client.remove_observation_override(fingerprint)
        click.echo(click.style(f"Observation {fingerprint} reopened", fg="green"))
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@observations_group.command("overrides")
@click.option(
    "--status",
    "-s",
    type=click.Choice(["accepted", "false_positive"]),
    default=None,
    help="Filter by override status",
)
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.pass_context
def observations_overrides(ctx, status: str, as_json: bool):
    """List all observation overrides.

    Examples:

        chainsmith observations overrides

        chainsmith observations overrides --status accepted
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        resp = client.list_observation_overrides(status=status)
        overrides = resp.get("overrides", [])

        if as_json:
            click.echo(json.dumps(resp, indent=2))
            return

        if not overrides:
            click.echo("No overrides found.")
            return

        click.echo(
            click.style(f"Observation Overrides ({resp.get('total', 0)} total)", fg="cyan", bold=True)
        )
        click.echo()

        for o in overrides:
            status_color = {"accepted": "yellow", "false_positive": "magenta"}.get(
                o["status"], "white"
            )
            click.echo(
                f"  {click.style(o['fingerprint'], bold=True)}  "
                f"{click.style(o['status'], fg=status_color)}  "
                f"{o.get('reason') or '(no reason)'}  "
                f"{o.get('updated_at', '')[:19]}"
            )

    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Report Commands
# ═══════════════════════════════════════════════════════════════════════════════


def _write_report(result: dict, fmt: str, output: str | None):
    """Write report output to file or terminal. Handles binary PDF content."""
    content = result.get("content", "")
    if fmt == "pdf":
        if not output:
            output = result.get("filename", "report.pdf")
        Path(output).write_bytes(content)
        click.echo(click.style(f"PDF report written to {output}", fg="green"))
    elif output:
        Path(output).write_text(content)
        click.echo(click.style(f"Report written to {output}", fg="green"))
    else:
        click.echo(content)


@cli.group("report")
def report_group():
    """Generate reports from historical scan data."""
    pass


@report_group.command("technical")
@click.option("--scan", "scan_id", required=True, help="Scan ID to report on")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["md", "json", "html", "pdf", "sarif"]),
    default="md",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def report_technical(ctx, scan_id: str, fmt: str, output: str | None):
    """Generate a technical report for a scan.

    Examples:

        chainsmith report technical --scan abc123

        chainsmith report technical --scan abc123 -f pdf -o report.pdf
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.generate_technical_report(scan_id, fmt)
        _write_report(result, fmt, output)
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@report_group.command("delta")
@click.option("--scan-a", required=True, help="Baseline scan ID")
@click.option("--scan-b", required=True, help="Comparison scan ID")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["md", "json", "html", "pdf", "sarif"]),
    default="md",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def report_delta(ctx, scan_a: str, scan_b: str, fmt: str, output: str | None):
    """Generate a delta (comparison) report between two scans.

    Examples:

        chainsmith report delta --scan-a abc123 --scan-b def456

        chainsmith report delta --scan-a abc123 --scan-b def456 -f pdf -o delta.pdf
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.generate_delta_report(scan_a, scan_b, fmt)
        _write_report(result, fmt, output)

    except ChainsmithAPIError as e:
        _handle_api_error(e)


@report_group.command("executive")
@click.option("--scan", "scan_id", required=True, help="Scan ID to report on")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["md", "json", "html", "pdf", "sarif"]),
    default="md",
    help="Output format",
)
@click.option("--engagement", "engagement_id", default=None, help="Engagement ID for context")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def report_executive(ctx, scan_id: str, fmt: str, engagement_id: str | None, output: str | None):
    """Generate an executive summary report for a scan.

    Examples:

        chainsmith report executive --scan abc123

        chainsmith report executive --scan abc123 -f pdf -o report.pdf
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.generate_executive_report(scan_id, fmt, engagement_id)
        _write_report(result, fmt, output)
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@report_group.command("compliance")
@click.option("--scan", "scan_id", required=True, help="Scan ID to report on")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["md", "json", "html", "pdf", "sarif"]),
    default="md",
    help="Output format",
)
@click.option("--engagement", "engagement_id", default=None, help="Engagement ID for context")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def report_compliance(ctx, scan_id: str, fmt: str, engagement_id: str | None, output: str | None):
    """Generate a compliance report for a scan.

    Examples:

        chainsmith report compliance --scan abc123

        chainsmith report compliance --scan abc123 --engagement eng-001 -f pdf -o compliance.pdf
    """
    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.generate_compliance_report(scan_id, fmt, engagement_id)
        _write_report(result, fmt, output)
    except ChainsmithAPIError as e:
        _handle_api_error(e)


@report_group.command("trend")
@click.option("--target", default=None, help="Target domain for trend")
@click.option("--engagement", "engagement_id", default=None, help="Engagement ID for trend")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["md", "json", "html", "pdf", "sarif"]),
    default="md",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def report_trend(ctx, target: str | None, engagement_id: str | None, fmt: str, output: str | None):
    """Generate a trend report across multiple scans.

    Examples:

        chainsmith report trend --target example.com

        chainsmith report trend --engagement eng-001 -f pdf -o trend.pdf
    """
    if not target and not engagement_id:
        click.echo(click.style("Error: --target or --engagement is required", fg="red"), err=True)
        sys.exit(1)

    try:
        client = _get_client(ctx)
    except RuntimeError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    try:
        result = client.generate_trend_report(fmt, engagement_id, target)
        _write_report(result, fmt, output)
    except ChainsmithAPIError as e:
        _handle_api_error(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Serve Command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=8000, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
@click.option("--coordinator", is_flag=True, help="Enable swarm coordinator mode")
def serve(host: str, port: int, reload: bool, coordinator: bool):
    """Start the web UI server.

    Examples:

        chainsmith serve

        chainsmith serve --host 0.0.0.0 --port 8080

        chainsmith serve --coordinator
    """
    import os

    try:
        import uvicorn
    except ImportError:
        click.echo(
            click.style("uvicorn not installed. Run: pip install uvicorn", fg="red"), err=True
        )
        sys.exit(1)

    if coordinator:
        os.environ["CHAINSMITH_SWARM_ENABLED"] = "true"

    click.echo(click.style("Chainsmith Recon", fg="cyan", bold=True))
    if coordinator:
        click.echo(click.style("  Swarm coordinator mode enabled", fg="yellow"))
    click.echo(f"Starting server at http://{host}:{port}")
    click.echo()

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Scratch Space Commands
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command("scratch-to-db")
@click.argument("scan_id", required=False)
@click.option("--all", "import_all", is_flag=True, help="Import all scratch directories")
@click.option("--dry-run", is_flag=True, help="Preview without importing")
@click.option("--keep", is_flag=True, help="Keep scratch files after import (default: delete on success)")
def scratch_to_db(scan_id: str | None, import_all: bool, dry_run: bool, keep: bool):
    """Import observations from scratch space into the database.

    When the database becomes unreachable during a scan, observations are
    written to ~/.chainsmith/scratch/<scan_id>/ as JSON files. This command
    imports those observations into the database and cleans up the scratch
    directory.

    Pass a specific SCAN_ID to import one scan, or --all to import everything.
    """
    import asyncio
    import json
    import shutil

    from app.db.writers import SCRATCH_DIR

    if not scan_id and not import_all:
        click.echo(click.style("Error: provide a SCAN_ID or use --all", fg="red"), err=True)
        raise SystemExit(1)

    if not SCRATCH_DIR.exists():
        click.echo("No scratch directory found — nothing to import.")
        return

    # Discover scratch directories
    if scan_id:
        scan_dirs = [SCRATCH_DIR / scan_id]
        if not scan_dirs[0].exists():
            click.echo(click.style(f"No scratch data for scan '{scan_id}'", fg="red"), err=True)
            raise SystemExit(1)
    else:
        scan_dirs = sorted(
            [d for d in SCRATCH_DIR.iterdir() if d.is_dir() and (d / "observations").exists()]
        )
        if not scan_dirs:
            click.echo("No scratch directories with observations found.")
            return

    async def _import():
        from app.config import get_config
        from app.db import init_db
        from app.db.repositories import ObservationRepository, _generate_fingerprint

        cfg = get_config()
        await init_db(
            backend=cfg.storage.backend,
            db_path=cfg.storage.db_path,
            postgresql_url=cfg.storage.postgresql_url,
        )

        repo = ObservationRepository()
        total_imported = 0
        total_skipped = 0

        for scan_dir in scan_dirs:
            sid = scan_dir.name
            obs_dir = scan_dir / "observations"

            if not obs_dir.exists():
                continue

            # Load scratch observations
            obs_files = sorted(obs_dir.glob("*.json"))
            if not obs_files:
                click.echo(f"  {sid}: no observation files")
                continue

            observations = []
            for f in obs_files:
                try:
                    observations.append(json.loads(f.read_text(encoding="utf-8")))
                except Exception as e:
                    click.echo(click.style(f"  Warning: could not read {f.name}: {e}", fg="yellow"))

            if not observations:
                continue

            # Get existing fingerprints for this scan to skip duplicates
            existing = await repo.get_observations(sid)
            existing_fps = {obs.get("fingerprint") for obs in existing if obs.get("fingerprint")}

            # Compute fingerprints for scratch observations and filter duplicates
            new_observations = []
            for obs in observations:
                host = obs.get("host") or obs.get("target_url", "")
                fp = _generate_fingerprint(
                    check_name=obs.get("check_name", obs.get("check", "")),
                    host=host,
                    title=obs.get("title", ""),
                    evidence=obs.get("evidence", ""),
                )
                if fp not in existing_fps:
                    new_observations.append(obs)
                    existing_fps.add(fp)  # prevent intra-batch dupes

            skipped = len(observations) - len(new_observations)

            click.echo(
                f"  {sid}: {len(obs_files)} files, "
                f"{len(new_observations)} new, {skipped} duplicates"
            )

            if dry_run or not new_observations:
                total_skipped += skipped
                continue

            # Import to DB
            count = await repo.bulk_create(sid, new_observations)
            total_imported += count
            total_skipped += skipped

            # Clean up scratch directory
            if not keep:
                try:
                    shutil.rmtree(scan_dir)
                    click.echo(f"    Cleaned up {scan_dir}")
                except Exception as e:
                    click.echo(click.style(f"    Warning: could not remove {scan_dir}: {e}", fg="yellow"))

        return total_imported, total_skipped

    click.echo(click.style("Scratch-to-DB Import", fg="cyan", bold=True))
    click.echo(f"  Source: {SCRATCH_DIR}")
    click.echo(f"  Scans:  {len(scan_dirs)}")
    if dry_run:
        click.echo(click.style("  Mode:   DRY RUN", fg="yellow"))
    click.echo()

    imported, skipped = asyncio.run(_import())

    if dry_run:
        click.echo(click.style(f"\nDry run complete. Would import observations from {len(scan_dirs)} scan(s).", fg="yellow"))
    else:
        click.echo(click.style(f"\nImported {imported} observations ({skipped} duplicates skipped).", fg="green"))


@cli.command("scratch-list")
def scratch_list():
    """List scratch directories awaiting import."""
    from app.db.writers import SCRATCH_DIR

    if not SCRATCH_DIR.exists():
        click.echo("No scratch directory found.")
        return

    scan_dirs = sorted(
        [d for d in SCRATCH_DIR.iterdir() if d.is_dir()]
    )

    if not scan_dirs:
        click.echo("No scratch data found.")
        return

    click.echo(click.style("Scratch Space Contents", fg="cyan", bold=True))
    for d in scan_dirs:
        obs_dir = d / "observations"
        file_count = len(list(obs_dir.glob("*.json"))) if obs_dir.exists() else 0
        meta_file = d / "metadata.json"
        meta = ""
        if meta_file.exists():
            import json
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                meta = f" ({data.get('reason', '')})"
            except Exception:
                pass
        click.echo(f"  {d.name}: {file_count} observation(s){meta}")


# ═══════════════════════════════════════════════════════════════════════════════
# Swarm Commands
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group("swarm")
def swarm_group():
    """Swarm distributed scanning commands."""
    pass


@swarm_group.command("generate-key")
@click.option("--name", required=True, help="Label for this API key")
def swarm_generate_key(name: str):
    """Generate a new swarm API key.

    Writes directly to the database -- run on the coordinator host.

    Examples:

        chainsmith swarm generate-key --name "agent-dmz-01"
    """
    import asyncio

    from app.config import get_config
    from app.db import init_db
    from app.swarm.auth import create_api_key

    async def _create():
        cfg = get_config()
        await init_db(
            backend=cfg.storage.backend,
            db_path=cfg.storage.db_path,
            postgresql_url=cfg.storage.postgresql_url,
        )
        return await create_api_key(name)

    key_id, raw_key = asyncio.run(_create())

    click.echo(click.style("Swarm API Key Created", fg="green", bold=True))
    click.echo(f"  Name:    {name}")
    click.echo(f"  Key ID:  {key_id}")
    click.echo(f"  API Key: {click.style(raw_key, fg='yellow', bold=True)}")
    click.echo()
    click.echo(click.style("  Save this key -- it will not be shown again.", fg="red"))


@swarm_group.command("list-keys")
def swarm_list_keys():
    """List all swarm API keys."""
    import asyncio

    from app.config import get_config
    from app.db import init_db
    from app.swarm.auth import list_api_keys

    async def _list():
        cfg = get_config()
        await init_db(
            backend=cfg.storage.backend,
            db_path=cfg.storage.db_path,
            postgresql_url=cfg.storage.postgresql_url,
        )
        return await list_api_keys()

    keys = asyncio.run(_list())

    if not keys:
        click.echo("No swarm API keys configured.")
        return

    click.echo(click.style(f"Swarm API Keys ({len(keys)})", fg="cyan", bold=True))
    click.echo()
    for k in keys:
        last_used = k.get("last_used_at") or "never"
        click.echo(f"  {click.style(k['name'], bold=True)}")
        click.echo(f"    ID:        {k['key_id']}")
        click.echo(f"    Created:   {k['created_at']}")
        click.echo(f"    Last used: {last_used}")
        click.echo()


@swarm_group.command("revoke-key")
@click.argument("key_id")
def swarm_revoke_key(key_id: str):
    """Revoke a swarm API key by ID."""
    import asyncio

    from app.config import get_config
    from app.db import init_db
    from app.swarm.auth import revoke_api_key

    async def _revoke():
        cfg = get_config()
        await init_db(
            backend=cfg.storage.backend,
            db_path=cfg.storage.db_path,
            postgresql_url=cfg.storage.postgresql_url,
        )
        return await revoke_api_key(key_id)

    if asyncio.run(_revoke()):
        click.echo(click.style(f"Key {key_id} revoked.", fg="green"))
    else:
        click.echo(click.style(f"Key {key_id} not found.", fg="red"), err=True)
        sys.exit(1)


@swarm_group.command("agent")
@click.option("--coordinator", required=True, help="Coordinator URL (e.g., http://10.0.0.1:8000)")
@click.option("--key", required=True, help="Swarm API key")
@click.option("--name", default=None, help="Agent name (default: hostname)")
@click.option("--suites", "-s", multiple=True, help="Suites this agent can run (default: all)")
@click.option("--max-concurrent", default=3, type=int, help="Max parallel checks")
def swarm_agent(coordinator: str, key: str, name: str, suites: tuple, max_concurrent: int):
    """Start a swarm agent that connects to a coordinator.

    Examples:

        chainsmith swarm agent --coordinator http://10.0.0.1:8000 --key abc123

        chainsmith swarm agent --coordinator http://10.0.0.1:8000 --key abc123 --name dmz-01 --suites network --suites web
    """
    import asyncio

    from app.swarm.agent import SwarmAgent

    click.echo(click.style("Chainsmith Swarm Agent", fg="cyan", bold=True))
    click.echo(f"  Coordinator: {coordinator}")
    click.echo(f"  Name:        {name or '(auto)'}")
    click.echo(f"  Suites:      {', '.join(suites) if suites else 'all'}")
    click.echo(f"  Concurrency: {max_concurrent}")
    click.echo()

    agent = SwarmAgent(
        coordinator_url=coordinator,
        api_key=key,
        name=name or "",
        capabilities=list(suites),
        max_concurrent=max_concurrent,
    )

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        click.echo("\nAgent stopped.")


@swarm_group.command("status")
@click.pass_context
def swarm_status(ctx):
    """Show coordinator swarm status.

    Uses the --server address from the parent CLI group.
    """
    server = ctx.obj.get("server", "127.0.0.1:8000")

    import httpx

    try:
        resp = httpx.get(f"http://{server}/api/swarm/status", timeout=5.0)
        resp.raise_for_status()
    except Exception as e:
        click.echo(click.style(f"Failed to reach coordinator: {e}", fg="red"), err=True)
        sys.exit(1)

    data = resp.json()

    click.echo(click.style("Swarm Coordinator Status", fg="cyan", bold=True))
    click.echo(f"  Running:       {data.get('is_running', False)}")
    click.echo(f"  Agents online: {data.get('agents_online', 0)}")
    click.echo(f"  Phase:         {data.get('current_phase') or '-'}")
    click.echo()
    click.echo(click.style("  Tasks", bold=True))
    click.echo(f"    Total:       {data.get('tasks_total', 0)}")
    click.echo(f"    Queued:      {data.get('tasks_queued', 0)}")
    click.echo(f"    Assigned:    {data.get('tasks_assigned', 0)}")
    click.echo(f"    In Progress: {data.get('tasks_in_progress', 0)}")
    click.echo(f"    Complete:    {data.get('tasks_complete', 0)}")
    click.echo(f"    Failed:      {data.get('tasks_failed', 0)}")
    click.echo()
    click.echo(f"  Observations:  {data.get('observations_count', 0)}")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
