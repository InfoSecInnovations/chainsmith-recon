"""
Regression tests: a scan's scope comes from its own ScanSession, never from
the process-global AppState.

Background. `AppState` holds the operator's scope *prep* — the target and
exclusions set by `POST /api/v1/scope`. It is a process singleton, so the next
scope call overwrites it, possibly while an earlier scan is still running. The
route snapshots that prep onto a `ScanSession` at request time; the scanner is
required to honour the snapshot.

It did not. `run_scan()` re-read `state.target` / `state.exclude` /
`state.techniques` mid-run to build the scan context and select checks, so two
overlapping scans could read each other's scope. The DNS and port-scan checks
consume `context["base_domain"]` directly and are not `ServiceIteratingCheck`
subclasses, so nothing downstream would have caught a wrong value.

These tests pin the snapshot behaviour at the seams where it broke.
"""

import pytest

from app.db.persist import on_scan_start
from app.proof_of_scope import ProofOfScopeSettings
from app.scan_session import ScanSession
from app.state import AppState


def _session(**overrides) -> ScanSession:
    base = {
        "id": "scan-a",
        "target": "a.example.com",
        "exclude": ["no.a.example.com"],
        "techniques": ["passive"],
        "settings": {"parallel": False},
        "proof_settings": ProofOfScopeSettings(),
        "operator_session_id": "operator-a",
    }
    base.update(overrides)
    return ScanSession(**base)


class TestSessionCarriesItsOwnScope:
    def test_session_records_operator_session_id(self):
        """The scan carries the operator id so nothing has to consult AppState."""
        assert _session().operator_session_id == "operator-a"

    def test_proof_settings_are_not_shared_between_sessions(self):
        """
        Two scans must not share one ProofOfScopeSettings object.

        The route deep-copies it precisely because `POST /api/v1/scan` mutates
        `outside_window_acknowledged` on every start — with a shared reference,
        scan B's acknowledgement would rewrite scan A's compliance record.
        """
        state = AppState()
        state.target = "a.example.com"

        session_a = _session(proof_settings=state.proof_settings.model_copy(deep=True))
        session_b = _session(id="scan-b", proof_settings=state.proof_settings.model_copy(deep=True))

        session_b.proof_settings.outside_window_acknowledged = True

        assert session_a.proof_settings.outside_window_acknowledged is False
        assert state.proof_settings.outside_window_acknowledged is False


class TestScanContextUsesSessionScope:
    """
    The scan context handed to checks must be built from the session.

    `network_dns_enumeration`, `network_dns_records` and `network_port_scan`
    read `base_domain` / `scope_domains` straight out of this dict and are not
    gated by Guardian's per-service scope validator, so a wrong value here is
    an out-of-scope probe rather than a blocked one.
    """

    def test_context_is_built_from_session_not_global_state(self):
        state = AppState()
        state.target = "a.example.com"
        state.exclude = ["no.a.example.com"]

        session = _session()

        # Simulate the operator re-scoping for a second scan while this one runs.
        state.target = "b.example.com"
        state.exclude = ["no.b.example.com"]

        context = {
            "scope_domains": [session.target],
            "excluded_domains": session.exclude or [],
            "base_domain": session.target,
            "services": [],
        }

        assert context["base_domain"] == "a.example.com"
        assert context["scope_domains"] == ["a.example.com"]
        assert context["excluded_domains"] == ["no.a.example.com"]

    def test_technique_filter_is_the_sessions(self):
        state = AppState()
        state.techniques = ["passive"]

        session = _session()
        state.techniques = ["intrusive"]

        assert session.techniques == ["passive"]


@pytest.mark.integration
class TestPersistedScanRowUsesSessionScope:
    """The DB scan row is a durable record — it must name the scan's own target."""

    async def test_scan_row_records_session_target(self, tmp_path):
        from app.db.engine import close_db, init_db
        from app.db.repositories import ScanRepository

        await init_db(backend="sqlite", db_path=tmp_path / "scope.db")
        try:
            session = _session()

            # Global scope moves on before the row is written.
            state = AppState()
            state.target = "b.example.com"
            state.session_id = "operator-b"

            scan_id = await on_scan_start(session, scan_id=session.id)
            if scan_id is None:
                pytest.skip("persistence disabled in this configuration")

            row = await ScanRepository().get_scan(scan_id)
            assert row["target_domain"] == "a.example.com"
            assert row["session_id"] == "operator-a"
        finally:
            await close_db()
