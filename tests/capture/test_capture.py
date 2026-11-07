"""
Tests for evidence capture (Phase 57.2 scaffolding).

Everything here is below the capture line: recording fact, with no model and no
judgment. The properties that matter are that the record is faithful, that the
two hashes answer the two different questions they exist for, that secrets never
reach a default view, and that capture can never break a scan.
"""

import asyncio
import json

import pytest

from app import workspace as ws
from app.capture import context as capture_context
from app.capture.hashing import apply_hashes, content_hash, normalise_text, probe_hash
from app.capture.models import Exchange
from app.capture.probes import probe
from app.capture.protocols import DEFAULT_PROTOCOLS, PROTOCOLS, volatile_headers
from app.capture.redaction import MASK, redact
from app.capture.settings import CaptureSettings
from app.capture.store import EvidenceStore, apply_size_cap, truncate_body
from app.capture.writer import EvidenceWriter

pytestmark = pytest.mark.unit


def make_exchange(**overrides) -> Exchange:
    base = {
        "id": "ex1",
        "scan_id": "scan-1",
        "check_name": "web_header_analysis",
        "host": "acme.test",
        "protocol": "http",
        "request_method": "GET",
        "request_url": "https://acme.test/",
        "request_headers": {"User-Agent": "Chainsmith"},
        "response_status": 200,
        "response_headers": {"Server": "nginx"},
        "response_body": "hello",
        "elapsed_ms": 12.0,
    }
    base.update(overrides)
    return Exchange(**base)


@pytest.fixture
def store(tmp_path):
    return EvidenceStore(root=tmp_path / "evidence")


@pytest.fixture
def writer(store):
    return EvidenceWriter(store=store, settings=CaptureSettings(enabled=True))


@pytest.fixture(autouse=True)
def _clean_context():
    capture_context.reset()
    yield
    capture_context.reset()


# ═══════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════


class TestProtocols:
    def test_the_eight_protocols(self):
        assert set(PROTOCOLS) == {"http", "dns", "tcp", "tls", "whois", "icmp", "llm", "local"}

    def test_http_and_llm_capture_by_default(self):
        """Non-HTTP is opt-in: a dns row is cheap to write and rarely read."""
        assert frozenset({"http", "llm"}) == DEFAULT_PROTOCOLS

    def test_llm_drops_provider_bookkeeping_headers(self):
        """Rate-limit counters say nothing about what was asked or answered."""
        assert "x-ratelimit-remaining-tokens" in volatile_headers("llm")

    def test_every_protocol_drops_date(self):
        assert all("date" in volatile_headers(p) for p in PROTOCOLS)

    def test_http_drops_the_websocket_handshake_nonce(self):
        """RFC 6455: the key is random per handshake and the accept derives from it."""
        assert {"sec-websocket-key", "sec-websocket-accept"} <= volatile_headers("http")


# ═══════════════════════════════════════════════════════════════════
# Normalisation and the two hashes
# ═══════════════════════════════════════════════════════════════════


class TestNormalisation:
    def test_uuid_markers_are_substituted(self):
        """The CAG checks mint a uuid4 per run; correct behaviour, must not alter identity."""
        a = normalise_text("marker=6f1e8f94-2b4a-4f6e-9a1c-0b8d2f3e4a5b")
        b = normalise_text("marker=11111111-2222-3333-4444-555555555555")
        assert a == b

    def test_timestamps_are_substituted(self):
        a = normalise_text('{"created":"2026-09-10T11:22:33Z"}')
        b = normalise_text('{"created":"2024-01-01T00:00:00Z"}')
        assert a == b

    def test_chainsmiths_short_hex_markers_are_substituted(self):
        """D-21: rag_corpus_poisoning and web_error_page mint 8-hex markers per run."""
        assert normalise_text("ID: chainsmith-canary-eaf024a5") == normalise_text(
            "ID: chainsmith-canary-62331fd6"
        )
        assert normalise_text("/chainsmith-probe-56a2e9ba") == normalise_text(
            "/chainsmith-probe-d027d7f6"
        )

    def test_the_fixed_probe_string_is_not_a_marker(self):
        """MCP payloads echo a constant `chainsmith-probe`; it carries meaning."""
        assert normalise_text("; echo chainsmith-probe") == "; echo chainsmith-probe"

    def test_ordinary_content_survives(self):
        assert "server error" in normalise_text("server error")


class TestProbeHash:
    def test_same_request_same_hash(self):
        assert probe_hash(make_exchange()) == probe_hash(make_exchange())

    def test_ignores_the_response(self):
        """The whole point: group sampling iterations of one probe."""
        first = make_exchange(response_body="yes")
        second = make_exchange(response_body="absolutely not")
        assert probe_hash(first) == probe_hash(second)

    def test_different_request_different_hash(self):
        assert probe_hash(make_exchange()) != probe_hash(
            make_exchange(request_url="https://acme.test/other")
        )

    def test_survives_a_per_run_marker_in_the_request(self):
        first = make_exchange(request_body="id=6f1e8f94-2b4a-4f6e-9a1c-0b8d2f3e4a5b")
        second = make_exchange(request_body="id=11111111-2222-3333-4444-555555555555")
        assert probe_hash(first) == probe_hash(second)

    def test_survives_a_random_404_path(self):
        first = make_exchange(request_url="https://acme.test/chainsmith-probe-56a2e9ba")
        second = make_exchange(request_url="https://acme.test/chainsmith-probe-d027d7f6")
        assert probe_hash(first) == probe_hash(second)

    def test_survives_a_websocket_handshake_key(self):
        first = make_exchange(request_headers={"Sec-WebSocket-Key": "c6OSLw3yZoEitFdm/H8ONw=="})
        second = make_exchange(request_headers={"Sec-WebSocket-Key": "CaEngpFCSUIqnQM+AL09Aw=="})
        assert probe_hash(first) == probe_hash(second)


class TestContentHash:
    def test_same_pair_same_hash(self):
        assert content_hash(make_exchange()) == content_hash(make_exchange())

    def test_covers_the_response(self):
        """A cached verdict must never be reused against a different answer."""
        first = make_exchange(response_body="yes")
        second = make_exchange(response_body="absolutely not")
        assert content_hash(first) != content_hash(second)

    def test_ignores_volatile_headers(self):
        first = make_exchange(response_headers={"Server": "nginx", "Date": "Mon, 1 Jan 2020"})
        second = make_exchange(response_headers={"Server": "nginx", "Date": "Tue, 2 Feb 2021"})
        assert content_hash(first) == content_hash(second)

    def test_ignores_header_name_casing(self):
        first = make_exchange(response_headers={"Server": "nginx"})
        second = make_exchange(response_headers={"server": "nginx"})
        assert content_hash(first) == content_hash(second)

    def test_ignores_elapsed_time(self):
        """Timing is recorded for the operator, not for identity."""
        assert content_hash(make_exchange(elapsed_ms=1.0)) == content_hash(
            make_exchange(elapsed_ms=999.0)
        )

    def test_a_failed_probe_differs_from_an_empty_response(self):
        empty = make_exchange(response_body="")
        failed = make_exchange(response_body="", error="Timeout")
        assert content_hash(empty) != content_hash(failed)

    def test_apply_hashes_stamps_both(self):
        exchange = apply_hashes(make_exchange())
        assert len(exchange.probe_hash) == 64
        assert len(exchange.content_hash) == 64
        assert exchange.probe_hash != exchange.content_hash


# ═══════════════════════════════════════════════════════════════════
# Size cap
# ═══════════════════════════════════════════════════════════════════


class TestSizeCap:
    def test_small_body_untouched(self):
        body, cut = truncate_body("hello", cap=1024)
        assert body == "hello"
        assert cut is False

    def test_large_body_truncated_and_flagged(self):
        body, cut = truncate_body("x" * 5000, cap=100)
        assert cut is True
        assert "truncated" in body

    def test_truncation_is_measured_in_bytes(self):
        """The cap is about storage, so multibyte characters count for more."""
        _body, cut = truncate_body("é" * 60, cap=100)
        assert cut is True

    def test_truncated_output_stays_decodable(self):
        body, _cut = truncate_body("é" * 200, cap=51)
        assert isinstance(body, str)

    def test_apply_size_cap_sets_the_flag(self):
        exchange = apply_size_cap(make_exchange(response_body="x" * 5000), cap=100)
        assert exchange.truncated is True

    def test_untruncated_exchange_is_not_flagged(self):
        assert apply_size_cap(make_exchange(), cap=4096).truncated is False


# ═══════════════════════════════════════════════════════════════════
# Redaction
# ═══════════════════════════════════════════════════════════════════


class TestRedaction:
    def test_authorization_header_is_masked(self):
        out = redact(make_exchange(request_headers={"Authorization": "Bearer sekrit-value"}))
        assert out.request_headers["Authorization"] == MASK

    def test_cookie_header_is_masked(self):
        out = redact(make_exchange(request_headers={"Cookie": "session=abc123"}))
        assert out.request_headers["Cookie"] == MASK

    @pytest.mark.parametrize(
        "secret",
        [
            "sk-abcdefghijklmnopqrstuvwx",
            "ghp_abcdefghijklmnopqrstuvwxyz12",
            "AKIAIOSFODNN7EXAMPLE",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
        ],
    )
    def test_token_shapes_masked_in_bodies(self, secret):
        out = redact(make_exchange(response_body=f"the key is {secret}"))
        assert secret not in out.response_body
        assert MASK in out.response_body

    def test_named_json_secret_fields_masked(self):
        out = redact(make_exchange(response_body='{"password":"hunter2"}'))
        assert "hunter2" not in out.response_body

    def test_ordinary_content_survives(self):
        out = redact(make_exchange(response_body="Content-Security-Policy missing"))
        assert "Content-Security-Policy missing" in out.response_body

    def test_llm_prompt_secrets_are_covered(self):
        """The sharpest case: agent rows carry prompts and get pasted into chats."""
        out = redact(
            make_exchange(
                protocol="llm",
                request_headers={"Authorization": "Bearer sk-abcdefghijklmnopqrstuvwx"},
                request_body='{"system":"you are...","api_key":"sk-abcdefghijklmnopqrstuvwx"}',
            )
        )
        assert out.request_headers["Authorization"] == MASK
        assert "sk-abcdefghijklmnopqrstuvwx" not in out.request_body

    def test_the_original_is_not_mutated(self):
        """Full fidelity at rest; redaction is a read-time view."""
        original = make_exchange(request_headers={"Authorization": "Bearer sekrit"})
        redact(original)
        assert original.request_headers["Authorization"] == "Bearer sekrit"

    def test_hashes_are_carried_through_unchanged(self):
        """They identify what was captured — recomputing here would fork identity."""
        original = apply_hashes(make_exchange(response_body="sk-abcdefghijklmnopqrstuvwx"))
        out = redact(original)
        assert out.content_hash == original.content_hash
        assert out.probe_hash == original.probe_hash


# ═══════════════════════════════════════════════════════════════════
# Attribution context
# ═══════════════════════════════════════════════════════════════════


class TestCaptureContext:
    def test_none_outside_a_check(self):
        assert capture_context.current() is None

    def test_set_inside_the_block(self):
        with capture_context.capture_context(scan_id="s1", check_name="web_robots_txt"):
            active = capture_context.current()
            assert active.scan_id == "s1"
            assert active.check_name == "web_robots_txt"

    def test_restored_on_exit(self):
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            pass
        assert capture_context.current() is None

    def test_nested_blocks_restore_the_outer_value(self):
        with capture_context.capture_context(scan_id="s1", check_name="outer"):
            with capture_context.capture_context(scan_id="s1", check_name="inner"):
                assert capture_context.current().check_name == "inner"
            assert capture_context.current().check_name == "outer"

    def test_iteration_rebinds_within_a_check(self):
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            with capture_context.iteration(3):
                assert capture_context.current().iteration == 3
            assert capture_context.current().iteration == 0

    def test_iteration_outside_a_check_is_a_noop(self):
        """Capture must never be the reason something fails."""
        with capture_context.iteration(3):
            assert capture_context.current() is None

    def test_candidate_binds(self):
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            with capture_context.candidate("cand-7"):
                assert capture_context.current().candidate_id == "cand-7"

    def test_concurrent_tasks_do_not_share_attribution(self):
        """Two parallel_safe checks are separate tasks and must stay separate."""
        seen: dict[str, str] = {}

        async def run_check(name: str) -> None:
            with capture_context.capture_context(scan_id="s1", check_name=name):
                await asyncio.sleep(0)
                seen[name] = capture_context.current().check_name

        async def main() -> None:
            await asyncio.gather(run_check("alpha"), run_check("beta"))

        asyncio.run(main())
        assert seen == {"alpha": "alpha", "beta": "beta"}

    def test_a_child_task_inherits_its_parents_attribution(self):
        """asyncio.gather inside one check must stay attributed to that check."""
        seen: list[str] = []

        async def sub_probe() -> None:
            seen.append(capture_context.current().check_name)

        async def main() -> None:
            with capture_context.capture_context(scan_id="s1", check_name="fanout"):
                await asyncio.gather(sub_probe(), sub_probe())

        asyncio.run(main())
        assert seen == ["fanout", "fanout"]


# ═══════════════════════════════════════════════════════════════════
# The store
# ═══════════════════════════════════════════════════════════════════


class TestEvidenceStore:
    def test_round_trip(self, store):
        written = apply_hashes(make_exchange())
        store.write(written)
        loaded = store.read("scan-1", "ex1")
        assert loaded.response_body == "hello"
        assert loaded.content_hash == written.content_hash

    def test_missing_document_is_none(self, store):
        assert store.read("scan-1", "nope") is None

    def test_read_scan_returns_everything(self, store):
        for i in range(3):
            store.write(apply_hashes(make_exchange(id=f"ex{i}")))
        assert len(store.read_scan("scan-1")) == 3

    def test_read_scan_of_unknown_scan_is_empty(self, store):
        assert store.read_scan("no-such-scan") == []

    def test_scans_are_sharded(self, store):
        store.write(apply_hashes(make_exchange(id="a", scan_id="scan-1")))
        store.write(apply_hashes(make_exchange(id="b", scan_id="scan-2")))
        assert len(store.read_scan("scan-1")) == 1
        assert len(store.read_scan("scan-2")) == 1

    def test_a_corrupt_document_does_not_lose_the_rest(self, store):
        """A corpus with one unreadable file is still a corpus."""
        store.write(apply_hashes(make_exchange(id="good")))
        bad = store.path_for("scan-1", "bad")
        bad.write_text("{not json")
        assert len(store.read_scan("scan-1")) == 1

    def test_delete_scan_removes_the_corpus(self, store):
        store.write(apply_hashes(make_exchange()))
        assert store.delete_scan("scan-1") == 1
        assert store.read_scan("scan-1") == []

    def test_store_roots_off_the_workspace(self, tmp_path):
        """Corpus portability: rsync the workspace, get the evidence."""
        w = ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())
        try:
            assert EvidenceStore().root == w.evidence_dir
        finally:
            ws.reset_workspace()


# ═══════════════════════════════════════════════════════════════════
# The writer
# ═══════════════════════════════════════════════════════════════════


class TestEvidenceWriter:
    def test_records_and_hashes(self, writer, store):
        with capture_context.capture_context(scan_id="s1", check_name="web_robots_txt"):
            exchange = writer.record(
                "http",
                "acme.test",
                request_method="GET",
                request_url="https://acme.test/robots.txt",
                response_status=200,
                response_body="User-agent: *",
            )
        assert exchange is not None
        assert exchange.check_name == "web_robots_txt"
        assert len(exchange.content_hash) == 64
        assert store.read("s1", exchange.id) is not None

    def test_disabled_records_nothing(self, store):
        writer = EvidenceWriter(store=store, settings=CaptureSettings(enabled=False))
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            assert writer.record("http", "acme.test") is None

    def test_undeclared_protocol_is_skipped(self, writer):
        """Non-HTTP is opt-in; dns is not captured by default."""
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            assert writer.record("dns", "acme.test") is None

    def test_opted_in_protocol_is_captured(self, store):
        writer = EvidenceWriter(
            store=store,
            settings=CaptureSettings(enabled=True, protocols=frozenset({"dns"})),
        )
        with capture_context.capture_context(scan_id="s1", check_name="network_dns_enumeration"):
            assert writer.record("dns", "acme.test", request_body="A acme.test") is not None

    def test_failed_probe_skipped_by_default(self, writer):
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            assert writer.record("http", "acme.test", error="Timeout") is None

    def test_failed_probe_recorded_when_enabled(self, store):
        """A timeout under one specific payload is occasionally the whole finding."""
        writer = EvidenceWriter(
            store=store, settings=CaptureSettings(enabled=True, capture_failures=True)
        )
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            exchange = writer.record("http", "acme.test", error="Timeout")
        assert exchange is not None
        assert exchange.error == "Timeout"
        assert exchange.completed is False

    def test_no_scan_attribution_records_nothing(self, writer):
        """A row that links to nothing is not worth writing."""
        assert writer.record("http", "acme.test") is None

    def test_explicit_attribution_works_outside_a_check(self, writer):
        """The agent LLM path and future local checks pass their own."""
        exchange = writer.record(
            "llm", "litellm.local", scan_id="s1", check_name="", request_body="prompt"
        )
        assert exchange is not None
        assert exchange.scan_id == "s1"

    def test_unknown_check_still_attributes_to_the_scan(self, writer):
        exchange = writer.record("http", "acme.test", scan_id="s1")
        assert exchange is not None
        assert exchange.check_name == ""

    def test_capture_never_breaks_the_caller(self, store, monkeypatch):
        """A broken store must not take a scan down with it."""

        def explode(_exchange):
            raise OSError("disk full")

        monkeypatch.setattr(store, "write", explode)
        writer = EvidenceWriter(store=store, settings=CaptureSettings(enabled=True))
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            assert writer.record("http", "acme.test") is None

    def test_body_is_capped_before_hashing(self, store):
        """Hashing the full body and storing a truncated one would make it unverifiable."""
        writer = EvidenceWriter(
            store=store, settings=CaptureSettings(enabled=True, max_body_bytes=100)
        )
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            exchange = writer.record("http", "acme.test", response_body="x" * 5000)

        stored = store.read("s1", exchange.id)
        assert stored.truncated is True
        assert content_hash(stored) == stored.content_hash

    def test_iteration_is_carried_onto_the_row(self, writer):
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            with capture_context.iteration(2):
                exchange = writer.record("http", "acme.test")
        assert exchange.iteration == 2

    def test_candidate_is_carried_onto_the_row(self, writer):
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            with capture_context.candidate("cand-7"):
                exchange = writer.record("http", "acme.test")
        assert exchange.candidate_id == "cand-7"


class TestProbe:
    """`probe()` — the chokepoint for the socket and resolver checks.

    They cannot use the HTTP interceptor: each opens its own socket. What they
    share is a shape — an async wrapper around an executor call that swallows
    its own errors — and `probe()` records that shape without changing it.
    """

    @pytest.fixture(autouse=True)
    def _writer(self, store):
        """Install a process-wide writer, since `probe()` uses the module-level
        `record()` exactly as the checks do."""
        from app.capture import writer as writer_module

        writer_module.set_writer(
            EvidenceWriter(
                store=store,
                settings=CaptureSettings(enabled=True, protocols=frozenset(PROTOCOLS)),
            )
        )
        yield
        writer_module.reset_writer()

    async def test_records_a_completed_exchange(self, store):
        with capture_context.capture_context(scan_id="s1", check_name="network_wildcard_dns"):
            async with probe("dns", "acme.test", request_body="A", qtype="A") as prb:
                prb.responded("10.0.0.1")

        (exchange,) = store.read_scan("s1")
        assert exchange.protocol == "dns"
        assert exchange.host == "acme.test"
        assert exchange.request_body == "A"
        assert exchange.request_headers["qtype"] == "A"
        assert exchange.response_body == "10.0.0.1"
        assert exchange.check_name == "network_wildcard_dns"

    async def test_a_silent_peer_records_an_empty_response(self, store):
        """A query that completed and returned nothing is not the same as a
        query that failed, and the row must be able to say which."""
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            async with probe("dns", "acme.test", request_body="A"):
                pass

        (exchange,) = store.read_scan("s1")
        assert exchange.response_body == ""
        assert exchange.error is None
        assert exchange.completed is True

    async def test_a_failure_is_recorded_as_a_failure(self, store):
        """The grader is told the probe *failed* rather than shown an empty
        response and left to infer."""
        from app.capture import writer as writer_module

        writer_module.set_writer(
            EvidenceWriter(
                store=store,
                settings=CaptureSettings(
                    enabled=True, protocols=frozenset(PROTOCOLS), capture_failures=True
                ),
            )
        )

        with capture_context.capture_context(scan_id="s1", check_name="a"):
            with pytest.raises(OSError):
                async with probe("tcp", "acme.test", request_body="HELO"):
                    raise OSError("connection refused")

        (exchange,) = store.read_scan("s1")
        assert exchange.error == "OSError: connection refused"
        assert exchange.completed is False

    async def test_recording_never_changes_control_flow(self, store):
        """The check's own `except` clause must see exactly what it saw before."""
        seen = None
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            try:
                async with probe("tcp", "acme.test"):
                    raise TimeoutError("too slow")
            except TimeoutError as exc:
                seen = exc

        assert isinstance(seen, TimeoutError)
        assert str(seen) == "too slow"

    async def test_a_return_inside_the_block_still_records(self, store):
        """Every instrumented site returns from inside the block."""

        async def resolve():
            with capture_context.capture_context(scan_id="s1", check_name="a"):
                async with probe("dns", "acme.test", request_body="A") as prb:
                    prb.responded("10.0.0.1")
                    return "10.0.0.1"

        assert await resolve() == "10.0.0.1"
        assert len(store.read_scan("s1")) == 1

    async def test_elapsed_is_measured(self, store):
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            async with probe("dns", "acme.test") as prb:
                await asyncio.sleep(0.01)
                prb.responded("10.0.0.1")

        (exchange,) = store.read_scan("s1")
        assert exchange.elapsed_ms >= 10

    async def test_non_http_protocols_are_opt_in(self, store):
        """A `dns` row is cheap to write and rarely what a grader reads, so the
        socket protocols capture only when the operator selects them."""
        from app.capture import writer as writer_module

        writer_module.set_writer(
            EvidenceWriter(store=store, settings=CaptureSettings(enabled=True))
        )

        with capture_context.capture_context(scan_id="s1", check_name="a"):
            async with probe("dns", "acme.test", request_body="A") as prb:
                prb.responded("10.0.0.1")

        assert store.read_scan("s1") == []


class TestLLMCapture:
    """The `llm` producer — the corpus phase 58 actually needs.

    Capture lives on `LLMClient.chat`, not in each provider, so a client added
    later is covered without its author knowing capture exists.
    """

    @pytest.fixture
    def client(self, store):
        from app.capture import writer as writer_module
        from app.lib.llm import LLMConfig, LLMResponse, NoLLMClient

        writer_module.set_writer(
            EvidenceWriter(store=store, settings=CaptureSettings(enabled=True))
        )

        class FakeClient(NoLLMClient):
            async def _chat(self, prompt, system=None, temperature=None, max_tokens=None):
                return LLMResponse(
                    content="the model said this",
                    model="fake-1",
                    provider="fake",
                    success=True,
                    usage={"input_tokens": 11, "output_tokens": 4},
                )

            @property
            def capture_host(self) -> str:
                return "api.fake.test"

        yield FakeClient(LLMConfig())
        writer_module.reset_writer()

    async def test_a_model_call_is_recorded(self, client, store):
        with capture_context.capture_context(scan_id="s1", check_name="triage"):
            await client.chat("what is this", system="you are a triage agent")

        (exchange,) = store.read_scan("s1")
        assert exchange.protocol == "llm"
        assert exchange.host == "api.fake.test"
        assert exchange.response_body == "the model said this"
        assert exchange.check_name == "triage"

    async def test_the_prompt_is_recorded_in_full(self, client, store):
        """System and messages both — an operator answering "why did triage say
        that" six months later needs what the model was actually asked."""
        with capture_context.capture_context(scan_id="s1", check_name="triage"):
            await client.chat("what is this", system="you are a triage agent")

        (exchange,) = store.read_scan("s1")
        body = json.loads(exchange.request_body)
        assert body["messages"] == [
            {"role": "system", "content": "you are a triage agent"},
            {"role": "user", "content": "what is this"},
        ]

    async def test_usage_is_on_the_row(self, client, store):
        """Kept out of the hash by `VOLATILE_HEADERS`, but on the row: it is how
        the corpus is costed."""
        with capture_context.capture_context(scan_id="s1", check_name="triage"):
            await client.chat("what is this")

        (exchange,) = store.read_scan("s1")
        assert exchange.response_headers["usage-input_tokens"] == "11"
        assert exchange.response_headers["model"] == "fake-1"

    async def test_the_provider_still_returns_its_response(self, client):
        response = await client.chat("what is this")
        assert response.content == "the model said this"
        assert response.success is True

    async def test_a_failed_call_is_recorded_as_an_error(self, store):
        from app.capture import writer as writer_module
        from app.lib.llm import LLMConfig, NoLLMClient

        writer_module.set_writer(
            EvidenceWriter(
                store=store, settings=CaptureSettings(enabled=True, capture_failures=True)
            )
        )
        try:
            with capture_context.capture_context(scan_id="s1", check_name="triage"):
                await NoLLMClient(LLMConfig()).chat("what is this")

            (exchange,) = store.read_scan("s1")
            assert exchange.error == "No LLM provider configured"
        finally:
            writer_module.reset_writer()


class TestCapturePolicy:
    """Decision D-20 — how much a check records is the check's own declaration.

    The §5.2 rule as written ("observation-linked exchanges by default") is not
    knowable at request time, and the volume case it names — port scan, DNS
    enumeration — is already covered by protocol gating. What is not covered is
    HTTP path-probing, which fires many requests each, mostly 404s, over a
    protocol that captures by default. The knob is where that is settled.
    """

    def writer_for(self, store, **settings) -> EvidenceWriter:
        return EvidenceWriter(store=store, settings=CaptureSettings(enabled=True, **settings))

    def test_all_records_everything(self, store):
        writer = self.writer_for(store)
        with capture_context.capture_context(scan_id="s1", check_name="a", policy="all"):
            writer.record("http", "acme.test")
        assert len(store.read_scan("s1")) == 1

    def test_none_records_nothing(self, store):
        writer = self.writer_for(store)
        with capture_context.capture_context(scan_id="s1", check_name="a", policy="none"):
            assert writer.record("http", "acme.test") is None
        assert store.read_scan("s1") == []

    def test_observations_only_holds_the_write(self, store):
        """Nothing reaches disk until the check finishes and the run is judged."""
        writer = self.writer_for(store)
        with capture_context.capture_context(
            scan_id="s1", check_name="a", policy="observations_only"
        ):
            writer.record("http", "acme.test")
        assert store.read_scan("s1") == []

    def test_a_run_that_found_something_keeps_its_exchanges(self, store):
        writer = self.writer_for(store)
        with capture_context.capture_context(
            scan_id="s1", check_name="web_path_probe", policy="observations_only"
        ):
            writer.record("http", "acme.test/admin")
            writer.record("http", "acme.test/.env")

        assert writer.commit_check("s1", "web_path_probe", keep=True) == 2
        assert len(store.read_scan("s1")) == 2

    def test_a_run_that_found_nothing_writes_nothing(self, store):
        """The whole point: 200 fruitless 404s become no corpus at all."""
        writer = self.writer_for(store)
        with capture_context.capture_context(
            scan_id="s1", check_name="web_path_probe", policy="observations_only"
        ):
            writer.record("http", "acme.test/admin")

        assert writer.commit_check("s1", "web_path_probe", keep=False) == 0
        assert store.read_scan("s1") == []

    def test_the_buffer_is_keyed_per_check(self, store):
        """Concurrent checks and concurrent scans drain through one writer."""
        writer = self.writer_for(store)
        for check in ("web_path_probe", "web_debug_endpoints"):
            with capture_context.capture_context(
                scan_id="s1", check_name=check, policy="observations_only"
            ):
                writer.record("http", "acme.test")

        assert writer.commit_check("s1", "web_path_probe", keep=True) == 1
        assert writer.commit_check("s1", "web_debug_endpoints", keep=False) == 0
        assert len(store.read_scan("s1")) == 1

    def test_committing_twice_is_a_no_op(self, store):
        writer = self.writer_for(store)
        with capture_context.capture_context(
            scan_id="s1", check_name="a", policy="observations_only"
        ):
            writer.record("http", "acme.test")

        assert writer.commit_check("s1", "a", keep=True) == 1
        assert writer.commit_check("s1", "a", keep=True) == 0

    def test_full_capture_overrides_the_check(self, store):
        """The scan-level flag an operator reaches for when they want the lot."""
        writer = self.writer_for(store, full_capture=True)
        with capture_context.capture_context(scan_id="s1", check_name="a", policy="none"):
            writer.record("http", "acme.test")
        assert len(store.read_scan("s1")) == 1

    def test_the_ai_suites_are_never_narrowed(self, store):
        """That corpus is the entire point of phase 58; a partial one would not
        support it."""
        writer = self.writer_for(store)
        for suite in ("ai", "mcp", "agent", "rag", "cag"):
            with capture_context.capture_context(
                scan_id=suite, check_name=f"{suite}_x", policy="none", suite=suite
            ):
                writer.record("http", "acme.test")
            assert len(store.read_scan(suite)) == 1

    def test_a_policy_free_context_records(self, store):
        """The default is to record: a check that should not be in the corpus
        says so."""
        writer = self.writer_for(store)
        with capture_context.capture_context(scan_id="s1", check_name="a"):
            writer.record("http", "acme.test")
        assert len(store.read_scan("s1")) == 1


class TestPerScanSettings:
    """The posture is per scan, not process-wide.

    Concurrent scans share one process. A module-level singleton would let one
    scan's `--capture` change what another scan records, which is exactly the
    ambient state the concurrent-scans work removed.
    """

    def test_the_scans_posture_wins_over_the_process_default(self, store):
        writer = EvidenceWriter(store=store)
        with capture_context.capture_context(
            scan_id="s1", check_name="a", settings=CaptureSettings(enabled=True)
        ):
            writer.record("http", "acme.test")
        assert len(store.read_scan("s1")) == 1

    def test_a_scan_without_capture_is_unaffected_by_one_with_it(self, store):
        writer = EvidenceWriter(store=store)
        with capture_context.capture_context(
            scan_id="on", check_name="a", settings=CaptureSettings(enabled=True)
        ):
            writer.record("http", "acme.test")
        with capture_context.capture_context(
            scan_id="off", check_name="a", settings=CaptureSettings(enabled=False)
        ):
            writer.record("http", "acme.test")

        assert len(store.read_scan("on")) == 1
        assert store.read_scan("off") == []

    def test_an_injected_posture_still_wins(self, store):
        """Tests and embedders pass one explicitly."""
        writer = EvidenceWriter(store=store, settings=CaptureSettings(enabled=True))
        with capture_context.capture_context(
            scan_id="s1", check_name="a", settings=CaptureSettings(enabled=False)
        ):
            writer.record("http", "acme.test")
        assert len(store.read_scan("s1")) == 1

    def test_from_request_defaults_to_the_default_protocols(self, store):
        """An operator who turns capture on and names no protocol wants the
        corpus, not silence."""
        settings = CaptureSettings.from_request(enabled=True, protocols=[])
        assert settings.protocols == DEFAULT_PROTOCOLS

    def test_from_request_honours_named_protocols(self):
        settings = CaptureSettings.from_request(enabled=True, protocols=["dns", "tcp"])
        assert settings.captures("dns") is True
        assert settings.captures("http") is False
