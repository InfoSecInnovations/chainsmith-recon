"""
app/capture/context.py - Who is this exchange for?

`AsyncHttpClient` is constructed per call site — 122 of them, all the same
`async with AsyncHttpClient(cfg)` idiom — and has no idea who called it. The
attribution is set instead in `BaseCheck.execute()`, the single wrapper every
check passes through, which already knows `self.name`.

The pattern is already in the codebase: `execute()` today loops over finished
results setting `observation.check_name = self.name`, making the same
association *after* the fact. This makes it *before* the fact instead, so a
request can be stamped as it happens rather than reconstructed afterwards.

**Two guardrails**, because this is deliberately a small piece of ambient state
in a codebase that just finished removing a large one (`app/state.py` ->
`ScanSession` + `ScanRegistry`):

1. The default is `None`, meaning *"not inside a check"*. The writer attributes
   such a row to the scan alone and never infers a check. This var is **never**
   a fallback for *which scan* — that question is answered by `ScanSession`, as
   it is everywhere else, and this must not grow into a second answer to it.

2. Thread boundaries are avoided, not handled. A `ContextVar` does not propagate
   into `run_in_executor`. Exactly 8 check modules use one, and they are the
   same 8 that speak non-HTTP protocols and call the writer directly with an
   explicit handle, so the var never has to survive a handoff.

`ContextVar` semantics are what is wanted here: values copy into new asyncio
tasks at creation, so a check that fans out with `asyncio.gather` inherits its
own attribution, and two concurrent checks are separate tasks with separate
values.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class CaptureContext:
    """Attribution for every exchange recorded while one check runs."""

    scan_id: str
    check_name: str
    candidate_id: str | None = None
    iteration: int = 0

    #: The check's resolved `capture:` policy (57.2, D-20) — "all",
    #: "observations_only" or "none". It rides on the context rather than being
    #: looked up by the writer because the check already knows it, and a lookup
    #: would put a registry read in the request path.
    policy: str = "all"
    #: The check's suite, for the always-full exemption in `settings.py`.
    suite: str = ""

    #: This scan's capture posture. Rides on the context because it is
    #: **per scan**, and concurrent scans share one process: a module-level
    #: singleton would let one scan's `--capture` flag silently change what
    #: another scan records. `None` falls back to the process-wide default.
    settings: object | None = None


_capture_context: contextvars.ContextVar[CaptureContext | None] = contextvars.ContextVar(
    "chainsmith_capture_context", default=None
)


def current() -> CaptureContext | None:
    """The active attribution, or None when not inside a check."""
    return _capture_context.get()


@contextmanager
def capture_context(
    scan_id: str,
    check_name: str,
    candidate_id: str | None = None,
    iteration: int = 0,
    policy: str = "all",
    suite: str = "",
    settings: object | None = None,
):
    """
    Attribute every exchange recorded in this block to one check.

    Entered by `BaseCheck.execute()`. Restores the previous value on exit, so a
    nested block (a check that grades a sub-probe) cannot leak its attribution
    to whatever runs next.
    """
    token = _capture_context.set(
        CaptureContext(
            scan_id=scan_id,
            check_name=check_name,
            candidate_id=candidate_id,
            iteration=iteration,
            policy=policy,
            suite=suite,
            settings=settings,
        )
    )
    try:
        yield
    finally:
        _capture_context.reset(token)


@contextmanager
def iteration(index: int):
    """
    Re-stamp the iteration index within an existing attribution.

    Phase 58 samples one probe N times; each pass records its own rows under the
    same check. A no-op outside a check rather than an error — capture must
    never be the reason something fails.
    """
    active = _capture_context.get()
    if active is None:
        yield
        return
    token = _capture_context.set(replace(active, iteration=index))
    try:
        yield
    finally:
        _capture_context.reset(token)


@contextmanager
def candidate(candidate_id: str):
    """Bind subsequent exchanges to the candidate they support."""
    active = _capture_context.get()
    if active is None:
        yield
        return
    token = _capture_context.set(replace(active, candidate_id=candidate_id))
    try:
        yield
    finally:
        _capture_context.reset(token)


def reset() -> None:
    """Clear the attribution. For tests."""
    _capture_context.set(None)
