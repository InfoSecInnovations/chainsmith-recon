"""
Lab backport 3c (and §5 "service-type coverage"): web checks run on `ai` hosts.

`network_service_probe` classifies any host that looks like model serving
(vLLM headers, `/v1/completions` in the body, ...) as `ai`, and that wins over
`http`/`api`. A web check whose `service_types` leaves out `ai` therefore never
runs on those hosts, which on fakobanko are chat, ml, agent, mcp and vector.
"""

from pathlib import Path

import pytest
import yaml

from app.checks.network.network_service_probe import ServiceProbeCheck

pytestmark = pytest.mark.unit

WEB = Path(__file__).resolve().parents[2] / "app" / "checks" / "web"

# HTML-only by design: they read page markup, which a JSON model API does not serve.
HTML_ONLY = {"web_favicon", "web_sri"}


def _web_checks() -> list[Path]:
    return sorted(p.parent for p in WEB.glob("*/contract.yaml"))


def _class_service_types(folder: Path) -> list[str]:
    from app.component_loader import _module_for, parse_entry

    contract = yaml.safe_load((folder / "contract.yaml").read_text(encoding="utf-8"))
    filename, class_name = parse_entry(contract["entry"])
    import importlib

    cls = getattr(importlib.import_module(_module_for(folder, filename)), class_name)
    return list(cls.service_types)


def test_a_vllm_host_classifies_as_ai():
    probe = ServiceProbeCheck()
    assert probe._classify_service({"Server": "vLLM/0.4.1"}, "application/json", "{}") == "ai"
    assert (
        probe._classify_service({}, "application/json", '{"endpoints": ["/v1/completions"]}')
        == "ai"
    )


@pytest.mark.parametrize("folder", _web_checks(), ids=lambda p: p.name)
def test_web_checks_run_on_ai_hosts(folder):
    contract = yaml.safe_load((folder / "contract.yaml").read_text(encoding="utf-8"))
    declared = contract.get("service_types") or []
    if folder.name in HTML_ONLY or not declared:
        pytest.skip("HTML-only or applies to every service type")
    assert "ai" in declared, f"{folder.name} contract.yaml service_types lacks `ai`"


@pytest.mark.parametrize("folder", _web_checks(), ids=lambda p: p.name)
def test_contract_and_class_agree(folder):
    contract = yaml.safe_load((folder / "contract.yaml").read_text(encoding="utf-8"))
    assert sorted(contract.get("service_types") or []) == sorted(_class_service_types(folder))
