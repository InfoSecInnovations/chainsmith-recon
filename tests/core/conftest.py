"""Fixtures for core/engine tests."""

import pytest

from app.checks.base import Service


@pytest.fixture
def sample_service() -> Service:
    """Basic HTTP service."""
    return Service(
        url="http://test.local:8080",
        host="test.local",
        port=8080,
        scheme="http",
        service_type="http",
        metadata={"discovered_by": "test"},
    )


@pytest.fixture
def sample_ai_service() -> Service:
    """AI service for AI check tests."""
    return Service(
        url="http://ai.test.local:8000",
        host="ai.test.local",
        port=8000,
        scheme="http",
        service_type="ai",
        metadata={"framework": "vllm"},
    )


@pytest.fixture
def sample_services(sample_service: Service, sample_ai_service: Service) -> list[Service]:
    """Multiple services for iteration tests."""
    return [sample_service, sample_ai_service]
