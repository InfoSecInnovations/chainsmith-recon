"""
Tests for LLM error classification and failure modes.

Covers:
- _classify_error for all HTTP status codes
- Exception-based classification (timeout, connection reset, DNS, SSL)
- Content filter detection (400 + keywords)
- Token limit detection (400 + keywords)
- Unknown error fallback
- Retryable vs non-retryable determination
"""

import pytest

from app.lib.llm import LLMErrorType, _classify_error

pytestmark = pytest.mark.unit


# ─── HTTP Status Code Classification ─────────────────────────────


class TestClassifyErrorByStatus:
    def test_rate_limit_429(self):
        error_type, retryable = _classify_error(429, "rate limit exceeded")
        assert error_type == LLMErrorType.RATE_LIMIT
        assert retryable is True

    def test_server_error_500(self):
        error_type, retryable = _classify_error(500, "internal server error")
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_bad_gateway_502(self):
        error_type, retryable = _classify_error(502, "bad gateway")
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_service_unavailable_503(self):
        error_type, retryable = _classify_error(503, "service unavailable")
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_unauthorized_401(self):
        error_type, retryable = _classify_error(401, "unauthorized")
        assert error_type == LLMErrorType.AUTH
        assert retryable is False

    def test_forbidden_403(self):
        error_type, retryable = _classify_error(403, "forbidden")
        assert error_type == LLMErrorType.AUTH
        assert retryable is False

    def test_not_found_404(self):
        error_type, retryable = _classify_error(404, "model not found")
        assert error_type == LLMErrorType.MODEL_NOT_FOUND
        assert retryable is False

    def test_unknown_status(self):
        error_type, retryable = _classify_error(418, "i'm a teapot")
        assert error_type == LLMErrorType.UNKNOWN
        assert retryable is False


# ─── Content Filter Detection (400) ──────────────────────────────


class TestContentFilterDetection:
    @pytest.mark.parametrize(
        "body",
        [
            "content policy violation detected",
            "request blocked by safety filter",
            "content moderation triggered",
            "blocked by content filter",
            "message contains harmful content",
            "request refused by model",
            "this input is not allowed",
        ],
    )
    def test_content_filter_keywords(self, body):
        error_type, retryable = _classify_error(400, body)
        assert error_type == LLMErrorType.CONTENT_FILTER
        assert retryable is False


# ─── Token Limit Detection (400) ─────────────────────────────────


class TestTokenLimitDetection:
    @pytest.mark.parametrize(
        "body",
        [
            "maximum token limit exceeded",
            "context length exceeded",
            "maximum context_length is 4096",
            "input is too long",
            "too many tokens in request",
        ],
    )
    def test_token_limit_keywords(self, body):
        error_type, retryable = _classify_error(400, body)
        assert error_type == LLMErrorType.TOKEN_LIMIT
        assert retryable is False

    def test_400_without_keywords_is_unknown(self):
        error_type, retryable = _classify_error(400, "invalid request format")
        assert error_type == LLMErrorType.UNKNOWN
        assert retryable is False


# ─── Exception-Based Classification ──────────────────────────────


class TestExceptionClassification:
    def test_timeout_exception(self):
        class TimeoutException(Exception):
            pass

        error_type, retryable = _classify_error(0, "", TimeoutException("request timed out"))
        assert error_type == LLMErrorType.TIMEOUT
        assert retryable is True

    def test_connection_reset_by_name(self):
        class ConnectionResetError(Exception):
            pass

        error_type, retryable = _classify_error(0, "", ConnectionResetError("reset"))
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_connection_reset_by_message(self):
        error_type, retryable = _classify_error(0, "", Exception("connection reset by peer"))
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_dns_failure(self):
        class DNSError(Exception):
            pass

        error_type, retryable = _classify_error(0, "", DNSError("name resolution failed"))
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_getaddrinfo_failure(self):
        error_type, retryable = _classify_error(0, "", Exception("getaddrinfo failed"))
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_ssl_certificate_error(self):
        class SSLError(Exception):
            pass

        error_type, retryable = _classify_error(0, "", SSLError("certificate verify failed"))
        assert error_type == LLMErrorType.AUTH
        assert retryable is False

    def test_generic_exception_status_zero(self):
        error_type, retryable = _classify_error(0, "", Exception("some unknown error"))
        assert error_type == LLMErrorType.TRANSIENT
        assert retryable is True

    def test_no_exception_status_zero(self):
        error_type, retryable = _classify_error(0, "")
        assert error_type == LLMErrorType.UNKNOWN
        assert retryable is False
