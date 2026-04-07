# Third-Party API & AI Authentication

Plan for managing credentials to external services and handling
authentication barriers encountered during security checks.

This document covers three concerns:
1. Authenticating to LLM providers and other APIs that Chainsmith consumes
2. Detecting and reporting MFA/CAPTCHA encountered on target systems
3. An extensible credential management framework for future integrations

Related documents:
- [authentication-authorization.md](authentication-authorization.md) — Chainsmith's own user auth
- [plan-data-protection-secrets.md](plan-data-protection-secrets.md) — Encrypted credential storage

## Problem Statement

Chainsmith has three distinct third-party authentication challenges:

**LLM Provider Auth.** Chainsmith calls OpenAI, Anthropic, and LiteLLM
APIs for chain analysis, verification, and adjudication. Currently this
uses bearer tokens from environment variables. As cloud-native providers
(Azure OpenAI, GCP Vertex AI, AWS Bedrock) are added, authentication
becomes more complex — OAuth2 flows, service accounts, temporary tokens
with expiry.

**Auth Barrier Encounters.** During reconnaissance checks, Chainsmith
probes target endpoints and may encounter MFA prompts, CAPTCHAs, or
login walls. These are not obstacles to bypass — they are observations to
detect and report. The framework needs a consistent way for checks to
recognize and classify these barriers.

**Future Integrations.** Chainsmith may integrate with ticketing systems
(Jira, Linear), SIEMs, notification services, or other APIs. The
credential management approach should be extensible without per-service
hardcoding.

## Current State

### LLM Provider Integration (`app/lib/llm.py`)

| Capability | Status |
|------------|--------|
| OpenAI API (bearer token) | Implemented |
| Anthropic API (bearer token) | Implemented |
| LiteLLM proxy (bearer token) | Implemented |
| No-LLM graceful degradation | Implemented |
| Auto-detection from env vars | Implemented |
| Persistent prefs store | Implemented |
| Token refresh / expiry handling | Not implemented |
| Azure OpenAI | Not implemented |
| GCP Vertex AI | Not implemented |
| AWS Bedrock | Not implemented |
| Credential rotation | Not implemented |

### Auth Barrier Handling in Checks

Currently, individual checks in `app/checks/web/` handle HTTP responses
ad-hoc. There is no shared framework for detecting or classifying
authentication barriers. A check that hits a CAPTCHA may report it as
a failed request or ignore it entirely.

## LLM Provider Authentication

### Tier 1: Bearer Token / API Key (Current)

Works for OpenAI, Anthropic, LiteLLM, and any OpenAI-compatible endpoint.
This is the MVP and remains the default path.

```
Provider         Config Source              Header
─────────────    ───────────────────────    ──────────────────────
OpenAI           OPENAI_API_KEY             Authorization: Bearer sk-...
Anthropic        ANTHROPIC_API_KEY          x-api-key: sk-ant-...
LiteLLM          LITELLM_BASE_URL           Authorization: Bearer <key>
OpenAI-compat    OPENAI_API_KEY + base_url  Authorization: Bearer <key>
```

No changes needed here. This continues to work as-is.

### Tier 2: Cloud Provider Auth — Short-Term (Application Tokens)

Both Azure OpenAI and GCP Vertex AI support API key / application token
auth alongside their native IAM flows. Use these as a short-term path
to avoid implementing full OAuth/service-account flows immediately.

**Azure OpenAI:**
```yaml
llm:
  provider: azure_openai
  azure:
    api_key: ${AZURE_OPENAI_API_KEY}        # API key (short-term)
    endpoint: https://my-instance.openai.azure.com
    api_version: "2024-06-01"
    deployment_name: gpt-4o                  # Azure uses deployment names, not model IDs
```

```python
# HTTP call pattern
headers = {
    "api-key": config.azure.api_key,         # Azure uses api-key header, not Authorization
    "Content-Type": "application/json",
}
url = f"{config.azure.endpoint}/openai/deployments/{config.azure.deployment_name}/chat/completions?api-version={config.azure.api_version}"
```

**GCP Vertex AI:**
```yaml
llm:
  provider: vertex_ai
  vertex:
    api_key: ${VERTEX_API_KEY}               # API key (short-term)
    project_id: my-project
    location: us-central1
    model: gemini-1.5-pro
```

Alternatively, use a service account key file:
```yaml
  vertex:
    credentials_file: ${GOOGLE_APPLICATION_CREDENTIALS}  # Path to SA JSON key
    project_id: my-project
    location: us-central1
```

**AWS Bedrock:**
```yaml
llm:
  provider: bedrock
  bedrock:
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    region: us-east-1
    model_id: anthropic.claude-3-sonnet
```

All three use static credentials as the short-term approach. This is
consistent with the existing env-var pattern and requires no new
authentication flows.

### Tier 3: Native Cloud Auth — Long-Term

Full cloud-native authentication for production/enterprise deployments.

| Provider | Mechanism | Library | Token Lifetime |
|----------|-----------|---------|----------------|
| Azure OpenAI | Azure AD / Entra ID, `DefaultAzureCredential` | `azure-identity` | ~1 hour, auto-refresh |
| GCP Vertex AI | Application Default Credentials, Workload Identity | `google-auth` | ~1 hour, auto-refresh |
| AWS Bedrock | IAM roles, instance profiles, `boto3` credential chain | `boto3` | ~1 hour, auto-refresh |

These all follow the same pattern: obtain a short-lived token, use it
until near expiry, refresh automatically. The `CredentialProvider`
abstraction handles this uniformly.

### CredentialProvider Abstraction

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

@dataclass
class AuthHeaders:
    """Headers and/or query params needed for an authenticated request."""
    headers: dict[str, str]
    params: dict[str, str] | None = None

class CredentialProvider(ABC):
    """Provides authentication credentials for an external service."""

    @abstractmethod
    async def get_auth(self) -> AuthHeaders:
        """Return auth headers/params. Refreshes token if expired."""
        ...

    @abstractmethod
    def is_expired(self) -> bool:
        """Check if current credentials need refresh."""
        ...

    async def ensure_valid(self) -> None:
        """Refresh credentials if expired or about to expire."""
        if self.is_expired():
            await self._refresh()

    @abstractmethod
    async def _refresh(self) -> None: ...


class StaticKeyProvider(CredentialProvider):
    """Bearer token / API key that doesn't expire. MVP default."""

    def __init__(self, header_name: str, key: str):
        self._header_name = header_name
        self._key = key

    async def get_auth(self) -> AuthHeaders:
        return AuthHeaders(headers={self._header_name: self._key})

    def is_expired(self) -> bool:
        return False

    async def _refresh(self) -> None:
        pass  # Static keys don't refresh


class AzureADProvider(CredentialProvider):
    """Azure AD token via DefaultAzureCredential."""

    def __init__(self, endpoint: str, deployment: str, api_version: str):
        self._endpoint = endpoint
        self._deployment = deployment
        self._api_version = api_version
        self._token: str | None = None
        self._expires_at: datetime | None = None

    async def get_auth(self) -> AuthHeaders:
        await self.ensure_valid()
        return AuthHeaders(
            headers={"Authorization": f"Bearer {self._token}"}
        )

    def is_expired(self) -> bool:
        if self._token is None or self._expires_at is None:
            return True
        # Refresh 5 minutes before expiry
        return datetime.utcnow() >= self._expires_at - timedelta(minutes=5)

    async def _refresh(self) -> None:
        from azure.identity.aio import DefaultAzureCredential
        credential = DefaultAzureCredential()
        token = await credential.get_token("https://cognitiveservices.azure.com/.default")
        self._token = token.token
        self._expires_at = datetime.utcfromtimestamp(token.expires_on)


class GCPProvider(CredentialProvider):
    """GCP token via Application Default Credentials."""
    ...

class AWSProvider(CredentialProvider):
    """AWS SigV4 signing via boto3 credential chain."""
    ...
```

Integration with existing `LLMClient`:

```python
class OpenAIClient(LLMClient):
    def __init__(self, config: LLMConfig, credential_provider: CredentialProvider):
        self._provider = credential_provider

    async def chat(self, messages: list[dict], **kwargs) -> LLMResponse:
        auth = await self._provider.get_auth()
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._url,
                headers={**self._base_headers, **auth.headers},
                json={"messages": messages, **kwargs},
            )
```

### Token Refresh & Retry Logic

When a provider returns 401 (unauthorized):

```
Request fails with 401
  │
  ├─ Is credential provider refreshable?
  │   ├── Yes ── refresh token ── retry request ONCE
  │   │            │
  │   │            └── Still 401? ── raise AuthError (credentials invalid)
  │   │
  │   └── No (static API key) ── raise AuthError immediately
  │
  └─ Log auth failure with provider name (not the credential value)
```

This integrates with the existing `LLMErrorType.AUTH` classification in
`LLMResponse`. The retry-on-refresh logic lives in `CredentialProvider`,
not in each `LLMClient`.

## Encountering MFA & CAPTCHA During Checks

Chainsmith's checks probe target systems and may encounter authentication
barriers. These are **positive security observations** — they indicate the
target has protections in place. Chainsmith should detect, classify, and
report them, not bypass them.

### Auth Barrier Types

| Type | Detection Signals | Severity |
|------|-------------------|----------|
| `login_required` | 401/403 response, redirect to `/login`, form with password field | Informational |
| `mfa_totp` | Form with "verification code", "OTP", "authenticator" fields after login | Informational (positive) |
| `mfa_push` | "Check your device" messaging, polling endpoint for approval | Informational (positive) |
| `mfa_sms` | "Code sent to your phone" messaging | Informational (positive) |
| `captcha_recaptcha` | `google.com/recaptcha` script include, `g-recaptcha` div | Informational |
| `captcha_hcaptcha` | `hcaptcha.com` script include, `h-captcha` div | Informational |
| `captcha_cloudflare` | Cloudflare challenge page (403 + `cf-ray` header + JS challenge) | Informational |
| `captcha_custom` | Generic challenge page with image/puzzle, no known provider | Informational |
| `certificate_required` | 403 with client certificate request, mTLS endpoint | Informational |
| `ip_restricted` | 403 with no auth mechanism offered, consistent across retries | Informational |
| `waf_blocked` | WAF signature in response (AWS WAF, Cloudflare, Akamai identifiers) | Informational |

### AuthBarrier Framework

Shared utility for checks to consistently detect auth barriers without
each check reimplementing detection:

```python
from dataclasses import dataclass, field
from enum import Enum

class BarrierType(str, Enum):
    LOGIN_REQUIRED = "login_required"
    MFA_TOTP = "mfa_totp"
    MFA_PUSH = "mfa_push"
    MFA_SMS = "mfa_sms"
    CAPTCHA_RECAPTCHA = "captcha_recaptcha"
    CAPTCHA_HCAPTCHA = "captcha_hcaptcha"
    CAPTCHA_CLOUDFLARE = "captcha_cloudflare"
    CAPTCHA_CUSTOM = "captcha_custom"
    CERTIFICATE_REQUIRED = "certificate_required"
    IP_RESTRICTED = "ip_restricted"
    WAF_BLOCKED = "waf_blocked"

@dataclass
class AuthBarrier:
    barrier_type: BarrierType
    endpoint: str
    detection_evidence: str          # What triggered detection (header, form field, etc.)
    provider: str | None = None      # e.g., "reCAPTCHA v3", "Cloudflare Turnstile"
    confidence: float = 1.0          # 0.0–1.0, for heuristic detections

@dataclass
class AuthBarrierDetector:
    """Detects authentication barriers in HTTP responses."""

    def detect(self, url: str, response: httpx.Response) -> list[AuthBarrier]:
        """Analyze an HTTP response for auth barrier indicators."""
        barriers: list[AuthBarrier] = []
        barriers.extend(self._check_captcha(url, response))
        barriers.extend(self._check_mfa(url, response))
        barriers.extend(self._check_login(url, response))
        barriers.extend(self._check_waf(url, response))
        barriers.extend(self._check_certificate(url, response))
        return barriers

    def _check_captcha(self, url: str, response: httpx.Response) -> list[AuthBarrier]:
        body = response.text.lower() if response.text else ""
        barriers = []

        if "google.com/recaptcha" in body or "g-recaptcha" in body:
            barriers.append(AuthBarrier(
                barrier_type=BarrierType.CAPTCHA_RECAPTCHA,
                endpoint=url,
                detection_evidence="reCAPTCHA script/element detected in response body",
                provider="Google reCAPTCHA",
            ))

        if "hcaptcha.com" in body or "h-captcha" in body:
            barriers.append(AuthBarrier(
                barrier_type=BarrierType.CAPTCHA_HCAPTCHA,
                endpoint=url,
                detection_evidence="hCaptcha script/element detected in response body",
                provider="hCaptcha",
            ))

        if response.status_code == 403 and "cf-ray" in response.headers:
            if "challenge" in body or "cf-challenge" in body:
                barriers.append(AuthBarrier(
                    barrier_type=BarrierType.CAPTCHA_CLOUDFLARE,
                    endpoint=url,
                    detection_evidence="Cloudflare challenge page (403 + cf-ray header)",
                    provider="Cloudflare",
                ))

        return barriers

    def _check_mfa(self, url: str, response: httpx.Response) -> list[AuthBarrier]:
        """Detect MFA prompts in response body."""
        body = response.text.lower() if response.text else ""
        barriers = []

        totp_signals = ["verification code", "authenticator", "one-time password",
                        "otp", "6-digit code", "enter code"]
        if any(signal in body for signal in totp_signals):
            barriers.append(AuthBarrier(
                barrier_type=BarrierType.MFA_TOTP,
                endpoint=url,
                detection_evidence="MFA/TOTP prompt detected in response body",
                confidence=0.8,  # Heuristic — could be false positive
            ))

        push_signals = ["check your device", "approve the request",
                        "push notification", "waiting for approval"]
        if any(signal in body for signal in push_signals):
            barriers.append(AuthBarrier(
                barrier_type=BarrierType.MFA_PUSH,
                endpoint=url,
                detection_evidence="MFA push notification prompt detected",
                confidence=0.7,
            ))

        return barriers

    def _check_login(self, url: str, response: httpx.Response) -> list[AuthBarrier]: ...
    def _check_waf(self, url: str, response: httpx.Response) -> list[AuthBarrier]: ...
    def _check_certificate(self, url: str, response: httpx.Response) -> list[AuthBarrier]: ...
```

### Check Integration

Checks use the detector as a shared utility:

```python
from app.lib.auth_barriers import AuthBarrierDetector, AuthBarrier

class SomeWebCheck(BaseCheck):
    def __init__(self):
        self._barrier_detector = AuthBarrierDetector()

    async def run(self, target: str, **kwargs) -> list[Observation]:
        response = await self._client.get(f"https://{target}/api/endpoint")

        # Check for auth barriers before processing response
        barriers = self._barrier_detector.detect(str(response.url), response)
        if barriers:
            return [self._barrier_to_observation(b) for b in barriers]

        # Normal check logic continues...

    def _barrier_to_observation(self, barrier: AuthBarrier) -> Observation:
        return Observation(
            title=f"Auth barrier detected: {barrier.barrier_type.value}",
            severity="informational",
            evidence=barrier.detection_evidence,
            check_name=self.name,
            tags=["auth-barrier", barrier.barrier_type.value],
        )
```

### Ethical Boundaries

Chainsmith **MUST NOT**:
- Attempt to solve CAPTCHAs (automated or via external services)
- Attempt to bypass MFA (token replay, session fixation, etc.)
- Brute-force login forms beyond authorized scope
- Intercept or replay MFA tokens

Chainsmith **SHOULD**:
- Detect and report the presence and type of auth barriers
- Note the barrier type in observations for the engagement report
- Continue scanning other endpoints that don't require auth
- Respect `robots.txt` and rate limits after barrier detection

### Authenticated Scanning (Phase 3 / Future)

Some engagements require scanning behind auth — the client provides
credentials and Chainsmith runs checks as an authenticated user. This is
standard for web app penetration testing tools.

```yaml
# Per-engagement authenticated scanning config
engagements:
  - name: "Client Portal Assessment"
    target: portal.client.com
    auth:
      type: form_login              # form_login | bearer_token | cookie | client_cert
      login_url: https://portal.client.com/login
      username: ${ENGAGEMENT_USERNAME}
      password: ${ENGAGEMENT_PASSWORD}
      mfa: manual                   # manual | totp_secret
      session_refresh: true         # Re-authenticate if session expires
```

Credential types for authenticated scanning:

| Type | Use Case | Session Management |
|------|----------|-------------------|
| `form_login` | Web app with login form | Maintain cookies, re-auth on 401 |
| `bearer_token` | API with pre-issued token | Include in headers, refresh if supported |
| `cookie` | Pre-authenticated session cookie | Include cookie, no refresh |
| `client_cert` | mTLS endpoints | Configure TLS client certificate |
| `totp_secret` | Automated TOTP for authorized testing | Generate TOTP codes from shared secret |

Authenticated scanning credentials are stored encrypted (per
[plan-data-protection-secrets.md](plan-data-protection-secrets.md),
engagement-level encryption).

## Credential Management Framework

### CredentialStore Abstraction

Unified interface for credential storage, used by both LLM provider auth
and future integrations:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

@dataclass
class StoredCredential:
    name: str
    value: str                       # The actual secret
    provider: str | None = None      # e.g., "openai", "anthropic", "azure"
    created_at: datetime | None = None
    last_accessed: datetime | None = None
    last_rotated: datetime | None = None
    expires_at: datetime | None = None
    metadata: dict | None = None     # Provider-specific metadata

class CredentialStore(ABC):
    """Backend-agnostic credential storage."""

    @abstractmethod
    async def get(self, name: str) -> StoredCredential | None: ...

    @abstractmethod
    async def set(self, name: str, credential: StoredCredential) -> None: ...

    @abstractmethod
    async def delete(self, name: str) -> None: ...

    @abstractmethod
    async def list_names(self) -> list[str]: ...


class EnvVarStore(CredentialStore):
    """Read credentials from environment variables. MVP default."""

    async def get(self, name: str) -> StoredCredential | None:
        value = os.environ.get(name)
        if value is None:
            return None
        return StoredCredential(name=name, value=value)

    async def set(self, name: str, credential: StoredCredential) -> None:
        raise NotImplementedError("Cannot write to environment variables at runtime")

    async def delete(self, name: str) -> None:
        raise NotImplementedError("Cannot delete environment variables at runtime")

    async def list_names(self) -> list[str]:
        # Return known credential env var names that are set
        known = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY",
                 "VERTEX_API_KEY", "AWS_ACCESS_KEY_ID"]
        return [k for k in known if k in os.environ]


class EncryptedFileStore(CredentialStore):
    """Phase 2: Encrypted local file (~/.chainsmith/secrets.enc)."""
    ...

class VaultStore(CredentialStore):
    """Phase 3: External vault (HashiCorp Vault, AWS Secrets Manager, etc.)."""
    ...
```

### Credential Resolution Order

When Chainsmith needs a credential, it checks stores in priority order:

```
1. Environment variable (always wins — allows CI/CD override)
2. EncryptedFileStore (~/.chainsmith/secrets.enc)
3. .env file (legacy compat)
4. VaultStore (if configured)
5. Auto-detection / interactive prompt
```

```python
class CredentialResolver:
    """Resolves credentials from multiple stores in priority order."""

    def __init__(self, stores: list[CredentialStore]):
        self._stores = stores

    async def resolve(self, name: str) -> StoredCredential | None:
        for store in self._stores:
            cred = await store.get(name)
            if cred is not None:
                return cred
        return None
```

### Key Rotation (Future Feature)

CLI-driven rotation with validation:

```bash
chainsmith credentials rotate OPENAI_API_KEY
Enter new API key: ********
Validating new key... OK (model access confirmed)
Updating credential store... done
Old key invalidated in store.
Rotation logged to audit trail.
```

Rotation steps:
1. Accept new credential value
2. Validate new credential works (provider-specific test call)
3. Update credential store
4. Log rotation event (timestamp, credential name, NOT the value)
5. Optionally: warn if old key should be revoked at provider

Rotation reminders:
```yaml
credentials:
  rotation_reminder_days: 90     # Warn when a credential is this old
  check_on_startup: true         # Check credential ages at startup
```

```
[WARN] Credential OPENAI_API_KEY is 95 days old (rotation recommended every 90 days)
```

## Implementation Phases

### Phase 1 — Cloud Provider Support & Auth Barriers (Near-Term)

- [ ] `CredentialProvider` abstraction with `StaticKeyProvider`
- [ ] Azure OpenAI client with API key auth (short-term)
- [ ] GCP Vertex AI client with API key / service account key (short-term)
- [ ] AWS Bedrock client with static credentials (short-term)
- [ ] `AuthBarrierDetector` utility class
- [ ] CAPTCHA detection (reCAPTCHA, hCaptcha, Cloudflare)
- [ ] MFA detection (TOTP prompt, push notification, SMS)
- [ ] WAF detection (Cloudflare, AWS WAF, Akamai)
- [ ] Auth barrier → Observation conversion in web checks
- [ ] Update `LLMClient` to use `CredentialProvider`

### Phase 2 — Credential Management & Native Cloud Auth (Mid-Term)

- [ ] `CredentialStore` abstraction with `EnvVarStore` and `EncryptedFileStore`
- [ ] `CredentialResolver` with priority chain
- [ ] CLI: `chainsmith credentials set/list/delete/rotate`
- [ ] `AzureADProvider` with `DefaultAzureCredential`
- [ ] `GCPProvider` with Application Default Credentials
- [ ] `AWSProvider` with boto3 credential chain
- [ ] Token refresh and retry-on-401 logic
- [ ] Credential age tracking and rotation reminders
- [ ] Audit trail for credential access and rotation

### Phase 3 — Advanced (Future)

- [ ] External vault integration (`VaultStore`)
- [ ] Authenticated scanning framework (per-engagement target credentials)
- [ ] WebUI credential management
- [ ] Full OAuth2 authorization code flow for providers requiring it
- [ ] CAPTCHA type fingerprinting (reCAPTCHA v2 vs v3, Turnstile version)
- [ ] Auth barrier statistics in scan reports
- [ ] Credential sharing across swarm agents for authenticated scanning

## Open Questions

1. **AuthBarrierDetector: check or utility?** Should barrier detection be
   its own check (runs against every endpoint) or a utility that existing
   checks call? A dedicated check is cleaner but may duplicate HTTP
   requests. A utility avoids duplication but couples checks to the
   detector.

2. **Cloudflare escalation**: Targets behind Cloudflare may escalate
   protections (rate limit → CAPTCHA → block) as Chainsmith probes
   endpoints. Should barrier detection trigger automatic backoff, or
   should the operator decide?

3. **Authenticated scanning credential scope**: Should target credentials
   be scoped per-check (different checks use different auth) or
   per-engagement (all checks share one session)? Per-engagement is
   simpler but may not model real-world access patterns.

4. **Auth barrier scenario testing**: How to test CAPTCHA and MFA
   detection without hitting real services? Need scenario targets
   that simulate these barriers. Extend the existing scenario system
   in `app/scenario_services/`.

5. **Credential rotation automation**: Should rotation ever be fully
   automatic (Chainsmith generates a new key at the provider), or
   always operator-initiated? Automatic rotation requires provider
   API access, which is a significant privilege escalation.

6. **Swarm agent credential distribution**: For authenticated scanning,
   swarm agents need target credentials. Should the coordinator pass
   credentials per-task (encrypted in the task payload), or should
   agents pull from a shared credential store? Per-task is more
   isolated; shared store is simpler but widens the blast radius.
