"""Integration-test fixtures.

These fixtures spin up the real FastAPI app with:
- A stub classifier backend (no torch dependency).
- An optional stub upstream Claude (respx-mounted transport).
- Real regex engine loaded from the shipped ruleset.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from firewall.api.auth import hash_api_key
from firewall.audit.logger import AuditLogger
from firewall.config import BlockingMode, Environment, Settings
from firewall.detection.classifier import Classifier
from firewall.detection.pipeline import DetectionPipeline, PipelineConfig
from firewall.detection.regex_engine import RegexEngine, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_PATH = REPO_ROOT / "rules" / "default_rules.yaml"

API_KEY_PLAINTEXT = "test-api-key-with-enough-entropy-1234"


class _StubBackend:
    def __init__(self, p: float) -> None:
        self._p = p

    def predict_proba(self, text: str) -> float:  # noqa: ARG002
        return self._p


class _FailingBackend:
    def predict_proba(self, text: str) -> float:  # noqa: ARG002
        from firewall.detection.classifier import ClassifierUnavailable

        raise ClassifierUnavailable("simulated")


def _build_settings(**overrides: object) -> Settings:
    """Build a dev-mode Settings object with the test API key hashed."""
    defaults: dict[str, object] = {
        "firewall_env": Environment.DEV,
        "firewall_api_keys_hashed": hash_api_key(API_KEY_PLAINTEXT),
        "block_threshold": 0.8,
        "warn_threshold": 0.5,
        "blocking_mode": BlockingMode.HARD_BLOCK,
        "debug_timing": False,
        "log_full_prompts": False,
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)  # type: ignore[call-arg]


def _build_app(
    settings: Settings,
    classifier_prob: float | None,
) -> TestClient:
    """Manually assemble the app with test-injected pipeline components.

    We don't go through `create_app` here because that would try to load the
    real classifier from disk. Instead we build the pipeline directly.
    """
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    from firewall.api.errors import FirewallError
    from firewall.api.rate_limit import InMemoryTokenBucket
    from firewall.api.routes import build_router
    from firewall.api.schemas import ErrorBody

    engine = RegexEngine(load_rules(RULES_PATH))
    clf = Classifier(model_path=Path("/tmp/nowhere"))
    if classifier_prob is None:
        clf.set_backend_for_tests(_FailingBackend())
    else:
        clf.set_backend_for_tests(_StubBackend(classifier_prob))
    pipeline = DetectionPipeline(
        engine,
        clf,
        PipelineConfig(
            block_threshold=settings.block_threshold,
            warn_threshold=settings.warn_threshold,
            mode=settings.blocking_mode,
            capture_timing=settings.debug_timing,
        ),
    )
    app = FastAPI()
    app.state.settings = settings
    app.state.pipeline = pipeline
    app.state.rate_limiter = InMemoryTokenBucket(
        rps=settings.rate_limit_rps, burst=settings.rate_limit_burst
    )
    from firewall.proxy.egress import EgressScanner

    app.state.audit = AuditLogger(log_full_prompts=settings.log_full_prompts)
    app.state.egress = EgressScanner()
    app.state.claude = None
    app.include_router(build_router())

    @app.exception_handler(FirewallError)
    async def _handler(request: Request, exc: FirewallError) -> JSONResponse:  # noqa: ARG001
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorBody(error_code=exc.error_code, message=str(exc)).model_dump(),
        )

    return TestClient(app)


@pytest.fixture
def client_benign_clf() -> Iterator[TestClient]:
    """Client with a low-confidence classifier stub — benign prompts should pass."""
    with _build_app(_build_settings(), classifier_prob=0.05) as c:
        yield c


@pytest.fixture
def client_hostile_clf() -> Iterator[TestClient]:
    """Client with a high-confidence classifier stub — everything looks adversarial."""
    with _build_app(_build_settings(), classifier_prob=0.95) as c:
        yield c


@pytest.fixture
def client_degraded() -> Iterator[TestClient]:
    """Client with a failing classifier — exercises degraded mode.

    We trigger one warm-up request to flip the classifier's sticky-degraded
    flag, so subsequent /health probes correctly report `degraded=true`.
    """
    with _build_app(_build_settings(), classifier_prob=None) as c:
        c.post(
            "/v1/check",
            json={"prompt": "warmup"},
            headers={"Authorization": f"Bearer {API_KEY_PLAINTEXT}"},
        )
        yield c


@pytest.fixture
def client_shadow_mode() -> Iterator[TestClient]:
    """Shadow mode: even hostile classifier + hostile prompt is allowed."""
    with _build_app(_build_settings(blocking_mode=BlockingMode.SHADOW), classifier_prob=0.99) as c:
        yield c


@pytest.fixture
def client_debug_timing() -> Iterator[TestClient]:
    """DEBUG_TIMING=true — verdicts should include the `latency` field."""
    with _build_app(_build_settings(debug_timing=True), classifier_prob=0.05) as c:
        yield c


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Correct auth header for the test API key."""
    return {"Authorization": f"Bearer {API_KEY_PLAINTEXT}"}
