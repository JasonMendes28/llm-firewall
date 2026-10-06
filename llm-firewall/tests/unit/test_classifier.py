"""Tests for firewall.detection.classifier.

We test the wrapper's contract without loading torch: a stub backend implements
the `_InferenceBackend` protocol and is injected via `set_backend_for_tests`.
The real transformers/torch backend is exercised by the integration tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from firewall.detection.classifier import Classifier, ClassifierUnavailable


class _StubBackend:
    """Deterministic stub returning a preset probability."""

    def __init__(self, proba: float) -> None:
        self._p = proba
        self.calls: list[str] = []

    def predict_proba(self, text: str) -> float:
        self.calls.append(text)
        return self._p


class _RaisingBackend:
    """Backend that simulates a transient inference failure."""

    def predict_proba(self, text: str) -> float:
        raise ClassifierUnavailable("simulated inference failure")


def test_predict_before_load_raises() -> None:
    c = Classifier(model_path=Path("/tmp/does-not-exist"))
    assert not c.is_available()
    with pytest.raises(ClassifierUnavailable):
        c.predict("hello")


def test_predict_after_stub_backend_installed() -> None:
    c = Classifier(model_path=Path("/tmp/x"))
    c.set_backend_for_tests(_StubBackend(0.42))
    assert c.is_available()
    assert c.predict("some text") == 0.42


def test_predict_clamps_out_of_range() -> None:
    c = Classifier(model_path=Path("/tmp/x"))
    c.set_backend_for_tests(_StubBackend(1.7))
    assert c.predict("x") == 1.0
    c.set_backend_for_tests(_StubBackend(-0.5))
    assert c.predict("x") == 0.0


def test_inference_failure_surfaces_as_unavailable() -> None:
    c = Classifier(model_path=Path("/tmp/x"))
    c.set_backend_for_tests(_RaisingBackend())
    with pytest.raises(ClassifierUnavailable, match="simulated"):
        c.predict("x")


def test_hash_pin_mismatch_refuses_load(tmp_path: Path) -> None:
    # Create a dummy model directory.
    d = tmp_path / "model"
    d.mkdir()
    (d / "config.json").write_text('{"a": 1}', encoding="utf-8")

    c = Classifier(
        model_path=d,
        expected_sha256="deadbeef" * 8,  # 64 hex chars, guaranteed mismatch
    )
    with pytest.raises(ClassifierUnavailable, match="hash mismatch"):
        c.load()


def test_missing_model_dir_surfaces_unavailable() -> None:
    c = Classifier(model_path=Path("/nonexistent/path"))
    with pytest.raises(ClassifierUnavailable):
        c.load()


def test_degraded_reason_populated_on_failure() -> None:
    c = Classifier(model_path=Path("/nonexistent/path"))
    with pytest.raises(ClassifierUnavailable):
        c.load()
    # After a failed load, the reason should still be readable for logs.
    assert c.degraded_reason is not None
    assert not c.is_available()
