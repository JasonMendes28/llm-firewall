"""DistilBERT-based semantic classifier for jailbreak / prompt-injection detection.

Design contract:
- Loaded ONCE at startup (`load()`), not per-request. Per-request load would add
  hundreds of ms and would OOM under concurrency.
- `predict()` returns a probability in [0.0, 1.0], OR raises
  `ClassifierUnavailable` if the model is not usable. The pipeline treats
  unavailability as an explicit degraded mode — see ADR-002.
- Optional artifact SHA-256 pinning: if configured, refuses to load a mismatched
  artifact. Prevents an attacker with write access to the model directory from
  swapping in a permissive model.

We deliberately do NOT instantiate transformers/torch at module import time —
the import cost is high, and it lets us unit-test the wrapper's degradation
behavior without pulling in the ML stack.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class ClassifierUnavailable(RuntimeError):
    """Raised when the classifier cannot serve a prediction.

    Callers should catch this and enter degraded mode rather than propagating —
    the whole point of graceful degradation is that classifier failures don't
    crash the firewall.
    """


class _InferenceBackend(Protocol):
    """Minimal interface implemented by both the real and test backends."""

    def predict_proba(self, text: str) -> float:
        """Return P(jailbreak) in [0.0, 1.0]."""


def _sha256_of_dir(model_dir: Path) -> str:
    """Compute a stable SHA-256 over the sorted contents of a model directory.

    We hash file names and contents in sorted order so the hash is deterministic
    regardless of filesystem enumeration order.

    Args:
        model_dir: Directory containing the model artifact files.

    Returns:
        Hex-encoded SHA-256.
    """
    h = hashlib.sha256()
    for path in sorted(model_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(model_dir).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()


class _TransformersBackend:
    """Real backend using HuggingFace transformers + torch.

    Imports are deferred to `__init__` so importing this module in tests does
    not require torch to be installed.
    """

    def __init__(
        self,
        model_path: Path,
        max_tokens: int,
        device: str,
    ) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:
            raise ClassifierUnavailable(f"transformers/torch not installed: {e}") from e

        if not model_path.exists():
            raise ClassifierUnavailable(f"model path does not exist: {model_path}")

        try:
            self._tokenizer = AutoTokenizer.from_pretrained(str(model_path))
            self._model = AutoModelForSequenceClassification.from_pretrained(str(model_path))
        except (OSError, ValueError) as e:
            raise ClassifierUnavailable(f"failed to load model from {model_path}: {e}") from e

        self._device = torch.device(device)
        self._model.to(self._device)
        self._model.eval()
        self._torch = torch
        self._max_tokens = max_tokens

    def predict_proba(self, text: str) -> float:
        """Return the model's P(jailbreak) for a single string."""
        try:
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=self._max_tokens,
                padding=False,
            ).to(self._device)
            with self._torch.no_grad():
                logits = self._model(**inputs).logits
                # Assumes binary classifier with label 1 == jailbreak.
                probs = self._torch.softmax(logits, dim=-1)[0]
            return float(probs[1].item())
        except (RuntimeError, ValueError) as e:
            # We wrap in ClassifierUnavailable so upstream degradation logic
            # kicks in on transient inference failures too, not just load failures.
            raise ClassifierUnavailable(f"inference failed: {e}") from e


class Classifier:
    """Public classifier facade.

    Two-phase lifecycle:
        1. Construction: cheap; no model loaded, no imports beyond stdlib.
        2. `load()`: heavy; loads the model, validates artifact hash if pinned.

    After `load()` succeeds, `predict()` returns floats. If `load()` was never
    called or raised, `predict()` raises `ClassifierUnavailable`.
    """

    def __init__(
        self,
        model_path: Path,
        max_tokens: int = 512,
        device: str = "cpu",
        expected_sha256: str = "",
    ) -> None:
        """Configure the classifier without loading it.

        Args:
            model_path: Directory containing the HuggingFace model artifact.
            max_tokens: Truncation limit for tokenization.
            device: "cpu" or "cuda".
            expected_sha256: If non-empty, the model directory's hash must match
                this value or `load()` will refuse. Prevents artifact tampering.
        """
        self._model_path = model_path
        self._max_tokens = max_tokens
        self._device = device
        self._expected_sha256 = expected_sha256.strip().lower()
        self._backend: _InferenceBackend | None = None
        self._degraded_reason: str | None = None
        # Sticky flag: once a prediction fails, we consider the classifier
        # unavailable until an operator restarts / reloads. This prevents a
        # flapping backend from oscillating verdicts.
        self._prediction_failure_sticky: bool = False

    def load(self) -> None:
        """Load the model into memory.

        Raises:
            ClassifierUnavailable: On any load failure. The service should catch
                this at startup and enter degraded mode (still starts, but the
                pipeline knows to skip the ML layer).
        """
        if self._expected_sha256:
            try:
                actual = _sha256_of_dir(self._model_path)
            except (OSError, FileNotFoundError) as e:
                raise ClassifierUnavailable(
                    f"cannot compute artifact hash for {self._model_path}: {e}"
                ) from e
            if actual != self._expected_sha256:
                raise ClassifierUnavailable(
                    f"artifact hash mismatch for {self._model_path}: "
                    f"expected {self._expected_sha256}, got {actual}"
                )
            logger.info("classifier artifact hash verified", extra={"sha256": actual})

        try:
            self._backend = _TransformersBackend(self._model_path, self._max_tokens, self._device)
        except ClassifierUnavailable as e:
            self._degraded_reason = str(e)
            raise
        logger.info("classifier loaded", extra={"path": str(self._model_path)})

    def set_backend_for_tests(self, backend: _InferenceBackend) -> None:
        """Inject a test backend without touching torch/transformers."""
        self._backend = backend
        self._degraded_reason = None
        self._prediction_failure_sticky = False

    def is_available(self) -> bool:
        """True iff a prediction can currently be served.

        Returns False if either (a) the model was never successfully loaded, or
        (b) a previous prediction failed and set the sticky-degradation flag.
        """
        return self._backend is not None and not self._prediction_failure_sticky

    @property
    def degraded_reason(self) -> str | None:
        """Human-readable reason the classifier is unavailable, if any."""
        return self._degraded_reason

    def predict(self, text: str) -> float:
        """Return the classifier's jailbreak probability for `text`.

        Args:
            text: Text to score. Callers pass the canonical (normalized) form.

        Returns:
            Probability in [0.0, 1.0].

        Raises:
            ClassifierUnavailable: If the classifier was never loaded or a
                previous load failed. The pipeline catches this and marks the
                verdict as `degraded=true`.
        """
        if self._backend is None or self._prediction_failure_sticky:
            raise ClassifierUnavailable(self._degraded_reason or "classifier not loaded")
        try:
            proba = self._backend.predict_proba(text)
        except ClassifierUnavailable as e:
            # Sticky-mark so /health flips to degraded and stays there until
            # an operator restarts the process. ADR-002 covers this.
            self._prediction_failure_sticky = True
            self._degraded_reason = str(e)
            raise
        # Defense-in-depth: clamp in case a backend misbehaves.
        if proba < 0.0:
            return 0.0
        if proba > 1.0:
            return 1.0
        return proba


def build_classifier_from_settings(settings: Any) -> Classifier:
    """Construct (but do not load) a Classifier from a Settings object.

    Kept as a small factory so tests can build classifiers directly without
    going through the Settings machinery.
    """
    return Classifier(
        model_path=settings.classifier_model_path,
        max_tokens=settings.classifier_max_tokens,
        device=settings.classifier_device,
        expected_sha256=settings.classifier_model_sha256,
    )
