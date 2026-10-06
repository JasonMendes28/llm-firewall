"""Detection pipeline orchestrator — the single entry point for the API layer.

Flow per request:
    1. Hash raw prompt + record length (for audit correlation, never returned as text).
    2. Normalize (Unicode NFKC, zero-width strip, homoglyph collapse, decoded probes).
    3. Regex evaluation on canonical + probes.
    4. Classifier prediction on canonical (best-effort; degrades gracefully).
       Runs off-thread in async mode to prevent event-loop blocking.
    5. Fusion + mode routing.
    6. Emit an immutable Verdict.
    7. Record Prometheus observability metrics.

Timing is measured for every stage but only surfaced to the caller when
DEBUG_TIMING is enabled (see ADR-010).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass

from firewall.api.metrics import (
    RISK_SCORE_HISTOGRAM,
    RULES_MATCHED_TOTAL,
    STAGE_DURATION_SECONDS,
    VERDICTS_TOTAL,
)
from firewall.config import BlockingMode
from firewall.detection.classifier import Classifier, ClassifierUnavailable
from firewall.detection.fusion import FusionInput, fuse
from firewall.detection.normalizer import normalize
from firewall.detection.regex_engine import RegexEngine
from firewall.detection.verdict import LatencyBreakdown, Verdict

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    """Runtime knobs for the pipeline. Mirrors the relevant Settings fields."""

    block_threshold: float
    warn_threshold: float
    mode: BlockingMode
    capture_timing: bool


class DetectionPipeline:
    """Orchestrates normalization -> regex -> classifier -> fusion -> verdict."""

    def __init__(
        self,
        regex_engine: RegexEngine,
        classifier: Classifier,
        config: PipelineConfig,
    ) -> None:
        """Wire up the pipeline.

        Args:
            regex_engine: Preloaded regex engine.
            classifier: Preloaded classifier.
            config: Runtime configuration.
        """
        self._regex = regex_engine
        self._classifier = classifier
        self._config = config

    def _record_metrics(
        self, verdict: Verdict, t_norm: float, t_reg: float, t_clf: float, t_fus: float
    ) -> None:
        """Record Prometheus stage timings and verdict statistics."""
        try:
            STAGE_DURATION_SECONDS.labels(stage="normalize").observe(t_norm / 1000.0)
            STAGE_DURATION_SECONDS.labels(stage="regex").observe(t_reg / 1000.0)
            STAGE_DURATION_SECONDS.labels(stage="classifier").observe(t_clf / 1000.0)
            STAGE_DURATION_SECONDS.labels(stage="fusion").observe(t_fus / 1000.0)

            VERDICTS_TOTAL.labels(
                action=verdict.action_taken.value,
                mode=verdict.mode,
                degraded=str(verdict.degraded).lower(),
            ).inc()

            RISK_SCORE_HISTOGRAM.labels(action=verdict.action_taken.value).observe(
                verdict.risk_score
            )

            for rule_id in verdict.matched_rule_ids:
                RULES_MATCHED_TOTAL.labels(rule_id=rule_id).inc()
        except Exception:  # noqa: BLE001, S110
            # Telemetry failures must never disrupt security verdict emission
            pass

    def analyze(self, prompt: str, request_id: str | None = None) -> Verdict:
        """Run the full detection pipeline synchronously against a single prompt.

        Args:
            prompt: The user prompt.
            request_id: Optional correlation ID.

        Returns:
            An immutable Verdict describing the outcome.
        """
        req_id = request_id or str(uuid.uuid4())
        t_start = time.perf_counter()

        prompt_hash = "sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        prompt_length = len(prompt)

        # 1. Normalize
        t0 = time.perf_counter()
        normalized = normalize(prompt)
        t_normalize = (time.perf_counter() - t0) * 1000.0

        # 2. Regex
        t0 = time.perf_counter()
        regex_result = self._regex.evaluate(normalized)
        t_regex = (time.perf_counter() - t0) * 1000.0

        # 3. Classifier — synchronous best effort
        classifier_prob: float | None = None
        degraded = False
        t0 = time.perf_counter()
        try:
            classifier_prob = self._classifier.predict(normalized.canonical)
        except ClassifierUnavailable as e:
            degraded = True
            logger.warning(
                "classifier_unavailable_degraded_mode",
                extra={"request_id": req_id, "reason": str(e)},
            )
        t_classifier = (time.perf_counter() - t0) * 1000.0

        # 4. Fusion
        t0 = time.perf_counter()
        fusion_out = fuse(
            FusionInput(
                regex_max_severity=regex_result.max_severity_weight,
                classifier_prob=classifier_prob,
                evasion_signal_count=len(normalized.evasion_signals),
            ),
            block_threshold=self._config.block_threshold,
            warn_threshold=self._config.warn_threshold,
            mode=self._config.mode,
        )
        t_fusion = (time.perf_counter() - t0) * 1000.0
        t_total = (time.perf_counter() - t_start) * 1000.0

        latency: LatencyBreakdown | None = None
        if self._config.capture_timing:
            latency = LatencyBreakdown(
                total_ms=round(t_total, 3),
                normalize_ms=round(t_normalize, 3),
                regex_ms=round(t_regex, 3),
                classifier_ms=round(t_classifier, 3),
                fusion_ms=round(t_fusion, 3),
            )

        verdict = Verdict(
            request_id=req_id,
            allowed=fusion_out.allowed,
            action_taken=fusion_out.action,
            risk_score=round(fusion_out.risk_score, 4),
            classifier_confidence=(
                round(classifier_prob, 4) if classifier_prob is not None else None
            ),
            matched_rule_ids=regex_result.matched_rule_ids,
            mode=self._config.mode.value,
            degraded=degraded,
            prompt_hash=prompt_hash,
            prompt_length=prompt_length,
            latency=latency,
        )
        self._record_metrics(verdict, t_normalize, t_regex, t_classifier, t_fusion)
        return verdict

    async def analyze_async(self, prompt: str, request_id: str | None = None) -> Verdict:
        """Run the full detection pipeline asynchronously.

        Offloads CPU-heavy classifier inference to the thread pool to keep the
        asyncio event loop non-blocking and responsive.
        """
        req_id = request_id or str(uuid.uuid4())
        t_start = time.perf_counter()

        prompt_hash = "sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        prompt_length = len(prompt)

        # 1. Normalize
        t0 = time.perf_counter()
        normalized = normalize(prompt)
        t_normalize = (time.perf_counter() - t0) * 1000.0

        # 2. Regex
        t0 = time.perf_counter()
        regex_result = self._regex.evaluate(normalized)
        t_regex = (time.perf_counter() - t0) * 1000.0

        # 3. Classifier — non-blocking off-thread execution
        classifier_prob: float | None = None
        degraded = False
        t0 = time.perf_counter()
        try:
            classifier_prob = await asyncio.to_thread(
                self._classifier.predict, normalized.canonical
            )
        except ClassifierUnavailable as e:
            degraded = True
            logger.warning(
                "classifier_unavailable_degraded_mode",
                extra={"request_id": req_id, "reason": str(e)},
            )
        t_classifier = (time.perf_counter() - t0) * 1000.0

        # 4. Fusion
        t0 = time.perf_counter()
        fusion_out = fuse(
            FusionInput(
                regex_max_severity=regex_result.max_severity_weight,
                classifier_prob=classifier_prob,
                evasion_signal_count=len(normalized.evasion_signals),
            ),
            block_threshold=self._config.block_threshold,
            warn_threshold=self._config.warn_threshold,
            mode=self._config.mode,
        )
        t_fusion = (time.perf_counter() - t0) * 1000.0
        t_total = (time.perf_counter() - t_start) * 1000.0

        latency: LatencyBreakdown | None = None
        if self._config.capture_timing:
            latency = LatencyBreakdown(
                total_ms=round(t_total, 3),
                normalize_ms=round(t_normalize, 3),
                regex_ms=round(t_regex, 3),
                classifier_ms=round(t_classifier, 3),
                fusion_ms=round(t_fusion, 3),
            )

        verdict = Verdict(
            request_id=req_id,
            allowed=fusion_out.allowed,
            action_taken=fusion_out.action,
            risk_score=round(fusion_out.risk_score, 4),
            classifier_confidence=(
                round(classifier_prob, 4) if classifier_prob is not None else None
            ),
            matched_rule_ids=regex_result.matched_rule_ids,
            mode=self._config.mode.value,
            degraded=degraded,
            prompt_hash=prompt_hash,
            prompt_length=prompt_length,
            latency=latency,
        )
        self._record_metrics(verdict, t_normalize, t_regex, t_classifier, t_fusion)
        return verdict
