"""Red-team report generator.

Runs the full detection pipeline against the shipped attack + benign corpora
and computes precision / recall / F1 / false-positive rate. Emits a JSON report
suitable for CI upload and for embedding in the security writeup.

Two modes:
- **Regex-only** (default): classifier stubbed to a fixed benign score. This
  measures what the deterministic layer alone catches — a lower bound on what
  the deployed system will catch.
- **With classifier** (`--classifier-heuristic`): a lightweight keyword-based
  stand-in for the real DistilBERT model. Not a substitute for evaluating a
  trained model, but it exercises the fusion path end-to-end.

The real trained-model numbers should come from `models/evaluate.py` — this
generator is deliberately independent of PyTorch so it can run in any CI.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from firewall.config import BlockingMode
from firewall.detection.classifier import Classifier
from firewall.detection.pipeline import DetectionPipeline, PipelineConfig
from firewall.detection.regex_engine import RegexEngine, load_rules
from firewall.detection.verdict import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "tests" / "redteam" / "corpus"
RULES_PATH = REPO_ROOT / "rules" / "default_rules.yaml"


@dataclass(frozen=True)
class CorpusStats:
    """Aggregate counts + metrics for a corpus split."""

    name: str
    n: int
    positives: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


@dataclass(frozen=True)
class CategoryStats:
    """Detection rate per attack category — useful for the writeup."""

    category: str
    n: int
    detected: int
    detection_rate: float


class _FixedBackend:
    """Classifier stub that returns a constant probability."""

    def __init__(self, p: float) -> None:
        self._p = p

    def predict_proba(self, text: str) -> float:  # noqa: ARG002
        return self._p


class _KeywordHeuristicBackend:
    """Very small keyword heuristic — a stand-in when no trained model exists.

    Deliberately weak so the report doesn't over-claim the classifier's power.
    """

    _HOT = (
        "jailbreak",
        "uncensored",
        "no restrictions",
        "ignore",
        "system prompt",
        "bypass",
        "dan",
        "do anything now",
        "developer mode",
    )

    def predict_proba(self, text: str) -> float:
        low = text.casefold()
        hits = sum(1 for w in self._HOT if w in low)
        return min(1.0, 0.2 * hits)


def _load_jsonl(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _build_pipeline(backend_factory: Callable[[], object]) -> DetectionPipeline:
    engine = RegexEngine(load_rules(RULES_PATH))
    clf = Classifier(model_path=Path("/tmp/nowhere"))
    clf.set_backend_for_tests(backend_factory())  # type: ignore[arg-type]
    return DetectionPipeline(
        engine,
        clf,
        PipelineConfig(
            block_threshold=0.8,
            warn_threshold=0.5,
            mode=BlockingMode.HARD_BLOCK,
            capture_timing=True,
        ),
    )


def _evaluate_split(
    pipeline: DetectionPipeline,
    rows: list[dict[str, str]],
    label: int,
) -> tuple[list[Verdict], list[int]]:
    """Run the pipeline over all rows and return verdicts + expected labels."""
    verdicts: list[Verdict] = []
    golds: list[int] = []
    for row in rows:
        v = pipeline.analyze(row["text"])
        verdicts.append(v)
        golds.append(label)
    return verdicts, golds


def _confusion(preds: list[int], golds: list[int]) -> tuple[int, int, int, int]:
    tp = sum(1 for p, g in zip(preds, golds, strict=True) if p == 1 and g == 1)
    fp = sum(1 for p, g in zip(preds, golds, strict=True) if p == 1 and g == 0)
    fn = sum(1 for p, g in zip(preds, golds, strict=True) if p == 0 and g == 1)
    tn = sum(1 for p, g in zip(preds, golds, strict=True) if p == 0 and g == 0)
    return tp, fp, fn, tn


def _metrics(name: str, preds: list[int], golds: list[int]) -> CorpusStats:
    tp, fp, fn, tn = _confusion(preds, golds)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return CorpusStats(
        name=name,
        n=len(preds),
        positives=sum(golds),
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        false_positive_rate=round(fpr, 4),
    )


def _per_category(rows: list[dict[str, str]], verdicts: list[Verdict]) -> list[CategoryStats]:
    """Detection rate broken down by attack category."""
    from collections import defaultdict

    totals: dict[str, int] = defaultdict(int)
    detected: dict[str, int] = defaultdict(int)
    for row, v in zip(rows, verdicts, strict=True):
        cat = row.get("category", "uncategorized")
        totals[cat] += 1
        if not v.allowed:
            detected[cat] += 1
    return [
        CategoryStats(
            category=cat,
            n=totals[cat],
            detected=detected[cat],
            detection_rate=round(detected[cat] / totals[cat], 4) if totals[cat] else 0.0,
        )
        for cat in sorted(totals)
    ]


def _latency_percentiles(verdicts: list[Verdict]) -> dict[str, float]:
    """Return p50/p95/p99 of total pipeline latency in ms."""
    times = sorted(v.latency.total_ms for v in verdicts if v.latency is not None)
    if not times:
        return {}

    def _p(pct: float) -> float:
        # Nearest-rank percentile — simple and enough for a report.
        idx = min(len(times) - 1, max(0, int(round(pct * (len(times) - 1)))))
        return round(times[idx], 3)

    return {
        "p50_ms": _p(0.50),
        "p95_ms": _p(0.95),
        "p99_ms": _p(0.99),
        "min_ms": round(times[0], 3),
        "max_ms": round(times[-1], 3),
        "n": len(times),
    }


def run(use_classifier_heuristic: bool) -> dict[str, object]:
    """Run the full red-team suite and return a JSON-serializable report."""
    backend_factory = (
        _KeywordHeuristicBackend if use_classifier_heuristic else lambda: _FixedBackend(0.05)
    )
    pipeline = _build_pipeline(backend_factory)  # type: ignore[arg-type]

    attacks_direct = _load_jsonl(CORPUS_DIR / "attacks_direct.jsonl")
    attacks_obf = _load_jsonl(CORPUS_DIR / "attacks_obfuscated.jsonl")
    attacks_mt = _load_jsonl(CORPUS_DIR / "attacks_multiturn.jsonl")
    benign = _load_jsonl(CORPUS_DIR / "benign_lookalikes.jsonl")

    v_direct, g_direct = _evaluate_split(pipeline, attacks_direct, 1)
    v_obf, g_obf = _evaluate_split(pipeline, attacks_obf, 1)
    v_mt, g_mt = _evaluate_split(pipeline, attacks_mt, 1)
    v_benign, g_benign = _evaluate_split(pipeline, benign, 0)

    all_verdicts = v_direct + v_obf + v_mt + v_benign
    all_golds = g_direct + g_obf + g_mt + g_benign
    all_preds = [0 if v.allowed else 1 for v in all_verdicts]

    overall = _metrics("overall", all_preds, all_golds)

    per_split = {
        "direct": _metrics("direct", [0 if v.allowed else 1 for v in v_direct], g_direct),
        "obfuscated": _metrics("obfuscated", [0 if v.allowed else 1 for v in v_obf], g_obf),
        "multiturn": _metrics("multiturn", [0 if v.allowed else 1 for v in v_mt], g_mt),
        "benign_lookalikes": _metrics(
            "benign_lookalikes", [0 if v.allowed else 1 for v in v_benign], g_benign
        ),
    }

    per_category = {
        "direct": [asdict(s) for s in _per_category(attacks_direct, v_direct)],
        "obfuscated": [asdict(s) for s in _per_category(attacks_obf, v_obf)],
        "multiturn": [asdict(s) for s in _per_category(attacks_mt, v_mt)],
        "benign_lookalikes": [asdict(s) for s in _per_category(benign, v_benign)],
    }

    latency = _latency_percentiles(all_verdicts)

    # False negatives — sample of missed attacks, hash-only per audit policy.
    missed = [
        {"prompt_hash": v.prompt_hash, "prompt_length": v.prompt_length}
        for v in (v_direct + v_obf + v_mt)
        if v.allowed
    ]
    # False positives — benign lookalikes we blocked (candidates for rule tuning).
    false_positives = [
        {"prompt_hash": v.prompt_hash, "prompt_length": v.prompt_length}
        for v in v_benign
        if not v.allowed
    ]

    return {
        "config": {
            "block_threshold": 0.8,
            "warn_threshold": 0.5,
            "mode": "hard_block",
            "classifier": "keyword_heuristic" if use_classifier_heuristic else "stub_benign",
        },
        "overall": asdict(overall),
        "per_split": {k: asdict(v) for k, v in per_split.items()},
        "per_category": per_category,
        "latency_ms": latency,
        "sample_false_negatives_hashes": missed,
        "sample_false_positives_hashes": false_positives,
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point for direct invocation."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--classifier-heuristic", action="store_true")
    p.add_argument("--output", type=Path, default=REPO_ROOT / "tests" / "redteam" / "report.json")
    ns = p.parse_args(argv)

    report = run(use_classifier_heuristic=ns.classifier_heuristic)
    ns.output.parent.mkdir(parents=True, exist_ok=True)
    ns.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
