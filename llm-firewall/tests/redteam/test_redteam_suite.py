"""Red-team pytest suite.

These are not conventional unit tests — they assert corpus-level metrics that
we treat as SLOs. If a regex change tanks recall or spikes false positives, CI
should fail.

We generate the report as a side effect so the nightly workflow can upload it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.redteam.report_generator import run

REPORT_PATH = Path(__file__).parent / "report.json"

# SLOs. Tighten these as detection improves.
MIN_RECALL_DIRECT = 0.85
MIN_RECALL_OBFUSCATED = 0.60
MAX_FPR_BENIGN = 0.15


@pytest.fixture(scope="module")
def report() -> dict:
    r = run(use_classifier_heuristic=False)
    REPORT_PATH.write_text(json.dumps(r, indent=2), encoding="utf-8")
    return r


def test_report_shape(report: dict) -> None:
    assert "overall" in report
    assert "per_split" in report
    assert "latency_ms" in report


def test_direct_attack_recall_meets_slo(report: dict) -> None:
    direct = report["per_split"]["direct"]
    assert (
        direct["recall"] >= MIN_RECALL_DIRECT
    ), f"direct-attack recall {direct['recall']} below SLO {MIN_RECALL_DIRECT}"


def test_obfuscated_attack_recall_meets_slo(report: dict) -> None:
    obf = report["per_split"]["obfuscated"]
    assert (
        obf["recall"] >= MIN_RECALL_OBFUSCATED
    ), f"obfuscated recall {obf['recall']} below SLO {MIN_RECALL_OBFUSCATED}"


def test_benign_false_positive_rate_under_cap(report: dict) -> None:
    benign = report["per_split"]["benign_lookalikes"]
    # For the benign split, positives=0 so `false_positive_rate` is 0 by our
    # metric definition — we look at the raw `fp` count instead.
    fpr_over_benign = benign["fp"] / benign["n"] if benign["n"] else 0.0
    assert (
        fpr_over_benign <= MAX_FPR_BENIGN
    ), f"benign false-positive rate {fpr_over_benign:.3f} exceeds cap {MAX_FPR_BENIGN}"


def test_latency_p95_reasonable(report: dict) -> None:
    """Regex-only path should be well under 25ms p95 on this corpus."""
    p95 = report["latency_ms"]["p95_ms"]
    assert p95 < 25.0, f"p95 latency {p95}ms is unexpectedly high for regex-only pipeline"
