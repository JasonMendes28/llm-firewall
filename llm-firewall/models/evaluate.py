"""Evaluate a trained classifier on a held-out dataset.

Emits precision, recall, F1, and the false-positive rate — the numbers we
publish in the red-team report.

Usage:
    python models/evaluate.py \
        --model ./models/artifact \
        --data ./tests/redteam/corpus/held_out.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from models.train import load_jsonl  # reuse loader for identical validation

logger = logging.getLogger("evaluate")


@dataclass(frozen=True)
class EvalArgs:
    """Parsed CLI args for evaluation."""

    model: Path
    data: Path
    batch_size: int
    max_length: int
    threshold: float
    output_json: Path | None


def parse_args(argv: list[str] | None = None) -> EvalArgs:
    """Parse CLI arguments."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", type=Path, required=True)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Decision threshold on P(jailbreak). Matches config's block/warn threshold.",
    )
    p.add_argument("--output-json", type=Path, default=None)
    ns = p.parse_args(argv)
    return EvalArgs(
        model=ns.model,
        data=ns.data,
        batch_size=ns.batch_size,
        max_length=ns.max_length,
        threshold=ns.threshold,
        output_json=ns.output_json,
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a shell exit code."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args(argv)

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as e:
        logger.error("missing dependency: %s", e)
        return 2

    rows = load_jsonl(args.data)
    texts = [r["text"] for r in rows]
    golds = [int(r["label"]) for r in rows]  # type: ignore[arg-type]

    tokenizer = AutoTokenizer.from_pretrained(str(args.model))
    model = AutoModelForSequenceClassification.from_pretrained(str(args.model))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device).eval()

    probs: list[float] = []
    with torch.no_grad():
        for i in range(0, len(texts), args.batch_size):
            batch_texts = texts[i : i + args.batch_size]
            enc = tokenizer(
                batch_texts,
                return_tensors="pt",
                truncation=True,
                max_length=args.max_length,
                padding=True,
            ).to(device)
            logits = model(**enc).logits
            batch_probs = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy().tolist()
            probs.extend(batch_probs)

    preds = [1 if p >= args.threshold else 0 for p in probs]

    tp = sum(1 for p, g in zip(preds, golds, strict=True) if p == 1 and g == 1)
    fp = sum(1 for p, g in zip(preds, golds, strict=True) if p == 1 and g == 0)
    fn = sum(1 for p, g in zip(preds, golds, strict=True) if p == 0 and g == 1)
    tn = sum(1 for p, g in zip(preds, golds, strict=True) if p == 0 and g == 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    report = {
        "n": len(rows),
        "threshold": args.threshold,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }
    logger.info("evaluation: %s", json.dumps(report))
    if args.output_json:
        args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logger.info("wrote %s", args.output_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
