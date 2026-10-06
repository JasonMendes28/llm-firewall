"""Fine-tune DistilBERT for jailbreak / prompt-injection classification.

Reproducibility contract:
- Seeds are pinned (Python, NumPy, torch).
- Dataset splits are stratified and seeded.
- The final artifact's SHA-256 is printed so operators can pin it via
  CLASSIFIER_MODEL_SHA256 in the runtime config.

Usage:
    python models/train.py \
        --data ./data/combined.jsonl \
        --output ./models/artifact \
        --epochs 3

Data format: one JSON object per line with fields:
    { "text": "<prompt>", "label": 0 | 1 }

This script deliberately keeps hyperparameters explicit and simple — this is a
detection model, not a research artifact. If you need better numbers, curate
better data first before tuning hyperparameters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import sys
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("train")


@dataclass(frozen=True)
class TrainArgs:
    """Parsed command-line arguments."""

    data: Path
    output: Path
    epochs: int
    batch_size: int
    learning_rate: float
    seed: int
    max_length: int
    base_model: str


def parse_args(argv: list[str] | None = None) -> TrainArgs:
    """Parse CLI arguments into a TrainArgs dataclass."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True, help="JSONL dataset path")
    p.add_argument("--output", type=Path, required=True, help="Output artifact dir")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=16)
    p.add_argument("--learning-rate", type=float, default=2e-5)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument("--base-model", type=str, default="distilbert-base-uncased")
    ns = p.parse_args(argv)
    return TrainArgs(
        data=ns.data,
        output=ns.output,
        epochs=ns.epochs,
        batch_size=ns.batch_size,
        learning_rate=ns.learning_rate,
        seed=ns.seed,
        max_length=ns.max_length,
        base_model=ns.base_model,
    )


def _seed_all(seed: int) -> None:
    """Seed Python, NumPy, and torch RNGs for reproducibility."""
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def load_jsonl(path: Path) -> list[dict[str, object]]:
    """Load a JSONL file with fields {text, label}. Rejects malformed rows loudly."""
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{i}: invalid JSON: {e}") from e
            if not isinstance(obj, dict) or "text" not in obj or "label" not in obj:
                raise ValueError(f"{path}:{i}: expected object with 'text' and 'label'")
            if obj["label"] not in (0, 1):
                raise ValueError(f"{path}:{i}: label must be 0 or 1")
            if not isinstance(obj["text"], str):
                raise ValueError(f"{path}:{i}: text must be string")
            rows.append(obj)
    if not rows:
        raise ValueError(f"{path}: dataset is empty")
    return rows


def sha256_of_dir(path: Path) -> str:
    """SHA-256 over sorted directory contents. Matches the runtime pin check."""
    h = hashlib.sha256()
    for p in sorted(path.rglob("*")):
        if not p.is_file():
            continue
        h.update(p.relative_to(path).as_posix().encode("utf-8"))
        h.update(b"\x00")
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a shell exit code."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args(argv)
    _seed_all(args.seed)

    # Heavy imports deferred so `--help` works without torch installed.
    try:
        import numpy as np
        import torch
        from sklearn.metrics import (
            accuracy_score,
            f1_score,
            precision_recall_fscore_support,
        )
        from sklearn.model_selection import train_test_split
        from torch.utils.data import DataLoader, Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            get_linear_schedule_with_warmup,
        )
    except ImportError as e:
        logger.error("missing dependency: %s", e)
        return 2

    rows = load_jsonl(args.data)
    texts = [r["text"] for r in rows]
    labels = [int(r["label"]) for r in rows]  # type: ignore[arg-type]

    train_x, val_x, train_y, val_y = train_test_split(
        texts, labels, test_size=0.15, random_state=args.seed, stratify=labels
    )
    logger.info(
        "dataset: %d rows | train %d | val %d | pos-rate %.3f",
        len(rows),
        len(train_x),
        len(val_x),
        sum(labels) / len(labels),
    )

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)

    class _Ds(Dataset):
        def __init__(self, xs: list[str], ys: list[int]) -> None:
            self.xs = xs
            self.ys = ys

        def __len__(self) -> int:
            return len(self.xs)

        def __getitem__(self, i: int) -> dict[str, torch.Tensor]:
            enc = tokenizer(
                self.xs[i],
                truncation=True,
                max_length=args.max_length,
                padding="max_length",
                return_tensors="pt",
            )
            return {
                "input_ids": enc["input_ids"].squeeze(0),
                "attention_mask": enc["attention_mask"].squeeze(0),
                "labels": torch.tensor(self.ys[i], dtype=torch.long),
            }

    train_loader = DataLoader(_Ds(train_x, train_y), batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(_Ds(val_x, val_y), batch_size=args.batch_size)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, num_labels=2)
    model.to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=total_steps // 10, num_training_steps=total_steps
    )

    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        for step, batch in enumerate(train_loader, start=1):
            batch = {k: v.to(device) for k, v in batch.items()}
            optimizer.zero_grad()
            out = model(**batch)
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            running += out.loss.item()
            if step % 50 == 0:
                logger.info("epoch %d step %d loss %.4f", epoch, step, running / step)

        # Validation.
        model.eval()
        preds: list[int] = []
        golds: list[int] = []
        with torch.no_grad():
            for batch in val_loader:
                batch = {k: v.to(device) for k, v in batch.items()}
                logits = model(**batch).logits
                preds.extend(logits.argmax(dim=-1).cpu().numpy().tolist())
                golds.extend(batch["labels"].cpu().numpy().tolist())
        acc = accuracy_score(golds, preds)
        f1 = f1_score(golds, preds)
        p, r, _, _ = precision_recall_fscore_support(
            golds, preds, average="binary", zero_division=0
        )
        logger.info(
            "epoch %d validation: acc=%.4f precision=%.4f recall=%.4f f1=%.4f",
            epoch,
            acc,
            p,
            r,
            f1,
        )

    args.output.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)
    artifact_hash = sha256_of_dir(args.output)
    logger.info("saved artifact to %s", args.output)
    logger.info("SHA-256: %s", artifact_hash)
    logger.info("Set CLASSIFIER_MODEL_SHA256=%s in .env to enable pinning.", artifact_hash)
    return 0


if __name__ == "__main__":
    sys.exit(main())
