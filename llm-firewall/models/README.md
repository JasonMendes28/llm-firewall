# Classifier Model — Training & Provenance

## Purpose
Fine-tune DistilBERT (`distilbert-base-uncased`) as a binary classifier:
label `1` = jailbreak/prompt-injection, label `0` = benign.

## Data sources
Positives (adversarial prompts) — combined and deduplicated:
- **JailbreakBench** (`walledai/JailbreakHub`) — public jailbreak dataset.
- **HarmBench** prompts (public split only — behavior tags not required for us).
- **PromptInject** dataset (Perez & Ribeiro 2022).
- **"Do Anything Now" (DAN)** community collection.

Negatives (benign prompts):
- **ShareGPT** conversations (first turn only, English-detected).
- **Alpaca** instruction dataset.

Sampling target: ~1:1 positive/negative ratio in the training split. Held-out
red-team split (`tests/redteam/corpus/`) is **never** seen during training or
validation — it is drawn from independent sources for the final report.

## Reproducibility
- Random seed pinned in `train.py`.
- Model artifact SHA-256 is computed and printed at the end of training. Set
  `CLASSIFIER_MODEL_SHA256` in `.env` to this value to enable pinning.

## Ethics / licensing note
All datasets used are publicly available for research. Redistribution of
attack prompts within this repo is limited to the small red-team corpus in
`tests/redteam/corpus/`, which contains only prompts that are already widely
public.

## Not committed
Model weights are **not** stored in git. Run `python models/train.py` to
produce them locally, or download from an internal artifact store as documented
in the deployment runbook.
