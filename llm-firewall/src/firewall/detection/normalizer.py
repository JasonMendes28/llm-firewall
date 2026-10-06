"""Input normalization and evasion-probe layer.

We produce a `NormalizedPrompt` that carries:
- `raw`: the exact bytes/chars the client sent (never mutated).
- `canonical`: NFKC-normalized, zero-width-stripped, case-folded view for detection.
- `decoded_probes`: candidate plaintext extracted from base64/hex substrings, for
  detection-layer inspection only. These are NEVER substituted back into what we
  forward upstream — see ADR-006.

The threat model here is prompt-encoding evasion: attackers hide "ignore previous
instructions" inside base64, homoglyph substitutions, zero-width characters, or
excessive whitespace. Every detection layer downstream operates on `canonical`
plus the `decoded_probes` list, not on `raw`.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# --- Constants (module-level; treated as data, not policy) ---

# Unicode "format" (Cf) characters commonly used for evasion: ZWSP, ZWNJ, ZWJ,
# BOM, LRE/RLE/PDF, etc. We categorically strip all Cf characters — legitimate
# prose does not need them, and their presence is a strong evasion signal.
_ZERO_WIDTH_CATEGORY = "Cf"

# Homoglyph normalization is largely handled by NFKC (e.g. fullwidth Latin ->
# ASCII), but we add a small explicit map for characters NFKC leaves alone.
_HOMOGLYPH_MAP = str.maketrans(
    {
        # Cyrillic look-alikes that NFKC does NOT collapse to Latin.
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        # Greek look-alikes.
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "ν": "v",
    }
)

# Base64 candidate: >=16 chars of the base64 alphabet, optional padding.
# Short base64 strings collide too often with normal tokens (e.g. random IDs),
# so we set a floor that keeps FP rate manageable while still catching real payloads.
_BASE64_CANDIDATE = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})")

# Hex candidate: >=32 hex chars (16 bytes) — same FP-rate reasoning as above.
_HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{32,})")

# Bounded probe depth: decoded output itself may contain another encoded blob.
# We recurse at most this many levels — deeper is almost certainly a DoS attempt.
_MAX_DECODE_DEPTH = 2

# Cap the total decoded content we're willing to inspect, to prevent
# amplification attacks (a small input expanding into MBs of decoded probes).
_MAX_DECODED_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class NormalizedPrompt:
    """Container for the multiple views of a prompt used by detection.

    Attributes:
        raw: Original, unmodified prompt as the client sent it.
        canonical: NFKC-normalized, zero-width-stripped, homoglyph-collapsed,
            case-folded view. This is the primary input to detection.
        decoded_probes: Plausible plaintext strings extracted from encoded
            substrings in the raw input. Bounded in count and size.
        evasion_signals: Names of evasion classes detected during normalization
            (e.g. "zero_width_chars", "homoglyphs", "base64_payload"). Used by
            the fusion layer as a small independent risk contribution.
    """

    raw: str
    canonical: str
    decoded_probes: list[str] = field(default_factory=list)
    evasion_signals: list[str] = field(default_factory=list)


def _strip_zero_width(s: str) -> tuple[str, bool]:
    """Remove all Unicode format-category characters.

    Returns:
        A tuple of (cleaned string, was_any_removed flag).
    """
    out_chars: list[str] = []
    removed = False
    for ch in s:
        if unicodedata.category(ch) == _ZERO_WIDTH_CATEGORY:
            removed = True
            continue
        out_chars.append(ch)
    return "".join(out_chars), removed


def _collapse_homoglyphs(s: str) -> tuple[str, bool]:
    """Collapse Cyrillic/Greek Latin-look-alikes to ASCII."""
    translated = s.translate(_HOMOGLYPH_MAP)
    return translated, translated != s


def _try_decode_base64(candidate: str) -> str | None:
    """Attempt to decode a base64 candidate to UTF-8.

    Returns:
        The decoded string if it looks like plausible text; None otherwise.
    """
    # Reject candidates whose length isn't a valid base64 length (must be multiple
    # of 4 after padding). Trying to decode invalid input is safe but wasteful.
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Filter to plausibly textual output: >=80% printable characters.
    if not text:
        return None
    printable_ratio = sum(1 for c in text if c.isprintable() or c.isspace()) / len(text)
    if printable_ratio < 0.80:
        return None
    return text


def _try_decode_hex(candidate: str) -> str | None:
    """Attempt to decode a hex candidate to UTF-8 printable text."""
    if len(candidate) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(candidate)
    except ValueError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable_ratio = sum(1 for c in text if c.isprintable() or c.isspace()) / len(text)
    if printable_ratio < 0.80:
        return None
    return text


def _extract_decoded_probes(text: str) -> tuple[list[str], list[str]]:
    """Extract decoded plaintext from encoded substrings, up to bounded depth.

    Returns:
        (probes, signals) where `signals` names which encoding classes were seen.
    """
    probes: list[str] = []
    signals: list[str] = []
    total_bytes = 0
    to_scan = [(text, 0)]

    while to_scan:
        current, depth = to_scan.pop()
        if depth >= _MAX_DECODE_DEPTH:
            continue

        for match in _BASE64_CANDIDATE.finditer(current):
            decoded = _try_decode_base64(match.group(0))
            if decoded:
                if "base64_payload" not in signals:
                    signals.append("base64_payload")
                total_bytes += len(decoded.encode("utf-8", errors="ignore"))
                if total_bytes > _MAX_DECODED_BYTES:
                    return probes, signals
                probes.append(decoded)
                to_scan.append((decoded, depth + 1))

        for match in _HEX_CANDIDATE.finditer(current):
            decoded = _try_decode_hex(match.group(0))
            if decoded:
                if "hex_payload" not in signals:
                    signals.append("hex_payload")
                total_bytes += len(decoded.encode("utf-8", errors="ignore"))
                if total_bytes > _MAX_DECODED_BYTES:
                    return probes, signals
                probes.append(decoded)
                to_scan.append((decoded, depth + 1))

    return probes, signals


def normalize(prompt: str) -> NormalizedPrompt:
    """Produce a NormalizedPrompt for downstream detection.

    Steps:
        1. NFKC normalize (collapses compatibility variants, e.g. fullwidth).
        2. Strip zero-width / format-category characters.
        3. Collapse residual Cyrillic/Greek homoglyphs to ASCII.
        4. Case-fold for case-insensitive matching.
        5. Extract decoded probes from base64/hex substrings (bounded).

    Args:
        prompt: The raw user prompt.

    Returns:
        A NormalizedPrompt containing the raw text, the canonical view, decoded
        probes, and a list of evasion signals seen.

    Raises:
        TypeError: If `prompt` is not a string. We prefer a loud failure to
            silent coercion.
    """
    if not isinstance(prompt, str):
        raise TypeError(f"normalize() requires str, got {type(prompt).__name__}")

    signals: list[str] = []

    # 1. NFKC.
    nfkc = unicodedata.normalize("NFKC", prompt)
    if nfkc != prompt:
        signals.append("unicode_compat_chars")

    # 2. Zero-width strip.
    stripped, zw_removed = _strip_zero_width(nfkc)
    if zw_removed:
        signals.append("zero_width_chars")

    # 3. Homoglyph collapse.
    dehomoglyphed, hg_changed = _collapse_homoglyphs(stripped)
    if hg_changed:
        signals.append("homoglyphs")

    # 4. Case-fold. `casefold()` is stronger than `lower()` for non-ASCII.
    canonical = dehomoglyphed.casefold()

    # 5. Decoded probes.
    probes, probe_signals = _extract_decoded_probes(prompt)
    # Case-fold probes too so downstream regex sees them uniformly.
    probes = [p.casefold() for p in probes]
    for s in probe_signals:
        if s not in signals:
            signals.append(s)

    return NormalizedPrompt(
        raw=prompt,
        canonical=canonical,
        decoded_probes=probes,
        evasion_signals=signals,
    )
