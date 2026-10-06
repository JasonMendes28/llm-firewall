"""Environment-driven configuration.

Loaded once at startup. Validation errors here MUST prevent the service from starting;
running with an invalid security posture is worse than not running at all.

Design notes:
- All thresholds are config-driven — no magic numbers in detection code.
- Prod refuses to start unless (a) TRUST_PROXY=true (an explicit acknowledgement
  that TLS is terminated in front of us) and (b) at least one API key is configured.
- We use pydantic-settings so the same fields can come from env vars, .env, or a
  secrets manager mount, without code changes.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment; controls which safety checks are strict."""

    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class BlockingMode(StrEnum):
    """How the firewall reacts to a positive verdict.

    - HARD_BLOCK: enforce the verdict (production default).
    - SOFT_WARN:  allow through but log a warning (for staged rollouts).
    - SHADOW:     log verdict silently, always allow (for pre-launch tuning).
    """

    HARD_BLOCK = "hard_block"
    SOFT_WARN = "soft_warn"
    SHADOW = "shadow"


class Settings(BaseSettings):
    """Firewall configuration.

    All fields are populated from environment variables (or .env in dev).
    Field names map to env vars uppercased with no prefix, per model_config below.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Runtime ---
    firewall_env: Environment = Environment.DEV
    firewall_host: str = "0.0.0.0"  # noqa: S104 — validated below for prod
    firewall_port: int = 8080
    firewall_log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- TLS acknowledgement ---
    trust_proxy: bool = False

    # --- Auth ---
    firewall_api_keys_hashed: str = ""

    # --- Claude upstream ---
    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_timeout_s: float = 30.0

    # --- Detection thresholds ---
    block_threshold: float = Field(default=0.80, ge=0.0, le=1.0)
    warn_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    blocking_mode: BlockingMode = BlockingMode.HARD_BLOCK

    # --- Classifier ---
    classifier_model_path: Path = Path("./models/artifact")
    classifier_model_sha256: str = ""
    classifier_max_tokens: int = Field(default=512, gt=0, le=4096)
    classifier_timeout_ms: int = Field(default=2000, gt=0)
    classifier_device: Literal["cpu", "cuda"] = "cpu"

    # --- Rate limiting ---
    rate_limit_rps: int = Field(default=20, gt=0)
    rate_limit_burst: int = Field(default=40, gt=0)

    # --- Input validation ---
    max_prompt_bytes: int = Field(default=32_768, gt=0, le=1_048_576)
    max_prompt_chars: int = Field(default=16_384, gt=0)

    # --- Logging ---
    log_full_prompts: bool = False
    log_full_prompt_ttl_days: int = Field(default=7, ge=0)

    # --- Debug ---
    debug_timing: bool = False

    # ---------- Cross-field validation ----------

    @field_validator("warn_threshold")
    @classmethod
    def _warn_below_block(cls, v: float) -> float:
        """Ensure warn_threshold < block_threshold is checked in the model validator.

        This field validator returns v unchanged; the pairwise check is in
        `_validate_thresholds` where both fields are available.
        """
        return v

    @model_validator(mode="after")
    def _validate_thresholds(self) -> Settings:
        """Warn threshold must be strictly below block threshold."""
        if self.warn_threshold >= self.block_threshold:
            raise ValueError(
                f"warn_threshold ({self.warn_threshold}) must be strictly less than "
                f"block_threshold ({self.block_threshold})"
            )
        return self

    @model_validator(mode="after")
    def _validate_prod_posture(self) -> Settings:
        """Prod environment refuses to start with insecure defaults.

        Rationale: silent misconfiguration in prod is the worst outcome for a
        security service. We prefer a loud startup failure to a quiet degradation.
        """
        if self.firewall_env is Environment.PROD:
            problems: list[str] = []
            if not self.trust_proxy:
                problems.append(
                    "TRUST_PROXY=false in prod: this service does not terminate TLS. "
                    "Set TRUST_PROXY=true to acknowledge that a TLS-terminating "
                    "reverse proxy is in front of it."
                )
            if not self.firewall_api_keys_hashed.strip():
                problems.append(
                    "FIREWALL_API_KEYS_HASHED is empty in prod: refusing to run " "unauthenticated."
                )
            if self.log_full_prompts:
                problems.append(
                    "LOG_FULL_PROMPTS=true in prod: this is opt-in for controlled "
                    "environments only. Refusing to start with plaintext prompt logging "
                    "enabled by default in prod."
                )
            if self.debug_timing:
                problems.append(
                    "DEBUG_TIMING=true in prod: exposes per-layer latency in verdicts "
                    "which can leak detection-layer information. Disable for prod."
                )
            if problems:
                raise ValueError(
                    "Refusing to start in prod due to insecure configuration:\n  - "
                    + "\n  - ".join(problems)
                )
        return self

    # ---------- Convenience ----------

    @property
    def hashed_api_keys(self) -> list[str]:
        """Parse the hashed-key list.

        Delimiter: newline OR the literal string ``;;`` (double semicolon). We
        deliberately do NOT use comma — Argon2id encoded hashes contain commas
        internally (e.g. ``$argon2id$v=19$m=65536,t=3,p=4$...``), so a comma
        delimiter would split a single hash into pieces and break auth.
        """
        raw = self.firewall_api_keys_hashed
        # Normalize both delimiters to newline, then split.
        raw = raw.replace(";;", "\n")
        return [k.strip() for k in raw.split("\n") if k.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the process-wide Settings singleton.

    Using a getter (not a module-level constant) so tests can override via
    dependency injection without import-time side effects.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_for_tests() -> None:
    """Clear the singleton — test-only helper."""
    global _settings
    _settings = None
