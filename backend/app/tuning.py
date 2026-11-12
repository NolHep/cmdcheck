"""Detection tuning: every number an admin may adjust, in one place.

The pipeline has two kinds of knowledge. *What* a command does lives in the
classifier rules and decoders — code, reviewed and tested. *How much that
matters* lives here: class weights, score thresholds, bonuses, and per-rule
enable/precision overrides. This half is data, editable from the admin tuner
and stored in `site_settings`, so a noisy rule can be turned down the minute
it misfires in production instead of waiting for a deploy.

Tuning is global by construction (CLAUDE.md invariant #1): there is one
active configuration for the whole site, never one per user or workspace.
Verdicts are persisted on the analysis row, so retuning changes how *new*
analyses score and leaves existing permalinks exactly as they were.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

logger = logging.getLogger(__name__)

SETTING_KEY = "detection_tuning"

# Severity weight per class — how damaging the behaviour is *if the detection
# is true*. Independent of per-rule confidence (= how likely it is true).
DEFAULT_CLASS_WEIGHTS: dict[str, float] = {
    "impact": 1.8,            # ransomware / disk wipe / recovery destruction
    "credential_theft": 1.6,
    "loader": 1.5,
    # High-confidence evasion (AMSI patch, Defender disable, log wiping) is
    # near-certain malicious; weighted so a lone high-conf hit reaches malicious.
    "defense_evasion": 1.5,
    "privilege_escalation": 1.5,
    "dropper": 1.4,
    "c2_persistence": 1.4,
    "lateral_movement": 1.3,
    "data_staging": 1.2,
    "recon": 0.6,             # noisy, low-severity on its own
}


class RuleOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # None keeps the precision written in the rule.
    precision: float | None = Field(default=None, ge=0.05, le=1.0)


class Tuning(BaseModel):
    """The complete, validated set of adjustable detection parameters."""

    model_config = ConfigDict(extra="forbid")

    class_weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_CLASS_WEIGHTS))

    # Points a class contributes before weighting, by confidence.
    points_low: float = Field(default=1.0, ge=0, le=20)
    points_medium: float = Field(default=4.0, ge=0, le=30)
    points_high: float = Field(default=10.0, ge=0, le=50)

    # Score at which each verdict tier starts.
    threshold_notable: float = Field(default=3.0, ge=0.5, le=50)
    threshold_suspicious: float = Field(default=7.0, ge=1, le=80)
    threshold_malicious: float = Field(default=14.0, ge=2, le=100)

    # Extra weight per real decode layer a signal was hidden under.
    depth_step: float = Field(default=0.4, ge=0, le=2)
    # Bonus per additional independent class (high counts 1, medium 0.5).
    correlation_bonus: float = Field(default=5.0, ge=0, le=20)
    # Encoded payload with no other finding: base + step per extra layer.
    encoding_base: float = Field(default=3.0, ge=0, le=20)
    encoding_step: float = Field(default=1.0, ge=0, le=10)
    # Arguments resemble a documented LOLBAS abuse example.
    lolbas_abuse_points: float = Field(default=5.0, ge=0, le=20)
    lolbas_abuse_similarity: float = Field(default=0.68, ge=0.4, le=1.0)
    # A known-abusable binary is merely present and nothing else fired.
    lolbin_presence_points: float = Field(default=2.0, ge=0, le=10)
    # Known-vulnerable driver referenced (BYOVD).
    loldrivers_points: float = Field(default=12.0, ge=0, le=50)
    # Distinct discovery commands in one paste that count as a burst.
    recon_burst: int = Field(default=4, ge=2, le=20)

    # rule id -> override. Only rules that differ from their defaults appear.
    rules: dict[str, RuleOverride] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> Tuning:
        if not (self.threshold_notable < self.threshold_suspicious < self.threshold_malicious):
            raise ValueError("thresholds must increase: notable < suspicious < malicious")
        if not (self.points_low <= self.points_medium <= self.points_high):
            raise ValueError("confidence points must not decrease: low <= medium <= high")
        unknown = set(self.class_weights) - set(DEFAULT_CLASS_WEIGHTS)
        if unknown:
            raise ValueError(f"unknown threat class: {', '.join(sorted(unknown))}")
        for name, weight in self.class_weights.items():
            if not 0 <= weight <= 5:
                raise ValueError(f"weight for {name} must be between 0 and 5")
        # A class left out keeps its default weight.
        self.class_weights = {**DEFAULT_CLASS_WEIGHTS, **self.class_weights}
        # Drop overrides that restate the default.
        self.rules = {
            rid: ov for rid, ov in self.rules.items() if not ov.enabled or ov.precision is not None
        }
        return self

    def confidence_points(self, confidence: str) -> float:
        return {"low": self.points_low, "medium": self.points_medium, "high": self.points_high}.get(
            confidence, self.points_low
        )


DEFAULT = Tuning()
_active: Tuning = DEFAULT


def get_active() -> Tuning:
    return _active


def set_active(tuning: Tuning | None) -> None:
    global _active
    _active = tuning or DEFAULT


def is_default(tuning: Tuning) -> bool:
    return tuning.model_dump() == DEFAULT.model_dump()


def dumps(tuning: Tuning) -> str:
    return json.dumps(tuning.model_dump(), sort_keys=True)


def loads(raw: str | None) -> Tuning:
    """Parse stored tuning. Anything unreadable falls back to defaults: a bad
    row in `site_settings` must never take detection down."""
    if not raw:
        return DEFAULT
    try:
        data: Any = json.loads(raw)
        return Tuning.model_validate(data)
    except Exception as exc:  # noqa: BLE001
        logger.error("Stored detection tuning is invalid, using defaults: %s", exc)
        return DEFAULT
