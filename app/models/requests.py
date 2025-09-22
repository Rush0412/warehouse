from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, root_validator

from .enums import RuleProcessingMode, RuleTargetFormat


class SigmaRulePayload(BaseModel):
    """Container for raw or pre-parsed sigma rule data."""

    rule_yaml: Optional[str] = Field(
        default=None, description="Raw sigma rule definition in YAML format."
    )
    parsed_rule: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Parsed sigma rule representation that adheres to the sigma specification.",
    )

    @root_validator(pre=True)
    def _ensure_payload(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        rule_yaml = values.get("rule_yaml")
        parsed_rule = values.get("parsed_rule")
        if not rule_yaml and not parsed_rule:
            raise ValueError("Either 'rule_yaml' or 'parsed_rule' must be provided.")
        return values


class RuleParseRequest(BaseModel):
    """Request payload for parsing a sigma rule."""

    rule_yaml: str = Field(..., description="Sigma rule definition in YAML format.")


class RuleParseResponse(BaseModel):
    """Response structure for parsed sigma rules."""

    parsed: Any
    errors: Optional[List[str]] = None


class RuleValidationRequest(BaseModel):
    """Request payload for validating sigma rules."""

    rule_yaml: str = Field(..., description="Sigma rule definition in YAML format.")


class RuleValidationResponse(BaseModel):
    """Response structure for sigma rule validation results."""

    valid: bool
    errors: Optional[List[str]] = None


class RuleConversionRequest(BaseModel):
    """Request payload for converting sigma rules to a target format."""

    payload: SigmaRulePayload = Field(..., description="Sigma rule payload to convert.")
    target_format: RuleTargetFormat = Field(
        ..., description="Target rule format for conversion."
    )
    processing_mode: RuleProcessingMode = Field(
        default=RuleProcessingMode.SINGLE,
        description="Processing mode, reserved for future use to extend conversion flows.",
    )
    options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional conversion options such as namespace or table name.",
    )


class BatchRuleConversionItem(BaseModel):
    """Single entry for batch conversion requests."""

    payload: SigmaRulePayload
    options: Dict[str, Any] = Field(default_factory=dict)


class BatchRuleConversionRequest(BaseModel):
    """Batch conversion payload supporting multiple rules at once."""

    target_format: RuleTargetFormat
    rules: List[BatchRuleConversionItem]

    @root_validator
    def _ensure_rules(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        rules = values.get("rules")
        if not rules:
            raise ValueError("At least one rule must be provided for batch conversion.")
        return values
