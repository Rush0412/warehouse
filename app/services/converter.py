from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping

from app.converters.aviator import AviatorConverter
from app.converters.base import BaseConverterAdapter
from app.converters.flink_cep import FlinkCEPConverter
from app.converters.flink_sql import FlinkSQLConverter
from app.models.enums import RuleTargetFormat
from app.models.requests import (
    BatchRuleConversionRequest,
    RuleConversionRequest,
)
from app.services.parser import SigmaParserService
from app.utils.errors import SigmaServiceError


@dataclass
class ConversionResult:
    """Represents a single conversion result."""

    format: RuleTargetFormat
    query: str


class SigmaConverterRegistry:
    """Registry that stores converter adapters for target formats."""

    def __init__(self) -> None:
        self._registry: Dict[RuleTargetFormat, BaseConverterAdapter] = {}

    def register(self, adapter: BaseConverterAdapter) -> None:
        self._registry[adapter.target_format] = adapter

    def get(self, target_format: RuleTargetFormat) -> BaseConverterAdapter:
        if target_format not in self._registry:
            raise SigmaServiceError(
                f"No converter registered for target format '{target_format}'."
            )
        return self._registry[target_format]


class DetectionExpressionBuilder:
    """Utility that converts sigma detection definitions into boolean expressions."""

    LOGICAL_KEYWORDS = {"and", "or", "not", "AND", "OR", "NOT"}

    def build(self, detection: Mapping[str, Any]) -> str:
        if not detection:
            raise SigmaServiceError("Sigma rule detection section is missing.")

        selections = {
            key: self._build_selection_expression(value)
            for key, value in detection.items()
            if key != "condition"
        }

        condition = detection.get("condition")
        if condition is None:
            if len(selections) == 1:
                return next(iter(selections.values()))
            return " OR ".join(f"({expr})" for expr in selections.values())

        condition = condition.strip()
        special_match = re.match(r"(\d+|all) of (.+)", condition, re.IGNORECASE)
        if special_match:
            count_str, pattern = special_match.groups()
            matched_expr = self._resolve_pattern(pattern.strip(), selections)
            if count_str.lower() == "all":
                return " AND ".join(f"({expr})" for expr in matched_expr)
            try:
                count = int(count_str)
            except ValueError as exc:  # pragma: no cover - defensive guard
                raise SigmaServiceError("Invalid occurrence count in detection condition.") from exc
            if count <= 1:
                return " OR ".join(f"({expr})" for expr in matched_expr)
            return f"AT_LEAST_{count}(" + ", ".join(matched_expr) + ")"

        token_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")

        def replace_token(match: re.Match[str]) -> str:
            token = match.group(0)
            if token in self.LOGICAL_KEYWORDS:
                return token.upper()
            if token in selections:
                return f"({selections[token]})"
            return token

        replaced = token_pattern.sub(replace_token, condition)
        return replaced

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_pattern(
        self, pattern: str, selections: Mapping[str, str]
    ) -> List[str]:
        matched = [expr for name, expr in selections.items() if fnmatch.fnmatch(name, pattern)]
        if not matched:
            raise SigmaServiceError(
                f"Detection condition references '{pattern}' but no matching selections were found."
            )
        return matched

    def _build_selection_expression(self, data: Any) -> str:
        if isinstance(data, Mapping):
            clauses = [self._field_expression(field, value) for field, value in data.items()]
            return " AND ".join(clauses)
        if isinstance(data, list):
            return " OR ".join(f"({self._build_selection_expression(item)})" for item in data)
        raise SigmaServiceError("Unsupported selection structure encountered during conversion.")

    def _field_expression(self, field: str, value: Any) -> str:
        base_field, operator = self._split_field_operator(field)
        if isinstance(value, list):
            expressions = [self._field_expression(field, item) for item in value]
            return " OR ".join(f"({expr})" for expr in expressions)
        if operator == "contains":
            return f"CONTAINS({base_field}, '{value}')"
        if operator == "startswith":
            return f"STARTS_WITH({base_field}, '{value}')"
        if operator == "endswith":
            return f"ENDS_WITH({base_field}, '{value}')"
        if operator == "re":
            return f"REGEXP({base_field}, '{value}')"
        if operator == "wildcard":
            return f"LIKE({base_field}, '{value}')"
        return f"{base_field} = '{value}'"

    def _split_field_operator(self, field: str) -> tuple[str, str]:
        if "|" not in field:
            return field, "equals"
        base, operator = field.split("|", 1)
        return base, operator


class SigmaConverterService:
    """Coordinates sigma rule conversions leveraging registered adapters."""

    def __init__(self, parser_service: SigmaParserService) -> None:
        self.parser_service = parser_service
        self.registry = SigmaConverterRegistry()
        self.expression_builder = DetectionExpressionBuilder()
        self._register_default_adapters()

    def _register_default_adapters(self) -> None:
        self.registry.register(AviatorConverter())
        self.registry.register(FlinkSQLConverter())
        self.registry.register(FlinkCEPConverter())

    def convert_rule(
        self, request: RuleConversionRequest
    ) -> ConversionResult:
        parsed = self.parser_service.parse_payload(request.payload)
        if isinstance(parsed, list):
            raise SigmaServiceError(
                "Multiple sigma rules detected; please use the batch conversion endpoint."
            )
        detection = parsed.get("detection") if isinstance(parsed, Mapping) else None
        if not detection:
            raise SigmaServiceError("Sigma rule is missing the detection definition.")
        expression = self.expression_builder.build(detection)
        adapter = self.registry.get(request.target_format)
        query = adapter.convert(parsed, expression=expression, options=request.options)
        return ConversionResult(format=request.target_format, query=query)

    def convert_batch(
        self, request: BatchRuleConversionRequest
    ) -> List[ConversionResult]:
        results: List[ConversionResult] = []
        for item in request.rules:
            single_request = RuleConversionRequest(
                payload=item.payload,
                target_format=request.target_format,
                options=item.options,
            )
            results.append(self.convert_rule(single_request))
        return results


__all__ = [
    "SigmaConverterService",
    "SigmaConverterRegistry",
    "DetectionExpressionBuilder",
    "ConversionResult",
]
