from __future__ import annotations

from typing import Any, Dict, Mapping

from app.converters.base import BaseConverterAdapter
from app.models.enums import RuleTargetFormat


class FlinkCEPConverter(BaseConverterAdapter):
    """Converter that emits a simplified Flink CEP pattern string."""

    target_format = RuleTargetFormat.FLINK_CEP

    def convert(
        self, payload: Mapping[str, Any], *, expression: str, options: Dict[str, Any]
    ) -> str:
        merged_options = self.merge_options(options)
        pattern_name = merged_options.get("pattern_name", "A")
        within = merged_options.get("within")
        pattern = f"PATTERN SEQ({pattern_name})"  # simplified placeholder for extensibility
        condition = f"WHERE {pattern_name}.{expression}"
        if within:
            return f"{pattern} WITHIN {within} {condition}"
        return f"{pattern} {condition}"
