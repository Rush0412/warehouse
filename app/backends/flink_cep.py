from __future__ import annotations

from typing import Any

from sigma.rule import SigmaRule
from sigma.conversion.state import ConversionState

from .base import SimpleTextBackend


class FlinkCEPBackend(SimpleTextBackend):
    """Generate simplified Flink CEP pattern expressions."""

    name = "Flink CEP Backend"

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Any,
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> str:
        base_query = super().finalize_query(rule, query, index, state, output_format)
        pattern_name = self.backend_options.get("pattern_name") or "A"
        within = self.backend_options.get("within")
        within_clause = f" WITHIN {within}" if within else ""
        return f"PATTERN SEQ({pattern_name}){within_clause} WHERE {pattern_name}.{base_query}"
