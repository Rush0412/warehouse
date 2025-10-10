from __future__ import annotations

from typing import Any

from sigma.rule import SigmaRule
from sigma.conversion.state import ConversionState

from .base import SimpleTextBackend


class FlinkSQLBackend(SimpleTextBackend):
    """Generate Flink SQL statements via pySigma conversion."""

    name = "Flink SQL Backend"

    wildcard_match_expression = "{field} LIKE {value}"

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Any,
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> str:
        base_query = super().finalize_query(rule, query, index, state, output_format)
        table_name = self.backend_options.get("table") or "event_stream"
        limit = self.backend_options.get("limit")
        limit_clause = f" LIMIT {int(limit)}" if isinstance(limit, (int, float, str)) and str(limit).isdigit() else ""
        return f"SELECT * FROM {table_name} WHERE {base_query}{limit_clause};"
