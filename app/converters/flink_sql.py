from __future__ import annotations

from typing import Any, Dict, Mapping

from app.converters.base import BaseConverterAdapter
from app.models.enums import RuleTargetFormat


class FlinkSQLConverter(BaseConverterAdapter):
    """Converter that produces a Flink SQL query."""

    target_format = RuleTargetFormat.FLINK_SQL

    def convert(
        self, payload: Mapping[str, Any], *, expression: str, options: Dict[str, Any]
    ) -> str:
        merged_options = self.merge_options(options)
        table_name = merged_options.get("table", "event_stream")
        limit_clause = ""
        if "limit" in merged_options:
            limit_clause = f" LIMIT {int(merged_options['limit'])}"
        return f"SELECT * FROM {table_name} WHERE {expression}{limit_clause};"
