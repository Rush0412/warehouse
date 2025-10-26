from __future__ import annotations

from typing import Any, Dict, Mapping

from app.converters.base import BaseConverterAdapter
from app.models.enums import RuleTargetFormat


class AviatorConverter(BaseConverterAdapter):
    """Simplified Aviator query converter."""

    target_format = RuleTargetFormat.AVIATOR

    def convert(
        self, payload: Mapping[str, Any], *, expression: str, options: Dict[str, Any]
    ) -> str:
        merged_options = self.merge_options(options)
        namespace = merged_options.get("namespace", "default")
        dataset = merged_options.get(
            "dataset", payload.get("logsource", {}).get("product", "events")
        )
        rule_title = payload.get("title", "sigma_rule")

        query_lines = [f"NAMESPACE {namespace}", f"DATASET {dataset}"]
        query_lines.append(f"FILTER {expression}")
        query_lines.append(f"// title: {rule_title}")
        return "\n".join(query_lines)
