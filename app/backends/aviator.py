from __future__ import annotations

from typing import Any

from sigma.rule import SigmaRule
from sigma.conversion.state import ConversionState

from .base import SimpleTextBackend


class AviatorBackend(SimpleTextBackend):
    """Generate Aviator style queries using the pySigma backend pipeline."""

    name = "Aviator Backend"
    or_token = "||"
    and_token = "&&"
    not_token = "!"
    eq_token = " == "

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Any,
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> str:
        base_query = super().finalize_query(rule, query, index, state, output_format)
        namespace = self.backend_options.get("namespace") or "default"
        dataset = (
            self.backend_options.get("dataset")
            or getattr(rule.logsource, "product", None)
            or "events"
        )
        title = rule.title or "sigma_rule"
        return "\n".join(
            [
                f"{base_query}",
            ]
        )
