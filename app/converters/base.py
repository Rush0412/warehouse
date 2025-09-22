from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Mapping

from app.models.enums import RuleTargetFormat


class BaseConverterAdapter(ABC):
    """Base interface for sigma rule conversion adapters."""

    target_format: RuleTargetFormat

    def __init__(self, *, default_options: Dict[str, Any] | None = None) -> None:
        self.default_options = default_options or {}

    @abstractmethod
    def convert(self, payload: Mapping[str, Any], *, expression: str, options: Dict[str, Any]) -> str:
        """Convert sigma rule payload into the target format."""

    def merge_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        merged = {**self.default_options, **(options or {})}
        return merged
